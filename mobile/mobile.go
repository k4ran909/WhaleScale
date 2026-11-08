// Package mobile is the Go side of the Android app, built into an .aar with
// 'gomobile bind'. It joins a network with a join code, keeps the device's
// identity in the app's private storage, and runs the agent engine on the
// TUN that Android's VpnService hands over.
//
// Its API sticks to the types gomobile can bind: strings, ints, errors, an
// interface the app implements (Platform) and a struct (TunnelConfig).
// Lists cross as newline-separated strings and the status as JSON.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.zx2c4.com/wireguard/tun"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/dnsserver"
	"github.com/k4ran909/whalescale/internal/engine"
	"github.com/k4ran909/whalescale/internal/joincode"
	"github.com/k4ran909/whalescale/internal/meshconn"
	"github.com/k4ran909/whalescale/internal/nodeauth"
	"github.com/k4ran909/whalescale/internal/version"
)

// Platform is implemented by the app's VpnService.
type Platform interface {
	// OpenTUN builds the VPN interface from cfg (VpnService.Builder) and
	// returns its file descriptor, detached: Go owns and closes it. It is
	// called when the tunnel starts and again whenever the routes change;
	// the previous interface is closed once the new one is in use.
	OpenTUN(cfg *TunnelConfig) (int32, error)
}

// TunnelConfig is how the VPN interface must be set up. Lists are
// newline-separated.
type TunnelConfig struct {
	// Addresses are this device's mesh addresses with prefix lengths
	// ("100.64.0.5/32"), for Builder.addAddress.
	Addresses string
	// Routes go into the tunnel ("100.64.0.0/10", approved subnets), for
	// Builder.addRoute.
	Routes string
	// DNS is the MagicDNS server, for Builder.addDnsServer.
	DNS string
	// SearchDomain is the MagicDNS suffix, for Builder.addSearchDomain.
	SearchDomain string
	MTU          int32
}

// stateFile is where a device's identity is kept, inside the app's
// private files directory.
func stateFile(dir string) string { return filepath.Join(dir, "state.json") }

var log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})) // gomobile sends stderr to logcat

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Version is the version of the Go core.
func Version() string { return version.Version }

// CheckJoinCode returns the server a join code is for, or why it isn't one.
func CheckJoinCode(code string) (string, error) {
	server, _, err := joincode.Decode(code)
	return server, err
}

// IsJoined reports whether this device has joined a network.
func IsJoined(dir string) bool {
	st, err := clientstate.Load(stateFile(dir))
	return err == nil && st != nil && st.NodeToken != ""
}

// Join registers this device with the network a join code is for (from the
// dashboard's Machines → Add device) under the given name. The machine key
// is created on the first join and kept across sign-outs.
func Join(dir, code, hostname string) error {
	server, authKey, err := joincode.Decode(code)
	if err != nil {
		return err
	}
	path := stateFile(dir)
	st, err := clientstate.Load(path)
	if err != nil {
		return err
	}
	if st != nil && st.NodeToken != "" {
		return fmt.Errorf("already joined %s as %s; sign out first", st.ServerURL, st.NodeName)
	}
	if st == nil {
		mk, err := clientstate.NewMachineKey()
		if err != nil {
			return err
		}
		st = &clientstate.State{MachineKey: mk}
	}
	st.ServerURL = strings.TrimRight(server, "/")
	pub, err := st.PublicKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	api := whalescalev1connect.NewControlServiceClient(httpClient, st.ServerURL)
	resp, err := api.Register(ctx, connect.NewRequest(&v1.RegisterRequest{
		AuthKey: authKey, MachineKey: pub, Hostname: hostname, Os: runtime.GOOS,
	}))
	if err != nil {
		return fmt.Errorf("couldn't join %s: %w", st.ServerURL, err)
	}
	if resp.Msg.AuthUrl != "" || resp.Msg.Node == nil {
		return errors.New("the server wants a browser sign-in; use a join code from Machines → Add device instead")
	}
	n := resp.Msg.Node
	st.NodeToken, st.ServerKey, st.NodeID, st.NodeName = resp.Msg.NodeToken, resp.Msg.ServerKey, n.Id, n.Name
	st.Prefs = clientstate.Prefs{AcceptRoutes: true}
	if err := clientstate.Save(path, st); err != nil {
		return fmt.Errorf("joined, but saving this device's identity failed: %w", err)
	}
	log.Info("joined", "server", st.ServerURL, "node", n.Name)
	return nil
}

// SignOut stops the tunnel, removes this device from the network and
// forgets its credentials. If the server can't be reached the device is
// still signed out here, and the error says what is left to do.
func SignOut(dir string) error {
	Stop()
	path := stateFile(dir)
	st, err := clientstate.Load(path)
	if err != nil || st == nil || st.NodeToken == "" {
		return err
	}
	creds := nodeauth.NewCredentials(st.MachineKey, st.NodeToken)
	var serverErr error
	if st.ServerKey != "" {
		serverErr = creds.SetServerKey(st.ServerKey)
	}
	if serverErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		api := whalescalev1connect.NewControlServiceClient(httpClient, st.ServerURL, connect.WithInterceptors(creds.Interceptor()))
		_, serverErr = api.Logout(ctx, connect.NewRequest(&v1.LogoutRequest{}))
		if connect.CodeOf(serverErr) == connect.CodeUnauthenticated {
			serverErr = nil // already removed there
		}
	}
	name := st.NodeName
	// Keep the machine key (as 'ws logout' does); forget the rest.
	*st = clientstate.State{MachineKey: st.MachineKey, LockTrust: st.LockTrust}
	if err := clientstate.Save(path, st); err != nil {
		return err
	}
	if serverErr != nil {
		return fmt.Errorf("signed out here, but the server couldn't be told (%v); remove %s in the dashboard", serverErr, name)
	}
	return nil
}

// The running tunnel. The VpnService and the app's screens share one
// process, so one engine serves both.
var (
	mu      sync.Mutex
	eng     *engine.Engine
	stopEng context.CancelFunc
)

// Start brings the tunnel up for the network this device joined, stopping
// any tunnel already running. osVersion is reported to the dashboard
// ("Android 15").
func Start(dir string, p Platform, osVersion string) error {
	if p == nil {
		return errors.New("no platform")
	}
	Stop()
	path := stateFile(dir)
	st, err := clientstate.Load(path)
	if err != nil {
		return err
	}
	if st == nil || st.NodeToken == "" {
		return errors.New("this device hasn't joined a network yet")
	}
	e, err := engine.New(engine.Options{
		State: st, StatePath: path, Port: engine.DefaultPort, Log: log,
		AcceptRoutes: st.Prefs.AcceptRoutes,
		Platform:     platform{p}, LocalDNS: localDNS, OSVersion: osVersion,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := e.Start(ctx); err != nil {
		cancel()
		return err
	}
	mu.Lock()
	eng, stopEng = e, cancel
	mu.Unlock()
	return nil
}

// Stop takes the tunnel down. It is safe to call when it isn't running.
func Stop() {
	mu.Lock()
	e, cancel := eng, stopEng
	eng, stopEng = nil, nil
	mu.Unlock()
	if e != nil {
		cancel()
		e.Close()
	}
}

// Status is the device's state as JSON, for the app's screens:
//
//	{"state": "logged-out" | "down" | "connecting" | "connected",
//	 "server", "name", "address", "user", "error",
//	 "peers": [{"name", "address", "os", "online", "path"}]}
//
// path is "direct", "relay", "peer-relay", "idle" or "none".
func Status(dir string) string {
	ps := clientstate.PublicStatus{Updated: time.Now(), State: "logged-out"}
	if st, err := clientstate.Load(stateFile(dir)); err == nil && st != nil && st.NodeToken != "" {
		ps.Server, ps.Name, ps.State = st.ServerURL, st.NodeName, "down"
		mu.Lock()
		e := eng
		mu.Unlock()
		if e != nil {
			fill(&ps, e.Status())
		}
	}
	b, _ := json.Marshal(ps)
	return string(b)
}

// fill adds a running engine's status to ps, as wsd does for the tray.
func fill(ps *clientstate.PublicStatus, s engine.Status) {
	ps.State, ps.Error = "connecting", s.LastError
	if s.Self == nil {
		return
	}
	ps.State, ps.Name, ps.User = "connected", s.Self.Name, s.Self.User
	if len(s.Self.Addresses) > 0 {
		ps.Address = s.Self.Addresses[0]
	}
	for _, p := range s.Peers {
		pp := clientstate.PublicPeer{Name: p.Name, OS: p.OS, Online: p.Online, Path: p.Path}
		if len(p.Addresses) > 0 {
			pp.Address = p.Addresses[0]
		}
		ps.Peers = append(ps.Peers, pp)
	}
}

// The phone's own network, as the app's ConnectivityManager reports it.
var (
	netMu    sync.Mutex
	netAddrs []net.Addr
	netDNS   []string
)

func init() {
	meshconn.SetInterfaceAddrs(func() ([]net.Addr, error) {
		netMu.Lock()
		defer netMu.Unlock()
		if len(netAddrs) == 0 {
			// Not told yet: try the system (refused on Android 11 and later).
			return net.InterfaceAddrs()
		}
		return append([]net.Addr(nil), netAddrs...), nil
	})
}

// SetNetwork tells the core about the phone's underlying network (Wi-Fi or
// mobile data, not the VPN): its addresses, with or without a prefix
// length, and its DNS servers, each newline-separated. Call it whenever the
// network changes; peers on the same Wi-Fi then connect directly, and names
// outside the mesh are looked up with those DNS servers.
func SetNetwork(addrs, dns string) {
	var as []net.Addr
	for _, s := range lines(addrs) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		a := p.Addr().WithZone("")
		as = append(as, &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(p.Bits(), a.BitLen())})
	}
	var ds []string
	for _, s := range lines(dns) {
		if a, err := netip.ParseAddr(s); err == nil {
			ds = append(ds, netip.AddrPortFrom(a, 53).String())
		}
	}
	netMu.Lock()
	netAddrs, netDNS = as, ds
	netMu.Unlock()
}

// localDNS answers the phone's lookups for names outside the mesh with
// its own DNS servers. The app isn't routed through its own VPN, so these
// queries leave by the underlying network.
func localDNS(ctx context.Context, query []byte) ([]byte, error) {
	netMu.Lock()
	ds := netDNS
	netMu.Unlock()
	return dnsserver.Upstream(ds)(ctx, query)
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// platform adapts the app's Platform to the engine's.
type platform struct{ p Platform }

func (p platform) OpenTUN(cfg engine.TunnelConfig) (tun.Device, error) {
	tc := &TunnelConfig{DNS: cfg.DNS.String(), SearchDomain: cfg.SearchDomain, MTU: int32(cfg.MTU)}
	tc.Addresses = joinPrefixes(cfg.Addresses)
	tc.Routes = joinPrefixes(cfg.Routes)
	fd, err := p.p.OpenTUN(tc)
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		return nil, errors.New("the system didn't give a VPN interface (is VPN permission granted?)")
	}
	return tunFromFD(int(fd))
}

func joinPrefixes(ps []netip.Prefix) string {
	ss := make([]string, len(ps))
	for i, p := range ps {
		ss[i] = p.String()
	}
	return strings.Join(ss, "\n")
}
