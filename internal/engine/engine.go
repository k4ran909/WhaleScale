// Package engine is the node agent's core: it follows the network map from
// the control server and drives WireGuard, the mesh socket, the packet
// filter, MagicDNS and OS network configuration to match.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/dnsserver"
	"github.com/k4ran909/whalescale/internal/filter"
	"github.com/k4ran909/whalescale/internal/gateway"
	"github.com/k4ran909/whalescale/internal/key"
	"github.com/k4ran909/whalescale/internal/meshconn"
	"github.com/k4ran909/whalescale/internal/osnet"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/relay"
)

const (
	MTU = 1280
	// DefaultPort is the UDP port wsd prefers, so a single router port
	// forward or firewall rule covers it.
	DefaultPort = 41641
)

var (
	meshRange4 = netip.MustParsePrefix("100.64.0.0/10")
)

type Options struct {
	State     *clientstate.State
	StatePath string
	// Userspace runs the TUN inside the process (gVisor netstack): no admin
	// rights or OS changes, but only this process can use the tunnel.
	Userspace bool
	TUNName   string
	Port      uint16
	Log       *slog.Logger
	// AdvertiseRoutes are subnets (or 0.0.0.0/0 and ::/0 to offer being an
	// exit node) this node forwards to; an admin must approve them.
	AdvertiseRoutes []netip.Prefix
	// AcceptRoutes installs subnet routes other nodes offer.
	AcceptRoutes bool
	// ExitNode names a peer (name, FQDN or mesh IP) to send all internet
	// traffic through. Traffic is dropped, not leaked, while it is
	// unavailable.
	ExitNode string
	// Exposures publishes local services (name -> localhost port) through
	// the server's gateway, once an admin approves them.
	Exposures map[string]uint16
	// Testing knobs.
	IncludeLoopback bool
	ForceRelay      bool
	HTTPClient      *http.Client
}

type Engine struct {
	opts    Options
	log     *slog.Logger
	nodeKey key.Private
	disco   key.Private
	api     whalescalev1connect.ControlServiceClient
	conn    *meshconn.Conn
	filter  *filter.Filter
	dns     *dnsserver.Server

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	netmap   *v1.NetworkMap
	dev      *device.Device
	tunDev   tun.Device
	tnet     *netstack.Net // userspace mode only
	wgPeers  map[key.Public]string
	relay    *relay.Client
	relayURL string
	osCfg    *osnet.Config
	osRoutes []netip.Prefix
	hc       *http.Client
	bypass   *osnet.Bypass
	exitRts  *osnet.ExitRoutes
	exitStat *ExitStatus
	gw       *gateway.Client
	router   *osnet.Router
	ready    chan struct{}
	lastErr  string

	epCh chan []netip.AddrPort
}

// New prepares an engine. Start runs it.
func New(opts Options) (*Engine, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	st := opts.State
	if st == nil || st.NodeToken == "" {
		return nil, errors.New("not logged in; run 'ws login' first")
	}
	if st.NodeKey == "" {
		k, err := key.NewPrivate()
		if err != nil {
			return nil, err
		}
		st.NodeKey = k.String()
		if opts.StatePath != "" {
			if err := clientstate.Save(opts.StatePath, st); err != nil {
				return nil, fmt.Errorf("save node key: %w", err)
			}
		}
	}
	nk, err := key.ParsePrivate(st.NodeKey)
	if err != nil {
		return nil, err
	}
	// The disco key is per process: nothing needs it to survive restarts.
	dk, err := key.NewPrivate()
	if err != nil {
		return nil, err
	}
	var bypass *osnet.Bypass
	if opts.ExitNode != "" && !opts.Userspace {
		bypass = osnet.NewBypass()
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{}
		if bypass != nil {
			// The control connection and relay must not follow the catch-all
			// routes into the tunnel they keep alive.
			d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: bypass.ControlDial}
			hc.Transport = &http.Transport{
				Proxy: http.ProxyFromEnvironment, DialContext: d.DialContext, ForceAttemptHTTP2: true,
				TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second,
			}
		}
	}
	e := &Engine{
		opts: opts, log: opts.Log, nodeKey: nk, disco: dk, hc: hc, bypass: bypass,
		api:     whalescalev1connect.NewControlServiceClient(hc, st.ServerURL),
		filter:  filter.New(),
		dns:     dnsserver.New(opts.Log),
		wgPeers: map[key.Public]string{},
		ready:   make(chan struct{}),
		epCh:    make(chan []netip.AddrPort, 1),
	}
	return e, nil
}

func (e *Engine) authed(req connect.AnyRequest) {
	req.Header().Set("Authorization", "Bearer "+e.opts.State.NodeToken)
}

// Start opens the mesh socket and begins following the control server.
func (e *Engine) Start(ctx context.Context) error {
	e.ctx, e.cancel = context.WithCancel(ctx)
	exclude := []netip.Prefix{meshRange4}
	if e.opts.ForceRelay {
		exclude = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	mopts := meshconn.Options{
		Port: e.opts.Port, DiscoKey: e.disco, NodeKey: e.nodeKey.Public(), Log: e.log,
		IncludeLoopback: e.opts.IncludeLoopback && !e.opts.ForceRelay,
		Exclude:         exclude,
		OnEndpoints: func(eps []netip.AddrPort) {
			select {
			case <-e.epCh:
			default:
			}
			e.epCh <- eps
		},
	}
	if e.bypass != nil {
		mopts.Control = e.bypass.ControlListen
	}
	conn, err := meshconn.New(mopts)
	if err != nil && mopts.Port != 0 {
		e.log.Warn("preferred UDP port busy; using a random one", "port", mopts.Port, "err", err)
		mopts.Port = 0
		conn, err = meshconn.New(mopts)
	}
	if err != nil {
		return err
	}
	e.conn = conn
	e.log.Info("mesh socket open", "udp_port", conn.Port(), "node_key", e.nodeKey.Public().ShortString())

	e.wg.Add(3)
	go e.endpointLoop()
	go e.mapLoop()
	go e.reportLoop()
	return nil
}

// Ready is closed once the first network map has been applied.
func (e *Engine) Ready() <-chan struct{} { return e.ready }

// Close tears everything down and restores OS settings.
func (e *Engine) Close() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exitRts != nil {
		e.exitRts.Close()
	}
	if e.router != nil {
		e.router.Close()
	}
	if e.osCfg != nil {
		osnet.Cleanup(*e.osCfg)
	}
	if e.dev != nil {
		e.dev.Close() // also closes the TUN
	}
	if e.conn != nil {
		e.conn.Close()
	}
}

func (e *Engine) updateNode(eps []netip.AddrPort) error {
	strs := make([]string, len(eps))
	for i, ep := range eps {
		strs[i] = ep.String()
	}
	var routes []string
	for _, r := range e.opts.AdvertiseRoutes {
		routes = append(routes, r.Masked().String())
	}
	var exposures []*v1.Exposure
	for name, port := range e.opts.Exposures {
		exposures = append(exposures, &v1.Exposure{Name: name, Port: uint32(port)})
	}
	req := connect.NewRequest(&v1.UpdateNodeRequest{
		NodeKey: e.nodeKey.Public().String(), DiscoKey: e.disco.Public().String(),
		Endpoints: strs, Os: runtime.GOOS, AdvertisedRoutes: routes, Exposures: exposures,
	})
	e.authed(req)
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	_, err := e.api.UpdateNode(ctx, req)
	return err
}

// endpointLoop reports our keys and endpoints, retrying until it sticks.
func (e *Engine) endpointLoop() {
	defer e.wg.Done()
	eps := e.conn.Endpoints()
	pending := true
	retry := time.NewTimer(0)
	defer retry.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case eps = <-e.epCh:
			pending = true
			retry.Reset(200 * time.Millisecond) // debounce bursts
			continue
		case <-retry.C:
		}
		if !pending {
			continue
		}
		if err := e.updateNode(eps); err != nil {
			e.log.Warn("report endpoints", "err", err)
			retry.Reset(5 * time.Second)
			continue
		}
		pending = false
	}
}

// mapLoop follows the network map stream, reconnecting with backoff.
func (e *Engine) mapLoop() {
	defer e.wg.Done()
	backoff := time.Second
	for e.ctx.Err() == nil {
		start := time.Now()
		err := e.streamOnce()
		if e.ctx.Err() != nil {
			return
		}
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			e.log.Error("control server rejected this node; run 'ws logout' and 'ws login' again", "err", err)
		} else {
			e.log.Warn("network map stream ended", "err", err)
		}
		e.mu.Lock()
		if err != nil {
			e.lastErr = err.Error()
		}
		e.mu.Unlock()
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (e *Engine) streamOnce() error {
	req := connect.NewRequest(&v1.StreamNetworkMapRequest{})
	e.authed(req)
	stream, err := e.api.StreamNetworkMap(e.ctx, req)
	if err != nil {
		return err
	}
	defer stream.Close()
	for stream.Receive() {
		msg := stream.Msg()
		if msg.KeepAlive || msg.NetworkMap == nil {
			continue
		}
		if err := e.apply(msg.NetworkMap); err != nil {
			e.log.Error("apply network map", "err", err)
			e.mu.Lock()
			e.lastErr = err.Error()
			e.mu.Unlock()
		}
	}
	return stream.Err()
}

// apply brings everything in line with a new network map.
func (e *Engine) apply(nm *v1.NetworkMap) error {
	self, err := selfAddrs(nm.Self)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dev == nil {
		if err := e.startDeviceLocked(self, nm); err != nil {
			return err
		}
	}
	e.netmap = nm

	// STUN and relay.
	var stunAddrs []netip.AddrPort
	for _, s := range nm.Stun {
		if ap, err := resolveUDP(s); err == nil {
			stunAddrs = append(stunAddrs, ap)
		} else {
			e.log.Warn("bad STUN server", "server", s, "err", err)
		}
	}
	e.conn.SetSTUNServers(stunAddrs)
	if len(nm.Relays) > 0 && nm.Relays[0] != e.relayURL {
		e.relayURL = nm.Relays[0]
		rc := relay.NewClient(e.relayURL, e.opts.State.NodeToken, e.hc, e.log)
		e.relay = rc
		e.conn.SetRelay(rc)
		e.wg.Add(1)
		go func() { defer e.wg.Done(); rc.Run(e.ctx) }()
	}

	// Gateway tunnel, for published local services.
	if nm.GatewayUrl != "" && len(e.opts.Exposures) > 0 && e.gw == nil {
		e.gw = gateway.NewClient(nm.GatewayUrl, e.opts.State.NodeToken, e.hc, e.log)
		e.gw.SetExposures(e.opts.Exposures)
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.gw.Run(e.ctx) }()
	}

	// Peers: mesh socket first, so WireGuard's endpoints resolve.
	var mpeers []meshconn.PeerConfig
	var subnets []netip.Prefix
	claimed := map[netip.Prefix]bool{}
	want := map[key.Public]string{}
	var exit *ExitStatus
	if e.opts.ExitNode != "" {
		exit = &ExitStatus{Name: e.opts.ExitNode, Problem: "no peer named " + e.opts.ExitNode}
	}
	dnsNames := map[string][]netip.Addr{nm.Self.Name: {self.v4, self.v6}}
	for _, p := range nm.Peers {
		nk, err1 := key.ParsePublic(p.NodeKey)
		dk, err2 := key.ParsePublic(p.DiscoKey)
		addrs := parseAddrs(p.Addresses)
		dnsNames[p.Name] = addrs
		if err1 != nil || err2 != nil || len(addrs) == 0 {
			continue // peer hasn't reported its keys yet
		}
		var eps []netip.AddrPort
		for _, s := range p.Endpoints {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				eps = append(eps, ap)
			}
		}
		mpeers = append(mpeers, meshconn.PeerConfig{Name: p.Name, NodeKey: nk, DiscoKey: dk, Endpoints: eps})
		var cfg strings.Builder
		for _, a := range addrs {
			fmt.Fprintf(&cfg, "allowed_ip=%s\n", netip.PrefixFrom(a, a.BitLen()))
		}
		if e.opts.AcceptRoutes {
			for _, r := range parsePrefixes(p.Routes) {
				if r.Bits() == 0 || claimed[r] {
					continue // exit routes are opt-in per node; first router wins
				}
				claimed[r] = true
				fmt.Fprintf(&cfg, "allowed_ip=%s\n", r)
				subnets = append(subnets, r)
			}
		}
		if exit != nil && matchesPeer(p, e.opts.ExitNode) {
			exit.Name = p.Name
			if !p.ExitNode {
				exit.Problem = p.Name + " is not an approved exit node"
			} else {
				// Kept while the exit node is offline too, so traffic resumes
				// the moment it returns.
				cfg.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
				if p.Online {
					exit.Problem, exit.Active = "", true
				} else {
					exit.Problem = p.Name + " is offline; internet traffic is blocked until it returns"
				}
			}
		}
		want[nk] = cfg.String()
	}
	e.conn.SetPeers(mpeers)
	if exit != nil && (e.exitStat == nil || *exit != *e.exitStat) {
		if exit.Problem != "" {
			e.log.Warn("exit node unavailable", "exit_node", exit.Name, "problem", exit.Problem)
		} else {
			e.log.Info("using exit node", "exit_node", exit.Name)
		}
	}
	e.exitStat = exit

	var uapi strings.Builder
	for k := range e.wgPeers {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&uapi, "public_key=%s\nremove=true\n", k.Hex())
		}
	}
	for k, allowed := range want {
		if e.wgPeers[k] == allowed {
			continue
		}
		fmt.Fprintf(&uapi, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n%s", k.Hex(), k.Hex(), allowed)
	}
	if uapi.Len() > 0 {
		if err := e.dev.IpcSet(uapi.String()); err != nil {
			return fmt.Errorf("configure wireguard: %w", err)
		}
	}
	e.wgPeers = want
	if err := e.syncOSRoutesLocked(subnets); err != nil {
		e.log.Warn("install subnet routes", "err", err)
	}

	// Packet filter.
	var rules []policy.Rule
	for _, fr := range nm.PacketFilter {
		var r policy.Rule
		for _, s := range fr.SrcPrefixes {
			if p, err := netip.ParsePrefix(s); err == nil {
				r.Src = append(r.Src, p)
			}
		}
		r.Dst = parsePrefixes(fr.DstPrefixes)
		for _, pr := range fr.Ports {
			r.Ports = append(r.Ports, policy.PortRange{First: uint16(pr.First), Last: uint16(pr.Last)})
		}
		rules = append(rules, r)
	}
	selfIPs := []netip.Addr{self.v4}
	if self.v6.IsValid() {
		selfIPs = append(selfIPs, self.v6)
	}
	e.filter.SetRules(rules, selfIPs)

	suffix := "whale.internal"
	if nm.Dns != nil && nm.Dns.Suffix != "" {
		suffix = nm.Dns.Suffix
	}
	e.dns.SetRecords(suffix, dnsNames)

	select {
	case <-e.ready:
	default:
		close(e.ready)
		e.log.Info("network map applied", "self", nm.Self.Name, "ipv4", self.v4, "peers", len(mpeers), "version", nm.Version)
	}
	return nil
}

type selfInfo struct{ v4, v6 netip.Addr }

func selfAddrs(n *v1.Node) (selfInfo, error) {
	var s selfInfo
	if n == nil {
		return s, errors.New("network map has no self node")
	}
	for _, a := range parseAddrs(n.Addresses) {
		if a.Is4() {
			s.v4 = a
		} else {
			s.v6 = a
		}
	}
	if !s.v4.IsValid() {
		return s, errors.New("self node has no IPv4 address")
	}
	return s, nil
}

func (e *Engine) startDeviceLocked(self selfInfo, nm *v1.NetworkMap) error {
	local := []netip.Addr{self.v4}
	if self.v6.IsValid() {
		local = append(local, self.v6)
	}
	var tdev tun.Device
	if e.opts.Userspace {
		td, tnet, err := netstack.CreateNetTUN(local, []netip.Addr{self.v4}, MTU)
		if err != nil {
			return fmt.Errorf("create userspace tun: %w", err)
		}
		tdev, e.tnet = td, tnet
		pc, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(self.v4, 53))
		if err != nil {
			return fmt.Errorf("listen for MagicDNS: %w", err)
		}
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.dns.Serve(pc) }()
		go func() { <-e.ctx.Done(); pc.Close() }()
	} else {
		name := e.opts.TUNName
		if name == "" {
			name = defaultTUNName()
		}
		td, err := tun.CreateTUN(name, MTU)
		if err != nil {
			return fmt.Errorf("create tun %q (needs admin/root; or use --tun=userspace): %w", name, err)
		}
		tdev = td
	}
	e.tunDev = tdev

	wglog := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { e.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
	}
	dev := device.NewDevice(&filteredTUN{Device: tdev, f: e.filter}, e.conn.Bind(), wglog)
	if err := dev.IpcSet("private_key=" + e.nodeKey.Hex() + "\n"); err != nil {
		dev.Close()
		return err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}
	e.dev = dev

	if !e.opts.Userspace {
		ifname, err := tdev.Name()
		if err != nil {
			return err
		}
		suffix := "whale.internal"
		if nm.Dns != nil && nm.Dns.Suffix != "" {
			suffix = nm.Dns.Suffix
		}
		route6 := netip.Prefix{}
		if self.v6.IsValid() {
			route6 = netip.PrefixFrom(self.v6, 48).Masked()
		}
		cfg := osnet.Config{Iface: ifname, IPv4: self.v4, IPv6: self.v6, Route4: meshRange4, Route6: route6,
			MTU: MTU, DNSSuffix: suffix}
		if err := osnet.Apply(cfg); err != nil {
			return fmt.Errorf("configure %s: %w", ifname, err)
		}
		// Serve MagicDNS on our own mesh address, now that the OS owns it.
		pc, err := net.ListenPacket("udp4", netip.AddrPortFrom(self.v4, 53).String())
		if err != nil {
			e.log.Warn("MagicDNS disabled: cannot listen on port 53", "err", err)
		} else {
			e.wg.Add(1)
			go func() { defer e.wg.Done(); e.dns.Serve(pc) }()
			go func() { <-e.ctx.Done(); pc.Close() }()
			cfg.DNSServer = self.v4
			if err := osnet.Apply(cfg); err != nil {
				e.log.Warn("split DNS setup failed; use IPs or 'ws ping'", "err", err)
				cfg.DNSServer = netip.Addr{}
			}
		}
		e.osCfg = &cfg
		e.log.Info("tun up", "iface", ifname, "ipv4", self.v4, "ipv6", self.v6)
		if e.opts.ExitNode != "" {
			e.bypass.SetTunnel(ifname)
			rts, err := osnet.StartExitRoutes(ifname)
			if err != nil {
				e.log.Error("could not route traffic to the exit node", "err", err)
			} else {
				e.exitRts = rts
				e.wg.Add(1)
				go e.bypassLoop()
			}
		}
		if len(e.opts.AdvertiseRoutes) > 0 {
			r, err := osnet.StartRouter(ifname, meshRange4, route6)
			if err != nil {
				e.log.Warn("subnet routing unavailable; advertised routes won't forward", "err", err)
			} else {
				e.router = r
			}
		}
	} else if len(e.opts.AdvertiseRoutes) > 0 {
		e.log.Warn("advertised routes need OS TUN mode on Linux; userspace mode can't forward")
	}
	return nil
}

// bypassLoop re-pins the agent's sockets when the physical network changes
// (Wi-Fi to Ethernet, say), so the tunnel survives it.
func (e *Engine) bypassLoop() {
	defer e.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			if e.bypass.Refresh() {
				e.log.Info("physical network changed; re-pinned the agent's sockets")
			}
		}
	}
}

// matchesPeer reports whether target names p (name, FQDN or mesh IP).
func matchesPeer(p *v1.Node, target string) bool {
	t := strings.TrimSuffix(strings.ToLower(target), ".")
	return p.Name == t || p.Fqdn == t || slices.Contains(p.Addresses, t)
}

// ExitStatus describes the exit node this node is set to use.
type ExitStatus struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Problem string `json:"problem,omitempty"`
}

// syncOSRoutesLocked makes the OS route the accepted subnets into the TUN.
func (e *Engine) syncOSRoutesLocked(want []netip.Prefix) error {
	if e.opts.Userspace || e.osCfg == nil {
		return nil // netstack's default route already covers them
	}
	have := map[netip.Prefix]bool{}
	for _, p := range e.osRoutes {
		have[p] = true
	}
	next := map[netip.Prefix]bool{}
	var errs []error
	for _, p := range want {
		next[p] = true
		if !have[p] {
			if err := osnet.AddRoute(e.osCfg.Iface, p); err != nil {
				errs = append(errs, err)
				delete(next, p)
			}
		}
	}
	for p := range have {
		if !next[p] {
			osnet.DelRoute(e.osCfg.Iface, p)
		}
	}
	e.osRoutes = e.osRoutes[:0]
	for p := range next {
		e.osRoutes = append(e.osRoutes, p)
	}
	return errors.Join(errs...)
}

// reportLoop shares path status with the server for the topology view.
func (e *Engine) reportLoop() {
	defer e.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	first := time.After(5 * time.Second)
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-first:
		case <-t.C:
		}
		var paths []*v1.PathReport
		for _, p := range e.conn.Status() {
			paths = append(paths, &v1.PathReport{
				ToNode: p.Name, Path: p.Path, Addr: p.Addr,
				LatencyMs: float64(p.Latency.Microseconds()) / 1000,
			})
		}
		req := connect.NewRequest(&v1.ReportStatusRequest{Paths: paths})
		e.authed(req)
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		if _, err := e.api.ReportStatus(ctx, req); err != nil {
			e.log.Debug("report status", "err", err)
		}
		cancel()
	}
}

func parsePrefixes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func defaultTUNName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun"
	case "windows":
		return "Whalescale"
	default:
		return "whale0"
	}
}

// Net returns the userspace network stack (userspace mode only).
func (e *Engine) Net() *netstack.Net {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tnet
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func resolveUDP(hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
	}
	ua, err := net.ResolveUDPAddr("udp4", hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// --- status and diagnostics, used by the local API ---

type PeerStatus struct {
	Name      string   `json:"name"`
	FQDN      string   `json:"fqdn"`
	User      string   `json:"user"`
	Addresses []string `json:"addresses"`
	OS        string   `json:"os"`
	Online    bool     `json:"online"`
	Routes    []string `json:"routes,omitempty"`
	ExitNode  bool     `json:"exit_node,omitempty"`
	meshconn.PeerStatus
}

type Status struct {
	// State is "running", or "stopped" while the tunnel is down.
	State          string         `json:"state"`
	Self           *v1.Node       `json:"self"`
	Peers          []PeerStatus   `json:"peers"`
	RelayURL       string         `json:"relay_url"`
	RelayConnected bool           `json:"relay_connected"`
	Endpoints      []string       `json:"endpoints"`
	Userspace      bool           `json:"userspace"`
	LastError      string         `json:"last_error,omitempty"`
	MapVersion     uint64         `json:"map_version"`
	ExitNode       *ExitStatus    `json:"exit_node,omitempty"`
	Exposures      []*v1.Exposure `json:"exposures,omitempty"`
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	nm, relayURL, rc, lastErr := e.netmap, e.relayURL, e.relay, e.lastErr
	e.mu.Unlock()
	st := Status{State: "running", RelayURL: relayURL, Userspace: e.opts.Userspace, LastError: lastErr}
	if rc != nil {
		st.RelayConnected = rc.Connected()
	}
	for _, ep := range e.conn.Endpoints() {
		st.Endpoints = append(st.Endpoints, ep.String())
	}
	if nm == nil {
		return st
	}
	st.Self, st.MapVersion, st.Exposures = nm.Self, nm.Version, nm.Exposures
	e.mu.Lock()
	if e.exitStat != nil {
		x := *e.exitStat
		st.ExitNode = &x
	}
	e.mu.Unlock()
	paths := map[string]meshconn.PeerStatus{}
	for _, ps := range e.conn.Status() {
		paths[ps.NodeKey] = ps
	}
	for _, p := range nm.Peers {
		ps := PeerStatus{Name: p.Name, FQDN: p.Fqdn, User: p.User, Addresses: p.Addresses, OS: p.Os, Online: p.Online,
			Routes: p.Routes, ExitNode: p.ExitNode}
		if path, ok := paths[p.NodeKey]; ok {
			ps.PeerStatus = path
		} else {
			ps.PeerStatus.Path = "none"
		}
		ps.PeerStatus.Name = p.Name
		st.Peers = append(st.Peers, ps)
	}
	slices.SortFunc(st.Peers, func(a, b PeerStatus) int { return strings.Compare(a.Name, b.Name) })
	return st
}

// findPeer resolves a name, FQDN or mesh IP to a peer.
func (e *Engine) findPeer(target string) (*v1.Node, error) {
	e.mu.Lock()
	nm := e.netmap
	e.mu.Unlock()
	if nm == nil {
		return nil, errors.New("no network map yet")
	}
	t := strings.TrimSuffix(strings.ToLower(target), ".")
	for _, p := range nm.Peers {
		if p.Name == t || p.Fqdn == t || slices.Contains(p.Addresses, t) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no peer named %q (or not visible under the access policy)", target)
}

type PingResult struct {
	Peer string `json:"peer"`
	meshconn.PingResult
}

// Ping runs a disco ping to a peer and reports which path answered.
func (e *Engine) Ping(ctx context.Context, target string) (PingResult, error) {
	p, err := e.findPeer(target)
	if err != nil {
		return PingResult{}, err
	}
	nk, err := key.ParsePublic(p.NodeKey)
	if err != nil {
		return PingResult{}, fmt.Errorf("peer %s has not come online yet", p.Name)
	}
	r, err := e.conn.Ping(ctx, nk)
	return PingResult{Peer: p.Name, PingResult: r}, err
}

func (e *Engine) Netcheck(ctx context.Context) meshconn.NetcheckReport {
	return e.conn.Netcheck(ctx)
}

// Lookup resolves a MagicDNS name.
func (e *Engine) Lookup(name string) ([]netip.Addr, bool) { return e.dns.Lookup(name) }
