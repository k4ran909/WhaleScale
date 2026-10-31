package engine

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
)

type testNet struct {
	t       *testing.T
	url     string
	authKey string
	log     *slog.Logger
	store   *store.Store
}

func newTestNet(t *testing.T, policyJSON string) *testNet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("WS_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	dir := tempDir(t)
	st, err := store.Open(ctx, filepath.Join(dir, "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Logf("store close: %v", err)
		}
	})
	st.CreateUser(ctx, "alice")
	st.CreateUser(ctx, "bob")
	_, keyA, _ := st.CreatePreAuthKey(ctx, "alice", true, false, time.Hour)

	stunPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var policyFile string
	if policyJSON != "" {
		policyFile = filepath.Join(dir, "policy.json")
		os.WriteFile(policyFile, []byte(policyJSON), 0o600)
	}

	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	t.Cleanup(hs.Close)
	srv, err := server.New(st, server.Config{
		PublicURL: hs.URL, STUN: []string{stunPC.LocalAddr().String()}, PolicyFile: policyFile, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	go srv.ServeSTUN(ctx, stunPC)
	// Stop the watcher (and wait for it) before the store closes: cleanups
	// run last-in-first-out, and Windows can't delete an open database.
	wctx, wcancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); srv.Watch(wctx, 100*time.Millisecond) }()
	t.Cleanup(func() { wcancel(); <-watchDone })
	return &testNet{t: t, url: hs.URL, authKey: keyA, log: log, store: st}
}

// node registers a node the way 'ws login' does and starts an engine.
func (n *testNet) node(name string, forceRelay bool) *Engine {
	return n.nodeWith(name, Options{ForceRelay: forceRelay})
}

func (n *testNet) nodeWith(name string, o Options) *Engine {
	t := n.t
	t.Helper()
	mk, _ := clientstate.NewMachineKey()
	st := &clientstate.State{ServerURL: n.url, MachineKey: mk}
	pub, _ := st.PublicKey()
	api := whalescalev1connect.NewControlServiceClient(httpClientForTest(), n.url)
	resp, err := api.Register(context.Background(), connect.NewRequest(&v1.RegisterRequest{
		AuthKey: n.authKey, MachineKey: pub, Hostname: name, Os: runtime.GOOS,
	}))
	if err != nil {
		t.Fatal(err)
	}
	st.NodeToken, st.NodeID, st.NodeName = resp.Msg.NodeToken, resp.Msg.Node.Id, resp.Msg.Node.Name

	o.State, o.Userspace, o.Log, o.IncludeLoopback = st, true, n.log.With("node", name), true
	e, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	select {
	case <-e.Ready():
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no network map", name)
	}
	return e
}

func selfIP(e *Engine) netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, _ := selfAddrs(e.netmap.Self)
	return s.v4
}

// waitPath waits until e reports the wanted path to peer.
func waitPath(t *testing.T, e *Engine, peer, want string) PeerStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, p := range e.Status().Peers {
			if p.Name == peer && p.Path == want {
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s path to %s: %+v", want, peer, e.Status().Peers)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// echo listens on e's mesh address and echoes one line per connection.
func echo(t *testing.T, e *Engine, port uint16) {
	t.Helper()
	ln, err := e.Net().ListenTCPAddrPort(netip.AddrPortFrom(selfIP(e), port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "echo: "+line)
			}()
		}
	}()
}

func roundTrip(from, to *Engine, port uint16, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := from.Net().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(selfIP(to), port))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(c, "hi\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if line != "echo: hi\n" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestDirectPath(t *testing.T) {
	n := newTestNet(t, "")
	a := n.node("node-a", false)
	b := n.node("node-b", false)

	ps := waitPath(t, a, "node-b", "direct")
	t.Logf("node-a -> node-b direct via %s (%v)", ps.Addr, ps.Latency)
	waitPath(t, b, "node-a", "direct")

	echo(t, b, 8080)
	if err := roundTrip(a, b, 8080, 10*time.Second); err != nil {
		t.Fatalf("TCP over direct path: %v", err)
	}

	// MagicDNS, resolved through the tunnel by node-a's own resolver.
	addrs, err := a.Net().LookupContextHost(context.Background(), "node-b.whale.internal")
	if err != nil || !slices.Contains(addrs, selfIP(b).String()) {
		t.Fatalf("MagicDNS lookup = %v, %v", addrs, err)
	}

	r, err := a.Ping(context.Background(), "node-b")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("disco ping: %+v", r)
}

func TestRelayFallback(t *testing.T) {
	n := newTestNet(t, "")
	a := n.node("relay-a", true)
	b := n.node("relay-b", true)

	waitPath(t, a, "relay-b", "relay")
	echo(t, b, 9000)
	if err := roundTrip(a, b, 9000, 15*time.Second); err != nil {
		t.Fatalf("TCP over relay: %v", err)
	}
	for _, p := range a.Status().Peers {
		if p.Path != "relay" {
			t.Fatalf("expected relay-only path, got %+v", p)
		}
	}
}

func TestPolicyEnforced(t *testing.T) {
	// Only pol-b may open connections to pol-a; not the other way round.
	n := newTestNet(t, `{"acls":[{"action":"accept","src":["node:pol-b"],"dst":["node:pol-a:*"]}]}`)
	a := n.node("pol-a", false)
	b := n.node("pol-b", false)
	waitPath(t, a, "pol-b", "direct")

	echo(t, a, 7000)
	echo(t, b, 7000)
	if err := roundTrip(b, a, 7000, 10*time.Second); err != nil {
		t.Fatalf("allowed direction failed: %v", err)
	}
	if err := roundTrip(a, b, 7000, 2*time.Second); err == nil {
		t.Fatal("pol-a reached pol-b, but the policy forbids it")
	}
}

// tempDir is t.TempDir with a patient cleanup: on Windows, virus scanners
// briefly hold freshly written database files open.
func tempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "whalescale-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for i := 0; i < 50; i++ {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("leaving %s behind: %v", dir, err)
	})
	return dir
}

func httpClientForTest() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

func TestSubnetRoutes(t *testing.T) {
	n := newTestNet(t, "")
	lan := netip.MustParsePrefix("10.99.0.0/24")
	router := n.nodeWith("router", Options{AdvertiseRoutes: []netip.Prefix{lan}})
	client := n.nodeWith("client", Options{AcceptRoutes: true})
	plain := n.nodeWith("plain", Options{})

	// Wait for the router's advertisement to reach the server.
	ctx := context.Background()
	var routerID uint64
	deadline := time.Now().Add(10 * time.Second)
	for routerID == 0 {
		routes, _ := n.store.ListRoutes(ctx)
		for _, r := range routes {
			if r.Prefix == lan && r.Advertised {
				routerID = r.NodeID
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("route never advertised")
		}
		time.Sleep(50 * time.Millisecond)
	}

	allowed := func(e *Engine, peer *Engine) string {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.wgPeers[peer.nodeKey.Public()]
	}
	if strings.Contains(allowed(client, router), "10.99.0.0/24") {
		t.Fatal("route used before approval")
	}

	// Approve; the server notices DB changes made outside the API within 5s,
	// and nodes get a new map.
	if err := n.store.SetRouteApproved(ctx, routerID, lan, true); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for !strings.Contains(allowed(client, router), "allowed_ip=10.99.0.0/24") {
		if time.Now().After(deadline) {
			t.Fatalf("client never installed the route: %q", allowed(client, router))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if strings.Contains(allowed(plain, router), "10.99.0.0/24") {
		t.Fatal("node without --accept-routes installed the route")
	}
	// The router's filter must now accept traffic into the subnet.
	router.mu.Lock()
	var covered bool
	for _, fr := range router.netmap.PacketFilter {
		for _, d := range fr.DstPrefixes {
			covered = covered || d == lan.String()
		}
	}
	router.mu.Unlock()
	if !covered {
		t.Fatal("router's packet filter does not cover the approved subnet")
	}
}
