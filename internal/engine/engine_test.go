package engine

import (
	"bufio"
	"context"
	"fmt"
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
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"

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
	return newTestNetGateway(t, policyJSON, "")
}

func newTestNetGateway(t *testing.T, policyJSON, gatewayDomain string) *testNet {
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
		GatewayDomain: gatewayDomain,
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
// briefly hold freshly written database files open. A file that stays open
// is our own leak (once a statement the SQLite driver never finalized), so
// that fails the test.
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
		t.Errorf("leaving %s behind: %v", dir, err)
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

func TestExitNode(t *testing.T) {
	n := newTestNet(t, "")
	gw := n.nodeWith("gw", Options{AdvertiseRoutes: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}})
	client := n.nodeWith("roamer", Options{ExitNode: "gw"})
	lost := n.nodeWith("lost", Options{ExitNode: "nope"})

	exitState := func(e *Engine) ExitStatus {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.exitStat == nil {
			return ExitStatus{}
		}
		return *e.exitStat
	}
	waitExit := func(e *Engine, ok func(ExitStatus) bool) ExitStatus {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			if s := exitState(e); ok(s) {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("exit status never matched: %+v", exitState(e))
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	routes := func() string {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.wgPeers[gw.nodeKey.Public()]
	}

	s := waitExit(client, func(s ExitStatus) bool { return strings.Contains(s.Problem, "not an approved exit node") })
	if s.Active || strings.Contains(routes(), "0.0.0.0/0") {
		t.Fatalf("unapproved exit node in use: %+v %q", s, routes())
	}
	waitExit(lost, func(s ExitStatus) bool { return strings.Contains(s.Problem, "no peer named nope") })

	// Approve both exit routes the way an admin would.
	ctx := context.Background()
	routesList, _ := n.store.ListRoutes(ctx)
	for _, r := range routesList {
		if r.IsExit() {
			if err := n.store.SetRouteApproved(ctx, r.NodeID, r.Prefix, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	s = waitExit(client, func(s ExitStatus) bool { return s.Active })
	if s.Name != "gw" || !strings.Contains(routes(), "allowed_ip=0.0.0.0/0") || !strings.Contains(routes(), "allowed_ip=::/0") {
		t.Fatalf("exit node not routed: %+v %q", s, routes())
	}
	if st := client.Status(); st.ExitNode == nil || !st.ExitNode.Active {
		t.Fatalf("status does not report the exit node: %+v", st.ExitNode)
	}
	// Other nodes must not pick up default routes just because one exists.
	lost.mu.Lock()
	other := lost.wgPeers[gw.nodeKey.Public()]
	lost.mu.Unlock()
	if strings.Contains(other, "0.0.0.0/0") {
		t.Fatal("a node that did not choose gw routes through it")
	}
}

func TestGateway(t *testing.T) {
	// A local service on the node: echoes what it saw.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			typ, msg, err := c.Read(r.Context())
			if err == nil {
				c.Write(r.Context(), typ, append([]byte("echo: "), msg...))
			}
			return
		}
		fmt.Fprintf(w, "hello %s %s xff=%s", r.Host, r.URL.Path, r.Header.Get("X-Forwarded-For"))
	}))
	defer backend.Close()
	_, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	n := newTestNetGateway(t, "", "apps.test")
	n.nodeWith("nas", Options{Exposures: map[string]uint16{"ha": uint16(port)}})

	get := func(host, path string) (int, string) {
		req, _ := http.NewRequest("GET", n.url+path, nil)
		req.Host = host
		resp, err := httpClientForTest().Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Wait for the exposure to reach the server; it isn't live yet.
	ctx := context.Background()
	var nasID uint64
	deadline := time.Now().Add(10 * time.Second)
	for nasID == 0 {
		if e, err := n.store.ExposureByName(ctx, "ha"); err == nil && e.Advertised && e.NodeName == "nas" {
			nasID = e.NodeID
		}
		if time.Now().After(deadline) {
			t.Fatal("exposure never advertised")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Names are first come, first served: a second machine asking for the
	// same one is refused (checked at the end).
	other := n.nodeWith("other", Options{Exposures: map[string]uint16{"ha": 9999}})
	if code, _ := get("ha.apps.test", "/"); code != http.StatusNotFound {
		t.Fatalf("unapproved exposure answered %d", code)
	}
	if code, _ := get(strings.TrimPrefix(n.url, "http://"), "/gateway/ask?domain=ha.apps.test"); code != http.StatusNotFound {
		t.Fatalf("ask approved an unapproved name: %d", code)
	}

	if err := n.store.SetExposureApproved(ctx, nasID, "ha", true); err != nil {
		t.Fatal(err)
	}
	var code int
	var body string
	deadline = time.Now().Add(15 * time.Second)
	for {
		code, body = get("ha.apps.test", "/lights")
		if code == http.StatusOK || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != http.StatusOK || !strings.HasPrefix(body, "hello ha.apps.test /lights xff=") || strings.HasSuffix(body, "xff=") {
		t.Fatalf("published service: %d %q", code, body)
	}
	// WebSockets (used by Home Assistant and many dashboards) pass through.
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	wc, _, err := websocket.Dial(wctx, "ws"+strings.TrimPrefix(n.url, "http")+"/ws", &websocket.DialOptions{Host: "ha.apps.test"})
	if err != nil {
		t.Fatalf("websocket through the gateway: %v", err)
	}
	wc.Write(wctx, websocket.MessageText, []byte("ping"))
	if _, msg, err := wc.Read(wctx); err != nil || string(msg) != "echo: ping" {
		t.Fatalf("websocket echo = %q, %v", msg, err)
	}
	wc.Close(websocket.StatusNormalClosure, "")

	if code, _ := get(strings.TrimPrefix(n.url, "http://"), "/gateway/ask?domain=ha.apps.test"); code != http.StatusOK {
		t.Fatalf("ask refused a live name: %d", code)
	}
	if code, _ := get("nothing.apps.test", "/"); code != http.StatusNotFound {
		t.Fatalf("unknown name answered %d", code)
	}

	// The second machine asked for the same name: it is told why it can't.
	deadline = time.Now().Add(10 * time.Second)
	for {
		var problem string
		for _, x := range other.Status().Exposures {
			if x.Name == "ha" {
				problem = x.Problem
			}
		}
		if strings.Contains(problem, "taken") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no 'taken' problem reported: %+v", other.Status().Exposures)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestPeerRelay(t *testing.T) {
	n := newTestNet(t, "")
	r := n.nodeWith("relay-vps", Options{OfferRelay: true})
	a := n.nodeWith("cgnat-a", Options{NoDirect: true})
	b := n.nodeWith("cgnat-b", Options{NoDirect: true})

	// Not approved yet: A and B can only use the server's relay.
	waitPath(t, a, "cgnat-b", "relay")
	if st := r.Status(); !strings.Contains(st.Relay, "waiting") {
		t.Fatalf("relay status before approval: %q", st.Relay)
	}

	ctx := context.Background()
	nodes, _ := n.store.ListNodes(ctx, "")
	for _, nd := range nodes {
		if nd.Name == "relay-vps" {
			if !nd.RelayOffered {
				t.Fatal("relay offer never reached the server")
			}
			if err := n.store.SetRelayApproved(ctx, nd.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}

	ps := waitPath(t, a, "cgnat-b", "peer-relay")
	if ps.Addr != "relay-vps" {
		t.Fatalf("peer relay path via %q", ps.Addr)
	}
	waitPath(t, b, "cgnat-a", "peer-relay")
	t.Logf("cgnat-a -> cgnat-b via peer relay %s (%v)", ps.Addr, ps.Latency)

	echo(t, b, 8443)
	if err := roundTrip(a, b, 8443, 10*time.Second); err != nil {
		t.Fatalf("TCP over the peer relay: %v", err)
	}
	if res, err := a.Ping(ctx, "cgnat-b"); err != nil || res.Via == "direct" {
		t.Fatalf("ping = %+v, %v", res, err)
	}

	// Taking the approval away stops relaying; traffic falls back to the
	// server relay rather than breaking.
	for _, nd := range nodes {
		if nd.Name == "relay-vps" {
			n.store.SetRelayApproved(ctx, nd.ID, false)
		}
	}
	waitPath(t, a, "cgnat-b", "relay")
	if err := roundTrip(a, b, 8443, 15*time.Second); err != nil {
		t.Fatalf("TCP after relay withdrawal: %v", err)
	}
}
