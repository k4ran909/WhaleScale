package engine

import (
	"context"
	"github.com/k4ran909/whalescale/internal/store/storetest"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
)

// clusterServer is one of several servers sharing a database file.
type clusterServer struct {
	srv   *server.Server
	store *store.Store
	url   string
	stop  func() // clean shutdown, as on SIGTERM
	crash func() // gone without a word: its rows linger until they time out
}

func startClusterServer(t *testing.T, dbPath string) *clusterServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stunPC, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	quicPC, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	srv, err := server.New(st, server.Config{PublicURL: hs.URL, STUN: []string{stunPC.LocalAddr().String()},
		RelayQUICAddr: quicPC.LocalAddr().String(), Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	go srv.ServeSTUN(ctx, stunPC)
	go srv.ServeRelayQUIC(ctx, quicPC)
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); srv.Watch(ctx, 100*time.Millisecond) }()
	var once atomic.Bool
	cs := &clusterServer{srv: srv, store: st, url: hs.URL}
	cs.stop = func() {
		if !once.CompareAndSwap(false, true) {
			return
		}
		cancel()
		<-watchDone
		hs.CloseClientConnections()
		hs.Close()
		stunPC.Close()
		quicPC.Close()
		st.Close()
	}
	cs.crash = func() {
		st.Close() // so the shutdown can't tell the others it's leaving
		cs.stop()
	}
	t.Cleanup(cs.stop)
	return cs
}

func (n *testNet) nodeAt(url, name string, o Options) *Engine {
	saved := n.url
	n.url = url
	defer func() { n.url = saved }()
	return n.nodeWith(name, o)
}

// Two servers share a database. Nodes connected to either see each other,
// changes made on one reach nodes on the other, and when a server goes
// away its nodes move to the other one: direct traffic doesn't miss a
// beat, relayed traffic resumes on the surviving server's relay, and the
// leader role moves too.
func TestClusterFailover(t *testing.T) {
	t.Run("shutdown", func(t *testing.T) { testClusterFailover(t, false) })
	t.Run("crash", func(t *testing.T) { testClusterFailover(t, true) })
}

func testClusterFailover(t *testing.T, crash bool) {
	dir := tempDir(t)
	dbPath := storetest.DSN(t, dir)
	s1 := startClusterServer(t, dbPath)
	time.Sleep(50 * time.Millisecond) // s1 is the older member
	s2 := startClusterServer(t, dbPath)
	ctx := context.Background()
	s1.store.CreateUser(ctx, "alice")
	_, authKey, _ := s1.store.CreatePreAuthKey(ctx, "alice", true, false, time.Hour)
	n := &testNet{t: t, url: s1.url, authKey: authKey, log: discardLog(), store: s1.store}

	a := n.nodeAt(s1.url, "cl-a", Options{})
	b := n.nodeAt(s2.url, "cl-b", Options{})
	c := n.nodeAt(s1.url, "cl-c", Options{ForceRelay: true})
	d := n.nodeAt(s2.url, "cl-d", Options{ForceRelay: true})
	waitPath(t, a, "cl-b", "direct")
	waitPath(t, c, "cl-d", "relay")
	for _, e := range []*Engine{b, d} {
		echo(t, e, 7400)
	}

	// Presence crosses servers: a (on s1) sees b (on s2) online.
	waitFor(t, "a sees b online", func() bool {
		for _, p := range a.Status().Peers {
			if p.Name == "cl-b" {
				return p.Online
			}
		}
		return false
	})
	waitFor(t, "s1 leads", s1.srv.Leader)
	if s2.srv.Leader() {
		t.Fatal("two leaders")
	}

	// A policy saved through s2 reaches a, which is connected to s1.
	_, apiKey, _ := s1.store.CreateAPIKey(ctx, time.Hour)
	admin := whalescalev1connect.NewAdminServiceClient(httpClientForTest(), s2.url)
	req := connect.NewRequest(&v1.SetPolicyRequest{Policy: `{"acls":[{"action":"accept","src":["*"],"dst":["*:7400"]}]}`})
	req.Header().Set("Authorization", "Bearer "+apiKey)
	if _, err := admin.SetPolicy(ctx, req); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a gets the policy saved on s2", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		f := a.netmap.PacketFilter
		return len(f) == 1 && len(f[0].Ports) == 1 && f[0].Ports[0].First == 7400
	})

	// Steady traffic a -> b while s1 goes away.
	var sent, failed atomic.Int64
	stopTraffic := make(chan struct{})
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		for {
			select {
			case <-stopTraffic:
				return
			case <-time.After(100 * time.Millisecond):
			}
			sent.Add(1)
			if err := roundTrip(a, b, 7400, 2*time.Second); err != nil {
				failed.Add(1)
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	if crash {
		s1.crash()
	} else {
		s1.stop()
	}

	waitFor(t, "a moves to s2", func() bool {
		a.apiMu.Lock()
		defer a.apiMu.Unlock()
		return a.apiURL == s2.url
	})
	waitFor(t, "s2 takes over as leader", s2.srv.Leader)
	// Relayed traffic resumes once everyone is on s2's relay.
	waitFor(t, "relayed traffic resumes", func() bool { return roundTrip(c, d, 7400, 2*time.Second) == nil })
	time.Sleep(time.Second)
	close(stopTraffic)
	<-trafficDone
	if failed.Load() != 0 {
		t.Fatalf("direct traffic disrupted by the failover: %d of %d round trips failed", failed.Load(), sent.Load())
	}
	t.Logf("%d round trips across the failover, none failed", sent.Load())
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !ok(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
	}
}

func discardLog() *slog.Logger {
	if os.Getenv("WS_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
