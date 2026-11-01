package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/localapi"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

// network starts a server and registers one machine on it, returning the
// machine's state as 'ws login' would save it.
func network(t *testing.T, hostname string) *clientstate.State {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	t.Cleanup(hs.Close)
	srv, err := server.New(st, server.Config{PublicURL: hs.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	st.CreateUser(ctx, "me")
	_, key, _ := st.CreatePreAuthKey(ctx, "me", false, false, time.Hour)
	mk, _ := clientstate.NewMachineKey()
	state := &clientstate.State{ServerURL: hs.URL, MachineKey: mk}
	pub, _ := state.PublicKey()
	resp, err := whalescalev1connect.NewControlServiceClient(hs.Client(), hs.URL).Register(ctx,
		connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: pub, Hostname: hostname}))
	if err != nil {
		t.Fatal(err)
	}
	state.NodeToken, state.NodeID, state.NodeName = resp.Msg.NodeToken, resp.Msg.Node.Id, resp.Msg.Node.Name
	return state
}

// One machine, two networks: switching moves the tunnel from one to the
// other, each with its own identity.
func TestProfileSwitch(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "state.json")
	t.Setenv("WHALESCALE_SOCKET", filepath.Join(os.TempDir(), "ws-prof-"+filepath.Base(dir)+".sock"))
	if err := clientstate.Save(base, network(t, "home-pc")); err != nil {
		t.Fatal(err)
	}
	if err := clientstate.Save(clientstate.ProfilePath(base, "work"), network(t, "work-pc")); err != nil {
		t.Fatal(err)
	}

	d := New(Options{StatePath: base, Userspace: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	lc := localapi.NewClient(localapi.SocketPath(base))
	waitSelf := func(want string) {
		t.Helper()
		var name string
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if s, err := lc.Status(); err == nil && s.Self != nil {
				if name = s.Self.Name; name == want {
					return
				}
			}
		}
		t.Fatalf("connected as %q, want %q", name, want)
	}

	for i := 0; i < 50; i++ {
		if _, err := lc.Prefs(); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := lc.Up(clientstate.Prefs{}); err != nil {
		t.Fatal(err)
	}
	waitSelf("home-pc")

	if err := lc.Switch("work"); err != nil {
		t.Fatal(err)
	}
	waitSelf("work-pc")
	if name, _ := clientstate.Current(base); name != "work" {
		t.Fatalf("current profile = %s", name)
	}
	if err := lc.Switch("nope"); err == nil || !strings.Contains(err.Error(), "no profile") {
		t.Fatalf("switch to a missing profile: %v", err)
	}
	if err := lc.Switch("default"); err != nil {
		t.Fatal(err)
	}
	waitSelf("home-pc")
}
