package mobile

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/joincode"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

// testServer runs a control server and returns a join code for it.
func testServer(t *testing.T) (code string, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, storetest.DSN(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.CreateUser(ctx, "alice")
	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	t.Cleanup(hs.Close)
	srv, err := server.New(st, server.Config{PublicURL: hs.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()

	// As the dashboard's Machines → Add device does.
	_, apiKey, err := st.CreateAPIKey(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin := whalescalev1connect.NewAdminServiceClient(httpClient, hs.URL)
	req := connect.NewRequest(&v1.CreatePreAuthKeyRequest{User: "alice", ExpirationSeconds: 3600})
	req.Header().Set("Authorization", "Bearer "+apiKey)
	resp, err := admin.CreatePreAuthKey(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Msg.JoinCodeQr, "<svg") {
		t.Fatalf("no QR code for the join code: %.60q", resp.Msg.JoinCodeQr)
	}
	if want := joincode.Encode(hs.URL, resp.Msg.Secret); resp.Msg.JoinCode != want {
		t.Fatalf("join code = %q, want %q", resp.Msg.JoinCode, want)
	}
	return resp.Msg.JoinCode, st
}

func status(t *testing.T, dir string) clientstate.PublicStatus {
	t.Helper()
	var ps clientstate.PublicStatus
	if err := json.Unmarshal([]byte(Status(dir)), &ps); err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestJoinAndSignOut(t *testing.T) {
	code, st := testServer(t)
	dir := t.TempDir()

	if _, err := CheckJoinCode("wskey-123"); err == nil {
		t.Fatal("a bare key passed as a join code")
	}
	if s, err := CheckJoinCode(code); err != nil || !strings.HasPrefix(s, "http://127.0.0.1") {
		t.Fatalf("CheckJoinCode = %q, %v", s, err)
	}
	if IsJoined(dir) || status(t, dir).State != "logged-out" {
		t.Fatal("joined before Join")
	}
	if err := Start(dir, nil, ""); err == nil {
		t.Fatal("Start without a platform")
	}

	if err := Join(dir, code, "pixel-9"); err != nil {
		t.Fatal(err)
	}
	if !IsJoined(dir) {
		t.Fatal("not joined after Join")
	}
	ps := status(t, dir)
	if ps.State != "down" || ps.Name != "pixel-9" {
		t.Fatalf("status after joining = %+v", ps)
	}
	saved, _ := clientstate.Load(stateFile(dir))
	if saved.MachineKey == "" || saved.NodeToken == "" || !saved.Prefs.AcceptRoutes {
		t.Fatalf("saved state = %+v", saved)
	}
	if fi, err := os.Stat(stateFile(dir)); err == nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("state file mode %v", fi.Mode())
	}
	if err := Join(dir, code, "again"); err == nil {
		t.Fatal("joined twice")
	}

	if err := SignOut(dir); err != nil {
		t.Fatal(err)
	}
	if IsJoined(dir) {
		t.Fatal("still joined after SignOut")
	}
	after, _ := clientstate.Load(stateFile(dir))
	if after.MachineKey != saved.MachineKey {
		t.Fatal("sign-out lost the machine key")
	}
	nodes, err := st.ListNodes(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("server still has %d node(s) after sign-out", len(nodes))
	}
	// Signing out twice is harmless.
	if err := SignOut(dir); err != nil {
		t.Fatal(err)
	}
}

func TestSetNetwork(t *testing.T) {
	t.Cleanup(func() { SetNetwork("", "") })
	SetNetwork("192.168.1.20/24\nfe80::1%wlan0\n2001:db8::5\nnonsense\n", "192.168.1.1\n\n8.8.8.8\nbad\n100.100.100.100")
	netMu.Lock()
	addrs, dns := netAddrs, netDNS
	netMu.Unlock()
	if len(addrs) != 3 || addrs[0].String() != "192.168.1.20/24" || addrs[2].String() != "2001:db8::5/128" {
		t.Fatalf("addrs = %v", addrs)
	}
	if strings.Join(dns, ",") != "192.168.1.1:53,8.8.8.8:53" {
		t.Fatalf("dns = %v", dns)
	}
}
