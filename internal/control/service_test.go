package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/store"
)

func TestRegisterAndNetworkMap(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.CreateUser(ctx, "alice")
	_, key, _ := st.CreatePreAuthKey(ctx, "alice", true, false, time.Hour)

	mux := http.NewServeMux()
	mux.Handle(whalescalev1connect.NewControlServiceHandler(New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := whalescalev1connect.NewControlServiceClient(srv.Client(), srv.URL)

	register := func(host string) *v1.RegisterResponse {
		t.Helper()
		priv, _ := clientstate.NewMachineKey()
		pub, _ := (&clientstate.State{MachineKey: priv}).PublicKey()
		resp, err := c.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: pub, Hostname: host, Os: "linux"}))
		if err != nil {
			t.Fatalf("register %s: %v", host, err)
		}
		return resp.Msg
	}
	a := register("pc-a")
	register("pc-b")

	req := connect.NewRequest(&v1.GetNetworkMapRequest{})
	req.Header().Set("Authorization", "Bearer "+a.NodeToken)
	nm, err := c.GetNetworkMap(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if nm.Msg.Self.Name != "pc-a" || len(nm.Msg.Peers) != 1 || nm.Msg.Peers[0].Name != "pc-b" {
		t.Fatalf("unexpected netmap: %+v", nm.Msg)
	}

	// Bad inputs map to the right codes.
	_, err = c.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: "wskey-nope", MachineKey: a.Node.MachineKey}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument && connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad key: got %v", err)
	}
	_, err = c.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: "not-a-key"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad machine key: got %v", err)
	}
	bad := connect.NewRequest(&v1.GetNetworkMapRequest{})
	bad.Header().Set("Authorization", "Bearer wsnode-wrong")
	if _, err := c.GetNetworkMap(ctx, bad); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad token: got %v", err)
	}
}
