package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/key"
	"github.com/k4ran909/whalescale/internal/nodeauth"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

// Once a node signs a request with its machine key, its bearer token is
// worth nothing, and a captured proof works neither twice nor elsewhere.
func TestMachineProofs(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.CreateUser(ctx, "ann")
	_, authKey, _ := st.CreatePreAuthKey(ctx, "ann", true, false, time.Hour)

	mux := http.NewServeMux()
	hs := httptest.NewServer(mux)
	defer hs.Close()
	host := hs.Listener.Addr().String()
	serverKey, _ := nodeauth.GenerateKey()
	svc := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{NodeAuthKey: serverKey, NodeAuthHosts: []string{host}})
	mux.Handle(whalescalev1connect.NewControlServiceHandler(svc))
	plain := whalescalev1connect.NewControlServiceClient(hs.Client(), hs.URL)

	mk, _ := clientstate.NewMachineKey()
	pub, _ := (&clientstate.State{MachineKey: mk}).PublicKey()
	reg, err := plain.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: authKey, MachineKey: pub, Hostname: "pc", Os: "linux"}))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Msg.ServerKey != svc.ServerKey() || reg.Msg.ServerKey == "" {
		t.Fatalf("register returned server key %q, want %q", reg.Msg.ServerKey, svc.ServerKey())
	}
	withHeader := func(h string) error {
		req := connect.NewRequest(&v1.GetNetworkMapRequest{})
		req.Header().Set("Authorization", h)
		_, err := plain.GetNetworkMap(ctx, req)
		return err
	}
	bearer := "Bearer " + reg.Msg.NodeToken
	if err := withHeader(bearer); err != nil {
		t.Fatalf("token before signing: %v", err)
	}

	creds := nodeauth.NewCredentials(mk, reg.Msg.NodeToken)
	if err := creds.SetServerKey(reg.Msg.ServerKey); err != nil {
		t.Fatal(err)
	}
	var captured string
	capture := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			captured = req.Header().Get("Authorization")
			return next(ctx, req)
		}
	})
	signed := whalescalev1connect.NewControlServiceClient(hs.Client(), hs.URL, connect.WithInterceptors(creds.Interceptor(), capture))
	nm, err := signed.GetNetworkMap(ctx, connect.NewRequest(&v1.GetNetworkMapRequest{}))
	if err != nil {
		t.Fatalf("signed request: %v", err)
	}
	if nm.Msg.Self.GetName() != "pc" || !nodeauth.IsProof(captured) {
		t.Fatalf("map self %v, header %q", nm.Msg.Self, captured)
	}
	if n, _ := st.NodeByMachineKey(ctx, pub); n == nil || !n.SignedAuth {
		t.Fatalf("node not marked as signing: %+v", n)
	}

	// The token is retired, and the proof doesn't work twice.
	for name, h := range map[string]string{"token": bearer, "replayed proof": captured} {
		if err := withHeader(h); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v, want unauthenticated", name, err)
		}
	}
	// A proof for one procedure doesn't authorize another.
	u, _ := url.Parse(hs.URL)
	h := creds.Header(http.MethodPost, u.Host, whalescalev1connect.ControlServiceGetNetworkMapProcedure)
	lr := connect.NewRequest(&v1.LogoutRequest{})
	lr.Header().Set("Authorization", h)
	if _, err := plain.Logout(ctx, lr); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("proof for another procedure: %v", err)
	}
	// Nor one for another server.
	if err := withHeader(creds.Header(http.MethodPost, "elsewhere.example.com", whalescalev1connect.ControlServiceGetNetworkMapProcedure)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("proof for another server: %v", err)
	}

	// The relay takes proofs for its own path only.
	nk, _ := key.NewPrivate()
	dk, _ := key.NewPrivate()
	if _, err := signed.UpdateNode(ctx, connect.NewRequest(&v1.UpdateNodeRequest{NodeKey: nk.Public().String(), DiscoKey: dk.Public().String()})); err != nil {
		t.Fatal(err)
	}
	relayURL := "ws://" + host + "/relay"
	if k, err := svc.RelayAuth(ctx, creds.ForURL(http.MethodGet, relayURL), http.MethodGet, "/relay"); err != nil || k != nk.Public() {
		t.Fatalf("relay proof: %v, %v", k, err)
	}
	if _, err := svc.RelayAuth(ctx, creds.ForURL(http.MethodGet, relayURL), http.MethodGet, "/gateway"); err == nil {
		t.Fatal("relay proof accepted for the gateway")
	}
	if _, err := svc.RelayAuth(ctx, bearer, http.MethodGet, "/relay"); err == nil {
		t.Fatal("retired token accepted by the relay")
	}

	// The signing client goes on working.
	if _, err := signed.GetNetworkMap(ctx, connect.NewRequest(&v1.GetNetworkMapRequest{})); err != nil {
		t.Fatal(err)
	}
}
