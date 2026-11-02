package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/key"
	"github.com/k4ran909/whalescale/internal/nodeauth"
)

func TestRelay(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	tokens := map[string]key.Public{"tok-a": a.Public(), "tok-b": b.Public()}
	srv := httptest.NewServer(NewServer(func(_ context.Context, cred, _, _ string) (key.Public, error) {
		tok := strings.TrimPrefix(cred, "Bearer ")
		if k, ok := tokens[tok]; ok {
			return k, nil
		}
		return key.Public{}, errors.New("bad token")
	}, log))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := NewClient(url, nodeauth.Bearer("tok-a"), nil, log)
	cb := NewClient(url, nodeauth.Bearer("tok-b"), nil, log)
	go ca.Run(ctx)
	go cb.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for !(ca.Connected() && cb.Connected()) {
		if time.Now().After(deadline) {
			t.Fatal("clients did not connect")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := ca.Send(b.Public(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-cb.Recv():
		if p.Src != a.Public() || string(p.Data) != "hello" {
			t.Fatalf("got %q from %v", p.Data, p.Src)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet not relayed")
	}

	// A client cannot spoof its source: the server stamps the authenticated key.
	bad := NewClient(url, nodeauth.Bearer("nope"), nil, log)
	bctx, bcancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer bcancel()
	if err := bad.session(bctx); err == nil {
		t.Fatal("unauthenticated client connected")
	}
}
