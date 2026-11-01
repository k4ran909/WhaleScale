package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/key"
)

func waitConnected(t *testing.T, cs ...*Client) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok := true
		for _, c := range cs {
			ok = ok && c.Connected()
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("clients did not connect")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestQUICRelay(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	c, _ := key.NewPrivate()
	tokens := map[string]key.Public{"tok-a": a.Public(), "tok-b": b.Public(), "tok-c": c.Public()}
	srv := NewServer(func(_ context.Context, tok string) (key.Public, error) {
		if k, ok := tokens[tok]; ok {
			return k, nil
		}
		return key.Public{}, errors.New("bad token")
	}, log)
	// The same relay serves WebSocket (fallback) and QUIC.
	hs := httptest.NewServer(srv)
	defer hs.Close()
	wsURL := "ws" + strings.TrimPrefix(hs.URL, "http")

	certPEM, err := NewQUICCert()
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := ParseQUICCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeQUIC(ctx, pc, cert)
	quicAddr := pc.LocalAddr().String()

	if err := ProbeQUIC(ctx, quicAddr, pin); err != nil {
		t.Fatalf("probe with the right pin: %v", err)
	}
	if err := ProbeQUIC(ctx, quicAddr, make([]byte, 32)); err == nil {
		t.Fatal("probe accepted a wrong pin")
	}

	ca := NewClient(wsURL, "tok-a", nil, log)
	cb := NewClient(wsURL, "tok-b", nil, log)
	ca.SetQUIC(quicAddr, pin, nil)
	cb.SetQUIC(quicAddr, pin, nil)
	go ca.Run(ctx)
	go cb.Run(ctx)
	waitConnected(t, ca, cb)
	if ca.Transport() != "quic" || cb.Transport() != "quic" {
		t.Fatalf("transports = %s, %s", ca.Transport(), cb.Transport())
	}

	recv := func(c *Client) Packet {
		t.Helper()
		select {
		case p := <-c.Recv():
			return p
		case <-time.After(5 * time.Second):
			t.Fatal("packet not relayed")
		}
		return Packet{}
	}
	// A small packet goes as a datagram, a big one on the stream.
	ca.Send(b.Public(), []byte("hello over quic"))
	if p := recv(cb); p.Src != a.Public() || string(p.Data) != "hello over quic" {
		t.Fatalf("got %q from %v", p.Data, p.Src)
	}
	big := bytes.Repeat([]byte("x"), 9000)
	cb.Send(a.Public(), big)
	if p := recv(ca); !bytes.Equal(p.Data, big) {
		t.Fatalf("big packet: %d bytes", len(p.Data))
	}

	// A client that can't verify the relay certificate falls back to
	// WebSocket and still works. (Its own identity: a second connection
	// with the same key would replace the first.)
	cbad := NewClient(wsURL, "tok-c", nil, log)
	cbad.SetQUIC(quicAddr, make([]byte, 32), nil)
	go cbad.Run(ctx)
	waitConnected(t, cbad)
	if cbad.Transport() != "websocket" {
		t.Fatalf("fallback transport = %s", cbad.Transport())
	}
	ca.Send(c.Public(), []byte("via websocket"))
	if p := recv(cbad); string(p.Data) != "via websocket" {
		t.Fatalf("fallback delivery: %q", p.Data)
	}

	// Bad tokens are refused on QUIC too.
	evil := NewClient(wsURL, "nope", nil, log)
	evil.SetQUIC(quicAddr, pin, nil)
	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	if err := evil.sessionQUIC(qctx); err == nil {
		t.Fatal("unauthenticated QUIC client connected")
	}
}
