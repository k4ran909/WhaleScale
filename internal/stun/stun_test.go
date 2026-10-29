package stun

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, a := range []string{"203.0.113.7:41641", "[2001:db8::1]:3478"} {
		want := netip.MustParseAddrPort(a)
		tx := NewTxID()
		gotTx, got, err := ParseResponse(Response(tx, want))
		if err != nil || got != want || gotTx != tx {
			t.Fatalf("%s: got %v %v, %v", a, got, gotTx == tx, err)
		}
	}
}

func TestServe(t *testing.T) {
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, srv, slog.New(slog.NewTextHandler(io.Discard, nil)))

	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx := NewTxID()
	if _, err := c.WriteTo(Request(tx), srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotTx, addr, err := ParseResponse(buf[:n])
	if err != nil || gotTx != tx || addr != c.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("got %v, %v", addr, err)
	}
}
