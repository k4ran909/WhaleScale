package dnsserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// FakeUpstream answers every A question with addr, on a local UDP port.
func FakeUpstream(t testing.TB, addr netip.Addr) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			m.Response, m.RecursionAvailable = true, true
			if q := m.Questions[0]; q.Type == dnsmessage.TypeA {
				m.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: addr.As4()},
				}}
			}
			if b, err := m.Pack(); err == nil {
				pc.WriteTo(b, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func pack(t *testing.T, name string) []byte {
	t.Helper()
	b, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ask(t *testing.T, s *Server, from netip.Addr, name string) dnsmessage.Message {
	t.Helper()
	b, ok := s.HandleFrom(context.Background(), from, pack(t, name))
	var m dnsmessage.Message
	if !ok || m.Unpack(b) != nil {
		t.Fatalf("bad response %x", b)
	}
	return m
}

func TestForward(t *testing.T) {
	want := netip.MustParseAddr("203.0.113.7")
	up := Upstream([]string{FakeUpstream(t, want)})
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetRecords("whale.internal", map[string][]netip.Addr{"pc": {netip.MustParseAddr("100.64.0.1")}})

	var fwdErr error
	var asked []netip.Addr
	s.SetForwarder(func(ctx context.Context, from netip.Addr, q []byte) ([]byte, error) {
		asked = append(asked, from)
		if fwdErr != nil {
			return nil, fwdErr
		}
		return up(ctx, q)
	})
	from := netip.MustParseAddr("100.64.0.9")

	m := ask(t, s, from, "example.com.")
	if m.ID != 42 || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != want.As4() {
		t.Fatalf("forwarded answer: %+v", m)
	}
	// Mesh names never leave the machine.
	if m := ask(t, s, from, "pc.whale.internal."); len(m.Answers) != 1 || len(asked) != 1 {
		t.Fatalf("mesh name forwarded or unanswered: %+v (asked %v)", m, asked)
	}
	fwdErr = errors.New("exit node offline")
	if m := ask(t, s, from, "example.com."); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("failed forward: rcode %v", m.RCode)
	}
	fwdErr = ErrRefused
	if m := ask(t, s, from, "example.com."); m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("refused forward: rcode %v", m.RCode)
	}
	if !slices.Equal(asked, []netip.Addr{from, from, from}) {
		t.Fatalf("forwarder saw %v", asked)
	}
}

func TestSystemResolvers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("# generated\nsearch lan\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nnameserver bogus\noptions edns0\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0o644)
	got := systemResolvers(p)
	want := []string{"127.0.0.53:53", "[fe80::1%eth0]:53", "1.1.1.1:53"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if systemResolvers(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Fatal("missing file should give no resolvers")
	}
}
