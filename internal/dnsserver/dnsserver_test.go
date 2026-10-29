package dnsserver

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetRecords("whale.internal", map[string][]netip.Addr{
		"pc-a": {netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd00::1")},
	})
	resp, ok := s.Handle(b)
	if !ok {
		t.Fatal("no response")
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHandle(t *testing.T) {
	m := query(t, "PC-A.whale.internal.", dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 ||
		m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{100, 64, 0, 1} {
		t.Fatalf("A: %+v", m)
	}
	m = query(t, "pc-a.whale.internal.", dnsmessage.TypeAAAA)
	if len(m.Answers) != 1 {
		t.Fatalf("AAAA: %+v", m)
	}
	if m = query(t, "nope.whale.internal.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("missing name: rcode %v", m.RCode)
	}
	if m = query(t, "example.com.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("out of zone: rcode %v", m.RCode)
	}
}
