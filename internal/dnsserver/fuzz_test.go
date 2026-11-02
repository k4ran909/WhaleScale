package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// MagicDNS answers whatever peers send to port 53.
func FuzzHandle(f *testing.F) {
	q, _ := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("pc.whale.internal."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	f.Add(q)
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c})
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetRecords("whale.internal", map[string][]netip.Addr{"pc": {netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a::1")}})
	f.Fuzz(func(t *testing.T, query []byte) {
		resp, ok := s.HandleFrom(context.Background(), netip.Addr{}, query)
		if !ok {
			return
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil {
			t.Fatalf("unparsable response %x to %x: %v", resp, query, err)
		}
	})
}
