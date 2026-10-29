package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/k4ran909/whalescale/internal/policy"
)

func ipv4Packet(proto uint8, src, dst string, sport, dport uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	return b
}

func TestInbound(t *testing.T) {
	f := New()
	f.SetRules([]policy.Rule{{
		Src:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Ports: []policy.PortRange{{First: 22, Last: 22}, {First: 8000, Last: 8100}},
	}, {
		Src:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Dst:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Ports: policy.AllPorts,
	}}, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	const me, bob, eve = "100.64.0.1", "100.64.0.2", "100.64.0.9"

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"bob ssh", ipv4Packet(protoTCP, bob, me, 50000, 22), true},
		{"bob range", ipv4Packet(protoUDP, bob, me, 50000, 8050), true},
		{"bob other port", ipv4Packet(protoTCP, bob, me, 50000, 443), false},
		{"bob ping", ipv4Packet(protoICMP, bob, me, 0, 0), true},
		{"eve ssh", ipv4Packet(protoTCP, eve, me, 50000, 22), false},
		{"eve ping", ipv4Packet(protoICMP, eve, me, 0, 0), false},
		{"garbage", []byte{0x45, 0}, false},
		{"bob to routed lan", ipv4Packet(protoTCP, bob, "192.168.1.7", 50000, 443), true},
		{"bob to unrouted net", ipv4Packet(protoTCP, bob, "10.0.0.7", 50000, 22), false},
		{"eve to routed lan", ipv4Packet(protoTCP, eve, "192.168.1.7", 50000, 443), false},
	}
	for _, c := range cases {
		if got := f.Inbound(c.pkt); got != c.want {
			t.Errorf("%s: Inbound = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStatefulReplies(t *testing.T) {
	f := New() // no rules: deny all new inbound
	const me, eve = "100.64.0.1", "100.64.0.9"
	reply := ipv4Packet(protoTCP, eve, me, 443, 51000)
	if f.Inbound(reply) {
		t.Fatal("unsolicited packet allowed")
	}
	f.Outbound(ipv4Packet(protoTCP, me, eve, 51000, 443))
	if !f.Inbound(reply) {
		t.Fatal("reply to our own connection was dropped")
	}
	if f.Inbound(ipv4Packet(protoTCP, eve, me, 443, 51001)) {
		t.Fatal("different local port must not match the flow")
	}
}
