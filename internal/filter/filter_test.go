package filter

import (
	"encoding/binary"
	"fmt"
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

func icmpPacket(src, dst string, typ byte, id uint16) []byte {
	b := ipv4Packet(protoICMP, src, dst, 0, 0)
	b[20], b[21] = typ, 0
	binary.BigEndian.PutUint16(b[24:26], id)
	return b
}

func TestPingRepliesFromBeyondTheMesh(t *testing.T) {
	f := New() // no rules: nobody may initiate
	const me, lanHost = "100.64.0.1", "192.168.1.5"
	reply := icmpPacket(lanHost, me, 0, 7)
	if f.Inbound(reply) {
		t.Fatal("unsolicited echo reply allowed")
	}
	f.Outbound(icmpPacket(me, lanHost, 8, 7))
	if !f.Inbound(reply) {
		t.Fatal("reply to our own ping was dropped")
	}
	if f.Inbound(icmpPacket(lanHost, me, 0, 8)) {
		t.Fatal("echo reply with a different identifier allowed")
	}
	if f.Inbound(icmpPacket(lanHost, me, 8, 7)) {
		t.Fatal("echo request from outside allowed by a reply flow")
	}
}

func TestFlowLog(t *testing.T) {
	f := New()
	f.SetRules([]policy.Rule{{
		Src:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Ports: []policy.PortRange{{First: 22, Last: 22}},
	}}, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	const me, bob, eve = "100.64.0.1", "100.64.0.2", "100.64.0.9"

	if f.DrainFlows(0) != nil {
		t.Fatal("flows recorded while logging was off")
	}
	f.SetFlowLogging(true)

	// bob opens SSH to us; we answer. One connection, both directions.
	f.Inbound(ipv4Packet(protoTCP, bob, me, 50000, 22))
	f.Inbound(ipv4Packet(protoTCP, bob, me, 50000, 22))
	f.Outbound(ipv4Packet(protoTCP, me, bob, 22, 50000))
	// We open HTTPS to bob; he answers.
	f.Outbound(ipv4Packet(protoTCP, me, bob, 51000, 443))
	f.Inbound(ipv4Packet(protoTCP, bob, me, 443, 51000))
	// eve tries SSH and is refused, twice.
	f.Inbound(ipv4Packet(protoTCP, eve, me, 40000, 22))
	f.Inbound(ipv4Packet(protoTCP, eve, me, 40001, 22))

	recs := f.DrainFlows(0)
	byPort := map[string]FlowRecord{}
	for _, r := range recs {
		key := fmt.Sprintf("%s>%s:%d out=%v deny=%v", r.Client, r.Server, r.Port, r.Outbound, r.Denied)
		byPort[key] = r
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 records, got %d: %v", len(recs), byPort)
	}
	ssh := byPort[bob+">"+me+":22 out=false deny=false"]
	if ssh.PacketsRecv != 2 || ssh.PacketsSent != 1 {
		t.Fatalf("ssh conn = %+v", ssh)
	}
	https := byPort[me+">"+bob+":443 out=true deny=false"]
	if https.PacketsSent != 1 || https.PacketsRecv != 1 {
		t.Fatalf("https conn = %+v", https)
	}
	denied := byPort[eve+">"+me+":22 out=false deny=true"]
	if denied.PacketsRecv != 2 {
		t.Fatalf("denied attempts = %+v", denied)
	}

	// Drained counters reset; idle connections report nothing.
	if again := f.DrainFlows(0); len(again) != 0 {
		t.Fatalf("second drain = %+v", again)
	}
	// Logging doesn't change enforcement: eve is still refused.
	if f.Inbound(ipv4Packet(protoTCP, eve, me, 40002, 22)) {
		t.Fatal("logging changed a verdict")
	}
}
