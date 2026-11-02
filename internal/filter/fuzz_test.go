package filter

import (
	"net/netip"
	"testing"

	"github.com/k4ran909/whalescale/internal/policy"
)

// Packets reach the filter straight out of WireGuard, from any peer.
func FuzzPackets(f *testing.F) {
	ipv4TCP := []byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 100, 64, 0, 2, 100, 64, 0, 1,
		0x30, 0x39, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0}
	f.Add(ipv4TCP)
	f.Add([]byte{0x60, 0, 0, 0, 0, 8, 17, 64})
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		flt := New()
		self := netip.MustParseAddr("100.64.0.1")
		flt.SetRules([]policy.Rule{
			{Src: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, Ports: []policy.PortRange{{First: 22, Last: 22}}},
			{Src: []netip.Prefix{netip.MustParsePrefix("::/0")}, Dst: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		}, []netip.Addr{self})
		flt.Inbound(pkt)
		flt.Outbound(pkt)
		flt.Inbound(pkt)
	})
}
