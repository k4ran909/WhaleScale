package meshconn

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/k4ran909/whalescale/internal/key"
)

// TestMeshPrefix6: the mesh's IPv6 range is never advertised or used as a
// direct path. A node used to advertise its tunnel's own IPv6 address; a
// peer then "reached" it through the tunnel, over the relay, and the path
// flapped (seen as 65-75% loss between two Windows machines behind a
// symmetric NAT).
func TestMeshPrefix6(t *testing.T) {
	mesh6 := netip.MustParsePrefix("fde0:7339:6a2a::/48")
	tunnel := netip.MustParseAddr("fde0:7339:6a2a::6440:2")
	lan := netip.MustParseAddr("192.168.1.4")
	SetInterfaceAddrs(func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: lan.AsSlice(), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: tunnel.AsSlice(), Mask: net.CIDRMask(128, 128)},
		}, nil
	})
	t.Cleanup(func() { SetInterfaceAddrs(nil) })

	c, _, _ := newTestConn(t)
	if c.pc6 == nil {
		t.Skip("no IPv6 UDP here, so IPv6 endpoints are never advertised")
	}

	advertised := func(a netip.Addr) bool {
		c.updateEndpoints()
		return slices.ContainsFunc(c.Endpoints(), func(ep netip.AddrPort) bool { return ep.Addr() == a })
	}
	if !advertised(tunnel) || !advertised(lan) {
		t.Fatalf("before: endpoints %v, want the LAN and (unfiltered) tunnel address", c.Endpoints())
	}

	// A peer advertising its own tunnel address, and a direct path already
	// taken through it.
	pd, _ := key.NewPrivate()
	pn, _ := key.NewPrivate()
	peerTunnel := netip.AddrPortFrom(netip.MustParseAddr("fde0:7339:6a2a::6440:1"), 41641)
	peerLAN := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.9"), 41641)
	c.SetPeers([]PeerConfig{{NodeKey: pn.Public(), DiscoKey: pd.Public(), Endpoints: []netip.AddrPort{peerTunnel, peerLAN}}})
	c.mu.Lock()
	p := c.peers[pn.Public()]
	p.bestAddr = peerTunnel
	c.byAddr[peerTunnel] = p
	c.mu.Unlock()

	c.SetMeshPrefix6(mesh6)

	if advertised(tunnel) {
		t.Errorf("after: still advertising the tunnel address: %v", c.Endpoints())
	}
	if !advertised(lan) {
		t.Errorf("after: lost the LAN address: %v", c.Endpoints())
	}
	c.mu.Lock()
	cands, best, learned := slices.Clone(p.candidates), p.bestAddr, c.byAddr[peerTunnel]
	c.mu.Unlock()
	if slices.Contains(cands, peerTunnel) || !slices.Contains(cands, peerLAN) {
		t.Errorf("candidates %v: want the LAN address without the tunnel one", cands)
	}
	if best.IsValid() || learned != nil {
		t.Errorf("the direct path through the tunnel survived: best %v, learned %v", best, learned != nil)
	}

	// A later network map repeating the tunnel endpoint doesn't bring it back.
	c.SetPeers([]PeerConfig{{NodeKey: pn.Public(), DiscoKey: pd.Public(), Endpoints: []netip.AddrPort{peerTunnel, peerLAN}}})
	c.mu.Lock()
	cands = slices.Clone(p.candidates)
	c.mu.Unlock()
	if slices.Contains(cands, peerTunnel) {
		t.Errorf("SetPeers took the tunnel address back: %v", cands)
	}
}
