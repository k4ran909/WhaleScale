package meshconn

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestPredictPorts(t *testing.T) {
	// Endpoint-independent NAT: one public port per IP, nothing to predict.
	if got := predictPorts([]netip.AddrPort{ap("203.0.113.7:41641"), ap("192.168.1.5:41641")}); got != nil {
		t.Fatalf("predicted for a cone NAT: %v", got)
	}
	// Symmetric NAT seen by two STUN servers: 50002, then 50004.
	got := predictPorts([]netip.AddrPort{ap("203.0.113.7:50002"), ap("203.0.113.7:50004"), ap("192.168.1.5:41641")})
	if len(got) != sprayCount || got[0] != ap("203.0.113.7:50006") || got[1] != ap("203.0.113.7:50008") {
		t.Fatalf("predictions = %v", got)
	}
	// Big gaps are capped; predictions never pass 65535.
	got = predictPorts([]netip.AddrPort{ap("203.0.113.7:65000"), ap("203.0.113.7:65500")})
	if len(got) == 0 || got[0] != ap("203.0.113.7:65532") {
		t.Fatalf("capped step predictions = %v", got)
	}
	for _, p := range got {
		if p.Port() < 65000 {
			t.Fatalf("prediction wrapped: %v", p)
		}
	}
}

// TestSprayReachesPredictedPort: a peer that looks symmetric gets pings at
// the ports its NAT would hand out next.
func TestSprayReachesPredictedPort(t *testing.T) {
	c, _, _ := newTestConn(t)
	// The "next mapping" of the peer's NAT is where we listen.
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	next := ln.LocalAddr().(*net.UDPAddr).Port
	if next < 2000 {
		t.Skip("listener port too low for the test pattern")
	}
	peerDisco, _ := key.NewPrivate()
	peerNode, _ := key.NewPrivate()
	c.SetPeers([]PeerConfig{{Name: "symmetric", NodeKey: peerNode.Public(), DiscoKey: peerDisco.Public(),
		Endpoints: []netip.AddrPort{
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(next-4)),
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(next-2)),
		}}})
	c.mu.Lock()
	p := c.peers[peerNode.Public()]
	c.mu.Unlock()
	c.sprayPredicted(p)

	ln.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := ln.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no probe reached the predicted port %d: %v", next, err)
	}
	if !disco.Is(buf[:n]) {
		t.Fatal("probe is not a disco ping")
	}
	// Rate limit: a second burst right away is suppressed.
	c.mu.Lock()
	last := p.lastSpray
	c.mu.Unlock()
	c.sprayPredicted(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !p.lastSpray.Equal(last) {
		t.Fatal("spray not rate limited")
	}
}
