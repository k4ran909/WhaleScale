package meshconn

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
)

func newTestConn(t *testing.T) (*Conn, key.Private, key.Private) {
	t.Helper()
	dk, _ := key.NewPrivate()
	nk, _ := key.NewPrivate()
	c, err := New(Options{DiscoKey: dk, NodeKey: nk.Public(), IncludeLoopback: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, dk, nk
}

// TestRelayRefusesImpostors: only listed clients can register, and only
// from the address they registered can frames be sent.
func TestRelayRefusesImpostors(t *testing.T) {
	relay, relayDisco, relayNode := newTestConn(t)
	client, clientDisco, clientNode := newTestConn(t)
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relay.Port())

	relay.SetRelayClients(map[key.Public]key.Public{clientDisco.Public(): clientNode.Public()})
	client.SetPeerRelays([]PeerRelayConfig{{Name: "r", NodeKey: relayNode.Public(), DiscoKey: relayDisco.Public(),
		Endpoints: []netip.AddrPort{relayAddr}}})
	client.helloRelays()

	deadline := time.Now().Add(5 * time.Second)
	for {
		client.mu.Lock()
		live := client.peerRelays[relayNode.Public()].live()
		client.mu.Unlock()
		if live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("legitimate client never registered with the relay")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// An outsider with its own disco key claims to be the client.
	evil, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer evil.Close()
	evilDisco, _ := key.NewPrivate()
	hello := helloFrame(disco.Seal(evilDisco, relayDisco.Public(), &disco.Ping{TxID: disco.NewTxID(), NodeKey: clientNode.Public()}))
	evil.WriteToUDPAddrPort(hello, relayAddr)
	// And tries to send through the relay without registering.
	evil.WriteToUDPAddrPort(relayFrame(frameToRelay, clientNode.Public(), []byte("spoofed")), relayAddr)

	evil.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := evil.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatalf("relay answered an impostor: %q", buf[:n])
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	reg := relay.relayServe.reg[clientNode.Public()]
	if len(relay.relayServe.reg) != 1 || reg.addr.Port() != client.Port() {
		t.Fatalf("registrations = %+v (the impostor must not have replaced the client)", relay.relayServe.reg)
	}
	if _, ok := relay.relayServe.byAddr[evil.LocalAddr().(*net.UDPAddr).AddrPort()]; ok {
		t.Fatal("impostor address registered")
	}
}

// TestRelayOffForgetsClients: turning relaying off drops all state, and a
// node not on the relay list is ignored.
func TestRelayOffForgetsClients(t *testing.T) {
	relay, relayDisco, relayNode := newTestConn(t)
	client, _, _ := newTestConn(t)
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relay.Port())
	relay.SetRelayClients(map[key.Public]key.Public{}) // relaying, but for nobody
	client.SetPeerRelays([]PeerRelayConfig{{Name: "r", NodeKey: relayNode.Public(), DiscoKey: relayDisco.Public(),
		Endpoints: []netip.AddrPort{relayAddr}}})
	client.helloRelays()
	time.Sleep(300 * time.Millisecond)
	client.mu.Lock()
	live := client.peerRelays[relayNode.Public()].live()
	client.mu.Unlock()
	if live {
		t.Fatal("relay served a node it was not told about")
	}
	relay.SetRelayClients(nil)
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.relayServe != nil {
		t.Fatal("relay state kept after turning relaying off")
	}
}
