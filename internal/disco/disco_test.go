package disco

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/k4ran909/whalescale/internal/key"
)

func TestSealOpen(t *testing.T) {
	a, _ := key.NewPrivate()
	b, _ := key.NewPrivate()
	nk, _ := key.NewPrivate()
	msgs := []Message{
		&Ping{TxID: NewTxID(), NodeKey: nk.Public()},
		&Pong{TxID: NewTxID(), Src: netip.MustParseAddrPort("198.51.100.4:41641")},
		&CallMeMaybe{Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("192.168.1.5:41641"),
			netip.MustParseAddrPort("[2001:db8::5]:41641"),
		}},
	}
	for _, m := range msgs {
		pkt := Seal(a, b.Public(), m)
		if !Is(pkt) {
			t.Fatal("sealed packet not recognised")
		}
		sender, got, err := Open(b, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if sender != a.Public() || !reflect.DeepEqual(got, m) {
			t.Fatalf("got %#v from %v, want %#v", got, sender, m)
		}
		// A third party cannot open it, and tampering is detected.
		c, _ := key.NewPrivate()
		if _, _, err := Open(c, pkt); err == nil {
			t.Fatal("wrong key opened the message")
		}
		pkt[len(pkt)-1] ^= 1
		if _, _, err := Open(b, pkt); err == nil {
			t.Fatal("tampered message accepted")
		}
	}
}

func TestNotWireGuard(t *testing.T) {
	// WireGuard handshake initiation: type 1, three zero bytes.
	wg := make([]byte, 148)
	wg[0] = 1
	if Is(wg) {
		t.Fatal("WireGuard packet mistaken for disco")
	}
}
