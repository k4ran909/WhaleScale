package disco

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/k4ran909/whalescale/internal/key"
)

// Disco messages arrive from anyone who can send a UDP packet.
func FuzzParse(f *testing.F) {
	for _, m := range []Message{&Ping{TxID: TxID{1}}, &Pong{TxID: TxID{2}}, &CallMeMaybe{}, &PQCommit{TxID: TxID{3}}, &PQDone{}} {
		f.Add(m.marshal())
	}
	f.Add([]byte{typePQInit, 0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parse(b)
		if err != nil {
			return
		}
		// Whatever parses survives a round trip.
		again, err := parse(m.marshal())
		if err != nil || reflect.TypeOf(again) != reflect.TypeOf(m) || !bytes.Equal(again.marshal(), m.marshal()) {
			t.Fatalf("round trip of %#v: %#v, %v", m, again, err)
		}
	})
}

func FuzzOpen(f *testing.F) {
	priv, _ := key.NewPrivate()
	peer, _ := key.NewPrivate()
	f.Add(Seal(peer, priv.Public(), &Ping{TxID: TxID{9}}))
	f.Add(append([]byte(nil), Magic...))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		Open(priv, pkt)
	})
}
