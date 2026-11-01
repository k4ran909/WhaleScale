// Package disco defines the path-discovery messages nodes exchange to find
// and verify direct UDP paths. Messages are sealed with NaCl box between the
// two nodes' disco keys, so they can't be forged or read by relays.
//
// Wire format: magic(6) | sender disco public key(32) | nonce(24) | box.
package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/nacl/box"

	"github.com/k4ran909/whalescale/internal/key"
)

// Magic starts every disco packet: "WS" followed by the UTF-8 whale emoji.
// WireGuard packets start with a message type 1-4 followed by three zero
// bytes, so the two can never be confused.
const Magic = "WS\xf0\x9f\x90\xb3"

const (
	headerLen = len(Magic) + 32 + 24

	typePing        byte = 1
	typePong        byte = 2
	typeCallMeMaybe byte = 3
	typePQInit      byte = 4
	typePQReply     byte = 5
	typePQCommit    byte = 6
	typePQDone      byte = 7

	addrLen = 18 // 16-byte IP + 2-byte port
)

type TxID [12]byte

func NewTxID() TxID {
	var t TxID
	rand.Read(t[:])
	return t
}

// Ping asks the receiver to answer with a Pong on the same path.
type Ping struct {
	TxID    TxID
	NodeKey key.Public // sender's WireGuard key
	// PSKID fingerprints the post-quantum pre-shared key the sender uses
	// with the receiver (zero: none), so the two notice if they disagree.
	// Older nodes send none and ignore it.
	PSKID [8]byte
}

// Pong answers a Ping and tells the pinger which address it came from.
type Pong struct {
	TxID TxID
	Src  netip.AddrPort
}

// Post-quantum pre-shared key exchange (see internal/pq). The node with the
// lower WireGuard key sends PQInit with a fresh ML-KEM-768 encapsulation
// key; the other encapsulates a secret to it in PQReply. Neither uses the
// derived key until PQCommit / PQDone confirm both have it.

// ML-KEM-768 sizes.
const (
	PQEncapKeySize  = 1184
	PQCiphertextLen = 1088
)

type PQInit struct {
	TxID     TxID
	EncapKey []byte
}

type PQReply struct {
	TxID       TxID
	Ciphertext []byte
}

// PQCommit: the initiator derived the key; the responder may switch to it.
type PQCommit struct{ TxID TxID }

// PQDone: the responder switched; the initiator switches too.
type PQDone struct{ TxID TxID }

func (m *PQInit) marshal() []byte {
	return append(append([]byte{typePQInit, 0}, m.TxID[:]...), m.EncapKey...)
}

func (m *PQReply) marshal() []byte {
	return append(append([]byte{typePQReply, 0}, m.TxID[:]...), m.Ciphertext...)
}

func (m *PQCommit) marshal() []byte { return append([]byte{typePQCommit, 0}, m.TxID[:]...) }
func (m *PQDone) marshal() []byte   { return append([]byte{typePQDone, 0}, m.TxID[:]...) }

// CallMeMaybe, sent over a relay, asks the receiver to ping these endpoints.
// Both sides pinging at once is what opens holes in NATs.
type CallMeMaybe struct {
	Endpoints []netip.AddrPort
}

type Message interface{ marshal() []byte }

func (m *Ping) marshal() []byte {
	b := []byte{typePing, 0}
	b = append(b, m.TxID[:]...)
	b = append(b, m.NodeKey[:]...)
	return append(b, m.PSKID[:]...)
}

func (m *Pong) marshal() []byte {
	b := []byte{typePong, 0}
	b = append(b, m.TxID[:]...)
	return appendAddr(b, m.Src)
}

func (m *CallMeMaybe) marshal() []byte {
	b := []byte{typeCallMeMaybe, 0}
	for _, ep := range m.Endpoints {
		b = appendAddr(b, ep)
	}
	return b
}

func appendAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().As16()
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func readAddr(b []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])).Unmap(), binary.BigEndian.Uint16(b[16:18]))
}

// Is reports whether a packet is a disco packet.
func Is(b []byte) bool {
	return len(b) >= headerLen && string(b[:len(Magic)]) == Magic
}

// Seal encrypts m from priv to the peer's disco key.
func Seal(priv key.Private, peer key.Public, m Message) []byte {
	var nonce [24]byte
	rand.Read(nonce[:])
	pub := priv.Public()
	out := make([]byte, 0, headerLen+64)
	out = append(out, Magic...)
	out = append(out, pub[:]...)
	out = append(out, nonce[:]...)
	p, k := [32]byte(peer), [32]byte(priv)
	return box.Seal(out, m.marshal(), &nonce, &p, &k)
}

var errBad = errors.New("malformed disco message")

// Open authenticates and decodes a disco packet addressed to priv.
func Open(priv key.Private, pkt []byte) (sender key.Public, m Message, err error) {
	if !Is(pkt) {
		return sender, nil, errBad
	}
	copy(sender[:], pkt[len(Magic):len(Magic)+32])
	var nonce [24]byte
	copy(nonce[:], pkt[len(Magic)+32:headerLen])
	p, k := [32]byte(sender), [32]byte(priv)
	plain, ok := box.Open(nil, pkt[headerLen:], &nonce, &p, &k)
	if !ok {
		return sender, nil, errors.New("disco message failed authentication")
	}
	m, err = parse(plain)
	return sender, m, err
}

func parse(b []byte) (Message, error) {
	if len(b) < 2 {
		return nil, errBad
	}
	body := b[2:]
	switch b[0] {
	case typePing:
		if len(body) < 12+32 {
			return nil, errBad
		}
		m := &Ping{}
		copy(m.TxID[:], body[:12])
		copy(m.NodeKey[:], body[12:44])
		if len(body) >= 44+8 {
			copy(m.PSKID[:], body[44:52])
		}
		return m, nil
	case typePong:
		if len(body) < 12+addrLen {
			return nil, errBad
		}
		m := &Pong{Src: readAddr(body[12:])}
		copy(m.TxID[:], body[:12])
		return m, nil
	case typePQInit, typePQReply, typePQCommit, typePQDone:
		if len(body) < 12 {
			return nil, errBad
		}
		var tx TxID
		copy(tx[:], body[:12])
		rest := body[12:]
		switch b[0] {
		case typePQInit:
			if len(rest) != PQEncapKeySize {
				return nil, errBad
			}
			return &PQInit{TxID: tx, EncapKey: append([]byte(nil), rest...)}, nil
		case typePQReply:
			if len(rest) != PQCiphertextLen {
				return nil, errBad
			}
			return &PQReply{TxID: tx, Ciphertext: append([]byte(nil), rest...)}, nil
		case typePQCommit:
			return &PQCommit{TxID: tx}, nil
		default:
			return &PQDone{TxID: tx}, nil
		}
	case typeCallMeMaybe:
		if len(body)%addrLen != 0 {
			return nil, errBad
		}
		m := &CallMeMaybe{}
		for ; len(body) > 0; body = body[addrLen:] {
			m.Endpoints = append(m.Endpoints, readAddr(body))
		}
		return m, nil
	}
	return nil, errBad
}
