// Package stun implements the small part of RFC 5389 Whalescale needs:
// Binding requests and responses carrying XOR-MAPPED-ADDRESS.
package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
)

const (
	headerLen        = 20
	magicCookie      = 0x2112A442
	bindingRequest   = 0x0001
	bindingSuccess   = 0x0101
	attrXorMapped    = 0x0020
	attrMappedLegacy = 0x0001
)

type TxID [12]byte

func NewTxID() TxID {
	var t TxID
	rand.Read(t[:])
	return t
}

// Request builds a Binding request.
func Request(tx TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

// Is reports whether b looks like a STUN message (any type).
func Is(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

func parseHeader(b []byte) (typ uint16, tx TxID, attrs []byte, err error) {
	if !Is(b) {
		return 0, tx, nil, errors.New("not a STUN message")
	}
	typ = binary.BigEndian.Uint16(b[0:2])
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+n > len(b) {
		return 0, tx, nil, errors.New("truncated STUN message")
	}
	copy(tx[:], b[8:20])
	return typ, tx, b[headerLen : headerLen+n], nil
}

// ParseResponse extracts the mapped address from a Binding success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	typ, tx, attrs, err := parseHeader(b)
	if err != nil {
		return tx, netip.AddrPort{}, err
	}
	if typ != bindingSuccess {
		return tx, netip.AddrPort{}, errors.New("not a binding success response")
	}
	var legacy netip.AddrPort
	for len(attrs) >= 4 {
		at := binary.BigEndian.Uint16(attrs[0:2])
		al := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+al > len(attrs) {
			break
		}
		val := attrs[4 : 4+al]
		switch at {
		case attrXorMapped:
			if ap, ok := decodeAddr(val, true, tx); ok {
				return tx, ap, nil
			}
		case attrMappedLegacy:
			legacy, _ = decodeAddr(val, false, tx)
		}
		attrs = attrs[4+(al+3)&^3:]
	}
	if legacy.IsValid() {
		return tx, legacy, nil
	}
	return tx, netip.AddrPort{}, errors.New("no mapped address in response")
}

func decodeAddr(v []byte, xor bool, tx TxID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], tx[:])
	if xor {
		port ^= magicCookie >> 16
	}
	switch v[1] {
	case 1:
		if len(v) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		for i := range a {
			a[i] = v[4+i]
			if xor {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 2:
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		for i := range a {
			a[i] = v[4+i]
			if xor {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// Response builds a Binding success response telling the client its address.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	alen := 8
	family := byte(1)
	if ip.Is6() {
		alen, family = 20, 2
	}
	b := make([]byte, headerLen+4+alen)
	binary.BigEndian.PutUint16(b[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+alen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(a[2:4], uint16(alen))
	a[5] = family
	binary.BigEndian.PutUint16(a[6:8], addr.Port()^(magicCookie>>16))
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], tx[:])
	raw := ip.AsSlice()
	for i := range raw {
		a[8+i] = raw[i] ^ key[i]
	}
	return b
}

// Serve answers Binding requests on pc until ctx is done.
func Serve(ctx context.Context, pc net.PacketConn, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		typ, tx, _, err := parseHeader(buf[:n])
		if err != nil || typ != bindingRequest {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		if _, err := pc.WriteTo(Response(tx, ua.AddrPort()), from); err != nil {
			log.Debug("stun reply", "to", from, "err", err)
		}
	}
}
