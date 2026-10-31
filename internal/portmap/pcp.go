package portmap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const (
	pcpVersion    = 2
	pcpOpMap      = 1
	pcpProtoUDP   = 17
	pcpUnsuppVers = 1
	pcpHeaderLen  = 24
	pcpMapLen     = 36
)

// pcpMap requests a UDP mapping for local:internal; lifetime 0 deletes it.
// nonce identifies the mapping across renewals.
func pcpMap(ctx context.Context, gw netip.AddrPort, local netip.Addr, internal, suggested uint16,
	lifetime time.Duration, nonce [12]byte) (netip.AddrPort, time.Duration, error) {
	req := make([]byte, pcpHeaderLen+pcpMapLen)
	req[0], req[1] = pcpVersion, pcpOpMap
	binary.BigEndian.PutUint32(req[4:8], uint32(lifetime/time.Second))
	client := local.As16() // IPv4-mapped
	copy(req[8:24], client[:])
	m := req[pcpHeaderLen:]
	copy(m[0:12], nonce[:])
	m[12] = pcpProtoUDP
	binary.BigEndian.PutUint16(m[16:18], internal)
	binary.BigEndian.PutUint16(m[18:20], suggested)
	any4 := netip.IPv4Unspecified().As16()
	copy(m[20:36], any4[:])

	var unsupported bool
	resp, err := exchange(ctx, gw, req, func(b []byte) bool {
		// NAT-PMP-only routers answer with version 0 and an error.
		if len(b) >= 2 && b[0] == 0 {
			unsupported = true
			return true
		}
		return len(b) >= pcpHeaderLen+pcpMapLen && b[0] == pcpVersion && b[1] == 0x80|pcpOpMap &&
			bytes.Equal(b[pcpHeaderLen:pcpHeaderLen+12], nonce[:])
	})
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	if unsupported {
		return netip.AddrPort{}, 0, errUnsupported
	}
	switch code := resp[3]; code {
	case 0:
	case pcpUnsuppVers:
		return netip.AddrPort{}, 0, errUnsupported
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("PCP result %d", code)
	}
	life := time.Duration(binary.BigEndian.Uint32(resp[4:8])) * time.Second
	rm := resp[pcpHeaderLen:]
	port := binary.BigEndian.Uint16(rm[18:20])
	ip := netip.AddrFrom16([16]byte(rm[20:36])).Unmap()
	return netip.AddrPortFrom(ip, port), life, nil
}

func newNonce() [12]byte {
	var n [12]byte
	rand.Read(n[:])
	return n
}
