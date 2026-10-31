package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// NAT-PMP (RFC 6886) and PCP (RFC 6887) both talk UDP to the gateway on
// port 5351. PCP is NAT-PMP's successor; routers usually speak one of the
// two, and NAT-PMP-only routers answer PCP with an "unsupported version".

const pmpPort = 5351

var errUnsupported = errors.New("router does not support this protocol")

// exchange sends req and returns the first reply accepted by ok, retrying
// with backoff.
func exchange(ctx context.Context, gw netip.AddrPort, req []byte, ok func([]byte) bool) ([]byte, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(gw))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	buf := make([]byte, 1100)
	wait := 250 * time.Millisecond
	for try := 0; try < 3; try++ {
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(wait)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.SetReadDeadline(deadline)
		for {
			n, err := c.Read(buf)
			if err != nil {
				break // timeout: retry
			}
			if ok(buf[:n]) {
				return buf[:n], nil
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		wait *= 2
	}
	return nil, errors.New("no reply")
}

// pmpExternalIP asks a NAT-PMP router for its external address (read-only).
func pmpExternalIP(ctx context.Context, gw netip.AddrPort) (netip.Addr, error) {
	resp, err := exchange(ctx, gw, []byte{0, 0}, func(b []byte) bool { return len(b) >= 12 && b[0] == 0 && b[1] == 128 })
	if err != nil {
		return netip.Addr{}, err
	}
	if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
		return netip.Addr{}, fmt.Errorf("NAT-PMP result %d", code)
	}
	return netip.AddrFrom4([4]byte(resp[8:12])), nil
}

// pmpMap asks for a UDP mapping; lifetime 0 deletes it.
func pmpMap(ctx context.Context, gw netip.AddrPort, internal, suggested uint16, lifetime time.Duration) (uint16, time.Duration, error) {
	req := make([]byte, 12)
	req[1] = 1 // map UDP
	binary.BigEndian.PutUint16(req[4:6], internal)
	binary.BigEndian.PutUint16(req[6:8], suggested)
	binary.BigEndian.PutUint32(req[8:12], uint32(lifetime/time.Second))
	resp, err := exchange(ctx, gw, req, func(b []byte) bool {
		return len(b) >= 16 && b[0] == 0 && b[1] == 129 && binary.BigEndian.Uint16(b[8:10]) == internal
	})
	if err != nil {
		return 0, 0, err
	}
	if code := binary.BigEndian.Uint16(resp[2:4]); code != 0 {
		return 0, 0, fmt.Errorf("NAT-PMP result %d", code)
	}
	return binary.BigEndian.Uint16(resp[10:12]), time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second, nil
}
