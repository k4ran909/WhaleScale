package engine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"
)

// MagicDNSAddr is where the OS sends DNS queries in OS TUN mode. It's in
// the mesh range, so queries are routed into the tunnel, where the agent
// answers them itself (interceptDNS): nothing listens on port 53 of the
// machine, which other software often holds (Windows' Internet Connection
// Sharing for WSL2 and Docker, local resolvers). The server never gives
// this address to a node.
var MagicDNSAddr = netip.MustParseAddr("100.100.100.100")

// parseDNSQuery returns the sender and DNS message of an IPv4 UDP packet
// to MagicDNSAddr port 53, or ok=false for anything else. Fragments aren't
// queries: DNS queries are small.
func parseDNSQuery(pkt []byte) (src netip.Addr, sport uint16, msg []byte, ok bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return src, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total > len(pkt) || total < ihl+8 {
		return src, 0, nil, false
	}
	if flagsFrag := binary.BigEndian.Uint16(pkt[6:8]); flagsFrag&0x3fff != 0 { // MF set or an offset
		return src, 0, nil, false
	}
	if netip.AddrFrom4([4]byte(pkt[16:20])) != MagicDNSAddr {
		return src, 0, nil, false
	}
	udp := pkt[ihl:total]
	if binary.BigEndian.Uint16(udp[2:4]) != 53 {
		return src, 0, nil, false
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		return src, 0, nil, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), binary.BigEndian.Uint16(udp[0:2]), udp[8:ulen], true
}

// dnsReply builds the IPv4 packet(s) that carry msg from MagicDNSAddr:53 to
// dst:dport, fragmenting to fit mtu. Each packet starts headroom bytes into
// its buffer, as tun.Device.Write wants.
func dnsReply(dst netip.Addr, dport uint16, msg []byte, mtu int, id uint16, headroom int) [][]byte {
	udp := make([]byte, 8+len(msg))
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], msg)
	src4, dst4 := MagicDNSAddr.As4(), dst.As4()
	sum := checksumAdd(0, src4[:])
	sum = checksumAdd(sum, dst4[:])
	sum += 17 + uint32(len(udp))
	csum := ^checksumFold(checksumAdd(sum, udp))
	if csum == 0 {
		csum = 0xffff // zero means "no checksum" in UDP
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)

	// Fragment payloads must be multiples of 8 bytes, except the last.
	per := (mtu - 20) &^ 7
	var out [][]byte
	for off := 0; off < len(udp); off += per {
		end := min(off+per, len(udp))
		buf := make([]byte, headroom+20+end-off)
		ip := buf[headroom:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		binary.BigEndian.PutUint16(ip[4:6], id)
		frag := uint16(off / 8)
		if end < len(udp) {
			frag |= 0x2000 // more fragments
		}
		binary.BigEndian.PutUint16(ip[6:8], frag)
		ip[8] = 64
		ip[9] = 17
		copy(ip[12:16], src4[:])
		copy(ip[16:20], dst4[:])
		binary.BigEndian.PutUint16(ip[10:12], ^checksumFold(checksumAdd(0, ip[:20])))
		copy(ip[20:], udp[off:end])
		out = append(out, buf)
	}
	return out
}

func checksumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// tunHeadroom is the space before a packet that tun.Device.Write wants
// (a virtio header on Linux, the address family on macOS).
const tunHeadroom = 16

// interceptDNS answers a DNS query the OS sent to MagicDNSAddr: the query
// is answered (or forwarded, through an exit node) off the packet path, and
// the reply written back to the OS through the TUN.
func (e *Engine) interceptDNS(pkt []byte) bool {
	src, sport, msg, ok := parseDNSQuery(pkt)
	if !ok {
		return false
	}
	select {
	case e.dnsSem <- struct{}{}:
	default:
		return true // too many at once: drop it, the OS retries
	}
	query := slices.Clone(msg) // the packet buffer goes back to WireGuard
	dev := e.tunDev
	go func() {
		defer func() { <-e.dnsSem }()
		ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
		defer cancel()
		resp, ok := e.dns.HandleFrom(ctx, src, query)
		if !ok || dev == nil {
			return
		}
		for _, b := range dnsReply(src, sport, resp, MTU, uint16(e.dnsID.Add(1)), tunHeadroom) {
			if _, err := dev.Write([][]byte{b}, tunHeadroom); err != nil {
				e.log.Debug("write MagicDNS reply", "err", err)
				return
			}
		}
	}()
	return true
}
