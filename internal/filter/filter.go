// Package filter enforces a node's inbound packet policy on decrypted
// tunnel traffic. It is stateful: replies to connections this node opened
// are allowed even when the policy would not allow the peer to initiate.
package filter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/k4ran909/whalescale/internal/policy"
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	flowTTL  = 2 * time.Minute
	maxFlows = 16384
)

// flow identifies traffic from the remote side's point of view.
type flow struct {
	proto     uint8
	remote    netip.AddrPort
	localPort uint16
}

type Filter struct {
	mu    sync.RWMutex
	rules []policy.Rule
	self  []netip.Addr

	flowMu sync.Mutex
	flows  map[flow]time.Time
	now    func() time.Time
}

func New() *Filter {
	return &Filter{flows: map[flow]time.Time{}, now: time.Now}
}

// SetRules replaces the inbound rules. A nil slice denies all new inbound.
// self lists this node's own addresses, which rules without Dst cover.
func (f *Filter) SetRules(rules []policy.Rule, self []netip.Addr) {
	f.mu.Lock()
	f.rules, f.self = rules, self
	f.mu.Unlock()
}

type packet struct {
	proto    uint8
	src, dst netip.Addr
	srcPort  uint16
	dstPort  uint16
	hasPorts bool
	// Non-first IPv4 fragment: no transport header.
	fragment bool
}

func parse(b []byte) (packet, bool) {
	var p packet
	if len(b) < 1 {
		return p, false
	}
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, false
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			p.fragment = true
			return p, true
		}
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return p, false
		}
		// Extension headers are not walked; such packets match only rules
		// that allow all ports from the source.
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		l4 = b[40:]
	default:
		return p, false
	}
	if (p.proto == protoTCP || p.proto == protoUDP) && len(l4) >= 4 {
		p.srcPort = binary.BigEndian.Uint16(l4[0:2])
		p.dstPort = binary.BigEndian.Uint16(l4[2:4])
		p.hasPorts = true
	}
	return p, true
}

// Outbound records a packet leaving this node so replies are let back in.
func (f *Filter) Outbound(b []byte) {
	p, ok := parse(b)
	if !ok || !p.hasPorts {
		return
	}
	k := flow{proto: p.proto, remote: netip.AddrPortFrom(p.dst, p.dstPort), localPort: p.srcPort}
	now := f.now()
	f.flowMu.Lock()
	if len(f.flows) >= maxFlows {
		f.expireLocked(now)
	}
	if len(f.flows) < maxFlows {
		f.flows[k] = now
	}
	f.flowMu.Unlock()
}

func (f *Filter) expireLocked(now time.Time) {
	for k, t := range f.flows {
		if now.Sub(t) > flowTTL {
			delete(f.flows, k)
		}
	}
}

// Inbound reports whether a decrypted packet from a peer may be delivered.
func (f *Filter) Inbound(b []byte) bool {
	p, ok := parse(b)
	if !ok {
		return false
	}
	if p.hasPorts {
		k := flow{proto: p.proto, remote: netip.AddrPortFrom(p.src, p.srcPort), localPort: p.dstPort}
		f.flowMu.Lock()
		t, seen := f.flows[k]
		if seen && f.now().Sub(t) <= flowTTL {
			f.flows[k] = f.now()
			f.flowMu.Unlock()
			return true
		}
		f.flowMu.Unlock()
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	toSelf := false
	for _, a := range f.self {
		if a == p.dst {
			toSelf = true
		}
	}
	for _, r := range f.rules {
		if !srcMatches(r.Src, p.src) {
			continue
		}
		if len(r.Dst) == 0 && !toSelf || len(r.Dst) > 0 && !srcMatches(r.Dst, p.dst) {
			continue
		}
		switch {
		case p.hasPorts:
			for _, pr := range r.Ports {
				if p.dstPort >= pr.First && p.dstPort <= pr.Last {
					return true
				}
			}
		case p.proto == protoICMP || p.proto == protoICMPv6 || p.fragment:
			// Ping and fragments are allowed from any source with any rule.
			return true
		default:
			if allPorts(r.Ports) {
				return true
			}
		}
	}
	return false
}

func srcMatches(pfxs []netip.Prefix, a netip.Addr) bool {
	for _, p := range pfxs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func allPorts(prs []policy.PortRange) bool {
	for _, pr := range prs {
		if pr.First == 0 && pr.Last == 65535 {
			return true
		}
	}
	return false
}
