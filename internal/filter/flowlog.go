package filter

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Flow logging counts traffic per connection: who opened it (client), who
// it went to (server, port), and the bytes and packets each way, plus
// inbound attempts the policy refused. It is separate from the reply
// table enforcement uses, so turning it on never changes what is allowed.

const maxLoggedConns = 8192

// FlowRecord is one connection's activity since the previous Drain.
type FlowRecord struct {
	Proto    uint8
	Client   netip.Addr
	Server   netip.Addr
	Port     uint16
	Outbound bool // this node opened the connection
	Denied   bool // an inbound attempt the policy refused
	Start    time.Time
	End      time.Time
	// From this node's point of view.
	BytesSent, BytesRecv     uint64
	PacketsSent, PacketsRecv uint64
}

type connKey struct {
	proto          uint8
	client, server netip.Addr
	port           uint16
	outbound       bool
	denied         bool
}

type connStats struct {
	key                      connKey
	first, last              time.Time
	bytesSent, bytesRecv     uint64
	packetsSent, packetsRecv uint64
}

type flowLog struct {
	mu     sync.Mutex
	byFlow map[flow]*connStats    // both directions of a connection share a flow key
	denied map[connKey]*connStats // refused inbound attempts, aggregated
}

// SetFlowLogging turns per-connection counting on or off.
func (f *Filter) SetFlowLogging(on bool) {
	f.logMu.Lock()
	defer f.logMu.Unlock()
	switch {
	case on && f.log == nil:
		f.log = &flowLog{byFlow: map[flow]*connStats{}, denied: map[connKey]*connStats{}}
	case !on:
		f.log = nil
	}
}

func (f *Filter) flowLogger() *flowLog {
	f.logMu.Lock()
	defer f.logMu.Unlock()
	return f.log
}

// logOutbound counts a packet this node sent. Its flow key matches both a
// connection this node opened and replies to one a peer opened.
func (l *flowLog) logOutbound(p packet, size int, now time.Time) {
	k, ok := outboundKey(p)
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cs := l.byFlow[k]
	if cs == nil {
		if len(l.byFlow) >= maxLoggedConns {
			return
		}
		cs = &connStats{key: connKey{proto: p.proto, client: p.src, server: p.dst, port: serverPort(p), outbound: true}, first: now}
		l.byFlow[k] = cs
	}
	cs.last = now
	cs.bytesSent += uint64(size)
	cs.packetsSent++
}

// logInbound counts a packet a peer sent, allowed or not.
func (l *flowLog) logInbound(p packet, size int, allowed bool, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !allowed {
		key := connKey{proto: p.proto, client: p.src, server: p.dst, port: serverPort(p), denied: true}
		cs := l.denied[key]
		if cs == nil {
			if len(l.denied) >= maxLoggedConns {
				return
			}
			cs = &connStats{key: key, first: now}
			l.denied[key] = cs
		}
		cs.last = now
		cs.bytesRecv += uint64(size)
		cs.packetsRecv++
		return
	}
	k, ok := inboundKey(p)
	if !ok {
		return
	}
	cs := l.byFlow[k]
	if cs == nil {
		if len(l.byFlow) >= maxLoggedConns {
			return
		}
		cs = &connStats{key: connKey{proto: p.proto, client: p.src, server: p.dst, port: serverPort(p)}, first: now}
		l.byFlow[k] = cs
	}
	cs.last = now
	cs.bytesRecv += uint64(size)
	cs.packetsRecv++
}

// serverPort is the destination port of the packet that opened the
// connection; ICMP has none.
func serverPort(p packet) uint16 {
	if p.hasPorts {
		return p.dstPort
	}
	return 0
}

// DrainFlows returns activity since the last call, busiest first, and
// forgets idle connections.
func (f *Filter) DrainFlows(limit int) []FlowRecord {
	l := f.flowLogger()
	if l == nil {
		return nil
	}
	now := f.now()
	l.mu.Lock()
	// Two directions of one connection share one connStats; report it once.
	seen := map[*connStats]bool{}
	var out []FlowRecord
	take := func(cs *connStats) {
		if seen[cs] || cs.packetsSent+cs.packetsRecv == 0 {
			return
		}
		seen[cs] = true
		k := cs.key
		out = append(out, FlowRecord{Proto: k.proto, Client: k.client, Server: k.server, Port: k.port,
			Outbound: k.outbound, Denied: k.denied, Start: cs.first, End: cs.last,
			BytesSent: cs.bytesSent, BytesRecv: cs.bytesRecv, PacketsSent: cs.packetsSent, PacketsRecv: cs.packetsRecv})
		cs.bytesSent, cs.bytesRecv, cs.packetsSent, cs.packetsRecv = 0, 0, 0, 0
		cs.first = now
	}
	for k, cs := range l.byFlow {
		take(cs)
		if now.Sub(cs.last) > flowTTL {
			delete(l.byFlow, k)
		}
	}
	for _, cs := range l.denied {
		take(cs)
	}
	clear(l.denied)
	l.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i].BytesSent+out[i].BytesRecv > out[j].BytesSent+out[j].BytesRecv
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
