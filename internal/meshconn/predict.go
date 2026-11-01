package meshconn

import (
	"net/netip"
	"slices"
	"time"
)

// Symmetric-NAT port prediction.
//
// A symmetric (endpoint-dependent) NAT gives each destination its own
// public port, so the port a peer learned from STUN is not the one it will
// use towards us, and a restrictive NAT on our side drops its packets. Such
// a peer reports two STUN endpoints on the same public IP with different
// ports; many NATs hand out ports in sequence, so the next mapping is
// likely just past the highest one seen, in steps of the observed gap. We
// periodically send a small burst of pings to those predicted ports: when
// one lands on the mapping the peer just opened towards us, its pong proves
// a direct path like any other.

const (
	sprayCount    = 16
	sprayInterval = 9 * time.Second
	maxSprayStep  = 32
)

// predictPorts returns likely next public endpoints for a peer behind a
// symmetric NAT, or nil if its endpoints don't look like one.
func predictPorts(eps []netip.AddrPort) []netip.AddrPort {
	byIP := map[netip.Addr][]uint16{}
	for _, ep := range eps {
		a := ep.Addr().Unmap()
		if !a.Is4() || a.IsLinkLocalUnicast() || ep.Port() == 0 {
			continue
		}
		byIP[a] = append(byIP[a], ep.Port())
	}
	var out []netip.AddrPort
	for ip, ports := range byIP {
		slices.Sort(ports)
		ports = slices.Compact(ports)
		if len(ports) < 2 {
			continue // one mapping per IP: not symmetric
		}
		step := uint16(maxSprayStep)
		for i := 1; i < len(ports); i++ {
			if d := ports[i] - ports[i-1]; d > 0 && d < step {
				step = d
			}
		}
		next := int(ports[len(ports)-1])
		for k := 1; k <= sprayCount; k++ {
			p := next + int(step)*k
			if p > 65535 {
				break
			}
			out = append(out, netip.AddrPortFrom(ip, uint16(p)))
		}
	}
	return out
}

// sprayPredicted pings predicted endpoints of p, at most every
// sprayInterval, while no direct path is known.
func (c *Conn) sprayPredicted(p *peer) {
	if c.opts.DisableDirect {
		return
	}
	c.mu.Lock()
	if time.Since(p.lastSpray) < sprayInterval {
		c.mu.Unlock()
		return
	}
	targets := predictPorts(p.cfg.Endpoints)
	if len(targets) > 0 {
		p.lastSpray = time.Now()
	}
	c.mu.Unlock()
	for _, a := range targets {
		c.sendPing(p, discoPath{udp: a}, nil)
	}
}
