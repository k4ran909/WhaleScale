package meshconn

import (
	"net/netip"
	"time"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
)

// Peer relays: an approved node forwards UDP between peers that can't
// reach each other directly. It is a UDP fast path ahead of the server's
// WebSocket relay, and it runs on the relay node's normal WireGuard socket,
// so the NAT mapping or port forward that socket already has is reused.
//
// Frames, all starting with relayMagic and a type byte:
//
//	hello      client -> relay   sealed disco Ping (registers the sender)
//	           relay -> client   sealed disco Pong (proves the relay works)
//	toRelay    client -> relay   dst node key(32) | payload
//	fromRelay  relay -> client   src node key(32) | payload
//
// A relay serves only nodes the control server lists, binds each node key
// to the address its sealed hello came from, and forwards only from that
// address, so nobody can register as, or send as, another node. Payloads
// are WireGuard ciphertext or sealed disco messages.

const (
	relayMagic = "WSPR"

	frameHello     byte = 1
	frameToRelay   byte = 2
	frameFromRelay byte = 3

	relayHeader = len(relayMagic) + 1

	helloInterval = 9 * time.Second  // keeps the client's NAT mapping open
	relayLive     = 30 * time.Second // a relay counts as usable this long after an ack
	regTTL        = 75 * time.Second // relay forgets clients that stop saying hello
)

func isRelayFrame(b []byte) bool {
	return len(b) > relayHeader && string(b[:len(relayMagic)]) == relayMagic
}

func relayFrame(typ byte, k key.Public, payload []byte) []byte {
	b := make([]byte, 0, relayHeader+32+len(payload))
	b = append(b, relayMagic...)
	b = append(b, typ)
	b = append(b, k[:]...)
	return append(b, payload...)
}

func helloFrame(sealed []byte) []byte {
	b := make([]byte, 0, relayHeader+len(sealed))
	b = append(b, relayMagic...)
	b = append(b, frameHello)
	return append(b, sealed...)
}

// PeerRelayConfig is what the network map says about a relay.
type PeerRelayConfig struct {
	Name      string
	NodeKey   key.Public
	DiscoKey  key.Public
	Endpoints []netip.AddrPort
}

// relayState is this node's view of one relay it may use.
type relayState struct {
	name              string
	nodeKey, discoKey key.Public
	candidates        []netip.AddrPort
	bestAddr          netip.AddrPort
	latency           time.Duration
	lastAck           time.Time
	lastHello         time.Time
	hellos            map[disco.TxID]pingState
}

func (r *relayState) live() bool { return r.bestAddr.IsValid() && time.Since(r.lastAck) < relayLive }

// relayServer is the state of this node acting as a relay.
type relayServer struct {
	clients map[key.Public]key.Public // disco key -> node key
	reg     map[key.Public]registration
	byAddr  map[netip.AddrPort]key.Public
}

type registration struct {
	addr netip.AddrPort
	seen time.Time
}

// SetPeerRelays replaces the relays this node may use, keeping state for
// unchanged ones.
func (c *Conn) SetPeerRelays(cfgs []PeerRelayConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := map[key.Public]bool{}
	for _, cfg := range cfgs {
		if cfg.NodeKey == c.opts.NodeKey {
			continue
		}
		keep[cfg.NodeKey] = true
		r := c.peerRelays[cfg.NodeKey]
		if r == nil || r.discoKey != cfg.DiscoKey {
			r = &relayState{nodeKey: cfg.NodeKey, discoKey: cfg.DiscoKey, hellos: map[disco.TxID]pingState{}}
			c.peerRelays[cfg.NodeKey] = r
		}
		r.name = cfg.Name
		r.candidates = c.usable(cfg.Endpoints)
	}
	for k, r := range c.peerRelays {
		if !keep[k] {
			delete(c.peerRelays, k)
			for _, p := range c.peers {
				if p.relayVia == r {
					p.relayVia = nil
				}
			}
		}
	}
}

// SetRelayClients turns relaying on (with the nodes it may serve, by disco
// key) or off (nil).
func (c *Conn) SetRelayClients(clients map[key.Public]key.Public) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if clients == nil {
		if c.relayServe != nil {
			c.log.Info("peer relay off")
		}
		c.relayServe = nil
		return
	}
	if c.relayServe == nil {
		c.log.Info("peer relay on: forwarding for peers that can't connect directly", "clients", len(clients))
		c.relayServe = &relayServer{reg: map[key.Public]registration{}, byAddr: map[netip.AddrPort]key.Public{}}
	}
	c.relayServe.clients = clients
	// Drop registrations of nodes no longer allowed.
	allowed := map[key.Public]bool{}
	for _, nk := range clients {
		allowed[nk] = true
	}
	for nk, r := range c.relayServe.reg {
		if !allowed[nk] {
			delete(c.relayServe.reg, nk)
			delete(c.relayServe.byAddr, r.addr)
		}
	}
}

// helloRelays registers with each relay every helloInterval, which also
// keeps the NAT mapping towards it open.
func (c *Conn) helloRelays() {
	c.mu.Lock()
	type send struct {
		r  *relayState
		to netip.AddrPort
		tx disco.TxID
	}
	var sends []send
	for _, r := range c.peerRelays {
		for tx, h := range r.hellos {
			if time.Since(h.sent) > pingTimeout {
				delete(r.hellos, tx)
			}
		}
		if time.Since(r.lastHello) < helloInterval && r.live() {
			continue
		}
		r.lastHello = time.Now()
		targets := r.candidates
		if r.live() {
			targets = []netip.AddrPort{r.bestAddr}
		}
		for _, a := range targets {
			tx := disco.NewTxID()
			r.hellos[tx] = pingState{to: a, sent: time.Now()}
			sends = append(sends, send{r, a, tx})
		}
	}
	c.mu.Unlock()
	for _, s := range sends {
		sealed := disco.Seal(c.opts.DiscoKey, s.r.discoKey, &disco.Ping{TxID: s.tx, NodeKey: c.opts.NodeKey})
		c.writeUDP(helloFrame(sealed), s.to)
	}
}

// probeViaRelays pings p through every live relay; a pong proves the path.
func (c *Conn) probeViaRelays(p *peer, reply chan PingResult) {
	c.mu.Lock()
	var relays []*relayState
	for _, r := range c.peerRelays {
		if r.live() && r.nodeKey != p.nodeKey {
			relays = append(relays, r)
		}
	}
	c.mu.Unlock()
	for _, r := range relays {
		c.sendPing(p, discoPath{peerRelay: r}, reply)
	}
}

func (c *Conn) handleRelayFrame(pkt []byte, from netip.AddrPort) {
	body := pkt[relayHeader:]
	switch pkt[len(relayMagic)] {
	case frameHello:
		c.handleHello(body, from)
	case frameToRelay:
		if len(body) < 32 {
			return
		}
		c.forward(key.Public(body[:32]), body[32:], from)
	case frameFromRelay:
		if len(body) < 32 {
			return
		}
		c.fromRelay(key.Public(body[:32]), body[32:], from)
	}
}

// handleHello handles a sealed hello: a Ping registers a client with this
// relay; a Pong acknowledges our own registration with a relay.
func (c *Conn) handleHello(sealed []byte, from netip.AddrPort) {
	sender, msg, err := disco.Open(c.opts.DiscoKey, sealed)
	if err != nil {
		return
	}
	switch m := msg.(type) {
	case *disco.Ping:
		c.mu.Lock()
		rs := c.relayServe
		if rs == nil || rs.clients[sender] != m.NodeKey {
			c.mu.Unlock()
			return
		}
		if old, ok := rs.reg[m.NodeKey]; ok && old.addr != from {
			delete(rs.byAddr, old.addr)
		}
		rs.reg[m.NodeKey] = registration{addr: from, seen: time.Now()}
		rs.byAddr[from] = m.NodeKey
		c.mu.Unlock()
		c.writeUDP(helloFrame(disco.Seal(c.opts.DiscoKey, sender, &disco.Pong{TxID: m.TxID, Src: from})), from)

	case *disco.Pong:
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, r := range c.peerRelays {
			if r.discoKey != sender {
				continue
			}
			h, ok := r.hellos[m.TxID]
			if !ok || h.to != from {
				return
			}
			delete(r.hellos, m.TxID)
			lat := time.Since(h.sent)
			if !r.live() || from == r.bestAddr || lat < r.latency/2 {
				if !r.live() {
					c.log.Info("peer relay reachable", "relay", r.name, "addr", from, "latency", lat.Round(time.Microsecond))
				}
				r.bestAddr, r.latency = from, lat
			}
			if from == r.bestAddr {
				r.lastAck = time.Now()
			}
			return
		}
	}
}

// forward relays a client's frame to its destination.
func (c *Conn) forward(dst key.Public, payload []byte, from netip.AddrPort) {
	c.mu.Lock()
	rs := c.relayServe
	if rs == nil {
		c.mu.Unlock()
		return
	}
	src, ok := rs.byAddr[from]
	srcReg := rs.reg[src]
	dstReg, dstOK := rs.reg[dst]
	c.mu.Unlock()
	if !ok || srcReg.addr != from || time.Since(srcReg.seen) > regTTL || !dstOK || time.Since(dstReg.seen) > regTTL {
		return
	}
	c.writeUDP(relayFrame(frameFromRelay, src, payload), dstReg.addr)
}

// fromRelay handles a frame a relay forwarded to us.
func (c *Conn) fromRelay(src key.Public, payload []byte, from netip.AddrPort) {
	c.mu.Lock()
	var r *relayState
	for _, x := range c.peerRelays {
		if x.bestAddr == from {
			r = x
			break
		}
	}
	p := c.peers[src]
	c.mu.Unlock()
	if r == nil || p == nil {
		return // not a relay we registered with, or not a peer
	}
	if disco.Is(payload) {
		c.handleDisco(payload, discoPath{peerRelay: r}, src)
		return
	}
	data := make([]byte, len(payload))
	copy(data, payload)
	c.deliver(data, p)
}
