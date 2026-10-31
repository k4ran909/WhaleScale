// Package meshconn is the UDP layer under WireGuard. It implements
// wireguard-go's conn.Bind with endpoints that name a peer by its node key
// rather than an ip:port, and decides per packet whether to send directly
// or through the relay:
//
//   - A heartbeat sends sealed disco pings to every candidate endpoint of
//     each peer. A pong proves a direct path and records its latency.
//   - While no direct path is proven, traffic goes via the relay, and a
//     CallMeMaybe over the relay asks the peer to ping us back at the same
//     time, which is what opens holes in both NATs.
//   - STUN, disco and WireGuard share one UDP socket, so the public mapping
//     STUN discovers is the same one peers punch through to.
//
// Phase 1 runs discovery for every peer. Restricting it to recently active
// peers is a scaling step for later.
package meshconn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
	"github.com/k4ran909/whalescale/internal/relay"
	"github.com/k4ran909/whalescale/internal/stun"
)

const (
	heartbeat = 3 * time.Second
	// A direct path is trusted this long after its last pong.
	trustDuration  = 6500 * time.Millisecond
	pingTimeout    = 5 * time.Second
	callMeMaybeGap = 5 * time.Second
	stunInterval   = 20 * time.Second
	recvQueue      = 1024
	maxPacket      = 65535
)

// Options configure a Conn.
type Options struct {
	Port     uint16 // UDP port; 0 picks one
	DiscoKey key.Private
	NodeKey  key.Public
	Log      *slog.Logger
	// Control, if set, is applied to the UDP sockets (used to keep them off
	// the tunnel when an exit node routes everything into it).
	Control func(network, address string, c syscall.RawConn) error
	// IncludeLoopback advertises 127.0.0.1 as an endpoint. Tests only.
	IncludeLoopback bool
	// DisableDirect never tries direct paths to peers (relays are still
	// reached over UDP). Tests only: simulates two strict NATs.
	DisableDirect bool
	// OnEndpoints is called when the node's own candidate endpoints change.
	OnEndpoints func([]netip.AddrPort)
	// Exclude lists prefixes never to advertise or use as direct paths,
	// such as the mesh's own address ranges (a tunnel inside the tunnel).
	Exclude []netip.Prefix
}

// PeerConfig is what the network map says about a peer.
type PeerConfig struct {
	Name      string
	NodeKey   key.Public
	DiscoKey  key.Public
	Endpoints []netip.AddrPort
}

type Conn struct {
	opts Options
	log  *slog.Logger
	pc4  *net.UDPConn
	pc6  *net.UDPConn // nil if IPv6 is unavailable
	port uint16

	ctx    context.Context
	cancel context.CancelFunc

	recv chan rxPacket

	bindMu   sync.Mutex
	bindDone chan struct{} // closed when the Bind is closed

	mu          sync.Mutex
	relay       *relay.Client
	stunServers []netip.AddrPort
	peers       map[key.Public]*peer // by node key
	byDisco     map[key.Public]*peer
	byAddr      map[netip.AddrPort]*peer
	stunTx      map[stun.TxID]stunReq
	stunResults map[netip.AddrPort]netip.AddrPort // server -> mapped
	endpoints   []netip.AddrPort
	peerRelays  map[key.Public]*relayState // relays we may use, by node key
	relayServe  *relayServer               // non-nil while we relay for others
}

type stunReq struct {
	server netip.AddrPort
	sent   time.Time
}

type rxPacket struct {
	data []byte
	ep   *endpoint
}

type pingState struct {
	to       netip.AddrPort // invalid means via a relay
	viaRelay *relayState    // set when sent through a peer relay
	sent     time.Time
	reply    chan PingResult
}

// discoPath is how a disco message travelled: directly over UDP, through
// a peer relay, or (both unset) through the server's relay.
type discoPath struct {
	udp       netip.AddrPort
	peerRelay *relayState
}

type peer struct {
	// Immutable: a peer whose disco key changes is replaced, not mutated.
	nodeKey, discoKey key.Public
	ep                *endpoint

	cfg PeerConfig // guarded by Conn.mu

	candidates  []netip.AddrPort // netmap endpoints + CallMeMaybe + seen pings
	bestAddr    netip.AddrPort
	bestLatency time.Duration
	lastPong    time.Time
	lastCMM     time.Time
	pings       map[disco.TxID]pingState

	// Peer relay path, proven by a pong that came back through it.
	relayVia     *relayState
	relayPong    time.Time
	relayLatency time.Duration

	rx, tx atomic.Uint64
}

// endpoint is a conn.Endpoint naming a peer by node key.
type endpoint struct{ key key.Public }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.key.Hex() }
func (e *endpoint) DstToBytes() []byte  { return e.key[:] }
func (e *endpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// New opens the UDP sockets and starts discovery. Close stops everything.
func New(opts Options) (*Conn, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	lc := net.ListenConfig{Control: opts.Control}
	listen := func(network string, port uint16) (*net.UDPConn, error) {
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, err
		}
		return pc.(*net.UDPConn), nil
	}
	pc4, err := listen("udp4", opts.Port)
	if err != nil {
		return nil, fmt.Errorf("listen udp4: %w", err)
	}
	port := uint16(pc4.LocalAddr().(*net.UDPAddr).Port)
	pc6, err := listen("udp6", port)
	if err != nil {
		opts.Log.Info("IPv6 UDP unavailable; continuing with IPv4 only", "err", err)
		pc6 = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		opts: opts, log: opts.Log, pc4: pc4, pc6: pc6, port: port,
		ctx: ctx, cancel: cancel,
		recv:        make(chan rxPacket, recvQueue),
		bindDone:    make(chan struct{}),
		peers:       map[key.Public]*peer{},
		byDisco:     map[key.Public]*peer{},
		byAddr:      map[netip.AddrPort]*peer{},
		stunTx:      map[stun.TxID]stunReq{},
		stunResults: map[netip.AddrPort]netip.AddrPort{},
		peerRelays:  map[key.Public]*relayState{},
	}
	close(c.bindDone) // not open yet
	go c.readUDP(pc4)
	if pc6 != nil {
		go c.readUDP(pc6)
	}
	go c.heartbeatLoop()
	go c.stunLoop()
	c.updateEndpoints()
	return c, nil
}

func (c *Conn) Port() uint16 { return c.port }

// Close shuts down sockets and background work.
func (c *Conn) Close() error {
	c.cancel()
	c.pc4.Close()
	if c.pc6 != nil {
		c.pc6.Close()
	}
	return nil
}

// SetRelay sets the relay client used when no direct path exists.
func (c *Conn) SetRelay(r *relay.Client) {
	c.mu.Lock()
	c.relay = r
	c.mu.Unlock()
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case p := <-r.Recv():
				c.handleRelayPacket(p)
			}
		}
	}()
}

// SetSTUNServers sets the STUN servers used for endpoint discovery.
func (c *Conn) SetSTUNServers(servers []netip.AddrPort) {
	c.mu.Lock()
	changed := !slices.Equal(c.stunServers, servers)
	c.stunServers = servers
	c.mu.Unlock()
	if changed {
		c.sendSTUN()
	}
}

// SetPeers replaces the peer set, keeping path state for unchanged peers.
func (c *Conn) SetPeers(cfgs []PeerConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := map[key.Public]bool{}
	for _, cfg := range cfgs {
		keep[cfg.NodeKey] = true
		eps := c.usable(cfg.Endpoints)
		p := c.peers[cfg.NodeKey]
		if p == nil || p.discoKey != cfg.DiscoKey {
			if p != nil {
				c.forgetLocked(p)
			}
			p = &peer{nodeKey: cfg.NodeKey, discoKey: cfg.DiscoKey, ep: &endpoint{key: cfg.NodeKey},
				pings: map[disco.TxID]pingState{}}
			c.peers[cfg.NodeKey] = p
		}
		cfg.Endpoints = eps
		p.cfg = cfg
		p.candidates = mergeAddrs(eps, p.candidates)
		c.byDisco[cfg.DiscoKey] = p
	}
	for k, p := range c.peers {
		if !keep[k] {
			c.forgetLocked(p)
			delete(c.peers, k)
		}
	}
}

func (c *Conn) forgetLocked(p *peer) {
	delete(c.byDisco, p.discoKey)
	for a, q := range c.byAddr {
		if q == p {
			delete(c.byAddr, a)
		}
	}
}

func (c *Conn) usable(eps []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for _, ep := range eps {
		if ep.IsValid() && !c.excluded(ep.Addr()) {
			out = append(out, netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()))
		}
	}
	return out
}

func (c *Conn) excluded(a netip.Addr) bool {
	for _, p := range c.opts.Exclude {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- conn.Bind ---

// Bind returns the conn.Bind to hand to wireguard-go.
func (c *Conn) Bind() conn.Bind { return (*bind)(c) }

type bind Conn

func (b *bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	c := (*Conn)(b)
	c.bindMu.Lock()
	defer c.bindMu.Unlock()
	select {
	case <-c.bindDone:
	default:
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	done := make(chan struct{})
	c.bindDone = done
	return []conn.ReceiveFunc{c.receiveFunc(done)}, c.port, nil
}

func (b *bind) Close() error {
	c := (*Conn)(b)
	c.bindMu.Lock()
	defer c.bindMu.Unlock()
	select {
	case <-c.bindDone:
	default:
		close(c.bindDone)
	}
	return nil
}

func (b *bind) SetMark(uint32) error { return nil }
func (b *bind) BatchSize() int       { return 16 }

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	c := (*Conn)(b)
	k, err := key.ParsePublicHex(s)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.peers[k]; p != nil {
		return p.ep, nil
	}
	return &endpoint{key: k}, nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	c := (*Conn)(b)
	e, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	c.mu.Lock()
	p := c.peers[e.key]
	var addr, relayAddr netip.AddrPort
	if p != nil && p.bestAddr.IsValid() && time.Since(p.lastPong) < trustDuration {
		addr = p.bestAddr
	} else if p != nil && p.relayVia != nil && time.Since(p.relayPong) < trustDuration {
		relayAddr = p.relayVia.bestAddr
	}
	r := c.relay
	c.mu.Unlock()
	if p == nil {
		return fmt.Errorf("unknown peer %s", e.key.ShortString())
	}
	var firstErr error
	for _, buf := range bufs {
		var err error
		if addr.IsValid() {
			err = c.writeUDP(buf, addr)
		} else if relayAddr.IsValid() {
			err = c.writeUDP(relayFrame(frameToRelay, e.key, buf), relayAddr)
		} else if r != nil {
			err = r.Send(e.key, buf)
		} else {
			err = errors.New("no path to peer")
		}
		if err == nil {
			p.tx.Add(uint64(len(buf)))
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Conn) receiveFunc(done chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var first rxPacket
		select {
		case <-done:
			return 0, net.ErrClosed
		case <-c.ctx.Done():
			return 0, net.ErrClosed
		case first = <-c.recv:
		}
		n := 0
		take := func(p rxPacket) {
			sizes[n] = copy(packets[n], p.data)
			eps[n] = p.ep
			n++
		}
		take(first)
		for n < len(packets) {
			select {
			case p := <-c.recv:
				take(p)
			default:
				return n, nil
			}
		}
		return n, nil
	}
}

func (c *Conn) deliver(data []byte, p *peer) {
	p.rx.Add(uint64(len(data)))
	select {
	case c.recv <- rxPacket{data: data, ep: p.ep}:
	default: // WireGuard is not keeping up; drop
	}
}

// --- sockets ---

func (c *Conn) writeUDP(b []byte, to netip.AddrPort) error {
	pc := c.pc4
	if to.Addr().Is6() {
		if c.pc6 == nil {
			return errors.New("no IPv6 socket")
		}
		pc = c.pc6
	}
	_, err := pc.WriteToUDPAddrPort(b, to)
	return err
}

func (c *Conn) readUDP(pc *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			// Windows reports ICMP port-unreachable as a read error; ignore.
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		pkt := buf[:n]
		switch {
		case stun.Is(pkt):
			c.handleSTUN(pkt)
		case isRelayFrame(pkt):
			c.handleRelayFrame(pkt, from)
		case disco.Is(pkt):
			c.handleDisco(pkt, discoPath{udp: from}, key.Public{})
		default:
			c.mu.Lock()
			p := c.byAddr[from]
			c.mu.Unlock()
			if p == nil {
				continue // not a verified path; WireGuard would reject it anyway
			}
			c.deliver(slices.Clone(pkt), p)
		}
	}
}

func (c *Conn) handleRelayPacket(rp relay.Packet) {
	if disco.Is(rp.Data) {
		c.handleDisco(rp.Data, discoPath{}, rp.Src)
		return
	}
	c.mu.Lock()
	p := c.peers[rp.Src]
	c.mu.Unlock()
	if p != nil {
		c.deliver(rp.Data, p)
	}
}

// --- disco ---

// handleDisco processes a disco message that arrived along path. relayFrom
// is the node key a relay (server or peer) says sent it.
func (c *Conn) handleDisco(pkt []byte, path discoPath, relayFrom key.Public) {
	udpFrom := path.udp
	sender, msg, err := disco.Open(c.opts.DiscoKey, pkt)
	if err != nil {
		return
	}
	c.mu.Lock()
	p := c.byDisco[sender]
	if p == nil || (!relayFrom.IsZero() && relayFrom != p.nodeKey) {
		c.mu.Unlock()
		return
	}
	viaUDP := udpFrom.IsValid()

	switch m := msg.(type) {
	case *disco.Ping:
		if m.NodeKey != p.nodeKey {
			c.mu.Unlock()
			return
		}
		if viaUDP {
			// The peer reached us from here, so replies will reach it too.
			c.byAddr[udpFrom] = p
			p.candidates = mergeAddrs([]netip.AddrPort{udpFrom}, p.candidates)
		}
		c.mu.Unlock()
		pong := disco.Seal(c.opts.DiscoKey, sender, &disco.Pong{TxID: m.TxID, Src: udpFrom})
		c.sendDisco(p, pong, path) // back the way it came

	case *disco.Pong:
		ps, ok := p.pings[m.TxID]
		if !ok {
			c.mu.Unlock()
			return
		}
		delete(p.pings, m.TxID)
		lat := time.Since(ps.sent)
		if viaUDP && ps.to == udpFrom {
			c.byAddr[udpFrom] = p
			stale := time.Since(p.lastPong) >= trustDuration
			// Switch only for a clearly better path, so near-equal paths
			// (say IPv4 and IPv6 on one LAN) don't flap.
			if !p.bestAddr.IsValid() || stale || udpFrom == p.bestAddr || lat < p.bestLatency/2 {
				if p.bestAddr != udpFrom {
					c.log.Info("direct path", "peer", p.cfg.Name, "addr", udpFrom, "latency", lat.Round(time.Microsecond))
				}
				p.bestAddr, p.bestLatency = udpFrom, lat
			}
			if udpFrom == p.bestAddr {
				p.lastPong = time.Now()
			}
		}
		if r := path.peerRelay; r != nil && ps.viaRelay == r {
			if p.relayVia != r || time.Since(p.relayPong) >= trustDuration {
				if p.relayVia == nil || time.Since(p.relayPong) >= trustDuration || lat < p.relayLatency/2 {
					c.log.Info("peer relay path", "peer", p.cfg.Name, "via", r.name, "latency", lat.Round(time.Microsecond))
					p.relayVia = r
				}
			}
			if p.relayVia == r {
				p.relayPong, p.relayLatency = time.Now(), lat
			}
		}
		c.mu.Unlock()
		if ps.reply != nil {
			res := PingResult{Latency: lat, Via: "relay"}
			switch {
			case viaUDP:
				res.Via, res.Addr = "direct", udpFrom
			case path.peerRelay != nil:
				res.Via, res.Relay = "peer-relay", path.peerRelay.name
			}
			select {
			case ps.reply <- res:
			default:
			}
		}

	case *disco.CallMeMaybe:
		p.candidates = mergeAddrs(c.usable(m.Endpoints), p.candidates)
		c.mu.Unlock()
		c.pingCandidates(p, nil)

	default:
		c.mu.Unlock()
	}
}

// sendDisco sends a sealed disco packet along path.
func (c *Conn) sendDisco(p *peer, pkt []byte, path discoPath) {
	if path.udp.IsValid() {
		c.writeUDP(pkt, path.udp)
		return
	}
	if r := path.peerRelay; r != nil {
		c.mu.Lock()
		addr := r.bestAddr
		c.mu.Unlock()
		if addr.IsValid() {
			c.writeUDP(relayFrame(frameToRelay, p.nodeKey, pkt), addr)
		}
		return
	}
	c.mu.Lock()
	r := c.relay
	c.mu.Unlock()
	if r != nil {
		r.Send(p.nodeKey, pkt)
	}
}

func (c *Conn) sendPing(p *peer, path discoPath, reply chan PingResult) {
	tx := disco.NewTxID()
	c.mu.Lock()
	p.pings[tx] = pingState{to: path.udp, viaRelay: path.peerRelay, sent: time.Now(), reply: reply}
	c.mu.Unlock()
	pkt := disco.Seal(c.opts.DiscoKey, p.discoKey, &disco.Ping{TxID: tx, NodeKey: c.opts.NodeKey})
	c.sendDisco(p, pkt, path)
}

// pingCandidates pings every known direct candidate of p.
func (c *Conn) pingCandidates(p *peer, reply chan PingResult) {
	if c.opts.DisableDirect {
		return
	}
	c.mu.Lock()
	cands := slices.Clone(p.candidates)
	if p.bestAddr.IsValid() && !slices.Contains(cands, p.bestAddr) {
		cands = append(cands, p.bestAddr)
	}
	c.mu.Unlock()
	for _, a := range cands {
		c.sendPing(p, discoPath{udp: a}, reply)
	}
}

func (c *Conn) heartbeatLoop() {
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		peers := make([]*peer, 0, len(c.peers))
		for _, p := range c.peers {
			// Drop unanswered pings.
			for tx, ps := range p.pings {
				if time.Since(ps.sent) > pingTimeout {
					delete(p.pings, tx)
				}
			}
			peers = append(peers, p)
		}
		myEps := slices.Clone(c.endpoints)
		c.mu.Unlock()
		c.helloRelays()

		for _, p := range peers {
			c.mu.Lock()
			trusted := p.bestAddr.IsValid() && time.Since(p.lastPong) < trustDuration
			best := p.bestAddr
			sendCMM := !trusted && time.Since(p.lastCMM) >= callMeMaybeGap
			if sendCMM {
				p.lastCMM = time.Now()
			}
			c.mu.Unlock()

			if trusted {
				c.sendPing(p, discoPath{udp: best}, nil) // keep the path and NAT mapping alive
				continue
			}
			c.pingCandidates(p, nil)
			c.probeViaRelays(p, nil)
			if sendCMM && len(myEps) > 0 {
				c.sendDisco(p, disco.Seal(c.opts.DiscoKey, p.discoKey, &disco.CallMeMaybe{Endpoints: myEps}), discoPath{})
			}
		}
	}
}

// PingResult describes the path a disco pong came back on.
type PingResult struct {
	Via     string // "direct", "peer-relay" or "relay"
	Addr    netip.AddrPort
	Relay   string // peer relay name, for "peer-relay"
	Latency time.Duration
}

// Ping sends disco pings over every path to a peer and returns the first
// pong. Used by 'ws ping'.
func (c *Conn) Ping(ctx context.Context, nodeKey key.Public) (PingResult, error) {
	c.mu.Lock()
	p := c.peers[nodeKey]
	c.mu.Unlock()
	if p == nil {
		return PingResult{}, errors.New("unknown peer")
	}
	reply := make(chan PingResult, 16)
	c.mu.Lock()
	direct := p.bestAddr.IsValid() && time.Since(p.lastPong) < trustDuration
	c.mu.Unlock()
	// With a proven direct path, a relay would only win by being first.
	if !direct {
		c.sendPing(p, discoPath{}, reply)
		c.probeViaRelays(p, reply)
	}
	c.pingCandidates(p, reply)
	select {
	case r := <-reply:
		return r, nil
	case <-ctx.Done():
		return PingResult{}, ctx.Err()
	}
}

// --- STUN and endpoints ---

func (c *Conn) stunLoop() {
	t := time.NewTicker(stunInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.sendSTUN()
			c.updateEndpoints()
		}
	}
}

func (c *Conn) sendSTUN() {
	c.mu.Lock()
	servers := slices.Clone(c.stunServers)
	for tx, r := range c.stunTx {
		if time.Since(r.sent) > pingTimeout {
			delete(c.stunTx, tx)
		}
	}
	c.mu.Unlock()
	for _, s := range servers {
		tx := stun.NewTxID()
		c.mu.Lock()
		c.stunTx[tx] = stunReq{server: s, sent: time.Now()}
		c.mu.Unlock()
		c.writeUDP(stun.Request(tx), s)
	}
}

func (c *Conn) handleSTUN(pkt []byte) {
	tx, mapped, err := stun.ParseResponse(pkt)
	if err != nil {
		return
	}
	c.mu.Lock()
	req, ok := c.stunTx[tx]
	delete(c.stunTx, tx)
	if ok {
		mapped = netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port())
		changed := c.stunResults[req.server] != mapped
		c.stunResults[req.server] = mapped
		c.mu.Unlock()
		if changed {
			c.updateEndpoints()
		}
		return
	}
	c.mu.Unlock()
}

// NetcheckReport summarises what STUN says about this node's NAT.
type NetcheckReport struct {
	Port      uint16                    `json:"port"`
	Mapped    map[string]netip.AddrPort `json:"mapped"` // per STUN server
	Endpoints []netip.AddrPort          `json:"endpoints"`
	// MappingVariesByDest is true when different STUN servers saw different
	// public ports: an endpoint-dependent ("symmetric") NAT, which defeats
	// simple hole punching and usually forces a relay.
	MappingVariesByDest bool `json:"mapping_varies_by_dest"`
	RelayConnected      bool `json:"relay_connected"`
}

// Netcheck runs a fresh STUN round and reports the result.
func (c *Conn) Netcheck(ctx context.Context) NetcheckReport {
	c.mu.Lock()
	clear(c.stunResults)
	n := len(c.stunServers)
	c.mu.Unlock()
	c.sendSTUN()
	deadline := time.After(2 * time.Second)
wait:
	for {
		c.mu.Lock()
		got := len(c.stunResults)
		c.mu.Unlock()
		if got >= n {
			break
		}
		select {
		case <-ctx.Done():
			break wait
		case <-deadline:
			break wait
		case <-time.After(50 * time.Millisecond):
		}
	}
	c.updateEndpoints()
	c.mu.Lock()
	defer c.mu.Unlock()
	r := NetcheckReport{Port: c.port, Mapped: map[string]netip.AddrPort{}, Endpoints: slices.Clone(c.endpoints)}
	var first netip.AddrPort
	for s, m := range c.stunResults {
		r.Mapped[s.String()] = m
		if m.Addr().Is4() {
			if !first.IsValid() {
				first = m
			} else if first != m {
				r.MappingVariesByDest = true
			}
		}
	}
	r.RelayConnected = c.relay != nil && c.relay.Connected()
	return r
}

func (c *Conn) updateEndpoints() {
	var eps []netip.AddrPort
	c.mu.Lock()
	for _, m := range c.stunResults {
		eps = append(eps, m)
	}
	c.mu.Unlock()
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() ||
				(ip.IsLoopback() && !c.opts.IncludeLoopback) || c.excluded(ip) {
				continue
			}
			if ip.Is6() && c.pc6 == nil {
				continue
			}
			eps = append(eps, netip.AddrPortFrom(ip, c.port))
		}
	}
	if c.opts.IncludeLoopback {
		eps = append(eps, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), c.port))
	}
	eps = mergeAddrs(eps, nil)
	slices.SortFunc(eps, func(a, b netip.AddrPort) int { return a.Compare(b) })

	c.mu.Lock()
	changed := !slices.Equal(eps, c.endpoints)
	c.endpoints = eps
	cb := c.opts.OnEndpoints
	c.mu.Unlock()
	if changed && cb != nil {
		cb(eps)
	}
}

// Endpoints returns this node's current candidate endpoints.
func (c *Conn) Endpoints() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.endpoints)
}

// --- status ---

type PeerStatus struct {
	Name     string        `json:"name"`
	NodeKey  string        `json:"node_key"`
	Path     string        `json:"path"` // "direct", "peer-relay", "relay" or "none"
	Addr     string        `json:"addr,omitempty"`
	Latency  time.Duration `json:"latency_ns,omitempty"`
	LastPong time.Time     `json:"last_pong,omitempty"`
	RxBytes  uint64        `json:"rx_bytes"`
	TxBytes  uint64        `json:"tx_bytes"`
}

func (c *Conn) Status() []PeerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	relayUp := c.relay != nil && c.relay.Connected()
	var out []PeerStatus
	for _, p := range c.peers {
		s := PeerStatus{Name: p.cfg.Name, NodeKey: p.nodeKey.String(), RxBytes: p.rx.Load(), TxBytes: p.tx.Load()}
		switch {
		case p.bestAddr.IsValid() && time.Since(p.lastPong) < trustDuration:
			s.Path, s.Addr, s.Latency, s.LastPong = "direct", p.bestAddr.String(), p.bestLatency, p.lastPong
		case p.relayVia != nil && time.Since(p.relayPong) < trustDuration:
			s.Path, s.Addr, s.Latency, s.LastPong = "peer-relay", p.relayVia.name, p.relayLatency, p.relayPong
		case relayUp:
			s.Path = "relay"
		default:
			s.Path = "none"
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b PeerStatus) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

func mergeAddrs(a, b []netip.AddrPort) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	for _, s := range [][]netip.AddrPort{a, b} {
		for _, x := range s {
			if x.IsValid() && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}
