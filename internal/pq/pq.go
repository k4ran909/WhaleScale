// Package pq adds a post-quantum layer to WireGuard: peers agree on a
// pre-shared key through an ML-KEM-768 exchange and rotate it every two
// minutes (the idea Rosenpass introduced). WireGuard mixes the PSK into
// every handshake, so traffic recorded today stays secret even from a
// future quantum computer that could break the X25519 handshake.
//
// The exchange travels in disco messages, sealed between the peers' disco
// keys, so it is authenticated (classically) and its contents are hidden.
// A recorded exchange gives nothing away: the ciphertext only opens with
// the initiator's decapsulation key, which never leaves the machine.
//
// A PSK the two sides disagree on breaks the tunnel, so the protocol never
// lets them drift apart for long:
//
//  1. The peer with the lower WireGuard key sends PQInit (encapsulation key).
//  2. The other encapsulates a secret: PQReply (ciphertext). Both derive the
//     PSK but neither uses it yet.
//  3. PQCommit: the initiator has it. The responder switches.
//  4. PQDone: the responder switched. The initiator switches.
//
// Messages are retransmitted until answered. Pings also carry a short
// fingerprint of the PSK in use; if peers disagree for longer than an
// exchange takes (a restart, a lost message), both drop back to no PSK,
// which always works, and start over.
package pq

import (
	"bytes"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"log/slog"
	"sync"
	"time"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
)

// Timing defaults.
const (
	RotateEvery   = 2 * time.Minute
	retryEvery    = time.Second
	maxTries      = 10
	mismatchGrace = 6 * time.Second
)

// timing is a manager's schedule; tests shorten it.
type timing struct {
	rotate, retry, grace time.Duration
	tries                int
}

// PSK is a WireGuard pre-shared key; zero means none.
type PSK [32]byte

// Manager runs the exchange with every peer.
type Manager struct {
	self  key.Public
	send  func(peer key.Public, m disco.Message) bool
	apply func(peer key.Public, psk PSK)
	log   *slog.Logger

	timing timing

	mu      sync.Mutex
	enabled bool
	peers   map[key.Public]*peerState

	// act serializes the effects (sends, PSK changes) decided under mu, in
	// the order they were decided, without holding mu while they run.
	act sync.Mutex
}

type peerState struct {
	psk   PSK
	since time.Time // when psk was applied; zero: none
	// Initiator: the exchange in flight, and when to start the next.
	out        *outgoing
	nextRotate time.Time
	// Responder: the latest exchange the initiator started.
	in *incoming
	// When the peer's pings started disagreeing with our PSK.
	mismatchSince time.Time
}

type outgoing struct {
	tx       disco.TxID
	dk       *mlkem.DecapsulationKey768
	psk      PSK
	commit   bool // past the reply: waiting for PQDone
	tries    int
	lastSent time.Time
}

type incoming struct {
	tx      disco.TxID
	ct      []byte
	psk     PSK
	applied bool
}

// New makes a manager for this node. send delivers a disco message to a
// peer; apply sets the PSK WireGuard uses with it.
func New(self key.Public, send func(key.Public, disco.Message) bool, apply func(key.Public, PSK), log *slog.Logger) *Manager {
	return &Manager{self: self, send: send, apply: apply, log: log, peers: map[key.Public]*peerState{},
		timing: timing{rotate: RotateEvery, retry: retryEvery, grace: mismatchGrace, tries: maxTries}}
}

type effect func()

func (m *Manager) run(effects []effect) {
	m.act.Lock()
	m.mu.Unlock()
	defer m.act.Unlock()
	for _, f := range effects {
		f()
	}
}

func (m *Manager) initiator(peer key.Public) bool { return bytes.Compare(m.self[:], peer[:]) < 0 }

// SetPeers says whether the exchange is on, and with which peers. Peers
// that go away are forgotten (a peer added back starts without a PSK, as
// WireGuard does); turning it off drops every PSK.
func (m *Manager) SetPeers(enabled bool, peers []key.Public) {
	m.mu.Lock()
	var effects []effect
	want := map[key.Public]bool{}
	if enabled {
		for _, p := range peers {
			want[p] = true
		}
	}
	for p, ps := range m.peers {
		if !want[p] {
			if !ps.since.IsZero() {
				effects = append(effects, func() { m.apply(p, PSK{}) })
			}
			delete(m.peers, p)
		}
	}
	now := time.Now()
	for p := range want {
		if m.peers[p] == nil {
			m.peers[p] = &peerState{nextRotate: now}
		}
	}
	m.enabled = enabled
	m.run(effects)
}

func derive(shared []byte, initiator, responder key.Public, tx disco.TxID) PSK {
	info := append(append(append([]byte{}, initiator[:]...), responder[:]...), tx[:]...)
	k, err := hkdf.Key(sha256.New, shared, []byte("whalescale pq psk v1"), string(info), 32)
	if err != nil {
		panic(err) // only for impossible lengths
	}
	return PSK(k)
}

func fingerprint(psk PSK) [8]byte {
	if psk == (PSK{}) {
		return [8]byte{}
	}
	h := sha256.Sum256(append([]byte("whalescale pq psk id\x00"), psk[:]...))
	return [8]byte(h[:8])
}

// PSKID fingerprints the PSK in use with peer, for pings.
func (m *Manager) PSKID(peer key.Public) [8]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ps := m.peers[peer]; ps != nil {
		return fingerprint(ps.psk)
	}
	return [8]byte{}
}

// Active reports whether a PSK is in use with peer, and since when.
func (m *Manager) Active(peer key.Public) (bool, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ps := m.peers[peer]; ps != nil && !ps.since.IsZero() {
		return true, ps.since
	}
	return false, time.Time{}
}

func (m *Manager) setPSK(effects []effect, peer key.Public, ps *peerState, psk PSK) []effect {
	ps.psk, ps.mismatchSince = psk, time.Time{}
	ps.since = time.Time{}
	if psk != (PSK{}) {
		ps.since = time.Now()
	}
	return append(effects, func() { m.apply(peer, psk) })
}

// Handle processes a PQ disco message from peer.
func (m *Manager) Handle(peer key.Public, msg disco.Message) {
	m.mu.Lock()
	ps := m.peers[peer]
	if ps == nil || !m.enabled {
		m.mu.Unlock()
		return
	}
	var effects []effect
	send := func(out disco.Message) { effects = append(effects, func() { m.send(peer, out) }) }
	switch msg := msg.(type) {
	case *disco.PQInit:
		if m.initiator(peer) {
			break // only the lower key starts exchanges
		}
		if ps.in != nil && ps.in.tx == msg.TxID {
			send(&disco.PQReply{TxID: msg.TxID, Ciphertext: ps.in.ct}) // our reply was lost
			break
		}
		ek, err := mlkem.NewEncapsulationKey768(msg.EncapKey)
		if err != nil {
			break
		}
		shared, ct := ek.Encapsulate()
		ps.in = &incoming{tx: msg.TxID, ct: ct, psk: derive(shared, peer, m.self, msg.TxID)}
		send(&disco.PQReply{TxID: msg.TxID, Ciphertext: ct})

	case *disco.PQReply:
		o := ps.out
		if o == nil || o.tx != msg.TxID {
			break
		}
		if !o.commit {
			shared, err := o.dk.Decapsulate(msg.Ciphertext)
			if err != nil {
				break
			}
			o.psk, o.commit, o.tries = derive(shared, m.self, peer, o.tx), true, 0
		}
		o.tries++
		o.lastSent = time.Now()
		send(&disco.PQCommit{TxID: o.tx})

	case *disco.PQCommit:
		in := ps.in
		if in == nil || in.tx != msg.TxID {
			break
		}
		if !in.applied {
			in.applied = true
			effects = m.setPSK(effects, peer, ps, in.psk)
		}
		send(&disco.PQDone{TxID: msg.TxID})

	case *disco.PQDone:
		o := ps.out
		if o == nil || o.tx != msg.TxID || !o.commit {
			break
		}
		effects = m.setPSK(effects, peer, ps, o.psk)
		ps.out, ps.nextRotate = nil, time.Now().Add(m.timing.rotate)
	}
	m.run(effects)
}

// Observe takes the PSK fingerprint from a peer's ping. Disagreeing for
// longer than an exchange can take means one side lost its key or a
// message went missing for good: both fall back to no PSK and start over.
func (m *Manager) Observe(peer key.Public, theirs [8]byte) {
	m.mu.Lock()
	ps := m.peers[peer]
	if ps == nil || !m.enabled {
		m.mu.Unlock()
		return
	}
	var effects []effect
	now := time.Now()
	switch {
	case theirs == fingerprint(ps.psk):
		ps.mismatchSince = time.Time{}
	case ps.mismatchSince.IsZero():
		ps.mismatchSince = now
	case now.Sub(ps.mismatchSince) >= m.timing.grace:
		m.log.Warn("post-quantum key out of step with peer; starting over", "peer", peer.ShortString())
		if ps.psk != (PSK{}) {
			effects = m.setPSK(effects, peer, ps, PSK{})
		}
		ps.mismatchSince, ps.out, ps.in, ps.nextRotate = time.Time{}, nil, nil, now
	}
	m.run(effects)
}

// Run drives retransmissions and rotations until done is closed.
func (m *Manager) Run(done <-chan struct{}) {
	t := time.NewTicker(m.timing.retry / 2)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		m.tick(time.Now())
	}
}

func (m *Manager) tick(now time.Time) {
	m.mu.Lock()
	if !m.enabled {
		m.mu.Unlock()
		return
	}
	var effects []effect
	for peer, ps := range m.peers {
		if !m.initiator(peer) {
			continue
		}
		o := ps.out
		switch {
		case o == nil && !now.Before(ps.nextRotate):
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				continue
			}
			o = &outgoing{tx: disco.NewTxID(), dk: dk}
			ps.out = o
		case o == nil || now.Sub(o.lastSent) < m.timing.retry:
			continue
		case o.tries >= m.timing.tries:
			// No answer: an older peer without this feature, or gone.
			// Try again at the next rotation.
			ps.out, ps.nextRotate = nil, now.Add(m.timing.rotate)
			continue
		}
		o.tries++
		o.lastSent = now
		var msg disco.Message = &disco.PQInit{TxID: o.tx, EncapKey: o.dk.EncapsulationKey().Bytes()}
		if o.commit {
			msg = &disco.PQCommit{TxID: o.tx}
		}
		effects = append(effects, func() { m.send(peer, msg) })
	}
	m.run(effects)
}
