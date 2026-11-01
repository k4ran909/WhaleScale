package pq

import (
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/disco"
	"github.com/k4ran909/whalescale/internal/key"
)

// pair connects two managers through a network that drops a share of
// messages, with pings exchanged the way meshconn does.
type pair struct {
	t       *testing.T
	keys    [2]key.Public
	mgr     [2]*Manager
	applied [2]PSK
	mu      sync.Mutex
	loss    float64
	rnd     *rand.Rand
	queue   chan func()
	done    chan struct{}
	running sync.WaitGroup
}

func newPair(t *testing.T, loss float64) *pair {
	p := &pair{t: t, loss: loss, rnd: rand.New(rand.NewSource(1)), queue: make(chan func(), 1024), done: make(chan struct{})}
	for i := range p.keys {
		k, _ := key.NewPrivate()
		p.keys[i] = k.Public()
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	short := timing{rotate: 400 * time.Millisecond, retry: 40 * time.Millisecond, grace: 300 * time.Millisecond, tries: maxTries}
	for i := range p.mgr {
		i := i
		p.mgr[i] = New(p.keys[i], func(peer key.Public, m disco.Message) bool {
			p.mu.Lock()
			drop := p.rnd.Float64() < p.loss
			p.mu.Unlock()
			if !drop {
				p.queue <- func() { p.mgr[1-i].Handle(p.keys[i], m) }
			}
			return true
		}, func(peer key.Public, psk PSK) {
			p.mu.Lock()
			p.applied[i] = psk
			p.mu.Unlock()
		}, log)
		p.mgr[i].timing = short
	}
	p.running.Add(1)
	go func() {
		defer p.running.Done()
		for {
			select {
			case <-p.done:
				return
			case f := <-p.queue:
				f()
			}
		}
	}()
	t.Cleanup(func() {
		close(p.done)
		p.running.Wait()
	})
	return p
}

func (p *pair) start(i int) {
	p.mgr[i].SetPeers(true, []key.Public{p.keys[1-i]})
	p.running.Add(1)
	go func() {
		defer p.running.Done()
		p.mgr[i].Run(p.done)
	}()
}

// pings exchanges ping fingerprints, as meshconn's heartbeat does.
func (p *pair) pings() {
	for i := range p.mgr {
		id := p.mgr[i].PSKID(p.keys[1-i])
		p.mgr[1-i].Observe(p.keys[i], id)
	}
}

func (p *pair) state() (PSK, PSK) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.applied[0], p.applied[1]
}

// waitAgree waits until both sides use the same, non-zero PSK that differs
// from not.
func (p *pair) waitAgree(not PSK, within time.Duration) PSK {
	p.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		p.pings()
		a, b := p.state()
		if a == b && a != (PSK{}) && a != not {
			return a
		}
		time.Sleep(20 * time.Millisecond)
	}
	a, b := p.state()
	p.t.Fatalf("no agreement: %x vs %x", a[:4], b[:4])
	return PSK{}
}

func TestExchangeAndRotation(t *testing.T) {
	p := newPair(t, 0)
	p.start(0)
	p.start(1)
	first := p.waitAgree(PSK{}, 5*time.Second)
	second := p.waitAgree(first, 5*time.Second) // rotated
	if first == second {
		t.Fatal("PSK didn't rotate")
	}
	if ok, _ := p.mgr[0].Active(p.keys[1]); !ok {
		t.Fatal("Active false with a PSK in use")
	}
}

func TestLossyNetworkConverges(t *testing.T) {
	p := newPair(t, 0.4)
	p.start(0)
	p.start(1)
	last := PSK{}
	for i := 0; i < 3; i++ {
		last = p.waitAgree(last, 10*time.Second)
	}
}

// A peer that restarts has no PSK; the other notices from its pings and
// both start over instead of staying out of step.
func TestRestartRecovers(t *testing.T) {
	p := newPair(t, 0)
	p.start(0)
	p.start(1)
	old := p.waitAgree(PSK{}, 5*time.Second)
	p.mgr[1].SetPeers(false, nil) // "restart": forgets everything
	p.mgr[1].SetPeers(true, []key.Public{p.keys[0]})
	p.waitAgree(old, 10*time.Second)
}

// Without an answering peer (an older client), nothing is ever applied.
func TestSilentPeerKeepsNoPSK(t *testing.T) {
	p := newPair(t, 1) // every message lost
	p.start(0)
	p.start(1)
	time.Sleep(time.Second)
	if a, b := p.state(); a != (PSK{}) || b != (PSK{}) {
		t.Fatal("a PSK was applied without a completed exchange")
	}
}

func TestDisableDropsPSK(t *testing.T) {
	p := newPair(t, 0)
	p.start(0)
	p.start(1)
	p.waitAgree(PSK{}, 5*time.Second)
	p.mgr[0].SetPeers(false, nil)
	if a, _ := p.state(); a != (PSK{}) {
		t.Fatal("PSK kept after turning the feature off")
	}
}
