package engine

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// udpEcho answers every datagram to e's mesh address on port.
func udpEcho(t *testing.T, e *Engine, port uint16) {
	t.Helper()
	pc, err := e.Net().ListenUDPAddrPort(netip.AddrPortFrom(selfIP(e), port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
}

// prober sends a numbered datagram every 50 ms from a to b's echo and
// records when replies arrive, to measure outages, and which never do.
// Lost probes are the robust measure: on a busy machine (CI, the race
// detector) replies can be late without anything being lost.
type prober struct {
	mu      sync.Mutex
	replies []time.Time
	sent    map[uint64]time.Time
	got     map[uint64]bool
	stopAt  time.Time
	once    sync.Once
	stop    chan struct{}
	done    chan struct{}
}

func startProber(t *testing.T, a, b *Engine, port uint16) *prober {
	t.Helper()
	c, err := a.Net().DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(selfIP(b), port))
	if err != nil {
		t.Fatal(err)
	}
	p := &prober{stop: make(chan struct{}), done: make(chan struct{}),
		sent: map[uint64]time.Time{}, got: map[uint64]bool{}}
	go func() {
		buf := make([]byte, 64)
		for {
			c.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := c.Read(buf); err == nil {
				p.mu.Lock()
				p.replies = append(p.replies, time.Now())
				if n >= 8 {
					p.got[binary.BigEndian.Uint64(buf)] = true
				}
				p.mu.Unlock()
			}
			select {
			case <-p.done:
				return
			default:
			}
		}
	}()
	go func() {
		defer close(p.done)
		var seq uint64
		for {
			select {
			case <-p.stop:
				c.Close()
				return
			case <-time.After(50 * time.Millisecond):
			}
			seq++
			p.mu.Lock()
			p.sent[seq] = time.Now()
			p.mu.Unlock()
			c.Write(binary.BigEndian.AppendUint64(nil, seq))
		}
	}()
	return p
}

// finish stops the prober (once) and waits for it.
func (p *prober) finish() {
	p.once.Do(func() {
		p.mu.Lock()
		p.stopAt = time.Now()
		p.mu.Unlock()
		close(p.stop)
	})
	<-p.done
}

// lost stops the prober and counts probes sent after since that were never
// answered, leaving out the last second's (their replies may be in flight).
func (p *prober) lost(since time.Time) int {
	p.finish()
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for seq, at := range p.sent {
		if at.After(since) && at.Before(p.stopAt.Add(-time.Second)) && !p.got[seq] {
			n++
		}
	}
	return n
}

// worstGap stops the prober and returns the longest time without a reply
// after since.
func (p *prober) worstGap(since time.Time) time.Duration {
	p.finish()
	p.mu.Lock()
	defer p.mu.Unlock()
	var worst time.Duration
	last := since
	for _, r := range p.replies {
		if r.Before(since) {
			continue
		}
		worst = max(worst, r.Sub(last))
		last = r
	}
	return max(worst, time.Since(last))
}

// cutDirect makes every direct path between a and b stop working in both
// directions, like losing the only network link; relays keep working.
// Each node's candidate addresses share its UDP port, so filter on that.
func cutDirect(t *testing.T, a, b *Engine) {
	t.Helper()
	portA, portB := a.conn.Port(), b.conn.Port()
	a.conn.SetUDPFilter(func(x netip.AddrPort) bool { return x.Port() == portB })
	b.conn.SetUDPFilter(func(x netip.AddrPort) bool { return x.Port() == portA })
}

// When the direct path dies, traffic moves to the relay quickly.
func TestPathFailover(t *testing.T) {
	n := newTestNet(t, "")
	a := n.node("mp-a", false)
	b := n.node("mp-b", false)
	waitPath(t, a, "mp-b", "direct")
	udpEcho(t, b, 7600)
	p := startProber(t, a, b, 7600)
	time.Sleep(time.Second)
	cut := time.Now()
	cutDirect(t, a, b)
	time.Sleep(10 * time.Second)
	gap := p.worstGap(cut)
	t.Logf("longest outage after the direct path died: %v", gap.Round(10*time.Millisecond))
	// About a second to notice silence and a second for the probe; it was
	// 5.5 s when only the 6.5 s trust window caught a dead path.
	if gap > 3*time.Second {
		t.Fatalf("failover took %v", gap)
	}
	waitPath(t, a, "mp-b", "relay")
}

// A network change (here simulated) makes the machine recheck everything
// at once: the relay reconnects, and direct paths are re-proven while
// traffic carries on.
func TestNetworkChange(t *testing.T) {
	n := newTestNet(t, "")
	a := n.node("nc-a", false)
	b := n.node("nc-b", false)
	waitPath(t, a, "nc-b", "direct")
	udpEcho(t, b, 7601)
	p := startProber(t, a, b, 7601)
	time.Sleep(time.Second)
	changed := time.Now()
	a.conn.NetworkChanged()
	waitPath(t, a, "nc-b", "direct") // re-proven
	time.Sleep(2 * time.Second)
	gap, lost := p.worstGap(changed), p.lost(changed)
	t.Logf("around the network change: longest gap %v, %d probes lost", gap.Round(time.Millisecond), lost)
	// The direct path stays in use while it is re-proven: at most a couple
	// of probes may go missing, and nothing like a failover's ~2 s outage.
	if lost > 2 || gap > time.Second {
		t.Fatalf("traffic stalled around the network change: gap %v, %d probes lost", gap, lost)
	}
	a.mu.Lock()
	rc := a.relay
	a.mu.Unlock()
	if rc == nil || rc.Reconnects() != 1 {
		t.Fatal("relay not reconnected after the network change")
	}
}

// In multipath mode every packet also travels through a relay, so the
// direct path dying loses nothing.
func TestMultipathNoLoss(t *testing.T) {
	n := newTestNet(t, "")
	a := n.nodeWith("mpr-a", Options{Multipath: true})
	b := n.nodeWith("mpr-b", Options{Multipath: true})
	waitPath(t, a, "mpr-b", "direct")
	udpEcho(t, b, 7602)
	p := startProber(t, a, b, 7602)
	time.Sleep(time.Second)
	cut := time.Now()
	cutDirect(t, a, b)
	time.Sleep(5 * time.Second)
	gap, lost := p.worstGap(cut), p.lost(cut)
	t.Logf("after the direct path died: longest gap between replies %v, %d probes lost", gap.Round(time.Millisecond), lost)
	// Every probe also went through the relay, so none may be lost. Replies
	// can still be late on a busy machine; a real outage would look like
	// the ~2 s single-path failover.
	if lost > 0 {
		t.Fatalf("multipath lost %d probes when the direct path died", lost)
	}
	if gap > time.Second {
		t.Fatalf("multipath traffic stalled for %v", gap)
	}
}

// With lazy discovery, idle peers aren't probed at all; the first traffic
// goes through the relay at once and a direct path follows within seconds.
func TestLazyDiscovery(t *testing.T) {
	n := newTestNet(t, "")
	a := n.nodeWith("lz-a", Options{LazyDiscovery: true})
	b := n.nodeWith("lz-b", Options{LazyDiscovery: true})
	echo(t, b, 7603)
	time.Sleep(4 * time.Second) // more than a heartbeat
	for _, p := range a.Status().Peers {
		if p.Name == "lz-b" && p.Path != "idle" {
			t.Fatalf("idle peer has path %q (it was probed)", p.Path)
		}
	}
	start := time.Now()
	if err := roundTrip(a, b, 7603, 5*time.Second); err != nil {
		t.Fatalf("first traffic to an idle peer: %v", err)
	}
	t.Logf("first round trip to an idle peer took %v", time.Since(start).Round(time.Millisecond))
	waitPath(t, a, "lz-b", "direct")
	t.Logf("direct path %v after traffic started", time.Since(start).Round(time.Millisecond))
}

// Closing an engine while a peer's packets are still arriving must be
// clean. Datagrams to a port nobody listens on make the userspace stack
// answer with ICMP, which raced the stack's own teardown when the TUN was
// closed before the peers stopped (wireguard-go closes it first).
func TestCloseUnderTraffic(t *testing.T) {
	n := newTestNet(t, "")
	a := n.node("cl-a", false)
	for i := range 4 {
		b := n.node("cl-b"+string(rune('0'+i)), false)
		waitPath(t, a, b.opts.State.NodeName, "direct")
		stop := make(chan struct{})
		var senders sync.WaitGroup
		for range 4 {
			c, err := a.Net().DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(selfIP(b), 9))
			if err != nil {
				t.Fatal(err)
			}
			senders.Add(1)
			go func() {
				defer senders.Done()
				defer c.Close()
				for {
					select {
					case <-stop:
						return
					default:
					}
					c.Write([]byte("nobody listens on port 9"))
				}
			}()
		}
		time.Sleep(300 * time.Millisecond)
		b.Close() // mid-stream
		close(stop)
		senders.Wait()
	}
}
