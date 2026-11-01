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
// records when replies arrive, to measure outages.
type prober struct {
	mu      sync.Mutex
	replies []time.Time
	stop    chan struct{}
	done    chan struct{}
}

func startProber(t *testing.T, a, b *Engine, port uint16) *prober {
	t.Helper()
	c, err := a.Net().DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(selfIP(b), port))
	if err != nil {
		t.Fatal(err)
	}
	p := &prober{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		buf := make([]byte, 64)
		for {
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(buf); err == nil {
				p.mu.Lock()
				p.replies = append(p.replies, time.Now())
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
			c.Write(binary.BigEndian.AppendUint64(nil, seq))
		}
	}()
	return p
}

// worstGap stops the prober and returns the longest time without a reply
// after since.
func (p *prober) worstGap(since time.Time) time.Duration {
	close(p.stop)
	<-p.done
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
	if gap := p.worstGap(changed); gap > 500*time.Millisecond {
		t.Fatalf("traffic stalled %v around the network change", gap)
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
	gap := p.worstGap(cut)
	t.Logf("longest gap between replies after the direct path died: %v", gap.Round(time.Millisecond))
	// Replies come every 50 ms; allow for scheduling jitter, not an outage.
	if gap > 300*time.Millisecond {
		t.Fatalf("multipath lost traffic for %v", gap)
	}
}
