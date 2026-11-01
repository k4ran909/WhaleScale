package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/server"
)

// wgPeerConfig returns the UAPI lines for one peer from e's WireGuard device.
func wgPeerConfig(t *testing.T, e *Engine, peer *Engine) map[string]string {
	t.Helper()
	cfg, err := e.wgDev.Load().IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	want := "public_key=" + peer.nodeKey.Public().Hex()
	out := map[string]string{}
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "public_key" {
			in = line == want
		}
		if in {
			out[k] = v
		}
	}
	return out
}

func pqStatus(e *Engine, peer string) bool {
	for _, p := range e.Status().Peers {
		if p.Name == peer {
			return p.PostQuantum
		}
	}
	return false
}

func TestPostQuantum(t *testing.T) {
	n := newTestNetWith(t, "", func(c *server.Config) { c.PostQuantum = true })
	a := n.node("pq-a", false)
	b := n.node("pq-b", false)
	c := n.node("pq-c", true) // relayed: the exchange crosses the relay
	d := n.node("pq-d", true)
	echo(t, b, 7500)
	echo(t, d, 7500)

	zero := strings.Repeat("0", 64)
	for _, pair := range [][2]*Engine{{a, b}, {c, d}} {
		x, y := pair[0], pair[1]
		waitFor(t, "post-quantum PSK in use", func() bool {
			return pqStatus(x, y.opts.State.NodeName) && pqStatus(y, x.opts.State.NodeName)
		})
		px, py := wgPeerConfig(t, x, y)["preshared_key"], wgPeerConfig(t, y, x)["preshared_key"]
		if px == "" || px == zero || px != py {
			t.Fatalf("WireGuard PSKs: %q vs %q", px, py)
		}
		if err := roundTrip(x, y, 7500, 10*time.Second); err != nil {
			t.Fatalf("traffic with PSK: %v", err)
		}
	}

	// Make a do a fresh handshake with b under the agreed PSK: drop the
	// peer and add it back with the same settings.
	cfg := wgPeerConfig(t, a, b)
	bk := b.nodeKey.Public()
	readd := func(psk string) {
		t.Helper()
		var allowed strings.Builder
		cur, _ := a.wgDev.Load().IpcGet()
		for _, line := range strings.Split(cur, "\n") {
			_ = line
		}
		for _, ip := range allowedIPs(t, a, b) {
			allowed.WriteString("allowed_ip=" + ip + "\n")
		}
		uapi := "public_key=" + bk.Hex() + "\nremove=true\n" +
			"public_key=" + bk.Hex() + "\nendpoint=" + bk.Hex() + "\npreshared_key=" + psk + "\n" + allowed.String()
		if err := a.wgDev.Load().IpcSet(uapi); err != nil {
			t.Fatal(err)
		}
	}
	readd(cfg["preshared_key"])
	if err := roundTrip(a, b, 7500, 10*time.Second); err != nil {
		t.Fatalf("handshake under the agreed PSK failed: %v", err)
	}
	// And with a wrong PSK the handshake fails: WireGuard really uses it.
	wrong := strings.Repeat("ab", 32)
	readd(wrong)
	if err := roundTrip(a, b, 7500, 3*time.Second); err == nil {
		t.Fatal("traffic flowed with mismatched PSKs; the PSK isn't being used")
	}
}

func allowedIPs(t *testing.T, e, peer *Engine) []string {
	t.Helper()
	cfg, err := e.wgDev.Load().IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	want := "public_key=" + peer.nodeKey.Public().Hex()
	var out []string
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "public_key" {
			in = line == want
		}
		if in && k == "allowed_ip" {
			out = append(out, v)
		}
	}
	return out
}
