package osnet

import (
	"sync"
	"syscall"
)

// When a node uses an exit node, the OS routes all traffic into the TUN.
// The agent's own packets (WireGuard, disco, STUN, the control connection
// and the relay) must still leave through the physical network, or they
// would loop back into the tunnel. Bypass marks or binds the agent's
// sockets so they skip the tunnel; ExitRoutes installs the catch-all
// routes. How depends on the OS:
//
//   - Linux: sockets carry fwmark 0x5753; policy routing sends unmarked
//     traffic to a table whose default route is the TUN (as wg-quick does).
//   - Windows: two /1 routes into the TUN; sockets are pinned to the
//     physical interface with IP_UNICAST_IF.
//   - macOS: the same /1 routes; sockets pinned with IP_BOUND_IF.

// BypassMark is the fwmark on the agent's own sockets (Linux). "WS".
const BypassMark = 0x5753

// Bypass keeps the agent's own sockets off the tunnel.
type Bypass struct {
	mu     sync.Mutex
	tun    string
	if4    int // physical interface for IPv4 (Windows/macOS)
	if6    int
	listen []bypassConn // long-lived sockets, re-pinned when the network changes
}

type bypassConn struct {
	network string
	raw     syscall.RawConn
}

// NewBypass detects the physical interface now, before any catch-all
// routes exist.
func NewBypass() *Bypass {
	b := &Bypass{}
	b.if4, b.if6 = physicalInterfaces("")
	return b
}

// SetTunnel names the TUN so later detection never picks it.
func (b *Bypass) SetTunnel(name string) {
	b.mu.Lock()
	b.tun = name
	b.mu.Unlock()
}

// ControlListen is a net.ListenConfig.Control for long-lived sockets.
func (b *Bypass) ControlListen(network, _ string, c syscall.RawConn) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listen = append(b.listen, bypassConn{network, c})
	return applyBypass(network, c, b.if4, b.if6)
}

// ControlDial is a net.Dialer.Control for outgoing connections.
func (b *Bypass) ControlDial(network, _ string, c syscall.RawConn) error {
	b.mu.Lock()
	if4, if6 := b.if4, b.if6
	b.mu.Unlock()
	return applyBypass(network, c, if4, if6)
}

// Refresh re-detects the physical interface (say, after switching from
// Wi-Fi to Ethernet) and re-pins long-lived sockets. It reports whether
// anything changed.
func (b *Bypass) Refresh() bool {
	b.mu.Lock()
	tun := b.tun
	b.mu.Unlock()
	if4, if6 := physicalInterfaces(tun)
	b.mu.Lock()
	defer b.mu.Unlock()
	if if4 == b.if4 && if6 == b.if6 {
		return false
	}
	b.if4, b.if6 = if4, if6
	for _, c := range b.listen {
		applyBypass(c.network, c.raw, if4, if6)
	}
	return true
}

// ExitRoutes sends all traffic into the TUN. Close removes the routes.
type ExitRoutes struct {
	undo []func()
}

func (r *ExitRoutes) Close() {
	for i := len(r.undo) - 1; i >= 0; i-- {
		r.undo[i]()
	}
	r.undo = nil
}

// StartExitRoutes installs catch-all routes into iface.
func StartExitRoutes(iface string) (*ExitRoutes, error) { return startExitRoutes(iface) }

func is6(network string) bool {
	return len(network) > 0 && network[len(network)-1] == '6'
}
