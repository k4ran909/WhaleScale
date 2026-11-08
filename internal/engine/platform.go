package engine

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// Platform gives the engine a TUN it doesn't create or configure itself, as
// on Android, where VpnService owns the interface and sets its addresses,
// routes and DNS server.
type Platform interface {
	// OpenTUN returns a TUN set up as cfg says. The engine calls it when
	// the first network map arrives and again whenever cfg changes (a subnet
	// route approved, say); it then moves to the new TUN and closes the old.
	// It runs with the engine's lock held: it must not call back into it.
	OpenTUN(cfg TunnelConfig) (tun.Device, error)
}

// TunnelConfig is what a Platform's TUN needs.
type TunnelConfig struct {
	// Addresses are this node's mesh addresses, as /32 and /128.
	Addresses []netip.Prefix
	// Routes go into the tunnel: the mesh ranges and accepted subnets.
	Routes []netip.Prefix
	// DNS is MagicDNSAddr: lookups sent there are answered in the tunnel.
	DNS netip.Addr
	// SearchDomain is the MagicDNS suffix, so short names resolve.
	SearchDomain string
	MTU          int
}

func (c TunnelConfig) equal(o TunnelConfig) bool {
	return slices.Equal(c.Addresses, o.Addresses) && slices.Equal(c.Routes, o.Routes) &&
		c.DNS == o.DNS && c.SearchDomain == o.SearchDomain && c.MTU == o.MTU
}

// tunnelConfig is the Platform configuration for a node with addresses
// self, the MagicDNS suffix and the subnets it accepts.
func tunnelConfig(self selfInfo, suffix string, subnets []netip.Prefix) TunnelConfig {
	cfg := TunnelConfig{DNS: MagicDNSAddr, SearchDomain: suffix, MTU: MTU,
		Addresses: []netip.Prefix{netip.PrefixFrom(self.v4, 32)}, Routes: []netip.Prefix{meshRange4}}
	if self.v6.IsValid() {
		cfg.Addresses = append(cfg.Addresses, netip.PrefixFrom(self.v6, 128))
		cfg.Routes = append(cfg.Routes, netip.PrefixFrom(self.v6, 48).Masked())
	}
	for _, p := range subnets {
		if !slices.Contains(cfg.Routes, p) {
			cfg.Routes = append(cfg.Routes, p)
		}
	}
	slices.SortFunc(cfg.Routes[1:], func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return cfg
}

// swapTUN is a TUN whose device can be replaced while WireGuard runs on
// it: Android hands over a new interface each time the routes change.
type swapTUN struct {
	mu     sync.RWMutex
	cur    tun.Device
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newSwapTUN(d tun.Device) *swapTUN {
	return &swapTUN{cur: d, events: make(chan tun.Event), closed: make(chan struct{})}
}

func (s *swapTUN) current() tun.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Swap moves to d and closes the device before it. A Read or Write that
// the old device fails because of that is retried on d.
func (s *swapTUN) Swap(d tun.Device) {
	s.mu.Lock()
	old := s.cur
	s.cur = d
	s.mu.Unlock()
	old.Close()
}

func (s *swapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		d := s.current()
		n, err := d.Read(bufs, sizes, offset)
		if err == nil || n > 0 || s.retry(d) != nil {
			return n, err
		}
	}
}

func (s *swapTUN) Write(bufs [][]byte, offset int) (int, error) {
	for {
		d := s.current()
		n, err := d.Write(bufs, offset)
		if err == nil || s.retry(d) != nil {
			return n, err
		}
	}
}

// retry says whether an error from d should be retried: only when d has
// since been swapped out (and this TUN isn't closing).
func (s *swapTUN) retry(d tun.Device) error {
	select {
	case <-s.closed:
		return os.ErrClosed
	default:
	}
	if s.current() == d {
		return errors.New("not swapped")
	}
	return nil
}

func (s *swapTUN) File() *os.File           { return s.current().File() }
func (s *swapTUN) MTU() (int, error)        { return s.current().MTU() }
func (s *swapTUN) Name() (string, error)    { return s.current().Name() }
func (s *swapTUN) Events() <-chan tun.Event { return s.events }
func (s *swapTUN) BatchSize() int           { return s.current().BatchSize() }

func (s *swapTUN) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		err = s.current().Close()
		close(s.events)
	})
	return err
}
