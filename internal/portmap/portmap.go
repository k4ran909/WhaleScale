// Package portmap asks the home router to forward the agent's WireGuard
// UDP port, so peers can reach this machine directly without a manual
// port forward or a relay. It tries PCP, then NAT-PMP, then UPnP IGD,
// renews the mapping at half its lifetime and removes it on shutdown.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

const (
	requestLifetime = 2 * time.Hour
	retryAfter      = 5 * time.Minute
)

// Mapping is a live port mapping on the router.
type Mapping struct {
	Protocol string         `json:"protocol"` // "pcp", "nat-pmp" or "upnp"
	External netip.AddrPort `json:"external"`
	Expires  time.Time      `json:"expires"`
}

// Report is what the router supports, from read-only queries.
type Report struct {
	Gateway    netip.Addr `json:"gateway"`
	PCP        bool       `json:"pcp"`
	NATPMP     bool       `json:"nat_pmp"`
	UPnP       bool       `json:"upnp"`
	ExternalIP netip.Addr `json:"external_ip,omitzero"`
	// DoubleNAT is true when the router's own external address is private
	// or carrier-grade NAT: a mapping on it can't make us reachable.
	DoubleNAT bool   `json:"double_nat"`
	Error     string `json:"error,omitempty"`
}

// Config wires a client to a network. Zero values mean "detect".
type Config struct {
	Gateway netip.Addr
	Local   netip.Addr
	Port    uint16 // the local UDP port to map
	Log     *slog.Logger
	// Testing: where the router listens.
	PMPPort    uint16
	SSDPTarget netip.AddrPort
}

// Client keeps one UDP mapping alive.
type Client struct {
	cfg   Config
	nonce [12]byte

	mu      sync.Mutex
	mapping *Mapping
	upnp    *igd
	lastErr error
	onMap   func(*Mapping)
}

func New(cfg Config, onMap func(*Mapping)) *Client {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.PMPPort == 0 {
		cfg.PMPPort = pmpPort
	}
	if !cfg.SSDPTarget.IsValid() {
		cfg.SSDPTarget = ssdpAddr
	}
	return &Client{cfg: cfg, nonce: newNonce(), onMap: onMap}
}

// Mapping returns the current mapping, or nil.
func (c *Client) Mapping() *Mapping {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mapping == nil || time.Now().After(c.mapping.Expires) {
		return nil
	}
	m := *c.mapping
	return &m
}

func (c *Client) set(m *Mapping, err error) {
	c.mu.Lock()
	changed := (m == nil) != (c.mapping == nil) || (m != nil && c.mapping != nil && m.External != c.mapping.External)
	c.mapping, c.lastErr = m, err
	cb := c.onMap
	c.mu.Unlock()
	if changed && cb != nil {
		cb(m)
	}
}

// Run keeps the mapping alive until ctx is done, then deletes it.
func (c *Client) Run(ctx context.Context) {
	defer c.release()
	for {
		m, err := c.mapOnce(ctx)
		c.set(m, err)
		wait := retryAfter
		if err == nil {
			c.cfg.Log.Info("router port mapping", "protocol", m.Protocol, "external", m.External,
				"expires_in", time.Until(m.Expires).Round(time.Second))
			wait = time.Until(m.Expires) / 2
		} else if ctx.Err() == nil {
			c.cfg.Log.Debug("no router port mapping", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *Client) addrs() (gw netip.AddrPort, local netip.Addr, err error) {
	if !c.cfg.Gateway.IsValid() || !c.cfg.Local.IsValid() {
		return gw, local, errors.New("no gateway")
	}
	return netip.AddrPortFrom(c.cfg.Gateway, c.cfg.PMPPort), c.cfg.Local, nil
}

func (c *Client) mapOnce(ctx context.Context) (*Mapping, error) {
	gw, local, err := c.addrs()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	port := c.cfg.Port

	ext, life, err := pcpMap(ctx, gw, local, port, port, requestLifetime, c.nonce)
	if err == nil && ext.IsValid() && ext.Port() != 0 {
		return &Mapping{Protocol: "pcp", External: ext, Expires: time.Now().Add(life)}, nil
	}
	errs := []error{fmt.Errorf("pcp: %w", err)}

	if p, life, err := pmpMap(ctx, gw, port, port, requestLifetime); err == nil && p != 0 {
		ip, err := pmpExternalIP(ctx, gw)
		if err == nil {
			return &Mapping{Protocol: "nat-pmp", External: netip.AddrPortFrom(ip, p), Expires: time.Now().Add(life)}, nil
		}
		errs = append(errs, fmt.Errorf("nat-pmp external address: %w", err))
	} else {
		errs = append(errs, fmt.Errorf("nat-pmp: %w", err))
	}

	c.mu.Lock()
	g := c.upnp
	c.mu.Unlock()
	if g == nil {
		if g, err = discoverIGD(ctx, c.cfg.Gateway, c.cfg.SSDPTarget); err != nil {
			return nil, errors.Join(append(errs, fmt.Errorf("upnp: %w", err))...)
		}
		c.mu.Lock()
		c.upnp = g
		c.mu.Unlock()
	}
	if err := g.addMapping(ctx, local, port, port, requestLifetime); err != nil {
		c.mu.Lock()
		c.upnp = nil // rediscover next time
		c.mu.Unlock()
		return nil, errors.Join(append(errs, fmt.Errorf("upnp: %w", err))...)
	}
	ip, err := g.externalIP(ctx)
	if err != nil {
		return nil, errors.Join(append(errs, fmt.Errorf("upnp external address: %w", err))...)
	}
	return &Mapping{Protocol: "upnp", External: netip.AddrPortFrom(ip, port), Expires: time.Now().Add(requestLifetime)}, nil
}

// release deletes the mapping on shutdown, best effort.
func (c *Client) release() {
	c.mu.Lock()
	m, g := c.mapping, c.upnp
	c.mapping = nil
	c.mu.Unlock()
	if m == nil {
		return
	}
	gw, local, err := c.addrs()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	switch m.Protocol {
	case "pcp":
		pcpMap(ctx, gw, local, c.cfg.Port, 0, 0, c.nonce)
	case "nat-pmp":
		pmpMap(ctx, gw, c.cfg.Port, 0, 0)
	case "upnp":
		if g != nil {
			g.deleteMapping(ctx, m.External.Port())
		}
	}
}

// Probe asks the router what it supports without creating a mapping.
func Probe(ctx context.Context, cfg Config) Report {
	c := New(cfg, nil)
	r := Report{Gateway: c.cfg.Gateway}
	gw, _, err := c.addrs()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	// PCP has no read-only request; an ANNOUNCE (opcode 0) tells us whether
	// the router speaks it.
	ann := make([]byte, pcpHeaderLen)
	ann[0] = pcpVersion
	local := c.cfg.Local.As16()
	copy(ann[8:24], local[:])
	if resp, err := exchange(ctx, gw, ann, func(b []byte) bool { return len(b) >= 4 }); err == nil && resp[0] == pcpVersion {
		r.PCP = true
	}
	if ip, err := pmpExternalIP(ctx, gw); err == nil {
		r.NATPMP, r.ExternalIP = true, ip
	}
	if g, err := discoverIGD(ctx, c.cfg.Gateway, c.cfg.SSDPTarget); err == nil {
		r.UPnP = true
		if !r.ExternalIP.IsValid() {
			if ip, err := g.externalIP(ctx); err == nil {
				r.ExternalIP = ip
			}
		}
	}
	r.DoubleNAT = r.ExternalIP.IsValid() && !isPublic(r.ExternalIP)
	return r
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}
