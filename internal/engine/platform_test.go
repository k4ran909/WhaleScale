package engine

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/k4ran909/whalescale/internal/dnsserver"
)

// fakePlatform stands in for Android's VpnService: each OpenTUN gets a
// fresh userspace stack, as each VpnService.Builder.establish() gets a
// fresh interface.
type fakePlatform struct {
	mu   sync.Mutex
	cfgs []TunnelConfig
	tnet *netstack.Net
}

func (p *fakePlatform) OpenTUN(cfg TunnelConfig) (tun.Device, error) {
	var local []netip.Addr
	for _, a := range cfg.Addresses {
		local = append(local, a.Addr())
	}
	td, tnet, err := netstack.CreateNetTUN(local, []netip.Addr{cfg.DNS}, cfg.MTU)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfgs = append(p.cfgs, cfg)
	p.tnet = tnet
	return td, nil
}

func (p *fakePlatform) last() (TunnelConfig, *netstack.Net, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfgs[len(p.cfgs)-1], p.tnet, len(p.cfgs)
}

func TestPlatformTUN(t *testing.T) {
	n := newTestNet(t, "")
	lan := netip.MustParsePrefix("10.99.0.0/24")
	router := n.nodeWith("router", Options{AdvertiseRoutes: []netip.Prefix{lan}})
	plat := &fakePlatform{}
	internet := netip.MustParseAddr("192.0.2.7")
	phone := n.nodeWith("phone", Options{Platform: plat, AcceptRoutes: true,
		LocalDNS: dnsserver.Upstream([]string{fakeResolver(t, internet)})})

	cfg, tnet, opened := plat.last()
	if opened != 1 {
		t.Fatalf("OpenTUN called %d times before any change", opened)
	}
	if len(cfg.Addresses) == 0 || cfg.Addresses[0] != netip.PrefixFrom(selfIP(phone), 32) {
		t.Fatalf("addresses = %v, want %v/32 first", cfg.Addresses, selfIP(phone))
	}
	if cfg.Routes[0] != meshRange4 || slices.Contains(cfg.Routes, lan) {
		t.Fatalf("routes before approval = %v", cfg.Routes)
	}
	if cfg.DNS != MagicDNSAddr || cfg.SearchDomain != "whale.internal" || cfg.MTU != MTU {
		t.Fatalf("config = %+v", cfg)
	}

	// Traffic and MagicDNS over the first TUN.
	echo(t, router, 8080)
	dial := func(tnet *netstack.Net) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(selfIP(router), 8080))
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "hi\n")
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil && line != "echo: hi\n" {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err := dial(tnet); err != nil {
		t.Fatalf("TCP through the platform TUN: %v", err)
	}
	lookup := func(tnet *netstack.Net, name string) []string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		addrs, err := tnet.LookupContextHost(ctx, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		return addrs
	}
	if got := lookup(tnet, "router.whale.internal"); !slices.Contains(got, selfIP(router).String()) {
		t.Fatalf("MagicDNS = %v", got)
	}
	// Other names go to LocalDNS (the phone's own DNS servers).
	if got := lookup(tnet, "example.com"); !slices.Contains(got, internet.String()) {
		t.Fatalf("lookup outside the mesh = %v, want %v", got, internet)
	}

	// Approving the subnet route brings a new TUN with the route in it.
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	var routerID uint64
	for routerID == 0 {
		routes, _ := n.store.ListRoutes(ctx)
		for _, r := range routes {
			if r.Prefix == lan && r.Advertised {
				routerID = r.NodeID
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("route never advertised")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := n.store.SetRouteApproved(ctx, routerID, lan, true); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		cfg, tnet, opened = plat.last()
		if slices.Contains(cfg.Routes, lan) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TUN never reopened with %v: %v (%d opens)", lan, cfg.Routes, opened)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if opened != 2 {
		t.Fatalf("OpenTUN called %d times, want 2", opened)
	}
	// WireGuard carries on over the new TUN.
	if err := dial(tnet); err != nil {
		t.Fatalf("TCP after the TUN was swapped: %v", err)
	}
}
