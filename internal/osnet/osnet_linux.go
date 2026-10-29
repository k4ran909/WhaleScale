package osnet

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func apply(c Config) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", c.Iface, "up", "mtu", strconv.Itoa(c.MTU)},
		{"ip", "addr", "replace", c.IPv4.String() + "/32", "dev", c.Iface},
		{"ip", "route", "replace", c.Route4.String(), "dev", c.Iface},
	}
	if c.IPv6.IsValid() {
		steps = append(steps,
			[]string{"ip", "-6", "addr", "replace", c.IPv6.String() + "/128", "dev", c.Iface},
			[]string{"ip", "-6", "route", "replace", c.Route6.String(), "dev", c.Iface})
	}
	for _, s := range steps {
		if err := run(s[0], s[1:]...); err != nil {
			return err
		}
	}
	if !c.DNSServer.IsValid() {
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		slog.Warn("resolvectl not found; MagicDNS names won't resolve from the OS", "suffix", c.DNSSuffix)
		return nil
	}
	if err := run("resolvectl", "dns", c.Iface, c.DNSServer.String()); err != nil {
		return fmt.Errorf("configure DNS: %w", err)
	}
	// A plain domain is both a search domain (so "ping laptop" works) and a
	// routing domain (only these names go to our resolver).
	return run("resolvectl", "domain", c.Iface, c.DNSSuffix)
}

func cleanup(c Config) error {
	if c.DNSServer.IsValid() {
		if _, err := exec.LookPath("resolvectl"); err == nil {
			run("resolvectl", "revert", c.Iface)
		}
	}
	return nil
}

func addRoute(iface string, p netip.Prefix) error {
	if p.Addr().Is6() {
		return run("ip", "-6", "route", "replace", p.String(), "dev", iface)
	}
	return run("ip", "route", "replace", p.String(), "dev", iface)
}

func delRoute(iface string, p netip.Prefix) error {
	if p.Addr().Is6() {
		return run("ip", "-6", "route", "del", p.String(), "dev", iface)
	}
	return run("ip", "route", "del", p.String(), "dev", iface)
}

func startRouter(iface string, mesh4, mesh6 netip.Prefix) (*Router, error) {
	r := &Router{}
	for _, sysctl := range []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"} {
		path := "/proc/sys/" + strings.ReplaceAll(sysctl, ".", "/")
		old, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			r.Close()
			return nil, fmt.Errorf("enable %s: %w", sysctl, err)
		}
		prev := old
		r.undo = append(r.undo, func() { os.WriteFile(path, prev, 0o644) })
	}
	nat := func(tool string, src netip.Prefix) error {
		if !src.IsValid() {
			return nil
		}
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s not found: install iptables to route subnets", tool)
		}
		rule := []string{"POSTROUTING", "-s", src.String(), "!", "-o", iface, "-j", "MASQUERADE",
			"-m", "comment", "--comment", "whalescale"}
		if err := run(tool, append([]string{"-t", "nat", "-A"}, rule...)...); err != nil {
			return err
		}
		r.undo = append(r.undo, func() { run(tool, append([]string{"-t", "nat", "-D"}, rule...)...) })
		return nil
	}
	if err := nat("iptables", mesh4); err != nil {
		r.Close()
		return nil, err
	}
	if err := nat("ip6tables", mesh6); err != nil {
		slog.Warn("IPv6 subnet routing disabled", "err", err)
	}
	return r, nil
}
