package osnet

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
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
