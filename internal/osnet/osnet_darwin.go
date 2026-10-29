package osnet

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func resolverFile(suffix string) string { return filepath.Join("/etc/resolver", suffix) }

func apply(c Config) error {
	steps := [][]string{
		{"ifconfig", c.Iface, "inet", c.IPv4.String(), c.IPv4.String(), "netmask", "255.255.255.255",
			"mtu", strconv.Itoa(c.MTU), "up"},
		{"route", "-q", "-n", "add", "-inet", c.Route4.String(), "-interface", c.Iface},
	}
	if c.IPv6.IsValid() {
		steps = append(steps,
			[]string{"ifconfig", c.Iface, "inet6", c.IPv6.String(), "prefixlen", "128"},
			[]string{"route", "-q", "-n", "add", "-inet6", c.Route6.String(), "-interface", c.Iface})
	}
	for _, s := range steps {
		if err := run(s[0], s[1:]...); err != nil {
			return err
		}
	}
	if !c.DNSServer.IsValid() {
		return nil
	}
	if err := os.MkdirAll("/etc/resolver", 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("# managed by whalescale\nnameserver %s\n", c.DNSServer)
	return os.WriteFile(resolverFile(c.DNSSuffix), []byte(body), 0o644)
}

func cleanup(c Config) error {
	if c.DNSServer.IsValid() {
		os.Remove(resolverFile(c.DNSSuffix))
	}
	return nil
}
