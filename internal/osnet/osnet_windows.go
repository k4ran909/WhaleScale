package osnet

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

const nrptComment = "whalescale"

func apply(c Config) error {
	name := "name=" + c.Iface
	steps := [][]string{
		// Assigning the address with the mesh range's mask also installs the
		// on-link route for the whole range.
		{"netsh", "interface", "ipv4", "set", "address", name, "source=static",
			"address=" + c.IPv4.String(), "mask=" + mask4(c.Route4.Bits()), "gateway=none"},
		{"netsh", "interface", "ipv4", "set", "subinterface", c.Iface, "mtu=" + strconv.Itoa(c.MTU), "store=active"},
	}
	if c.IPv6.IsValid() {
		steps = append(steps,
			[]string{"netsh", "interface", "ipv6", "add", "address", c.Iface,
				fmt.Sprintf("%s/%d", c.IPv6, c.Route6.Bits()), "store=active"})
	}
	for _, s := range steps {
		if err := run(s[0], s[1:]...); err != nil {
			return err
		}
	}
	if !c.DNSServer.IsValid() {
		return nil
	}
	// Name Resolution Policy Table: send only *.suffix to our resolver.
	removeNRPT()
	ps := fmt.Sprintf("Add-DnsClientNrptRule -Namespace '.%s' -NameServers '%s' -Comment '%s'",
		c.DNSSuffix, c.DNSServer, nrptComment)
	return run("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
}

func removeNRPT() {
	run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientNrptRule | Where-Object Comment -eq '"+nrptComment+"' | Remove-DnsClientNrptRule -Force")
}

func cleanup(c Config) error {
	if c.DNSServer.IsValid() {
		removeNRPT()
	}
	return nil
}

func addRoute(iface string, p netip.Prefix) error {
	fam := "ipv4"
	if p.Addr().Is6() {
		fam = "ipv6"
	}
	return run("netsh", "interface", fam, "add", "route", p.String(), "interface="+iface, "store=active")
}

func delRoute(iface string, p netip.Prefix) error {
	fam := "ipv4"
	if p.Addr().Is6() {
		fam = "ipv6"
	}
	return run("netsh", "interface", fam, "delete", "route", p.String(), "interface="+iface)
}

func startRouter(string, netip.Prefix, netip.Prefix) (*Router, error) {
	return nil, errors.New("subnet routing is only supported on Linux so far")
}
