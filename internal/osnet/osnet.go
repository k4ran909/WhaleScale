// Package osnet configures the operating system for a TUN interface:
// addresses, routes to the mesh ranges and split DNS for the MagicDNS suffix.
// It shells out to each platform's standard tools.
package osnet

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

type Config struct {
	Iface string
	// Addrs are this node's mesh addresses. Prefix is the mesh range they
	// belong to, routed into the TUN.
	IPv4, IPv6     netip.Addr
	Route4, Route6 netip.Prefix
	MTU            int
	// DNSServer answers for DNSSuffix (split DNS). Zero disables DNS setup.
	DNSServer netip.Addr
	DNSSuffix string
}

// Apply configures the interface. Cleanup undoes what interface removal
// doesn't undo on its own (mainly DNS).
func Apply(c Config) error   { return apply(c) }
func Cleanup(c Config) error { return cleanup(c) }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// mask4 renders a prefix length as a dotted IPv4 netmask.
func mask4(bits int) string {
	m := uint32(0xffffffff) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&0xff, m>>8&0xff, m&0xff)
}

// AddRoute sends a prefix into the TUN; DelRoute removes it.
func AddRoute(iface string, p netip.Prefix) error { return addRoute(iface, p) }
func DelRoute(iface string, p netip.Prefix) error { return delRoute(iface, p) }

// Router forwards traffic between the mesh and local networks for
// advertised subnet routes. Close undoes its changes.
type Router struct {
	undo []func()
}

func (r *Router) Close() {
	for i := len(r.undo) - 1; i >= 0; i-- {
		r.undo[i]()
	}
	r.undo = nil
}

// StartRouter enables forwarding and source NAT for mesh traffic leaving
// through non-mesh interfaces, so LAN hosts need no route back to the mesh.
func StartRouter(iface string, mesh4, mesh6 netip.Prefix) (*Router, error) {
	return startRouter(iface, mesh4, mesh6)
}
