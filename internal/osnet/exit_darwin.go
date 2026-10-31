package osnet

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

func applyBypass(network string, c syscall.RawConn, if4, if6 int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if is6(network) {
			if if6 > 0 {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, if6)
			}
			return
		}
		if if4 > 0 {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, if4)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// physicalInterfaces asks the routing table for the default route's
// interface. The catch-all /1 routes leave the default route in place, so
// this keeps working after they are installed.
func physicalInterfaces(tun string) (int, int) {
	idx := func(fam string) int {
		out, err := exec.Command("route", "-n", "get", fam, "default").Output()
		if err != nil {
			return 0
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
			if !ok || k != "interface" {
				continue
			}
			name := strings.TrimSpace(v)
			if name == tun {
				return 0
			}
			if ifc, err := net.InterfaceByName(name); err == nil {
				return ifc.Index
			}
		}
		return 0
	}
	return idx("-inet"), idx("-inet6")
}

func startExitRoutes(iface string) (*ExitRoutes, error) {
	r := &ExitRoutes{}
	for _, h := range []struct{ fam, prefix string }{
		{"-inet", "0.0.0.0/1"}, {"-inet", "128.0.0.0/1"}, {"-inet6", "::/1"}, {"-inet6", "8000::/1"},
	} {
		if err := run("route", "-q", "-n", "add", h.fam, h.prefix, "-interface", iface); err != nil {
			if h.fam == "-inet6" {
				continue
			}
			r.Close()
			return nil, err
		}
		h := h
		r.undo = append(r.undo, func() { run("route", "-q", "-n", "delete", h.fam, h.prefix, "-interface", iface) })
	}
	return r, nil
}
