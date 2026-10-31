package osnet

import (
	"fmt"
	"strconv"
	"syscall"
)

// exitTable holds the TUN default route; the rule priorities sit just
// below wg-quick's defaults so the two don't collide.
const (
	exitTable    = "5753"
	exitPrioMain = "5208"
	exitPrioTun  = "5209"
)

// Linux needs no interface pinning: the fwmark alone steers the socket.
func physicalInterfaces(string) (int, int) { return 0, 0 }

func applyBypass(_ string, c syscall.RawConn, _, _ int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, BypassMark)
	})
	if err != nil {
		return err
	}
	if serr == syscall.EPERM {
		return fmt.Errorf("setting SO_MARK needs root (CAP_NET_ADMIN): %w", serr)
	}
	return serr
}

func startExitRoutes(iface string) (*ExitRoutes, error) {
	r := &ExitRoutes{}
	mark := strconv.Itoa(BypassMark)
	for _, fam := range []string{"-4", "-6"} {
		def := "0.0.0.0/0"
		if fam == "-6" {
			def = "::/0"
		}
		steps := []struct{ add, del []string }{
			// The TUN's own table: everything goes into the tunnel.
			{[]string{"ip", fam, "route", "replace", def, "dev", iface, "table", exitTable},
				[]string{"ip", fam, "route", "del", def, "dev", iface, "table", exitTable}},
			// Main table first, but ignoring its default route: LAN and mesh
			// routes keep working, only "everything else" changes.
			{[]string{"ip", fam, "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", exitPrioMain},
				[]string{"ip", fam, "rule", "del", "table", "main", "suppress_prefixlength", "0", "priority", exitPrioMain}},
			// Unmarked traffic (everything but our own sockets) uses the TUN table.
			{[]string{"ip", fam, "rule", "add", "not", "fwmark", mark, "table", exitTable, "priority", exitPrioTun},
				[]string{"ip", fam, "rule", "del", "not", "fwmark", mark, "table", exitTable, "priority", exitPrioTun}},
		}
		for _, st := range steps {
			if err := run(st.add[0], st.add[1:]...); err != nil {
				if fam == "-6" {
					break // no IPv6 on this host: IPv4 exit still works
				}
				r.Close()
				return nil, err
			}
			del := st.del
			r.undo = append(r.undo, func() { run(del[0], del[1:]...) })
		}
	}
	return r, nil
}
