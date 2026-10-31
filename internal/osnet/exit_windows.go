package osnet

import (
	"math"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF / IPV6_UNICAST_IF (ws2ipdef.h); not exported by x/sys.
const unicastIF = 31

// halves cover the whole address space with routes more specific than any
// default route, so they win without touching the existing default.
var halves = []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}

func applyBypass(network string, c syscall.RawConn, if4, if6 int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if is6(network) {
			if if6 > 0 {
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, unicastIF, if6)
			}
			return
		}
		if if4 > 0 {
			// IPv4 wants the index in network byte order.
			i := uint32(if4)
			be := i>>24 | i>>8&0xff00 | i<<8&0xff0000 | i<<24
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, unicastIF, int(int32(be)))
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// physicalInterfaces picks the up adapter with a gateway and the lowest
// metric, skipping the tunnel.
func physicalInterfaces(tun string) (if4, if6 int) {
	size := uint32(15 << 10)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return 0, 0
		}
	}
	best4, best6 := uint32(math.MaxUint32), uint32(math.MaxUint32)
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp || aa.FirstGatewayAddress == nil {
			continue
		}
		if tun != "" && windows.UTF16PtrToString(aa.FriendlyName) == tun {
			continue
		}
		if aa.IfIndex != 0 && aa.Ipv4Metric < best4 {
			best4, if4 = aa.Ipv4Metric, int(aa.IfIndex)
		}
		if aa.Ipv6IfIndex != 0 && aa.Ipv6Metric < best6 {
			best6, if6 = aa.Ipv6Metric, int(aa.Ipv6IfIndex)
		}
	}
	return if4, if6
}

func startExitRoutes(iface string) (*ExitRoutes, error) {
	r := &ExitRoutes{}
	for _, h := range halves {
		fam := "ipv4"
		if netip.MustParsePrefix(h).Addr().Is6() {
			fam = "ipv6"
		}
		if err := run("netsh", "interface", fam, "add", "route", h, "interface="+iface, "metric=0", "store=active"); err != nil {
			if fam == "ipv6" {
				continue // no IPv6: IPv4 exit still works
			}
			r.Close()
			return nil, err
		}
		h, fam := h, fam
		r.undo = append(r.undo, func() { run("netsh", "interface", fam, "delete", "route", h, "interface="+iface) })
	}
	return r, nil
}
