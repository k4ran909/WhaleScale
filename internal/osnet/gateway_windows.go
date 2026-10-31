package osnet

import (
	"errors"
	"math"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultGateway takes the IPv4 gateway of the up adapter with the lowest
// metric, as physicalInterfaces does.
func defaultGateway() (netip.Addr, error) {
	size := uint32(15 << 10)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return netip.Addr{}, err
		}
	}
	best, bestMetric := netip.Addr{}, uint32(math.MaxUint32)
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for g := aa.FirstGatewayAddress; g != nil; g = g.Next {
			ip, ok := netip.AddrFromSlice(g.Address.IP())
			if !ok || !ip.Unmap().Is4() || ip.Unmap().IsUnspecified() {
				continue
			}
			if aa.Ipv4Metric < bestMetric {
				best, bestMetric = ip.Unmap(), aa.Ipv4Metric
			}
		}
	}
	if !best.IsValid() {
		return best, errors.New("no IPv4 default gateway")
	}
	return best, nil
}
