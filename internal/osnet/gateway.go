package osnet

import (
	"errors"
	"net"
	"net/netip"
)

// DefaultGateway returns the IPv4 default gateway (normally the home
// router) and the local address this machine uses to reach it.
func DefaultGateway() (gw, local netip.Addr, err error) {
	gw, err = defaultGateway()
	if err != nil {
		return gw, local, err
	}
	if !gw.Is4() || !gw.IsPrivate() {
		return gw, local, errors.New("default gateway is not a private IPv4 address")
	}
	// Dialing UDP sends nothing; it only picks the source address.
	c, err := net.Dial("udp4", netip.AddrPortFrom(gw, 5351).String())
	if err != nil {
		return gw, local, err
	}
	defer c.Close()
	local = c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	return gw, local, nil
}
