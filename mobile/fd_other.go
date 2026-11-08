//go:build !linux

package mobile

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD: only Android hands over a VPN interface as a descriptor. Other
// systems build the package for its tests.
func tunFromFD(int) (tun.Device, error) {
	return nil, errors.New("a TUN from a file descriptor needs Android or Linux")
}
