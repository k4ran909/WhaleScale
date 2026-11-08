package mobile

import (
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD wraps the VPN interface's file descriptor (Linux, which the
// android build counts as).
func tunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return dev, nil
}
