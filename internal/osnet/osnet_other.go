//go:build !linux && !windows && !darwin

package osnet

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
)

func apply(Config) error {
	return fmt.Errorf("TUN mode is not supported on %s yet; use --tun=userspace", runtime.GOOS)
}

func cleanup(Config) error { return nil }

func addRoute(string, netip.Prefix) error { return errors.ErrUnsupported }
func delRoute(string, netip.Prefix) error { return errors.ErrUnsupported }

func startRouter(string, netip.Prefix, netip.Prefix) (*Router, error) {
	return nil, errors.ErrUnsupported
}
