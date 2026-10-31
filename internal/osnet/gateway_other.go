//go:build !linux && !windows && !darwin

package osnet

import (
	"errors"
	"net/netip"
)

func defaultGateway() (netip.Addr, error) { return netip.Addr{}, errors.ErrUnsupported }
