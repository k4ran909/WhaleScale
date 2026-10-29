//go:build !linux && !windows && !darwin

package osnet

import (
	"fmt"
	"runtime"
)

func apply(Config) error {
	return fmt.Errorf("TUN mode is not supported on %s yet; use --tun=userspace", runtime.GOOS)
}

func cleanup(Config) error { return nil }
