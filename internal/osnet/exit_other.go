//go:build !linux && !windows && !darwin

package osnet

import (
	"errors"
	"syscall"
)

func physicalInterfaces(string) (int, int)                { return 0, 0 }
func applyBypass(string, syscall.RawConn, int, int) error { return nil }
func startExitRoutes(string) (*ExitRoutes, error)         { return nil, errors.ErrUnsupported }
