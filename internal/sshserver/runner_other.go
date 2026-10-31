//go:build !linux && !darwin

package sshserver

import (
	"context"
	"errors"
	"runtime"
)

// OSRunner can't start sessions on this OS yet (Windows needs ConPTY).
type OSRunner struct{}

func (OSRunner) Run(context.Context, *Session) (int, error) {
	return 0, errors.New("the mesh SSH server is not supported on " + runtime.GOOS + " yet")
}
