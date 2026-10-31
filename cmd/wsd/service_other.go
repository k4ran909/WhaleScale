//go:build !linux && !windows && !darwin

package main

import (
	"errors"
	"runtime"
)

func runningAsService() bool         { return false }
func runService(args []string) error { return errors.New("not a service") }

func installService(*flags) error {
	return errors.New("service install is not supported on " + runtime.GOOS + "; run wsd from your init system")
}

func uninstallService() error { return installService(nil) }
