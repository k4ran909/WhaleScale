//go:build !linux && !windows && !darwin

package osinfo

func version() string { return "" }
