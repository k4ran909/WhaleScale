//go:build !windows

package clientstate

// Protect locks down a state directory. On Unix the directory is created
// 0700 and files written 0600, which is enough.
func Protect(string) error { return nil }
