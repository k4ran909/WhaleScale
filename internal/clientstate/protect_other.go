//go:build !windows

package clientstate

import "os"

// Protect locks down a state directory. On Unix the directory is created
// 0700 and files written 0600, which is enough.
func Protect(string) error { return nil }

// protectPublic: the public directory is 0755 and its files 0644 already.
func protectPublic(dir string) error { return os.Chmod(dir, 0o755) }
