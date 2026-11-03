//go:build !windows

package winconsole

// OwnWindow is always false outside Windows: terminals keep output visible.
func OwnWindow() bool { return false }
