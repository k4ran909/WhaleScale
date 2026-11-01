//go:build race

// Package israce reports whether the race detector is on, so timing
// assertions can be skipped under its slowdown.
package israce

const Enabled = true
