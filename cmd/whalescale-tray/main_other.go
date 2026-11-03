//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "whalescale-tray is Windows-only for now; use 'ws status'.")
	os.Exit(1)
}
