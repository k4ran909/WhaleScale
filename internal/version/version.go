// Package version holds build metadata, set with -ldflags at release time.
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "none"
)

func String() string { return fmt.Sprintf("%s (%s)", Version, Commit) }
