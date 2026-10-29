// Command wsd is the Whalescale node agent. In Phase 1 it will run the
// WireGuard data plane, NAT traversal and DNS. For now it only reports its
// version so packaging and CI have a real binary to build.
package main

import (
	"fmt"
	"os"

	"github.com/k4ran909/whalescale/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("wsd", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "wsd: the data plane arrives in Phase 1. Use 'ws login' and 'ws status' for now.")
	os.Exit(1)
}
