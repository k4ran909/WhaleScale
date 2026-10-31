// Command wsd is the Whalescale node agent: it runs the WireGuard data plane,
// NAT traversal, the relay client and MagicDNS, following the network map
// from the control server. 'ws up' and 'ws down' control it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/daemon"
	"github.com/k4ran909/whalescale/internal/engine"
	"github.com/k4ran909/whalescale/internal/version"
)

const usage = `wsd - Whalescale node agent

Usage:
  wsd [flags]                     run in the foreground
  wsd install-service [flags]     install and start as a system service (root/Administrator)
  wsd uninstall-service           stop and remove the service
  wsd version

Flags:
`

type flags struct {
	statePath, tunMode, tunName string
	port                        uint
	verbose                     bool
}

func parseFlags(args []string) (*flags, *flag.FlagSet) {
	f := &flags{}
	fs := flag.NewFlagSet("wsd", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	defState, _ := clientstate.DefaultPath()
	fs.StringVar(&f.statePath, "state", defState, "state file written by 'ws login'")
	fs.StringVar(&f.tunMode, "tun", "os", `"os" for a real interface (needs admin/root), "userspace" for an in-process stack`)
	fs.StringVar(&f.tunName, "tun-name", "", "interface name (default: whale0, Whalescale on Windows, utun on macOS)")
	fs.UintVar(&f.port, "port", engine.DefaultPort, "UDP port for WireGuard and path discovery (0 = random)")
	fs.BoolVar(&f.verbose, "verbose", false, "debug logging")
	fs.Parse(args)
	return f, fs
}

// serviceArgs are the flags a service runs with: the user's, with the
// state forced into the system directory.
func (f *flags) serviceArgs() []string {
	args := []string{"--state", filepath.Join(clientstate.SystemDir(), "state.json"), "--tun", f.tunMode,
		"--port", fmt.Sprint(f.port)}
	if f.tunName != "" {
		args = append(args, "--tun-name", f.tunName)
	}
	if f.verbose {
		args = append(args, "--verbose")
	}
	return args
}

func main() {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "version":
		fmt.Println("wsd", version.String())
		return
	case "install-service":
		f, _ := parseFlags(args)
		err = installService(f)
	case "uninstall-service":
		err = uninstallService()
	case "":
		if runningAsService() {
			err = runService(args)
		} else {
			f, _ := parseFlags(args)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = run(ctx, f, os.Stderr)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		parseFlags([]string{"-h"})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wsd:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, f *flags, logOut io.Writer) error {
	level := slog.LevelInfo
	if f.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: level}))
	if f.tunMode != "os" && f.tunMode != "userspace" {
		return fmt.Errorf("--tun must be os or userspace")
	}
	log.Info("wsd starting", "version", version.Version, "state", f.statePath, "tun", f.tunMode)
	if f.tunMode == "userspace" {
		log.Info("userspace mode: the tunnel is only reachable from inside wsd; use 'ws ping' and 'ws status' to check paths")
	}
	d := daemon.New(daemon.Options{
		StatePath: f.statePath, Userspace: f.tunMode == "userspace", TUNName: f.tunName,
		Port: uint16(f.port), Log: log,
	})
	return d.Run(ctx)
}
