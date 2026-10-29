// Command wsd is the Whalescale node agent: it runs the WireGuard data plane,
// NAT traversal, the relay client and MagicDNS, following the network map
// from the control server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/engine"
	"github.com/k4ran909/whalescale/internal/localapi"
	"github.com/k4ran909/whalescale/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("wsd", version.String())
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "wsd:", err)
		os.Exit(1)
	}
}

func run() error {
	defState, _ := clientstate.DefaultPath()
	statePath := flag.String("state", defState, "state file written by 'ws login'")
	tunMode := flag.String("tun", "os", `"os" for a real interface (needs admin/root), "userspace" for an in-process stack`)
	tunName := flag.String("tun-name", "", "interface name (default: whale0, Whalescale on Windows, utun on macOS)")
	port := flag.Uint("port", engine.DefaultPort, "UDP port for WireGuard and path discovery (0 = random)")
	verbose := flag.Bool("verbose", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *tunMode != "os" && *tunMode != "userspace" {
		return fmt.Errorf("--tun must be os or userspace")
	}
	st, err := clientstate.Load(*statePath)
	if err != nil {
		return err
	}
	if st == nil || st.NodeToken == "" {
		return fmt.Errorf("not logged in (no credentials in %s); run 'ws login' first", *statePath)
	}

	sock := localapi.SocketPath(*statePath)
	ln, err := localapi.Listen(sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)

	e, err := engine.New(engine.Options{
		State: st, StatePath: *statePath, Userspace: *tunMode == "userspace",
		TUNName: *tunName, Port: uint16(*port), Log: log,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := e.Start(ctx); err != nil {
		return err
	}
	defer e.Close()

	go http.Serve(ln, localapi.Handler(e))
	log.Info("wsd running", "node", st.NodeName, "server", st.ServerURL, "tun", *tunMode, "socket", sock, "version", version.Version)
	if *tunMode == "userspace" {
		log.Info("userspace mode: the tunnel is only reachable from inside wsd; use 'ws ping' and 'ws status' to check paths")
	}
	<-ctx.Done()
	log.Info("shutting down")
	return nil
}
