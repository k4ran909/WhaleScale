// Command whalescale is the Whalescale server: control plane, relay, STUN,
// web console and admin CLI.
//
// Admin subcommands open the database directly, so run them on the server
// host. The web console and the AdminService API cover remote admin.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/version"
)

const usage = `whalescale - self-hosted mesh VPN server

Usage:
  whalescale serve       [flags]           run the server (see 'whalescale serve -h')
  whalescale configtest  [flags]           validate configuration and show where each value came from
  whalescale doctor      [flags]           check a running server end to end
  whalescale users       create NAME | list | delete NAME
  whalescale preauthkeys create --user NAME [--reusable] [--ephemeral] [--expiration 24h]
  whalescale preauthkeys list | expire PREFIX
  whalescale apikeys     create [--expiration 2160h] | list | expire PREFIX
  whalescale nodes       list [--user NAME] | delete ID
  whalescale routes      list | approve NODE PREFIX | unapprove NODE PREFIX
  whalescale exposures   list | approve NAME | unapprove NAME
  whalescale relays      list | approve NODE | unapprove NODE
  whalescale flows       [--node NAME] [--since 1h] [--denied] [--limit 100]
  whalescale audit       [--since 24h] [--actor X] [--action X] [--limit 100] | --verify
  whalescale policy      check FILE | explain SRC DST:PORT [--file FILE]
  whalescale migrate     apply pending database migrations and exit
  whalescale version

Settings come from the config file (default %s), conf.d/*.yaml beside it,
WHALESCALE_* environment variables, then flags. Admin commands use its 'db'.
`

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "Whalescale", "config.yaml")
	}
	return "/etc/whalescale/config.yaml"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, defaultConfigPath())
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = cmdServe(args)
	case "configtest":
		err = cmdConfigtest(args)
	case "doctor":
		err = cmdDoctor(args)
	case "users":
		err = cmdUsers(args)
	case "preauthkeys":
		err = cmdPreAuthKeys(args)
	case "apikeys":
		err = cmdAPIKeys(args)
	case "nodes":
		err = cmdNodes(args)
	case "routes":
		err = cmdRoutes(args)
	case "exposures":
		err = cmdExposures(args)
	case "relays":
		err = cmdRelays(args)
	case "flows":
		err = cmdFlows(args)
	case "audit":
		err = cmdAudit(args)
	case "policy":
		err = cmdPolicy(args)
	case "migrate":
		err = cmdMigrate(args)
	case "version", "--version":
		fmt.Println("whalescale", version.String())
	case "help", "-h", "--help":
		fmt.Printf(usage, defaultConfigPath())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, defaultConfigPath())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// adminFlags makes a flag set whose --db defaults to the configured database.
func adminFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	db := fs.String("db", configuredDB(), "path to the SQLite database")
	return fs, db
}

// configuredDB reads 'db' from the server configuration (file, conf.d,
// environment), the same place 'serve' gets it.
//
// A broken configuration (a missing --config/WHALESCALE_CONFIG file, a
// typo'd key) is fatal: silently falling back to ./whalescale.db would
// make admin commands change the wrong database.
func configuredDB() string {
	opts, _, err := loadServeConfig(nil, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: loading configuration:", err)
		fmt.Fprintln(os.Stderr, "fix the config, or pass --db explicitly with WHALESCALE_CONFIG unset")
		os.Exit(1)
	}
	return opts.db
}

func openStore(fs *flag.FlagSet, db *string, args []string) (*store.Store, error) {
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return store.Open(context.Background(), *db)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
