// Command whalescale is the Whalescale server: control plane plus admin CLI.
//
// Admin subcommands open the database directly, so run them on the server
// host. A remote admin API arrives with the web console in Phase 2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/stun"
	"github.com/k4ran909/whalescale/internal/version"
)

const usage = `whalescale - self-hosted mesh VPN server

Usage:
  whalescale serve      [--listen :8080] [--public-url URL] [--stun-listen :3478]
                        [--policy FILE] [--dns-suffix whale.internal] [--tls-cert F --tls-key F]
  whalescale policy     check FILE
  whalescale users      create NAME | list
  whalescale preauthkeys create --user NAME [--reusable] [--ephemeral] [--expiration 24h]
  whalescale preauthkeys list | expire PREFIX
  whalescale nodes      list [--user NAME] | delete ID
  whalescale migrate    apply pending database migrations and exit
  whalescale version

Every command accepts --db (default: $WHALESCALE_DB or ./whalescale.db).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = cmdServe(args)
	case "users":
		err = cmdUsers(args)
	case "preauthkeys":
		err = cmdPreAuthKeys(args)
	case "nodes":
		err = cmdNodes(args)
	case "migrate":
		err = cmdMigrate(args)
	case "policy":
		err = cmdPolicy(args)
	case "version", "--version":
		fmt.Println("whalescale", version.String())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDB() string {
	if p := os.Getenv("WHALESCALE_DB"); p != "" {
		return p
	}
	return "whalescale.db"
}

// openStore parses fs (which must define "db") and opens the database.
func openStore(fs *flag.FlagSet, db *string, args []string) (*store.Store, error) {
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return store.Open(context.Background(), *db)
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	db := fs.String("db", defaultDB(), "path to the SQLite database")
	return fs, db
}

func cmdServe(args []string) error {
	fs, db := newFlags("serve")
	listen := fs.String("listen", ":8080", "address to listen on")
	publicURL := fs.String("public-url", "", "URL nodes use to reach this server (default: http://<listen>)")
	stunListen := fs.String("stun-listen", ":3478", "comma-separated UDP addresses for STUN; two ports let nodes detect symmetric NAT; empty disables")
	dnsSuffix := fs.String("dns-suffix", "whale.internal", "MagicDNS domain suffix")
	policyFile := fs.String("policy", "", "access policy file (JSON); default allows all traffic")
	certFile := fs.String("tls-cert", "", "TLS certificate file (PEM)")
	keyFile := fs.String("tls-key", "", "TLS private key file (PEM)")
	st, err := openStore(fs, db, args)
	if err != nil {
		return err
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("--tls-cert and --tls-key must be set together")
	}
	tlsOn := *certFile != ""
	if !tlsOn && !isLoopback(*listen) {
		log.Warn("serving without TLS on a non-loopback address: auth keys and node tokens travel in cleartext. Use --tls-cert/--tls-key or a TLS reverse proxy.")
	}
	if *publicURL == "" {
		host := *listen
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		scheme := "http"
		if tlsOn {
			scheme = "https"
		}
		*publicURL = scheme + "://" + host
	}
	pu, err := url.Parse(*publicURL)
	if err != nil || pu.Hostname() == "" {
		return fmt.Errorf("bad --public-url %q", *publicURL)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var stunAdvertise []string
	for _, a := range splitList(*stunListen) {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			return fmt.Errorf("stun listen %s: %w", a, err)
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		stunAdvertise = append(stunAdvertise, net.JoinHostPort(pu.Hostname(), port))
		go func() {
			if err := stun.Serve(ctx, pc, log); err != nil {
				log.Error("stun", "err", err)
			}
		}()
	}

	srv, err := server.New(st, server.Config{
		PublicURL: *publicURL, STUN: stunAdvertise, DNSSuffix: *dnsSuffix, PolicyFile: *policyFile, Log: log,
	})
	if err != nil {
		return err
	}
	go srv.Watch(ctx, 5*time.Second)

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("whalescale listening", "addr", *listen, "public_url", *publicURL, "stun", stunAdvertise,
			"tls", tlsOn, "db", *db, "version", version.Version)
		if tlsOn {
			errc <- hs.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
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

func cmdPolicy(args []string) error {
	if len(args) < 2 || args[0] != "check" {
		return errors.New("usage: whalescale policy check FILE [--db PATH]")
	}
	fs, db := newFlags("policy check")
	file := args[1]
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	p, err := policy.Parse(b)
	if err != nil {
		return err
	}
	var names []string
	if st, err := store.Open(context.Background(), *db); err == nil {
		if users, err := st.ListUsers(context.Background()); err == nil {
			for _, u := range users {
				names = append(names, u.Name)
			}
		}
		st.Close()
	}
	warnings := p.Lint(names)
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}
	fmt.Printf("%s: ok (%d acl rules, %d groups, %d warnings)\n", file, len(p.ACLs), len(p.Groups), len(warnings))
	return nil
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

func cmdUsers(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale users create NAME | list")
	}
	fs, db := newFlags("users " + args[0])
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		if fs.NArg() != 1 {
			return errors.New("usage: whalescale users create NAME")
		}
		u, err := st.CreateUser(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Printf("created user %s (id %d)\n", u.Name, u.ID)
	case "list":
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCREATED")
		for _, u := range users {
			fmt.Fprintf(tw, "%d\t%s\t%s\n", u.ID, u.Name, u.CreatedAt.Format(time.DateTime))
		}
		tw.Flush()
	default:
		return fmt.Errorf("unknown users subcommand %q", args[0])
	}
	return nil
}

func cmdPreAuthKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale preauthkeys create|list|expire")
	}
	fs, db := newFlags("preauthkeys " + args[0])
	user := fs.String("user", "", "user the key enrolls nodes as")
	reusable := fs.Bool("reusable", false, "allow the key to register more than one node")
	ephemeral := fs.Bool("ephemeral", false, "mark nodes registered with this key as ephemeral")
	expiration := fs.Duration("expiration", 24*time.Hour, "how long the key stays valid")
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		if *user == "" {
			return errors.New("--user is required")
		}
		if *expiration <= 0 {
			return errors.New("--expiration must be positive")
		}
		k, plain, err := st.CreatePreAuthKey(ctx, *user, *reusable, *ephemeral, *expiration)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "pre-auth key for %s (expires %s, reusable=%v). It is shown only once:\n",
			k.User, k.ExpiresAt.Format(time.DateTime), k.Reusable)
		fmt.Println(plain)
	case "list":
		keys, err := st.ListPreAuthKeys(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tPREFIX\tUSER\tREUSABLE\tEPHEMERAL\tUSED\tEXPIRES\tVALID")
		now := time.Now()
		for _, k := range keys {
			valid := now.Before(k.ExpiresAt) && (k.Reusable || !k.Used)
			fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%v\t%v\t%s\t%v\n", k.ID, k.Prefix, k.User, k.Reusable, k.Ephemeral, k.Used,
				k.ExpiresAt.Format(time.DateTime), valid)
		}
		tw.Flush()
	case "expire":
		if fs.NArg() != 1 {
			return errors.New("usage: whalescale preauthkeys expire PREFIX")
		}
		if err := st.ExpirePreAuthKey(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("expired key", fs.Arg(0))
	default:
		return fmt.Errorf("unknown preauthkeys subcommand %q", args[0])
	}
	return nil
}

func cmdNodes(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale nodes list|delete")
	}
	fs, db := newFlags("nodes " + args[0])
	user := fs.String("user", "", "only show nodes owned by this user")
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "list":
		nodes, err := st.ListNodes(ctx, *user)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tUSER\tIPV4\tIPV6\tOS\tLAST SEEN")
		for _, n := range nodes {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Name, n.User, n.IPv4, n.IPv6, n.OS,
				n.LastSeen.Format(time.DateTime))
		}
		tw.Flush()
	case "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: whalescale nodes delete ID")
		}
		id, err := strconv.ParseUint(fs.Arg(0), 10, 64)
		if err != nil {
			return fmt.Errorf("bad node id %q", fs.Arg(0))
		}
		if err := st.DeleteNode(ctx, id); err != nil {
			return err
		}
		fmt.Println("deleted node", id)
	default:
		return fmt.Errorf("unknown nodes subcommand %q", args[0])
	}
	return nil
}

func cmdMigrate(args []string) error {
	fs, db := newFlags("migrate")
	st, err := openStore(fs, db, args)
	if err != nil {
		return err
	}
	defer st.Close()
	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("database schema at version", v)
	return nil
}
