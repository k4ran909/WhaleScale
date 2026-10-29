// Command ws is the Whalescale client CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/version"
)

const usage = `ws - Whalescale client

Usage:
  ws login  --server URL [--authkey KEY] [--hostname NAME]
  ws status [--json]
  ws logout
  ws version

The auth key may also come from $WS_AUTHKEY, which keeps it out of shell history.
State is kept in $WHALESCALE_STATE or the user config dir.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "login":
		err = cmdLogin(args)
	case "status":
		err = cmdStatus(args)
	case "logout":
		err = cmdLogout(args)
	case "version", "--version":
		fmt.Println("ws", version.String())
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

var httpClient = &http.Client{Timeout: 15 * time.Second}

func client(server string) whalescalev1connect.ControlServiceClient {
	return whalescalev1connect.NewControlServiceClient(httpClient, strings.TrimRight(server, "/"))
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "control server URL, e.g. https://ws.example.com")
	authKey := fs.String("authkey", os.Getenv("WS_AUTHKEY"), "pre-auth key from 'whalescale preauthkeys create'")
	hostname := fs.String("hostname", "", "node name (default: this machine's hostname)")
	fs.Parse(args)

	if *server == "" || *authKey == "" {
		return errors.New("--server and --authkey (or $WS_AUTHKEY) are required")
	}
	u, err := url.Parse(*server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--server must be an http(s) URL, got %q", *server)
	}
	if u.Scheme == "http" && !isLocal(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "warning: server URL is plain http; your auth key and node token are sent unencrypted")
	}

	path, err := clientstate.DefaultPath()
	if err != nil {
		return err
	}
	st, err := clientstate.Load(path)
	if err != nil {
		return err
	}
	if st != nil && st.NodeToken != "" {
		return fmt.Errorf("already logged in to %s as %q; run 'ws logout' first", st.ServerURL, st.NodeName)
	}
	if st == nil {
		key, err := clientstate.NewMachineKey()
		if err != nil {
			return err
		}
		st = &clientstate.State{MachineKey: key}
	}
	st.ServerURL = strings.TrimRight(*server, "/")
	pub, err := st.PublicKey()
	if err != nil {
		return err
	}

	name := *hostname
	if name == "" {
		name, _ = os.Hostname()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client(st.ServerURL).Register(ctx, connect.NewRequest(&v1.RegisterRequest{
		AuthKey:    *authKey,
		MachineKey: pub,
		Hostname:   name,
		Os:         runtime.GOOS,
	}))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	n := resp.Msg.Node
	st.NodeToken, st.NodeID, st.NodeName = resp.Msg.NodeToken, n.Id, n.Name
	if err := clientstate.Save(path, st); err != nil {
		return fmt.Errorf("registered, but saving state failed: %w", err)
	}
	fmt.Printf("logged in as %s (user %s), addresses %s\n", n.Name, n.User, strings.Join(n.Addresses, ", "))
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the network map as JSON")
	fs.Parse(args)

	path, err := clientstate.DefaultPath()
	if err != nil {
		return err
	}
	st, err := clientstate.Load(path)
	if err != nil {
		return err
	}
	if st == nil || st.NodeToken == "" {
		return errors.New("not logged in; run 'ws login'")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req := connect.NewRequest(&v1.GetNetworkMapRequest{})
	req.Header().Set("Authorization", "Bearer "+st.NodeToken)
	resp, err := client(st.ServerURL).GetNetworkMap(ctx, req)
	if err != nil {
		return fmt.Errorf("get network map: %w", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Msg)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\tNAME\tUSER\tADDRESSES\tOS\tLAST SEEN")
	row := func(mark string, n *v1.Node) {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", mark, n.Name, n.User, strings.Join(n.Addresses, ", "), n.Os,
			n.LastSeen.AsTime().Local().Format(time.DateTime))
	}
	row("*", resp.Msg.Self)
	for _, p := range resp.Msg.Peers {
		row("", p)
	}
	tw.Flush()
	fmt.Printf("\nserver %s  ·  %d peer(s)  ·  * = this node\n", st.ServerURL, len(resp.Msg.Peers))
	return nil
}

func cmdLogout(args []string) error {
	path, err := clientstate.DefaultPath()
	if err != nil {
		return err
	}
	st, err := clientstate.Load(path)
	if err != nil {
		return err
	}
	if st == nil || st.NodeToken == "" {
		fmt.Println("not logged in")
		return nil
	}
	// Keep the machine key; forget server credentials. Server-side removal
	// is 'whalescale nodes delete' until a Logout RPC lands in Phase 1.
	st.NodeToken, st.NodeID, st.NodeName = "", 0, ""
	if err := clientstate.Save(path, st); err != nil {
		return err
	}
	fmt.Println("logged out locally; ask an admin to run 'whalescale nodes delete' to remove the node")
	return nil
}

func isLocal(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
