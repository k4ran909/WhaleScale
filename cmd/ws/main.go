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
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/localapi"
	"github.com/k4ran909/whalescale/internal/version"
)

const usage = `ws - Whalescale client

Usage:
  ws login  --server URL [--authkey KEY] [--hostname NAME]
                              without a key, prints a link to sign in with your browser
  ws up     [--accept-routes] [--advertise-routes CIDR,...] [--advertise-exit-node]
            [--exit-node NAME]  send all internet traffic through NAME ("" to stop)
            [--relay]           relay for peers that can't connect directly (needs approval)
                              start the tunnel (flags you pass replace saved ones)
  ws down                     stop the tunnel; wsd keeps running
  ws expose PORT --name NAME  publish http://localhost:PORT at https://NAME.<gateway domain>
  ws expose --remove NAME     stop publishing it
  ws expose                   list published services
  ws status [--json]          peers and the path to each (direct / relay)
  ws ping [-c N] NAME         disco ping; shows whether the reply came direct or via relay
  ws netcheck [--json]        public address, NAT type, relay reachability
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
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdDown(args)
	case "expose":
		err = cmdExpose(args)
	case "status":
		err = cmdStatus(args)
	case "ping":
		err = cmdPing(args)
	case "netcheck":
		err = cmdNetcheck(args)
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

	if *server == "" {
		return errors.New("--server is required")
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
	n, token := resp.Msg.Node, resp.Msg.NodeToken
	if resp.Msg.AuthUrl != "" {
		if n, token, err = waitBrowserLogin(st.ServerURL, resp.Msg.AuthUrl, resp.Msg.RegistrationId); err != nil {
			return err
		}
	}
	st.NodeToken, st.NodeID, st.NodeName = token, n.Id, n.Name
	if err := clientstate.Save(path, st); err != nil {
		return fmt.Errorf("registered, but saving state failed: %w", err)
	}
	fmt.Printf("logged in as %s (user %s), addresses %s\n", n.Name, n.User, strings.Join(n.Addresses, ", "))
	if _, err := localapi.NewClient(localapi.SocketPath(path)).Prefs(); err == nil {
		fmt.Println("wsd is running: start the tunnel with 'ws up'")
	} else {
		fmt.Println("next: start wsd (or 'wsd install-service'), then 'ws up'")
	}
	return nil
}

// waitBrowserLogin shows the sign-in link and waits until the user has
// finished logging in, for up to ten minutes.
func waitBrowserLogin(server, authURL, regID string) (*v1.Node, string, error) {
	fmt.Printf("\nTo add this device, open this link and sign in:\n\n    %s\n\n", authURL)
	openBrowser(authURL)
	fmt.Println("Waiting for you to sign in...")
	long := whalescalev1connect.NewControlServiceClient(&http.Client{Timeout: 70 * time.Second}, strings.TrimRight(server, "/"))
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		resp, err := long.WaitRegistration(ctx, connect.NewRequest(&v1.WaitRegistrationRequest{RegistrationId: regID}))
		cancel()
		if err == nil {
			return resp.Msg.Node, resp.Msg.NodeToken, nil
		}
		switch connect.CodeOf(err) {
		case connect.CodeDeadlineExceeded, connect.CodeUnavailable:
			time.Sleep(time.Second)
		default:
			return nil, "", fmt.Errorf("login: %w", err)
		}
	}
	return nil, "", errors.New("timed out waiting for the browser login; run 'ws login' again")
}

// openBrowser tries to open url; the printed link is the fallback.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	accept := fs.Bool("accept-routes", false, "use subnet routes other machines advertise")
	advertise := fs.String("advertise-routes", "", "comma-separated subnets this machine routes to, e.g. 192.168.1.0/24")
	exit := fs.Bool("advertise-exit-node", false, "offer this machine as an exit node (needs admin approval)")
	exitNode := fs.String("exit-node", "", "send all internet traffic through this machine (name, FQDN or mesh IP); empty to stop")
	offerRelay := fs.Bool("relay", false, "offer this machine as a UDP relay for peers that can't connect directly (best on a server with a public IP or port forward)")
	fs.Parse(args)

	_, path, err := loadState()
	if err != nil {
		return err
	}
	lc := localapi.NewClient(localapi.SocketPath(path))
	prefs, err := lc.Prefs()
	if errors.Is(err, localapi.ErrNotRunning) {
		return errors.New("wsd is not running; start it (or run 'wsd install-service') first")
	}
	if err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["accept-routes"] {
		prefs.AcceptRoutes = *accept
	}
	if set["exit-node"] {
		prefs.ExitNode = strings.TrimSpace(*exitNode)
	}
	if set["relay"] {
		prefs.Relay = *offerRelay
	}
	if set["advertise-routes"] || set["advertise-exit-node"] {
		var routes []string
		if set["advertise-routes"] {
			for _, r := range strings.Split(*advertise, ",") {
				if r = strings.TrimSpace(r); r != "" {
					routes = append(routes, r)
				}
			}
		} else {
			for _, r := range prefs.AdvertiseRoutes {
				if r != "0.0.0.0/0" && r != "::/0" {
					routes = append(routes, r)
				}
			}
		}
		wantExit := *exit
		if !set["advertise-exit-node"] {
			wantExit = slices.Contains(prefs.AdvertiseRoutes, "0.0.0.0/0")
		}
		if wantExit {
			routes = append(routes, "0.0.0.0/0", "::/0")
		}
		prefs.AdvertiseRoutes = routes
	}
	got, err := lc.Up(prefs)
	if err != nil {
		return err
	}
	fmt.Println("tunnel up")
	if got.Relay {
		fmt.Println("  offering to relay for peers (approve it in the console or with 'whalescale relays approve')")
	}
	if got.ExitNode != "" {
		fmt.Printf("  internet traffic goes through exit node %s (blocked, not leaked, while it is unavailable)\n", got.ExitNode)
	}
	if got.AcceptRoutes {
		fmt.Println("  accepting subnet routes from other machines")
	}
	if len(got.AdvertiseRoutes) > 0 {
		fmt.Printf("  advertising %s (approve them in the console or with 'whalescale routes approve')\n",
			strings.Join(got.AdvertiseRoutes, ", "))
	}
	return nil
}

func cmdExpose(args []string) error {
	fs := flag.NewFlagSet("expose", flag.ExitOnError)
	name := fs.String("name", "", "public name: the service appears at https://NAME.<gateway domain>")
	remove := fs.String("remove", "", "stop publishing this name")
	// Accept "ws expose 8123 --name ha" as well as flags first.
	var port string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		port, args = args[0], args[1:]
	}
	fs.Parse(args)
	if port == "" && fs.NArg() > 0 {
		port = fs.Arg(0)
	}

	_, path, err := loadState()
	if err != nil {
		return err
	}
	lc := localapi.NewClient(localapi.SocketPath(path))
	prefs, err := lc.Prefs()
	if errors.Is(err, localapi.ErrNotRunning) {
		return errors.New("wsd is not running; start it first")
	}
	if err != nil {
		return err
	}

	switch {
	case *remove != "":
		if _, ok := prefs.Exposures[*remove]; !ok {
			return fmt.Errorf("%q is not published", *remove)
		}
		delete(prefs.Exposures, *remove)
	case port != "":
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("bad port %q", port)
		}
		if *name == "" {
			return errors.New("--name is required, e.g. ws expose 8123 --name ha")
		}
		if prefs.Exposures == nil {
			prefs.Exposures = map[string]uint16{}
		}
		prefs.Exposures[strings.ToLower(*name)] = uint16(p)
	default:
		s, err := lc.Status()
		if err != nil {
			return err
		}
		if len(prefs.Exposures) == 0 {
			fmt.Println("nothing published; try: ws expose 8123 --name ha")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tLOCAL\tPUBLIC URL\tSTATE")
		for n, p := range prefs.Exposures {
			url, state := "-", "starting"
			for _, x := range s.Exposures {
				if x.Name == n {
					if x.Url != "" {
						url = x.Url
					}
					state = "live"
					if x.Problem != "" {
						state = x.Problem
					}
				}
			}
			fmt.Fprintf(tw, "%s\tlocalhost:%d\t%s\t%s\n", n, p, url, state)
		}
		tw.Flush()
		return nil
	}
	if prefs.Down {
		return errors.New("the tunnel is down; run 'ws up' first")
	}
	if _, err := lc.Up(prefs); err != nil {
		return err
	}
	if *remove != "" {
		fmt.Printf("stopped publishing %s\n", *remove)
	} else {
		fmt.Printf("publishing localhost:%s as %q; an admin must approve it (console > Gateway, or 'whalescale exposures approve')\n", port, strings.ToLower(*name))
		fmt.Println("check with: ws expose")
	}
	return nil
}

func cmdDown(args []string) error {
	_, path, err := loadState()
	if err != nil {
		return err
	}
	err = localapi.NewClient(localapi.SocketPath(path)).Down()
	if errors.Is(err, localapi.ErrNotRunning) {
		return errors.New("wsd is not running")
	}
	if err != nil {
		return err
	}
	fmt.Println("tunnel down (wsd keeps running; 'ws up' starts it again)")
	return nil
}

func loadState() (*clientstate.State, string, error) {
	path, err := clientstate.DefaultPath()
	if err != nil {
		return nil, "", err
	}
	st, err := clientstate.Load(path)
	if err != nil {
		return nil, "", err
	}
	if st == nil || st.NodeToken == "" {
		return nil, "", errors.New("not logged in; run 'ws login'")
	}
	return st, path, nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print as JSON")
	fs.Parse(args)

	st, path, err := loadState()
	if err != nil {
		return err
	}
	lc := localapi.NewClient(localapi.SocketPath(path))
	s, err := lc.Status()
	if errors.Is(err, localapi.ErrNotRunning) {
		fmt.Fprintln(os.Stderr, "wsd is not running; showing the server's view (no path info)")
		return serverStatus(st, *asJSON)
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(s)
	}
	if s.State == "stopped" {
		fmt.Println("the tunnel is down; run 'ws up' to start it")
		return nil
	}
	if s.Self == nil {
		fmt.Println("wsd is running but has no network map yet")
		if s.LastError != "" {
			fmt.Println("last error:", s.LastError)
		}
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\tNAME\tADDRESS\tUSER\tOS\tPATH\tLATENCY")
	fmt.Fprintf(tw, "*\t%s\t%s\t%s\t%s\t-\t-\n", s.Self.Name, first(s.Self.Addresses), s.Self.User, s.Self.Os)
	for _, p := range s.Peers {
		path, lat := p.Path, "-"
		switch {
		case !p.Online:
			path = "offline"
		case p.Path == "direct":
			path = "direct " + p.Addr
			lat = p.Latency.Round(10 * time.Microsecond).String()
		case p.Path == "peer-relay":
			path = "peer-relay via " + p.Addr
			lat = p.Latency.Round(10 * time.Microsecond).String()
		}
		fmt.Fprintf(tw, "\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, first(p.Addresses), p.User, p.OS, path, lat)
	}
	tw.Flush()
	for _, p := range s.Peers {
		if len(p.Routes) > 0 || p.ExitNode {
			extra := strings.Join(p.Routes, ", ")
			if p.ExitNode {
				extra = strings.TrimPrefix(extra+", exit node", ", ")
			}
			fmt.Printf("  %s routes %s\n", p.Name, extra)
		}
	}
	for _, x := range s.Exposures {
		if x.Problem == "" {
			fmt.Printf("  published: %s -> localhost:%d\n", x.Url, x.Port)
		} else {
			fmt.Printf("  published %s (localhost:%d): NOT LIVE: %s\n", x.Name, x.Port, x.Problem)
		}
	}
	if s.Relay != "" {
		fmt.Printf("  peer relay: %s\n", s.Relay)
	}
	if x := s.ExitNode; x != nil {
		if x.Active {
			fmt.Printf("  exit node: %s (active)\n", x.Name)
		} else {
			fmt.Printf("  exit node: %s (NOT ACTIVE: %s)\n", x.Name, x.Problem)
		}
	}
	relay := "disconnected"
	if s.RelayConnected {
		relay = "connected"
	}
	fmt.Printf("\nrelay %s (%s)  ·  %d peer(s)  ·  * = this node\n", relay, s.RelayURL, len(s.Peers))
	if s.LastError != "" {
		fmt.Println("last error:", s.LastError)
	}
	return nil
}

func serverStatus(st *clientstate.State, asJSON bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req := connect.NewRequest(&v1.GetNetworkMapRequest{})
	req.Header().Set("Authorization", "Bearer "+st.NodeToken)
	resp, err := client(st.ServerURL).GetNetworkMap(ctx, req)
	if err != nil {
		return fmt.Errorf("get network map: %w", err)
	}
	if asJSON {
		return printJSON(resp.Msg)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\tNAME\tUSER\tADDRESSES\tOS\tONLINE")
	row := func(mark string, n *v1.Node) {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\n", mark, n.Name, n.User, strings.Join(n.Addresses, ", "), n.Os, n.Online)
	}
	row("*", resp.Msg.Self)
	for _, p := range resp.Msg.Peers {
		row("", p)
	}
	tw.Flush()
	return nil
}

func cmdPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	count := fs.Int("c", 5, "number of pings (0 = until a direct path is found, max 30)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ws ping [-c N] NAME|FQDN|IP")
	}
	_, path, err := loadState()
	if err != nil {
		return err
	}
	lc := localapi.NewClient(localapi.SocketPath(path))
	n := *count
	if n <= 0 {
		n = 30
	}
	for i := 0; i < n; i++ {
		r, err := lc.Ping(fs.Arg(0))
		if errors.Is(err, localapi.ErrNotRunning) {
			return errors.New("wsd is not running; start it first")
		}
		if err != nil {
			fmt.Println("timeout:", err)
		} else if r.Via == "peer-relay" {
			fmt.Printf("pong from %s via peer relay %s in %v\n", r.Peer, r.Relay, r.Latency.Round(10*time.Microsecond))
		} else if r.Via == "direct" {
			fmt.Printf("pong from %s via %s in %v\n", r.Peer, r.Addr, r.Latency.Round(10*time.Microsecond))
			if *count <= 0 {
				return nil
			}
		} else {
			fmt.Printf("pong from %s via relay in %v\n", r.Peer, r.Latency.Round(10*time.Microsecond))
		}
		if i < n-1 {
			time.Sleep(time.Second)
		}
	}
	return nil
}

func cmdNetcheck(args []string) error {
	_, path, err := loadState()
	if err != nil {
		return err
	}
	r, err := localapi.NewClient(localapi.SocketPath(path)).Netcheck()
	if errors.Is(err, localapi.ErrNotRunning) {
		return errors.New("wsd is not running; start it first")
	}
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "--json" {
		return printJSON(r)
	}
	fmt.Printf("UDP port:      %d\n", r.Port)
	if len(r.Mapped) == 0 {
		fmt.Println("STUN:          no response (UDP may be blocked; traffic will use the relay)")
	}
	for srv, m := range r.Mapped {
		fmt.Printf("STUN %-21s you are %s\n", srv+":", m)
	}
	switch {
	case len(r.Mapped) < 2:
		fmt.Println("NAT type:      unknown (needs two STUN ports; run the server with --stun-listen :3478,:3479)")
	case r.MappingVariesByDest:
		fmt.Println("NAT type:      symmetric (mapping varies by destination): direct paths are unlikely, expect relay")
	default:
		fmt.Println("NAT type:      endpoint-independent mapping: hole punching should work")
	}
	fmt.Printf("relay:         connected=%v\n", r.RelayConnected)
	fmt.Println("endpoints:")
	for _, ep := range r.Endpoints {
		fmt.Println("  ", ep)
	}
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func first(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return ss[0]
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
