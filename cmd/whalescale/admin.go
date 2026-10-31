package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/k4ran909/whalescale/internal/control"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

func table(header string) *tabwriter.Writer {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, header)
	return tw
}

func cmdUsers(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale users create NAME | list | delete NAME")
	}
	fs, db := adminFlags("users " + args[0])
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
		users, err := st.ListUserDetails(ctx)
		if err != nil {
			return err
		}
		tw := table("ID\tNAME\tEMAIL\tNODES\tCREATED")
		for _, u := range users {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\n", u.ID, u.Name, u.Email, u.NodeCount, u.CreatedAt.Format(time.DateTime))
		}
		tw.Flush()
	case "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: whalescale users delete NAME")
		}
		if err := st.DeleteUser(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("deleted user", fs.Arg(0))
	default:
		return fmt.Errorf("unknown users subcommand %q", args[0])
	}
	return nil
}

func cmdPreAuthKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale preauthkeys create|list|expire")
	}
	fs, db := adminFlags("preauthkeys " + args[0])
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
		tw := table("ID\tPREFIX\tUSER\tREUSABLE\tEPHEMERAL\tUSED\tEXPIRES\tVALID")
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

func cmdAPIKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale apikeys create|list|expire")
	}
	fs, db := adminFlags("apikeys " + args[0])
	expiration := fs.Duration("expiration", 90*24*time.Hour, "how long the key stays valid")
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		k, plain, err := st.CreateAPIKey(ctx, *expiration)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "API key %s (expires %s). Use it to sign in to the console or call the admin API. Shown only once:\n",
			k.Prefix, k.ExpiresAt.Format(time.DateTime))
		fmt.Println(plain)
	case "list":
		keys, err := st.ListAPIKeys(ctx)
		if err != nil {
			return err
		}
		tw := table("ID\tPREFIX\tCREATED\tEXPIRES\tLAST USED\tVALID")
		for _, k := range keys {
			last := "never"
			if !k.LastUsed.IsZero() {
				last = k.LastUsed.Format(time.DateTime)
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%v\n", k.ID, k.Prefix, k.CreatedAt.Format(time.DateTime),
				k.ExpiresAt.Format(time.DateTime), last, k.Valid())
		}
		tw.Flush()
	case "expire":
		if fs.NArg() != 1 {
			return errors.New("usage: whalescale apikeys expire PREFIX")
		}
		if err := st.ExpireAPIKey(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Println("expired API key", fs.Arg(0))
	default:
		return fmt.Errorf("unknown apikeys subcommand %q", args[0])
	}
	return nil
}

func cmdNodes(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale nodes list|delete")
	}
	fs, db := adminFlags("nodes " + args[0])
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
		tw := table("ID\tNAME\tUSER\tIPV4\tIPV6\tOS\tROUTES\tLAST SEEN")
		for _, n := range nodes {
			routes := fmt.Sprintf("%d/%d", len(n.Routes), len(n.AdvertisedRoutes))
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Name, n.User, n.IPv4, n.IPv6, n.OS, routes,
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

func cmdRoutes(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale routes list | approve NODE PREFIX | unapprove NODE PREFIX")
	}
	fs, db := adminFlags("routes " + args[0])
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "list":
		routes, err := st.ListRoutes(ctx)
		if err != nil {
			return err
		}
		tw := table("NODE\tPREFIX\tADVERTISED\tAPPROVED\tKIND")
		for _, r := range routes {
			kind := "subnet"
			if r.IsExit() {
				kind = "exit node"
			}
			fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%s\n", r.NodeName, r.Prefix, r.Advertised, r.Approved, kind)
		}
		tw.Flush()
	case "approve", "unapprove":
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: whalescale routes %s NODE PREFIX", args[0])
		}
		id, err := nodeID(ctx, st, fs.Arg(0))
		if err != nil {
			return err
		}
		p, err := netip.ParsePrefix(fs.Arg(1))
		if err != nil {
			return err
		}
		if err := st.SetRouteApproved(ctx, id, p, args[0] == "approve"); err != nil {
			return err
		}
		fmt.Printf("%sd %s on %s (running servers pick this up within 5s)\n", args[0], p, fs.Arg(0))
	default:
		return fmt.Errorf("unknown routes subcommand %q", args[0])
	}
	return nil
}

func cmdExposures(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale exposures list | approve NAME | unapprove NAME")
	}
	fs, db := adminFlags("exposures " + args[0])
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "list":
		list, err := st.ListExposures(ctx)
		if err != nil {
			return err
		}
		tw := table("NAME\tNODE\tLOCAL PORT\tADVERTISED\tAPPROVED")
		for _, e := range list {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%v\t%v\n", e.Name, e.NodeName, e.Port, e.Advertised, e.Approved)
		}
		tw.Flush()
	case "approve", "unapprove":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: whalescale exposures %s NAME", args[0])
		}
		e, err := st.ExposureByName(ctx, fs.Arg(0))
		if err != nil {
			return fmt.Errorf("no exposure named %q", fs.Arg(0))
		}
		if err := st.SetExposureApproved(ctx, e.NodeID, e.Name, args[0] == "approve"); err != nil {
			return err
		}
		fmt.Printf("%sd %s (port %d on %s); running servers pick this up within 5s\n", args[0], e.Name, e.Port, e.NodeName)
	default:
		return fmt.Errorf("unknown exposures subcommand %q", args[0])
	}
	return nil
}

func cmdRelays(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: whalescale relays list | approve NODE | unapprove NODE")
	}
	fs, db := adminFlags("relays " + args[0])
	st, err := openStore(fs, db, args[1:])
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "list":
		nodes, err := st.ListNodes(ctx, "")
		if err != nil {
			return err
		}
		tw := table("NODE\tOFFERED\tAPPROVED")
		for _, n := range nodes {
			if n.RelayOffered || n.RelayApproved {
				fmt.Fprintf(tw, "%s\t%v\t%v\n", n.Name, n.RelayOffered, n.RelayApproved)
			}
		}
		tw.Flush()
	case "approve", "unapprove":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: whalescale relays %s NODE", args[0])
		}
		id, err := nodeID(ctx, st, fs.Arg(0))
		if err != nil {
			return err
		}
		if err := st.SetRelayApproved(ctx, id, args[0] == "approve"); err != nil {
			return err
		}
		fmt.Printf("%sd %s as a peer relay; running servers pick this up within 5s\n", args[0], fs.Arg(0))
	default:
		return fmt.Errorf("unknown relays subcommand %q", args[0])
	}
	return nil
}

func cmdFlows(args []string) error {
	fs, db := adminFlags("flows")
	node := fs.String("node", "", "only flows reported by this machine")
	since := fs.Duration("since", time.Hour, "how far back to look")
	denied := fs.Bool("denied", false, "only connections the access policy refused")
	limit := fs.Int("limit", 100, "maximum rows")
	st, err := openStore(fs, db, args)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	flows, err := st.QueryFlows(ctx, store.FlowQuery{Node: *node, Since: time.Now().Add(-*since), DeniedOnly: *denied, Limit: *limit})
	if err != nil {
		return err
	}
	if len(flows) == 0 {
		fmt.Println("no flows (is the server running with flow-logs: true?)")
		return nil
	}
	names := map[string]string{}
	if nodes, err := st.ListNodes(ctx, ""); err == nil {
		for _, n := range nodes {
			names[n.IPv4.String()], names[n.IPv6.String()] = n.Name, n.Name
		}
	}
	label := func(ip string) string {
		if n := names[ip]; n != "" {
			return n
		}
		return ip
	}
	tw := table("TIME\tREPORTED BY\tCLIENT\tSERVER\tPROTO\tVERDICT\tSENT\tRECEIVED")
	for _, f := range flows {
		verdict := "allow"
		if f.Denied {
			verdict = "DENY"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s:%d\t%s\t%s\t%s\t%s\n", f.End.Format(time.TimeOnly), f.NodeName,
			label(f.Client), label(f.Server), f.Port, protoName(f.Proto), verdict, humanBytes(f.BytesSent), humanBytes(f.BytesRecv))
	}
	tw.Flush()
	return nil
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	}
	return strconv.Itoa(int(p))
}

func humanBytes(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
}

// nodeID accepts a node ID or name.
func nodeID(ctx context.Context, st *store.Store, s string) (uint64, error) {
	if id, err := strconv.ParseUint(s, 10, 64); err == nil {
		return id, nil
	}
	nodes, err := st.ListNodes(ctx, "")
	if err != nil {
		return 0, err
	}
	for _, n := range nodes {
		if n.Name == s {
			return n.ID, nil
		}
	}
	return 0, fmt.Errorf("no node named %q", s)
}

func cmdPolicy(args []string) error {
	if len(args) >= 1 && args[0] == "explain" {
		return cmdPolicyExplain(args[1:])
	}
	if len(args) < 2 || args[0] != "check" {
		return errors.New("usage: whalescale policy check FILE | explain SRC DST:PORT [--file FILE]")
	}
	fs, db := adminFlags("policy check")
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
	var nodes []store.Node
	if st, err := store.Open(context.Background(), *db); err == nil {
		if users, err := st.ListUsers(context.Background()); err == nil {
			for _, u := range users {
				names = append(names, u.Name)
			}
		}
		nodes, _ = st.ListNodes(context.Background(), "")
		st.Close()
	}
	warnings := p.Lint(names)
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}
	fails := p.RunTests(control.PolicyNodes(nodes))
	for _, f := range fails {
		fmt.Println("test failed:", f)
	}
	if len(fails) > 0 {
		return fmt.Errorf("%d of the policy's tests failed", len(fails))
	}
	fmt.Printf("%s: ok (%d acl rules, %d groups, %d tests passed, %d warnings)\n", file, len(p.ACLs), len(p.Groups), len(p.Tests), len(warnings))
	return nil
}

// cmdPolicyExplain says whether SRC may reach DST:PORT under the policy in
// --file, else the server's (policy file, then the console's), else allow-all.
func cmdPolicyExplain(args []string) error {
	fs, db := adminFlags("policy explain")
	file := fs.String("file", "", "policy file to evaluate (default: the server's policy)")
	var pos []string
	for len(args) > 0 {
		if !strings.HasPrefix(args[0], "-") {
			pos, args = append(pos, args[0]), args[1:]
			continue
		}
		fs.Parse(args)
		args = fs.Args()
	}
	if len(pos) != 2 {
		return errors.New("usage: whalescale policy explain SRC DST:PORT [--file FILE]\n  e.g. whalescale policy explain bob node:nas:445")
	}
	st, err := store.Open(context.Background(), *db)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	var text, source string
	switch {
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		text, source = string(b), *file
	default:
		if opts, _, err := loadServeConfig(nil, true); err == nil && opts.policyFile != "" {
			b, err := os.ReadFile(opts.policyFile)
			if err != nil {
				return err
			}
			text, source = string(b), opts.policyFile
		} else if t, ok, _ := st.Setting(ctx, control.PolicySettingKey); ok {
			text, source = t, "the policy saved in the console"
		}
	}
	p := policy.AllowAll()
	if text != "" {
		if p, err = policy.Parse([]byte(text)); err != nil {
			return err
		}
	} else {
		source = "the default allow-all policy"
	}
	all, err := st.ListNodes(ctx, "")
	if err != nil {
		return err
	}
	nodes := control.PolicyNodes(all)
	src, err := policy.Resolve(pos[0], nodes)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dst, port, err := policy.ResolveDst(pos[1], nodes)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	ex := p.Explain(src, dst, port, nodes)
	verdict := "DENIED"
	if ex.Allowed {
		verdict = "ALLOWED"
	}
	fmt.Printf("%s → %s port %d: %s  (using %s)\n", src, dst, port, verdict, source)
	for _, r := range ex.Reasons {
		fmt.Println("  -", r)
	}
	return nil
}

func cmdMigrate(args []string) error {
	fs, db := adminFlags("migrate")
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
