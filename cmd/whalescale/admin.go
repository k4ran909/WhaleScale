package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

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
	if len(args) < 2 || args[0] != "check" {
		return errors.New("usage: whalescale policy check FILE [--db PATH]")
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
