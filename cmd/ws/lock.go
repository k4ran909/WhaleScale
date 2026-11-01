package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/localapi"
	"github.com/k4ran909/whalescale/internal/netlock"
)

const lockUsage = `usage:
  ws lock status                     this machine's view of the lock
  ws lock keygen [--out FILE]        make a lock key (keep the file off the server)
  ws lock init     --key FILE [--trust wslock:...,...]
                                     turn the lock on, trusting your key (and others), and sign every machine
  ws lock sign     --key FILE [NODE ...]
                                     sign machines (default: every one not validly signed)
  ws lock add-key  --key FILE wslock:...
  ws lock remove-key --key FILE wslock:...
  ws lock disable  --key FILE | enable --key FILE

Admin commands talk to the admin API: --server (default: this machine's
server) and an API key in $WS_API_KEY or --api-key-file.`

func cmdLock(args []string) error {
	if len(args) == 0 {
		return errors.New(lockUsage)
	}
	switch args[0] {
	case "status":
		return lockStatus()
	case "keygen":
		return lockKeygen(args[1:])
	case "init", "sign", "add-key", "remove-key", "disable", "enable":
		return lockAdmin(args[0], args[1:])
	}
	return errors.New(lockUsage)
}

func lockStatus() error {
	_, path, err := loadState()
	if err != nil {
		return err
	}
	s, err := localapi.NewClient(localapi.SocketPath(path)).Status()
	if err != nil {
		return err
	}
	l := s.Lock
	switch {
	case l == nil || !l.Enabled:
		fmt.Println("Network lock: off")
	default:
		fmt.Printf("Network lock: on (version %d)\n", l.Version)
		fmt.Println("Trusted keys:")
		for _, k := range l.TrustedKeys {
			fmt.Println("  " + k)
		}
		if l.SelfSigned {
			fmt.Println("This machine is signed.")
		} else {
			fmt.Println("This machine is NOT signed: other machines refuse it. Ask an admin to run 'ws lock sign'.")
		}
		if len(l.LockedOut) > 0 {
			fmt.Println("Refused (not signed):", strings.Join(l.LockedOut, ", "))
		}
	}
	if l != nil && l.Error != "" {
		fmt.Println("Warning: the server sent lock data that doesn't verify:", l.Error)
	}
	return nil
}

func lockKeygen(args []string) error {
	fs := flag.NewFlagSet("lock keygen", flag.ExitOnError)
	out := fs.String("out", "wslock.key", "where to write the private key")
	fs.Parse(args)
	priv, err := netlock.GenerateKey()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(netlock.EncodePrivate(priv)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s. Keep it safe and off the server: whoever holds it can add machines to a locked network.\n", *out)
	fmt.Println(netlock.EncodePublic(priv.Public().(ed25519.PublicKey)))
	return nil
}

// lockAdmin runs the commands that sign with a lock key and talk to the
// admin API.
func lockAdmin(cmd string, args []string) error {
	fs := flag.NewFlagSet("lock "+cmd, flag.ExitOnError)
	keyFile := fs.String("key", "", "lock private key file (from 'ws lock keygen')")
	server := fs.String("server", "", "server URL (default: the one this machine uses)")
	apiKeyFile := fs.String("api-key-file", "", "file holding an admin API key (default: $WS_API_KEY)")
	trust := fs.String("trust", "", "init: more keys to trust, comma-separated")
	fs.Parse(args)
	if *keyFile == "" {
		return errors.New("--key is required")
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := netlock.ParsePrivate(string(b))
	if err != nil {
		return err
	}
	me := []byte(priv.Public().(ed25519.PublicKey))

	admin, apiKey, err := adminClient(*server, *apiKeyFile)
	if err != nil {
		return err
	}
	authed := func(r connect.AnyRequest) connect.AnyRequest {
		r.Header().Set("Authorization", "Bearer "+apiKey)
		return r
	}
	ctx := context.Background()
	getReq := connect.NewRequest(&v1.GetLockRequest{})
	authed(getReq)
	lr, err := admin.GetLock(ctx, getReq)
	if err != nil {
		return err
	}
	chain := lr.Msg.Chain
	// Check what the server says before signing on top of it.
	if err := netlock.VerifyChain(chain); err != nil {
		return fmt.Errorf("the server's lock history doesn't verify, refusing to sign on top of it: %w", err)
	}
	var head *v1.LockState
	if len(chain) > 0 {
		head = chain[len(chain)-1]
	}
	update := func(next *v1.LockState) error {
		netlock.SignState(next, priv)
		if err := netlock.Next(head, next); err != nil {
			return err
		}
		req := connect.NewRequest(&v1.UpdateLockRequest{State: next})
		authed(req)
		if _, err := admin.UpdateLock(ctx, req); err != nil {
			return err
		}
		head = next
		return nil
	}
	nextFrom := func(keys [][]byte, disabled bool) *v1.LockState {
		return &v1.LockState{Version: head.Version + 1, Keys: keys, Disabled: disabled}
	}
	if cmd != "init" && head == nil {
		return errors.New("the network lock isn't set up; run 'ws lock init' first")
	}

	switch cmd {
	case "init":
		if head != nil {
			return fmt.Errorf("the network lock is already set up (version %d); use add-key, enable or sign", head.Version)
		}
		keys := [][]byte{me}
		for _, s := range strings.Split(*trust, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			k, err := netlock.ParsePublic(s)
			if err != nil {
				return err
			}
			keys = append(keys, k)
		}
		if err := update(&v1.LockState{Version: 1, Keys: keys}); err != nil {
			return err
		}
		fmt.Printf("network lock on, trusting %d key(s)\n", len(keys))
		return lockSign(ctx, admin, authed, priv, head, nil)
	case "sign":
		return lockSign(ctx, admin, authed, priv, head, fs.Args())
	case "add-key", "remove-key":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: ws lock %s --key FILE wslock:...", cmd)
		}
		k, err := netlock.ParsePublic(fs.Arg(0))
		if err != nil {
			return err
		}
		has := slices.ContainsFunc(head.Keys, func(t []byte) bool { return string(t) == string(k) })
		keys := slices.Clone(head.Keys)
		if cmd == "add-key" {
			if has {
				return errors.New("that key is already trusted")
			}
			keys = append(keys, k)
		} else {
			if !has {
				return errors.New("that key isn't trusted")
			}
			keys = slices.DeleteFunc(keys, func(t []byte) bool { return string(t) == string(k) })
			if len(keys) == 0 {
				return errors.New("can't remove the last trusted key; use 'ws lock disable' to turn the lock off")
			}
		}
		if err := update(nextFrom(keys, head.Disabled)); err != nil {
			return err
		}
		fmt.Printf("lock version %d: %d trusted key(s)\n", head.Version, len(keys))
		if cmd == "remove-key" {
			fmt.Println("Machines signed only by the removed key are refused until re-signed: run 'ws lock sign'.")
		}
	case "disable", "enable":
		if head.Disabled == (cmd == "disable") {
			return fmt.Errorf("the lock is already %sd", cmd)
		}
		if err := update(nextFrom(head.Keys, cmd == "disable")); err != nil {
			return err
		}
		fmt.Printf("network lock %sd (version %d)\n", cmd, head.Version)
	}
	return nil
}

// lockSign signs the named machines, or every machine whose signature
// isn't valid under head.
func lockSign(ctx context.Context, admin whalescalev1connect.AdminServiceClient, authed func(connect.AnyRequest) connect.AnyRequest,
	priv ed25519.PrivateKey, head *v1.LockState, names []string) error {
	req := connect.NewRequest(&v1.ListNodesRequest{})
	authed(req)
	resp, err := admin.ListNodes(ctx, req)
	if err != nil {
		return err
	}
	var sigs []*v1.SignedNodeKey
	var signed []string
	found := map[string]bool{}
	for _, n := range resp.Msg.Nodes {
		key, err := base64.StdEncoding.DecodeString(n.NodeKey)
		if err != nil || len(key) != 32 {
			continue // never connected yet; sign it once it has
		}
		if len(names) > 0 {
			if !slices.Contains(names, n.Name) {
				continue
			}
			found[n.Name] = true
		} else if netlock.NodeSigned(head, key, n.LockSignature) {
			continue
		}
		sigs = append(sigs, &v1.SignedNodeKey{NodeKey: n.NodeKey, Signature: netlock.SignNode(priv, key)})
		signed = append(signed, n.Name)
	}
	for _, n := range names {
		if !found[n] {
			return fmt.Errorf("no connected machine named %q", n)
		}
	}
	if len(sigs) == 0 {
		fmt.Println("every connected machine is already signed")
		return nil
	}
	sreq := connect.NewRequest(&v1.SignNodesRequest{Signatures: sigs})
	authed(sreq)
	if _, err := admin.SignNodes(ctx, sreq); err != nil {
		return err
	}
	fmt.Printf("signed %d machine(s): %s\n", len(signed), strings.Join(signed, ", "))
	return nil
}

// adminClient connects to the admin API: server defaults to the one this
// machine uses, the API key comes from apiKeyFile or $WS_API_KEY.
func adminClient(server, apiKeyFile string) (whalescalev1connect.AdminServiceClient, string, error) {
	if server == "" {
		if base, err := clientstate.DefaultPath(); err == nil {
			_, path := clientstate.Current(base)
			if st, err := clientstate.Load(path); err == nil && st != nil {
				server = st.ServerURL
			}
		}
	}
	if server == "" {
		return nil, "", errors.New("--server is required (this machine isn't logged in)")
	}
	apiKey := os.Getenv("WS_API_KEY")
	if apiKeyFile != "" {
		b, err := os.ReadFile(apiKeyFile)
		if err != nil {
			return nil, "", err
		}
		apiKey = strings.TrimSpace(string(b))
	}
	if apiKey == "" {
		return nil, "", errors.New("an API key is needed: set $WS_API_KEY or pass --api-key-file ('whalescale apikeys create' makes one)")
	}
	return whalescalev1connect.NewAdminServiceClient(httpClient, strings.TrimRight(server, "/")), apiKey, nil
}
