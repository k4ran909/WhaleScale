// Command tool signs releases and writes their SBOM (scripts/ci/release-archives.sh
// runs it). Run from the repository root:
//
//	go run ./internal/release/tool keygen -out FILE   make a release key
//	go run ./internal/release/tool sign FILE          writes FILE.minisig; the key comes from $RELEASE_SIGNING_KEY
//	go run ./internal/release/tool verify FILE        checks FILE.minisig against the release key
//	go run ./internal/release/tool sbom -version V [-time T] PROGRAM...   CycloneDX JSON on stdout
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/k4ran909/whalescale/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tool keygen|sign|verify|sbom ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "sbom":
		err = sbom(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// keygen writes a new key to -out (never over an existing file) and its
// public half to -out.pub and stdout.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the private key (keep it secret)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("keygen needs -out FILE")
	}
	k, err := release.NewKey()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(k.Encode() + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(k.PublicKeyFile()), 0o644); err != nil {
		return err
	}
	fmt.Print(k.PublicKeyFile())
	return nil
}

// sign signs file with $RELEASE_SIGNING_KEY, and checks the result against
// the public key built into Whalescale: a release signed with any other
// key would fail every update, so it fails here first.
func sign(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sign FILE")
	}
	secret := os.Getenv("RELEASE_SIGNING_KEY")
	if secret == "" {
		return errors.New("RELEASE_SIGNING_KEY is empty: add the release_signing_key secret in Woodpecker (docs/woodpecker.md)")
	}
	k, err := release.ParseKey(secret)
	if err != nil {
		return err
	}
	if k.PublicKey() != release.PublicKey {
		return errors.New("RELEASE_SIGNING_KEY isn't the key in internal/release.PublicKey")
	}
	msg, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	sig := k.Sign(msg, baseName(args[0]), time.Now())
	if err := release.Verify(release.PublicKey, msg, sig); err != nil {
		return fmt.Errorf("the new signature doesn't verify: %w", err)
	}
	return os.WriteFile(args[0]+".minisig", []byte(sig), 0o644)
}

func verify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: verify FILE")
	}
	msg, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(args[0] + ".minisig")
	if err != nil {
		return err
	}
	if err := release.Verify(release.PublicKey, msg, string(sig)); err != nil {
		return err
	}
	fmt.Println("good signature from the Whalescale release key")
	return nil
}

func sbom(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	version := fs.String("version", "", "release version, like v1.2.3")
	when := fs.String("time", "", "RFC 3339 timestamp (default now); the commit time keeps the file reproducible")
	fs.Parse(args)
	t := time.Now()
	if *when != "" {
		var err error
		if t, err = time.Parse(time.RFC3339, *when); err != nil {
			return err
		}
	}
	if *version == "" || fs.NArg() == 0 {
		return errors.New("usage: sbom -version V PROGRAM...")
	}
	doc, err := release.SBOM(*version, t, fs.Args())
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(doc, '\n'))
	return err
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
