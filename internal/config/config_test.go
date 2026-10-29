package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func flags() (*flag.FlagSet, *string, *string, *string) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "")
	url := fs.String("public-url", "", "")
	admins := fs.String("oidc-admins", "", "")
	return fs, listen, url, admins
}

func TestLayering(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "config.yaml")
	os.WriteFile(main, []byte("listen: \":443\"\npublic-url: https://a.example\noidc-admins: [a@x.io, b@x.io]\n"), 0o600)
	os.MkdirAll(filepath.Join(dir, "conf.d"), 0o700)
	os.WriteFile(filepath.Join(dir, "conf.d", "10-local.yaml"), []byte("public-url: https://b.example\n"), 0o600)
	t.Setenv("WHALESCALE_LISTEN", ":9443")

	fs, listen, url, admins := flags()
	src, err := Load(fs, main, true, []string{"--oidc-admins=c@x.io"})
	if err != nil {
		t.Fatal(err)
	}
	if *listen != ":9443" || *url != "https://b.example" || *admins != "c@x.io" {
		t.Fatalf("got listen=%s url=%s admins=%s", *listen, *url, *admins)
	}
	if src["listen"] != "env WHALESCALE_LISTEN" || !strings.HasSuffix(src["public-url"], "10-local.yaml") || src["oidc-admins"] != "flag" {
		t.Fatalf("sources = %v", src)
	}
}

func TestUnknownKey(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "config.yaml")
	os.WriteFile(main, []byte("lisen: \":443\"\n"), 0o600)
	fs, _, _, _ := flags()
	if _, err := Load(fs, main, true, nil); err == nil || !strings.Contains(err.Error(), `"lisen"`) {
		t.Fatalf("typo not reported: %v", err)
	}
}

func TestMissingDefaultFileIsFine(t *testing.T) {
	fs, listen, _, _ := flags()
	if _, err := Load(fs, filepath.Join(t.TempDir(), "nope.yaml"), false, nil); err != nil || *listen != ":8080" {
		t.Fatalf("err=%v listen=%s", err, *listen)
	}
	fs, _, _, _ = flags()
	if _, err := Load(fs, filepath.Join(t.TempDir(), "nope.yaml"), true, nil); err == nil {
		t.Fatal("explicit missing config file should fail")
	}
}
