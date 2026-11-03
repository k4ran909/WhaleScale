package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k4ran909/whalescale/internal/joincode"
)

// Each command must get its own arguments: a dispatcher that drops or
// shifts one breaks the command entirely, and nothing else would notice.
func TestDispatchPassesArguments(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "lock.key")
	if err := run("lock", []string{"keygen", "--out", keyFile}); err != nil {
		t.Fatalf("ws lock keygen: %v", err)
	}
	if b, err := os.ReadFile(keyFile); err != nil || !strings.HasPrefix(string(b), "wslock-private:") {
		t.Fatalf("key file: %q, %v", b, err)
	}
	// With no server or key configured these fail, but with their own
	// errors: proof the subcommand and flags arrived.
	t.Setenv("WHALESCALE_STATE", filepath.Join(t.TempDir(), "state.json"))
	t.Setenv("WS_API_KEY", "")
	for cmd, want := range map[string]string{
		"access request node:db:5432": "not logged in",
		"mcp --server http://x":       "API key is needed",
		"lock sign --key " + keyFile:  "--server is required",
	} {
		f := strings.Fields(cmd)
		err := run(f[0], f[1:])
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ws %s: %v, want an error containing %q", cmd, err, want)
		}
	}
}

// 'ws login' takes the dashboard's join code as its argument; anything
// else as an argument is a mistake worth saying so about.
func TestLoginArguments(t *testing.T) {
	t.Setenv("WHALESCALE_STATE", filepath.Join(t.TempDir(), "state.json"))
	code := joincode.Encode("https://ws.example.com", "wskey-ab12-cd34")
	for args, want := range map[string]string{
		"":                                       "give the join code",
		"wskey-ab12-cd34":                        "unexpected argument",
		"wsjoin-damaged!":                        "join code is damaged",
		"--server https://other.example " + code: "is for https://ws.example.com, not https://other.example",
		code + " extra":                          "unexpected argument",
	} {
		err := run("login", strings.Fields(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ws login %s: %v, want an error containing %q", args, err, want)
		}
	}
}
