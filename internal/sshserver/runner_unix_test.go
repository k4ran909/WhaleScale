//go:build linux || darwin

package sshserver

import (
	"bytes"
	"context"
	"os/user"
	"strings"
	"testing"
	"time"
)

// TestOSRunner runs real commands as the current user, with and without
// a PTY.
func TestOSRunner(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	var out bytes.Buffer
	code, err := OSRunner{}.Run(context.Background(), &Session{
		User: u.Username, Cmd: "echo hi-$USER; exit 4", Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out,
	})
	if err != nil || code != 4 || strings.TrimSpace(out.String()) != "hi-"+u.Username {
		t.Fatalf("exec: code=%d err=%v out=%q", code, err, out.String())
	}

	out.Reset()
	resize := make(chan Window)
	close(resize)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err = OSRunner{}.Run(ctx, &Session{
		User: u.Username, Cmd: "tty >/dev/null && echo has-tty; stty size", Term: "xterm", Window: Window{Cols: 99, Rows: 33},
		Stdin: strings.NewReader(""), Stdout: &out, Resize: resize,
	})
	if err != nil || code != 0 || !strings.Contains(out.String(), "has-tty") || !strings.Contains(out.String(), "33 99") {
		t.Fatalf("pty: code=%d err=%v out=%q", code, err, out.String())
	}

	if _, err := (OSRunner{}).Run(context.Background(), &Session{User: "no-such-user-xyz"}); err == nil {
		t.Fatal("unknown user accepted")
	}
}
