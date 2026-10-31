package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeRunner struct {
	mu   sync.Mutex
	last Session
}

func (f *fakeRunner) Run(_ context.Context, s *Session) (int, error) {
	f.mu.Lock()
	f.last = *s
	f.mu.Unlock()
	fmt.Fprintf(s.Stdout, "hello %s cmd=%q term=%q", s.User, s.Cmd, s.Term)
	return 3, nil
}

type recording struct {
	meta RecordingMeta
	data []byte
}

func startServer(t *testing.T, record bool) (addr string, hostKey ssh.PublicKey, runner *fakeRunner, recs chan recording) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	runner = &fakeRunner{}
	recs = make(chan recording, 4)
	s := &Server{
		HostKey: signer, Runner: runner, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authorize: func(remote netip.Addr, localUser string) Decision {
			if !remote.IsLoopback() || localUser != "karan" {
				return Decision{Reason: "not in policy"}
			}
			return Decision{Allowed: true, Record: record, SrcNode: "laptop", SrcUser: "karan"}
		},
		Recorded: func(m RecordingMeta, b []byte) { recs <- recording{m, b} },
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln)
	return ln.Addr().String(), signer.PublicKey(), runner, recs
}

func dial(addr, user string, hostKey ssh.PublicKey) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 5 * time.Second})
}

func TestLoginAndExec(t *testing.T) {
	addr, hk, runner, _ := startServer(t, false)
	c, err := dial(addr, "karan", hk)
	if err != nil {
		t.Fatalf("allowed login failed: %v", err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	out, err := sess.Output("uptime")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("exit status: %v", err)
	}
	if string(out) != `hello karan cmd="uptime" term=""` {
		t.Fatalf("output %q", out)
	}

	// A PTY request reaches the runner with its size.
	sess, _ = c.NewSession()
	if err := sess.RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	sess.Run("")
	runner.mu.Lock()
	got := runner.last
	runner.mu.Unlock()
	if got.Term != "xterm-256color" || got.Window != (Window{Cols: 120, Rows: 40}) {
		t.Fatalf("pty: term=%q window=%+v", got.Term, got.Window)
	}

	// No SFTP and no port forwarding.
	sess, _ = c.NewSession()
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("sftp subsystem accepted")
	}
	if _, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("port forwarding accepted")
	}
}

func TestLoginRefused(t *testing.T) {
	addr, hk, _, _ := startServer(t, false)
	if c, err := dial(addr, "root", hk); err == nil {
		c.Close()
		t.Fatal("login as a user the policy doesn't allow succeeded")
	}
}

func TestRecording(t *testing.T) {
	addr, hk, _, recs := startServer(t, true)
	c, err := dial(addr, "karan", hk)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	sess.Run("ls")
	select {
	case r := <-recs:
		lines := strings.Split(strings.TrimSpace(string(r.data)), "\n")
		if len(lines) != 2 || !strings.Contains(lines[0], `"version":2`) || !strings.Contains(lines[0], `"width":80`) ||
			!strings.Contains(lines[1], `hello karan`) {
			t.Fatalf("recording:\n%s", r.data)
		}
		if r.meta.SrcNode != "laptop" || r.meta.LocalUser != "karan" || r.meta.Ended.Before(r.meta.Started) {
			t.Fatalf("meta = %+v", r.meta)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no recording delivered")
	}
}
