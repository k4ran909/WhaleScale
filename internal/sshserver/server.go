// Package sshserver is the mesh SSH server. A connection's identity is its
// source mesh address (WireGuard binds each peer's addresses to its key, so
// they can't be spoofed), and the access policy decides which local users
// that identity may log in as. There are no keys or passwords to manage.
package sshserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Decision is the policy's answer for one login.
type Decision struct {
	Allowed bool
	Record  bool
	// Who is connecting, for logs and recordings.
	SrcNode, SrcUser string
	Reason           string
}

// Authorizer decides whether the peer at remote may log in as localUser.
type Authorizer func(remote netip.Addr, localUser string) Decision

// Window is a terminal size.
type Window struct{ Cols, Rows uint32 }

// Session is one shell or command to run.
type Session struct {
	User   string
	Cmd    string // empty: login shell
	Term   string // set when a PTY was requested
	Window Window
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Resize <-chan Window
}

// Runner executes sessions on the local OS.
type Runner interface {
	Run(ctx context.Context, s *Session) (exitCode int, err error)
}

// RecordingMeta describes a finished recorded session.
type RecordingMeta struct {
	LocalUser, SrcNode, SrcUser string
	Started, Ended              time.Time
}

type Server struct {
	HostKey   ssh.Signer
	Authorize Authorizer
	Runner    Runner
	// Recorded receives finished recordings (asciinema v2).
	Recorded func(RecordingMeta, []byte)
	Log      *slog.Logger
}

func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-Whalescale",
		NoClientAuth:  true,
		NoClientAuthCallback: func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
			remote := addrOf(c.RemoteAddr())
			d := s.Authorize(remote, c.User())
			if !d.Allowed {
				s.Log.Warn("ssh login refused", "from", remote, "node", d.SrcNode, "local_user", c.User(), "reason", d.Reason)
				return nil, errors.New("not allowed by the access policy")
			}
			rec := ""
			if d.Record {
				rec = "1"
			}
			return &ssh.Permissions{Extensions: map[string]string{"src-node": d.SrcNode, "src-user": d.SrcUser, "record": rec}}, nil
		},
	}
	cfg.AddHostKey(s.HostKey)
	return cfg
}

func addrOf(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	cfg := s.config()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(c, cfg)
	}
}

func (s *Server) handleConn(c net.Conn, cfg *ssh.ServerConfig) {
	c.SetDeadline(time.Now().Add(30 * time.Second)) // for the handshake
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	defer sc.Close()
	ext := sc.Permissions.Extensions
	s.Log.Info("ssh login", "from", sc.RemoteAddr(), "node", ext["src-node"], "user", ext["src-user"],
		"local_user", sc.User(), "recorded", ext["record"] == "1")
	go ssh.DiscardRequests(reqs) // no port forwarding
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions are supported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(sc, ch, creqs)
	}
}

// allowedEnv are the client variables passed through.
func allowedEnv(name string) bool {
	return name == "TERM" || name == "LANG" || name == "COLORTERM" || strings.HasPrefix(name, "LC_")
}

func (s *Server) handleSession(sc *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	sess := &Session{User: sc.User(), Stdin: ch, Stdout: ch, Stderr: ch.Stderr()}
	resize := make(chan Window, 4)
	sess.Resize = resize
	started := make(chan struct{})
	var once sync.Once
	start := func() {
		once.Do(func() {
			close(started)
			go s.run(sc, ch, sess)
		})
	}
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			term, w, ok := parsePTYReq(req.Payload)
			if ok {
				sess.Term, sess.Window = term, w
			}
			req.Reply(ok, nil)
		case "window-change":
			if len(req.Payload) >= 8 {
				w := Window{Cols: binary.BigEndian.Uint32(req.Payload), Rows: binary.BigEndian.Uint32(req.Payload[4:])}
				select {
				case resize <- w:
				default:
				}
			}
		case "env":
			name, value, ok := parseEnv(req.Payload)
			if ok && allowedEnv(name) {
				sess.Env = append(sess.Env, name+"="+value)
			}
			req.Reply(ok && allowedEnv(name), nil)
		case "shell":
			req.Reply(true, nil)
			start()
		case "exec":
			cmd, ok := parseString(req.Payload)
			req.Reply(ok, nil)
			if ok {
				sess.Cmd = cmd
				start()
			}
		default: // subsystem (sftp), x11, agent forwarding, ...
			req.Reply(false, nil)
		}
	}
}

func (s *Server) run(sc *ssh.ServerConn, ch ssh.Channel, sess *Session) {
	ext := sc.Permissions.Extensions
	var rec *recorder
	if ext["record"] == "1" {
		rec = newRecorder(sess.Window, sess.Term)
		sess.Stdout = io.MultiWriter(ch, rec)
		sess.Stderr = io.MultiWriter(ch.Stderr(), rec)
	}
	started := time.Now()
	code, err := s.Runner.Run(context.Background(), sess)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "whalescale: %v\r\n", err)
		code = 255
	}
	status := make([]byte, 4)
	binary.BigEndian.PutUint32(status, uint32(code))
	ch.SendRequest("exit-status", false, status)
	ch.Close()
	if rec != nil && s.Recorded != nil {
		s.Recorded(RecordingMeta{LocalUser: sess.User, SrcNode: ext["src-node"], SrcUser: ext["src-user"],
			Started: started, Ended: time.Now()}, rec.bytes())
	}
}

func parseString(b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(b)
	if uint32(len(b)-4) < n {
		return "", false
	}
	return string(b[4 : 4+n]), true
}

func parseEnv(b []byte) (string, string, bool) {
	name, ok := parseString(b)
	if !ok {
		return "", "", false
	}
	value, ok := parseString(b[4+len(name):])
	return name, value, ok
}

func parsePTYReq(b []byte) (string, Window, bool) {
	term, ok := parseString(b)
	if !ok || len(b) < 4+len(term)+8 {
		return "", Window{}, false
	}
	rest := b[4+len(term):]
	return term, Window{Cols: binary.BigEndian.Uint32(rest), Rows: binary.BigEndian.Uint32(rest[4:])}, true
}
