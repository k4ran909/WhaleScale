//go:build linux || darwin

package sshserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

// OSRunner starts the user's login shell (or runs a command through it)
// as that user, with a PTY when the client asked for one.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, s *Session) (int, error) {
	u, err := user.Lookup(s.User)
	if err != nil {
		return 0, fmt.Errorf("no local user %q", s.User)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	var attrs syscall.SysProcAttr
	if os.Geteuid() == 0 {
		var groups []uint32
		if ids, err := u.GroupIds(); err == nil {
			for _, g := range ids {
				if n, err := strconv.Atoi(g); err == nil {
					groups = append(groups, uint32(n))
				}
			}
		}
		attrs.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
	} else if uid != os.Geteuid() {
		return 0, fmt.Errorf("wsd is not running as root, so it can only log you in as %q", currentUser())
	}

	shell := loginShell(u)
	var cmd *exec.Cmd
	if s.Cmd == "" {
		cmd = exec.CommandContext(ctx, shell, "-l")
	} else {
		cmd = exec.CommandContext(ctx, shell, "-c", s.Cmd)
	}
	cmd.Dir = u.HomeDir
	cmd.Env = append([]string{
		"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}, s.Env...)
	if s.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+s.Term)
	}

	if s.Term == "" {
		attrs.Setsid = true
		cmd.SysProcAttr = &attrs
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Stdin, s.Stdout, s.Stderr
		return exitCode(cmd.Run())
	}
	attrs.Setsid, attrs.Setctty = true, true
	f, err := pty.StartWithAttrs(cmd, &pty.Winsize{Cols: uint16(s.Window.Cols), Rows: uint16(s.Window.Rows)}, &attrs)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	go func() {
		for w := range s.Resize {
			pty.Setsize(f, &pty.Winsize{Cols: uint16(w.Cols), Rows: uint16(w.Rows)})
		}
	}()
	go io.Copy(f, s.Stdin)
	io.Copy(s.Stdout, f) // ends when the shell exits and the PTY closes
	return exitCode(cmd.Wait())
}

func exitCode(err error) (int, error) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

// loginShell reads the user's shell from the user database.
func loginShell(u *user.User) string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("dscl", ".", "-read", "/Users/"+u.Username, "UserShell").Output()
		if err == nil {
			if f := strings.Fields(string(out)); len(f) == 2 {
				return f[1]
			}
		}
		return "/bin/zsh"
	}
	if f, err := os.Open("/etc/passwd"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Split(sc.Text(), ":")
			if len(fields) >= 7 && fields[0] == u.Username && fields[6] != "" {
				return fields[6]
			}
		}
	}
	if out, err := exec.Command("getent", "passwd", u.Username).Output(); err == nil {
		if fields := strings.Split(strings.TrimSpace(string(out)), ":"); len(fields) >= 7 && fields[6] != "" {
			return fields[6]
		}
	}
	return "/bin/sh"
}
