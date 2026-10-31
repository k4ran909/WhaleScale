package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/localapi"
)

func TestParseRoutes(t *testing.T) {
	if _, err := ParseRoutes([]string{"192.168.1.0/24", "0.0.0.0/0", "::/0", "fd00:1::/64"}); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"192.168.1.5":    "prefix length",
		"192.168.1.5/24": "did you mean 192.168.1.0/24",
		"lan":            "bad route",
	} {
		if _, err := ParseRoutes([]string{in}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", in, err, want)
		}
	}
}

// TestLocalAPIWhenLoggedOut covers the daemon before 'ws login': status
// reports stopped, and up explains what to do.
func TestLocalAPIWhenLoggedOut(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	t.Setenv("WHALESCALE_SOCKET", filepath.Join(os.TempDir(), "ws-test-"+filepath.Base(dir)+".sock"))
	d := New(Options{StatePath: state, Userspace: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()

	lc := localapi.NewClient(localapi.SocketPath(state))
	var err error
	for i := 0; i < 50; i++ {
		if _, err = lc.Prefs(); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("local API never came up: %v", err)
	}
	st, err := lc.Status()
	if err != nil || st.State != "stopped" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if _, err := lc.Up(clientstate.Prefs{}); err == nil || !strings.Contains(err.Error(), "ws login") {
		t.Fatalf("up before login: %v", err)
	}
	if _, err := lc.Up(clientstate.Prefs{AdvertiseRoutes: []string{"10.0.0.1/8"}}); err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("bad route not rejected: %v", err)
	}
}
