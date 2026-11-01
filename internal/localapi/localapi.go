// Package localapi is the channel between the ws CLI and a running wsd:
// HTTP over a Unix socket (supported on Windows 10+ as well).
package localapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/engine"
)

// maxSocketPath stays under the ~108-byte sun_path limit on every OS.
const maxSocketPath = 100

// SocketPath is $WHALESCALE_SOCKET, else wsd.sock next to the state file.
// Paths too long for a Unix socket map to a short, stable name in the temp
// directory, so ws and wsd still agree on it.
func SocketPath(statePath string) string {
	if p := os.Getenv("WHALESCALE_SOCKET"); p != "" {
		return p
	}
	p := filepath.Join(filepath.Dir(statePath), "wsd.sock")
	if len(p) <= maxSocketPath {
		return p
	}
	abs, _ := filepath.Abs(statePath)
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(os.TempDir(), "whalescale-"+hex.EncodeToString(sum[:6])+".sock")
}

// Listen removes a stale socket and listens with owner-only access.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// On Windows the socket's directory needs an explicit ACL; file modes
	// don't apply there.
	if err := clientstate.Protect(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("another wsd is already running (socket %s)", path)
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	os.Chmod(path, 0o600)
	return ln, nil
}

// Backend is what the local API controls (the daemon).
type Backend interface {
	// Engine is nil while the tunnel is down.
	Engine() *engine.Engine
	Prefs() clientstate.Prefs
	Up(clientstate.Prefs) error
	Down() error
	// Switch makes another profile (network) active.
	Switch(profile string) error
}

func Handler(b Backend) http.Handler {
	mux := http.NewServeMux()
	// withEngine answers 409 while the tunnel is down.
	withEngine := func(f func(w http.ResponseWriter, r *http.Request, e *engine.Engine)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			e := b.Engine()
			if e == nil {
				http.Error(w, "the tunnel is down; run 'ws up'", http.StatusConflict)
				return
			}
			f(w, r, e)
		}
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		e := b.Engine()
		if e == nil {
			writeJSON(w, engine.Status{State: "stopped"})
			return
		}
		writeJSON(w, e.Status())
	})
	mux.HandleFunc("GET /v1/ping", withEngine(func(w http.ResponseWriter, r *http.Request, e *engine.Engine) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		res, err := e.Ping(ctx, r.URL.Query().Get("peer"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, res)
	}))
	mux.HandleFunc("GET /v1/netcheck", withEngine(func(w http.ResponseWriter, r *http.Request, e *engine.Engine) {
		writeJSON(w, e.Netcheck(r.Context()))
	}))
	mux.HandleFunc("GET /v1/lookup", withEngine(func(w http.ResponseWriter, r *http.Request, e *engine.Engine) {
		addrs, ok := e.Lookup(r.URL.Query().Get("name"))
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, addrs)
	}))
	mux.HandleFunc("GET /v1/prefs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, b.Prefs())
	})
	mux.HandleFunc("POST /v1/up", func(w http.ResponseWriter, r *http.Request) {
		var p clientstate.Prefs
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
			http.Error(w, "bad prefs: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := b.Up(p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, b.Prefs())
	})
	mux.HandleFunc("POST /v1/switch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Profile string `json:"profile"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := b.Switch(req.Profile); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/down", func(w http.ResponseWriter, r *http.Request) {
		if err := b.Down(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Client talks to wsd.
type Client struct {
	hc *http.Client
}

// ErrNotRunning means nothing is listening on the socket.
var ErrNotRunning = errors.New("wsd is not running")

func NewClient(socket string) *Client {
	return &Client{hc: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, "unix", socket)
				if err != nil {
					return nil, fmt.Errorf("%w (%v)", ErrNotRunning, err)
				}
				return c, nil
			},
		},
	}}
}

func (c *Client) get(path string, q url.Values, out any) error {
	u := "http://wsd" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	resp, err := c.hc.Get(u)
	if err != nil {
		if errors.Is(err, ErrNotRunning) {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.New(string(b))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Status() (engine.Status, error) {
	var s engine.Status
	return s, c.get("/v1/status", nil, &s)
}

func (c *Client) Ping(peer string) (engine.PingResult, error) {
	var r engine.PingResult
	return r, c.get("/v1/ping", url.Values{"peer": {peer}}, &r)
}

func (c *Client) Netcheck() (engine.NetcheckReport, error) {
	var r engine.NetcheckReport
	return r, c.get("/v1/netcheck", nil, &r)
}

func (c *Client) Prefs() (clientstate.Prefs, error) {
	var p clientstate.Prefs
	return p, c.get("/v1/prefs", nil, &p)
}

func (c *Client) post(path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	resp, err := c.hc.Post("http://wsd"+path, "application/json", r)
	if err != nil {
		if errors.Is(err, ErrNotRunning) {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.New(strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Up saves prefs and (re)starts the tunnel.
func (c *Client) Up(p clientstate.Prefs) (clientstate.Prefs, error) {
	var out clientstate.Prefs
	return out, c.post("/v1/up", p, &out)
}

// Down stops the tunnel; wsd keeps running.
func (c *Client) Down() error { return c.post("/v1/down", nil, nil) }

// Switch makes another profile active.
func (c *Client) Switch(profile string) error {
	return c.post("/v1/switch", map[string]string{"profile": profile}, nil)
}
