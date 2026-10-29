// Package localapi is the channel between the ws CLI and a running wsd:
// HTTP over a Unix socket (supported on Windows 10+ as well).
package localapi

import (
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
	"time"

	"github.com/k4ran909/whalescale/internal/engine"
	"github.com/k4ran909/whalescale/internal/meshconn"
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

func Handler(e *engine.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, e.Status())
	})
	mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		res, err := e.Ping(ctx, r.URL.Query().Get("peer"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("GET /v1/netcheck", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, e.Netcheck(r.Context()))
	})
	mux.HandleFunc("GET /v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		addrs, ok := e.Lookup(r.URL.Query().Get("name"))
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, addrs)
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

func (c *Client) Netcheck() (meshconn.NetcheckReport, error) {
	var r meshconn.NetcheckReport
	return r, c.get("/v1/netcheck", nil, &r)
}
