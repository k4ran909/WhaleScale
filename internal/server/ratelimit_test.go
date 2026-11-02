package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(3, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := l.wrap(ok)
	do := func(remote string, xff ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/auth/apikey", nil)
		r.RemoteAddr = remote
		for _, x := range xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for i := range 3 {
		if c := do("198.51.100.1:1000").Code; c != 200 {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	w := do("198.51.100.1:1001")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "21" {
		t.Fatalf("over the limit: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if do("198.51.100.2:1000").Code != 200 {
		t.Fatal("another client was limited")
	}
	// 3 a minute: one more every 20 seconds.
	now = now.Add(20 * time.Second)
	if do("198.51.100.1:1000").Code != 200 || do("198.51.100.1:1000").Code != http.StatusTooManyRequests {
		t.Fatal("bucket didn't refill at the configured rate")
	}

	// IPv6 clients share a /64; loopback isn't limited.
	for i := range 3 {
		do("[2001:db8:1:2::" + string(rune('a'+i)) + "]:1")
	}
	if do("[2001:db8:1:2::ff]:1").Code != http.StatusTooManyRequests {
		t.Fatal("rotating addresses in one /64 escaped the limit")
	}
	for range 10 {
		if do("127.0.0.1:5000").Code != 200 {
			t.Fatal("loopback was limited")
		}
	}

	// X-Forwarded-For counts only from trusted proxies, and only the hops
	// they added: what a client sends ahead of them is ignored.
	for range 3 {
		do("203.0.113.9:1")
	}
	if do("10.1.2.3:443", "198.51.100.77").Code != 200 {
		t.Fatal("client behind a trusted proxy was charged to someone else")
	}
	if do("10.1.2.3:443", "203.0.113.9").Code != http.StatusTooManyRequests {
		t.Fatal("trusted proxy's client escaped its limit")
	}
	if do("10.1.2.3:443", "198.51.100.200, 203.0.113.9", "10.9.9.9").Code != http.StatusTooManyRequests {
		t.Fatal("a spoofed hop ahead of the proxy chain was believed")
	}
	if do("203.0.113.9:2", "192.0.2.1").Code != http.StatusTooManyRequests {
		t.Fatal("an untrusted peer's X-Forwarded-For was believed")
	}
	if l.limited.Load() == 0 {
		t.Fatal("refusals not counted")
	}

	if newLimiter(-1, nil).wrap(ok) == nil {
		t.Fatal("disabled limiter")
	}
}

// Registration and API key login are limited per client end to end; other
// calls aren't.
func TestRateLimitedEndpoints(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	srv, err := New(st, Config{PublicURL: "http://" + hs.Listener.Addr().String(), RateLimit: 2,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	hs.Start()
	t.Cleanup(hs.Close)

	// The test client is on loopback, a trusted proxy: it names the client.
	from := func(ip string) connect.ClientOption {
		return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				req.Header().Set("X-Forwarded-For", ip)
				return next(ctx, req)
			}
		}))
	}
	c := whalescalev1connect.NewControlServiceClient(hs.Client(), hs.URL, from("192.0.2.10"))
	register := func() error {
		_, err := c.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: "wskey-nope", MachineKey: "x"}))
		return err
	}
	for range 2 {
		if err := register(); connect.CodeOf(err) == connect.CodeUnavailable {
			t.Fatalf("limited too early: %v", err)
		}
	}
	if err := register(); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("third registration: %v, want unavailable (429)", err)
	}
	// Authenticated calls don't spend the budget.
	for range 5 {
		_, err := c.GetNetworkMap(ctx, connect.NewRequest(&v1.GetNetworkMapRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("node call: %v", err)
		}
	}
	post := func(ip string) int {
		req, _ := http.NewRequest("POST", hs.URL+"/auth/apikey", strings.NewReader("key=wsapi-nope"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := hs.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if post("192.0.2.10") != http.StatusTooManyRequests {
		t.Fatal("API key login not limited with the same client's budget")
	}
	if c := post("192.0.2.11"); c == http.StatusTooManyRequests {
		t.Fatal("another client was limited")
	}
}
