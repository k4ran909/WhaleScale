package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/k4ran909/whalescale/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	console := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>console</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	srv, err := New(st, Config{PublicURL: "http://" + hs.Listener.Addr().String(), Console: console,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler() // panics on conflicting mux patterns
	hs.Start()
	t.Cleanup(hs.Close)
	return hs, st
}

func TestConsoleRoutes(t *testing.T) {
	hs, _ := newTestServer(t)
	for path, want := range map[string]string{"/": "console", "/machines": "console", "/assets/app.js": "console.log"} {
		resp, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, body)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: missing CSP", path)
		}
	}
	resp, _ := http.Post(hs.URL+"/", "text/plain", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST / = %d", resp.StatusCode)
	}
}

func adminCall(t *testing.T, c *http.Client, url, method, body string, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/whalescale.v1.AdminService/"+method, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAdminAuth(t *testing.T) {
	hs, st := newTestServer(t)
	_, apiKey, _ := st.CreateAPIKey(context.Background(), time.Hour)
	c := hs.Client()

	if code, _ := adminCall(t, c, hs.URL, "ListUsers", "{}", nil); code != 401 {
		t.Fatalf("no credentials: %d", code)
	}
	code, out := adminCall(t, c, hs.URL, "CreateUser", `{"name":"karan"}`, map[string]string{"Authorization": "Bearer " + apiKey})
	if code != 200 {
		t.Fatalf("api key: %d %v", code, out)
	}

	// Trade the API key for a session cookie, as the console does.
	resp, err := c.Post(hs.URL+"/auth/apikey", "application/json", strings.NewReader(`{"key":"`+apiKey+`"}`))
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("api key login: %v %v", resp.StatusCode, err)
	}
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "ws_session" {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatalf("session cookie = %+v", cookie)
	}
	ck := map[string]string{"Cookie": "ws_session=" + cookie.Value}

	// Cookie alone is refused (CSRF guard); with the Connect header it works.
	if code, _ := adminCall(t, c, hs.URL, "ListUsers", "{}", ck); code != 401 {
		t.Fatalf("cookie without Connect header: %d", code)
	}
	ck["Connect-Protocol-Version"] = "1"
	code, out = adminCall(t, c, hs.URL, "ListUsers", "{}", ck)
	if code != 200 || len(out["users"].([]any)) != 1 {
		t.Fatalf("cookie + header: %d %v", code, out)
	}

	// Policy round trip: invalid is rejected, valid is stored.
	code, _ = adminCall(t, c, hs.URL, "SetPolicy", `{"policy":"{\"acls\":[{\"action\":\"allow\"}]}"}`, ck)
	if code != 400 {
		t.Fatalf("invalid policy accepted: %d", code)
	}
	code, out = adminCall(t, c, hs.URL, "SetPolicy", `{"policy":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"karan\"],\"dst\":[\"*:22\"]}]}"}`, ck)
	if code != 200 {
		t.Fatalf("valid policy: %d %v", code, out)
	}
	code, out = adminCall(t, c, hs.URL, "GetPolicy", "{}", ck)
	if code != 200 || out["source"] != "database" {
		t.Fatalf("GetPolicy = %v", out)
	}
}

func TestPolicyTestsAndExplain(t *testing.T) {
	hs, st := newTestServer(t)
	ctx := context.Background()
	_, apiKey, _ := st.CreateAPIKey(ctx, time.Hour)
	st.CreateUser(ctx, "karan")
	st.CreateUser(ctx, "guest")
	auth := map[string]string{"Authorization": "Bearer " + apiKey}
	c := hs.Client()

	// The policy says guest may reach karan's machines on 22, and its own
	// test claims port 443 too: saving must be refused.
	failing := `{"policy":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"guest\"],\"dst\":[\"karan:22\"]}],\"tests\":[{\"src\":\"guest\",\"accept\":[\"karan:443\"]}]}"}`
	code, out := adminCall(t, c, hs.URL, "SetPolicy", failing, auth)
	if code != 400 || !strings.Contains(fmt.Sprint(out["message"]), "should reach karan:443") {
		t.Fatalf("policy failing its tests was saved: %d %v", code, out)
	}
	passing := strings.Replace(failing, `karan:443\"]}]`, `karan:22\"],\"deny\":[\"karan:443\"]}]`, 1)
	if code, out := adminCall(t, c, hs.URL, "SetPolicy", passing, auth); code != 200 {
		t.Fatalf("passing policy refused: %d %v", code, out)
	}

	code, out = adminCall(t, c, hs.URL, "ExplainAccess", `{"src":"guest","dst":"karan:443"}`, auth)
	if code != 200 || out["allowed"] == true || !strings.Contains(fmt.Sprint(out["reasons"]), "only ports 22") {
		t.Fatalf("explain guest→karan:443 = %d %v", code, out)
	}
	// Against a draft that opens everything.
	code, out = adminCall(t, c, hs.URL, "ExplainAccess",
		`{"src":"guest","dst":"karan:443","policy":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}"}`, auth)
	if code != 200 || out["allowed"] != true {
		t.Fatalf("explain with draft = %d %v", code, out)
	}
	if code, _ := adminCall(t, c, hs.URL, "ExplainAccess", `{"src":"group:x","dst":"karan:1"}`, auth); code != 400 {
		t.Fatalf("group as source should be a bad request: %d", code)
	}
}
