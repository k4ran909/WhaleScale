package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/k4ran909/whalescale/internal/store/storetest"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/store"
)

// fakeRepo serves a policy file like a Git host's raw URL, with ETags.
type fakeRepo struct {
	mu       sync.Mutex
	body     string
	requests int
	down     bool
}

func (f *fakeRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != "Bearer repo-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sum := sha256.Sum256([]byte(f.body))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	io.WriteString(w, f.body)
}

func (f *fakeRepo) set(body string) {
	f.mu.Lock()
	f.body = body
	f.mu.Unlock()
}

const repoPolicyA = `{"acls":[{"action":"accept","src":["*"],"dst":["*:22"]}]}`
const repoPolicyB = `{"acls":[{"action":"accept","src":["*"],"dst":["*:443"]}]}`

func newSyncServer(t *testing.T, st *store.Store, repoURL string) (*Server, error) {
	t.Helper()
	return New(st, Config{PublicURL: "http://127.0.0.1:1",
		PolicySync: &PolicySyncConfig{URL: repoURL, Token: "repo-token", Interval: time.Hour, WebhookSecret: "hook-secret"},
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func TestPolicySync(t *testing.T) {
	repo := &fakeRepo{body: repoPolicyA}
	rs := httptest.NewServer(repo)
	defer rs.Close()
	st, err := store.Open(context.Background(), storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv, err := newSyncServer(t, st, rs.URL+"/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	text, source := srv.control.Policy()
	if source != "url" || text != repoPolicyA {
		t.Fatalf("initial sync: source=%s text=%s", source, text)
	}
	ctx := context.Background()

	// Unchanged upstream: a 304, nothing applied.
	if err := srv.psync.fetch(ctx, false); err != nil {
		t.Fatal(err)
	}
	// A new commit is picked up.
	repo.set(repoPolicyB)
	if err := srv.psync.fetch(ctx, false); err != nil {
		t.Fatal(err)
	}
	if text, _ := srv.control.Policy(); text != repoPolicyB {
		t.Fatalf("change not applied: %s", text)
	}
	// A broken commit is refused; the previous policy stays.
	repo.set(`{"acls": [`)
	if err := srv.psync.fetch(ctx, false); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if text, _ := srv.control.Policy(); text != repoPolicyB {
		t.Fatal("invalid policy replaced the good one")
	}
	if st := srv.psync.Status(); st.Error == "" || strings.Contains(st.URL, "token") {
		t.Fatalf("status = %+v", st)
	}
	// A policy failing its own tests is refused too.
	repo.set(`{"acls":[], "tests":[{"src":"bob","accept":["karan:22"]}]}`)
	if err := srv.psync.fetch(ctx, false); err == nil {
		t.Fatal("policy failing its tests accepted")
	}

	// The console can't edit a synced policy.
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	_, apiKey, _ := st.CreateAPIKey(ctx, time.Hour)
	code, _ := adminCall(t, hs.Client(), hs.URL, "SetPolicy", `{"policy":"{\"acls\":[]}"}`, map[string]string{"Authorization": "Bearer " + apiKey})
	if code != http.StatusBadRequest && code != http.StatusPreconditionFailed {
		t.Fatalf("editing a synced policy: %d", code)
	}

	// Webhooks: a bad signature is refused, a GitHub-style one accepted.
	post := func(hdr map[string]string, body string) int {
		req, _ := http.NewRequest("POST", hs.URL+"/policy/sync", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := hs.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	body := `{"ref":"refs/heads/main"}`
	mac := hmac.New(sha256.New, []byte("hook-secret"))
	mac.Write([]byte(body))
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if code := post(map[string]string{"X-Hub-Signature-256": "sha256=00"}, body); code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", code)
	}
	if code := post(map[string]string{"X-Hub-Signature-256": good}, body); code != http.StatusAccepted {
		t.Fatalf("good signature: %d", code)
	}
	if code := post(map[string]string{"X-Gitlab-Token": "hook-secret"}, body); code != http.StatusAccepted {
		t.Fatalf("gitlab token: %d", code)
	}
}

func TestPolicySyncStartup(t *testing.T) {
	repo := &fakeRepo{body: repoPolicyA}
	rs := httptest.NewServer(repo)
	defer rs.Close()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), storetest.DSN(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// No cached copy and the repository is down: refuse to start.
	repo.down = true
	if _, err := newSyncServer(t, st, rs.URL+"/p.json"); err == nil {
		t.Fatal("started without any policy")
	}
	// One good sync caches the policy; a later restart during an outage uses it.
	repo.down = false
	if _, err := newSyncServer(t, st, rs.URL+"/p.json"); err != nil {
		t.Fatal(err)
	}
	repo.down = true
	srv, err := newSyncServer(t, st, rs.URL+"/p.json")
	if err != nil {
		t.Fatalf("restart during outage: %v", err)
	}
	if text, source := srv.control.Policy(); source != "url" || text != repoPolicyA {
		t.Fatalf("cached policy not used: %s %s", source, text)
	}
}
