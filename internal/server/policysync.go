package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/k4ran909/whalescale/internal/policy"
)

// Policy sync ("GitOps"): the policy lives in a Git repository and the
// server follows the raw file URL of a branch (GitHub, GitLab, Gitea and
// friends all serve one). It polls with ETags and can be poked by a
// signed push webhook. A version that doesn't parse or fails its own tests
// is refused, and the previous policy stays in force.

const maxPolicySize = 1 << 20

// PolicySyncConfig follows a policy at an HTTPS URL.
type PolicySyncConfig struct {
	URL string
	// Token, if set, is sent as "Authorization: Bearer" (private repos).
	Token    string
	Interval time.Duration
	// WebhookSecret enables POST /policy/sync for push webhooks.
	WebhookSecret string
}

// PolicySyncStatus is shown in the console and by doctor.
type PolicySyncStatus struct {
	URL      string // without query string, which may carry a token
	LastSync time.Time
	Revision string
	Error    string
}

type policySync struct {
	srv  *Server
	cfg  PolicySyncConfig
	hc   *http.Client
	poke chan struct{}

	mu     sync.Mutex
	etag   string
	status PolicySyncStatus
}

func newPolicySync(s *Server, cfg PolicySyncConfig) (*policySync, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLocalHost(u.Hostname()))) {
		return nil, fmt.Errorf("policy-url %q must be an https URL", cfg.URL)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	shown := *u
	shown.RawQuery, shown.User = "", nil
	return &policySync{srv: s, cfg: cfg, hc: &http.Client{Timeout: 20 * time.Second}, poke: make(chan struct{}, 1),
		status: PolicySyncStatus{URL: shown.String()}}, nil
}

func isLocalHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func (ps *policySync) Status() PolicySyncStatus {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.status
}

// fetch downloads the policy if it changed and applies it.
func (ps *policySync) fetch(ctx context.Context, startup bool) error {
	req, err := http.NewRequestWithContext(ctx, "GET", ps.cfg.URL, nil)
	if err != nil {
		return err
	}
	ps.mu.Lock()
	if ps.etag != "" {
		req.Header.Set("If-None-Match", ps.etag)
	}
	ps.mu.Unlock()
	if ps.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+ps.cfg.Token)
	}
	resp, err := ps.hc.Do(req)
	if err != nil {
		return ps.fail(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		ps.mu.Lock()
		ps.status.LastSync, ps.status.Error = time.Now(), ""
		ps.mu.Unlock()
		return nil
	case http.StatusOK:
	default:
		return ps.fail(fmt.Errorf("fetching policy: HTTP %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize+1))
	if err != nil {
		return ps.fail(err)
	}
	if len(body) > maxPolicySize {
		return ps.fail(errors.New("policy file is larger than 1 MB"))
	}
	p, err := policy.Parse(body)
	if err != nil {
		return ps.fail(fmt.Errorf("synced policy is invalid, keeping the previous one: %w", err))
	}
	if fails := ps.srv.warnFailingTests(p); len(fails) > 0 && !startup {
		return ps.fail(fmt.Errorf("synced policy fails %d of its tests, keeping the previous one", len(fails)))
	}
	sum := sha256.Sum256(body)
	rev := hex.EncodeToString(sum[:])[:12]
	ps.mu.Lock()
	changed := rev != ps.status.Revision
	ps.etag = resp.Header.Get("ETag")
	ps.status.LastSync, ps.status.Revision, ps.status.Error = time.Now(), rev, ""
	ps.mu.Unlock()
	if changed {
		ps.srv.control.SetPolicy(p, string(body), "url")
		ps.srv.control.Audit(ctx, "git", "policy synced", "url", ps.status.URL, "revision", rev, "acls", len(p.ACLs))
		// Kept so a restart while the repository is unreachable still
		// starts with the last good policy instead of a permissive one.
		ps.srv.control.Changed()
		if err := ps.srv.store.SetSetting(ctx, syncedPolicyKey, string(body)); err != nil {
			ps.srv.log.Warn("could not cache synced policy", "err", err)
		}
	}
	return nil
}

const syncedPolicyKey = "policy_synced_cache"

// start fetches the policy before the server serves anything. If the
// repository is unreachable it uses the cached last good copy; with no
// copy it refuses to start rather than run without the intended policy.
func (ps *policySync) start(ctx context.Context) error {
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := ps.fetch(fctx, true)
	if err == nil {
		return nil
	}
	text, ok, cerr := ps.srv.store.Setting(ctx, syncedPolicyKey)
	if cerr != nil || !ok {
		return fmt.Errorf("could not fetch the policy from %s and no earlier copy is cached: %w", ps.status.URL, err)
	}
	p, perr := policy.Parse([]byte(text))
	if perr != nil {
		return fmt.Errorf("could not fetch the policy, and the cached copy is invalid: %w", err)
	}
	ps.srv.control.SetPolicy(p, text, "url")
	ps.srv.log.Warn("policy repository unreachable; using the last synced copy until it is back", "err", err)
	return nil
}

func (ps *policySync) fail(err error) error {
	ps.mu.Lock()
	ps.status.Error = err.Error()
	ps.mu.Unlock()
	ps.srv.log.Error("policy sync", "err", err)
	return err
}

// run polls until ctx is done; a webhook pokes it to fetch right away.
func (ps *policySync) run(ctx context.Context) {
	t := time.NewTicker(ps.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// With several servers, only the leader polls the repository;
			// the others pick up what it stores.
			if !ps.srv.leader.Load() {
				continue
			}
		case <-ps.poke:
		}
		fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		ps.fetch(fctx, false)
		cancel()
	}
}

// webhook accepts push notifications: GitHub/Gitea sign the body with
// HMAC-SHA256 (X-Hub-Signature-256 / X-Gitea-Signature), GitLab sends the
// secret as X-Gitlab-Token.
func (ps *policySync) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !ps.verify(r.Header, body) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	select {
	case ps.poke <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusAccepted)
}

func (ps *policySync) verify(h http.Header, body []byte) bool {
	secret := []byte(ps.cfg.WebhookSecret)
	if tok := h.Get("X-Gitlab-Token"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), secret) == 1
	}
	sig := strings.TrimPrefix(h.Get("X-Hub-Signature-256"), "sha256=")
	if sig == "" {
		sig = h.Get("X-Gitea-Signature")
	}
	got, err := hex.DecodeString(sig)
	if err != nil || len(got) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}
