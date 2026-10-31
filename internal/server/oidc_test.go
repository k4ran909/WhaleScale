package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/store"
)

// fakeIdP is a minimal OpenID provider: it "logs in" whoever email is set
// to, enforces PKCE and signs real RS256 ID tokens.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu         sync.Mutex
	email      string
	challenges map[string]string // code -> PKCE challenge
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, challenges: map[string]string{}}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	iss := p.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", http.StatusBadRequest)
			return
		}
		code := "code-" + q.Get("state")
		p.mu.Lock()
		p.challenges[code] = q.Get("code_challenge")
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.Form.Get("code")
		p.mu.Lock()
		challenge, email := p.challenges[code], p.email
		delete(p.challenges, code)
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if challenge == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		idt, _ := jwt.Signed(signer).Claims(map[string]any{
			"iss": iss, "sub": "sub-" + email, "aud": "whalescale", "email": email, "email_verified": true,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	return p
}

func (p *fakeIdP) as(email string) {
	p.mu.Lock()
	p.email = email
	p.mu.Unlock()
}

func newOIDCServer(t *testing.T, idp *fakeIdP) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	srv, err := New(st, Config{
		PublicURL: "http://" + hs.Listener.Addr().String(),
		OIDC: &OIDCConfig{Issuer: idp.srv.URL, ClientID: "whalescale", ClientSecret: "s3cret",
			Admins: []string{"admin@example.com"}, AllowedDomains: []string{"corp.example"}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	hs.Start()
	t.Cleanup(hs.Close)
	return hs, st
}

func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func TestOIDCConsoleLogin(t *testing.T) {
	idp := newFakeIdP(t)
	hs, _ := newOIDCServer(t, idp)

	idp.as("admin@example.com")
	b := browser()
	resp, err := b.Get(hs.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		t.Fatalf("admin login ended at %s (status %d)", resp.Request.URL, resp.StatusCode)
	}
	u, _ := url.Parse(hs.URL)
	var session string
	for _, c := range b.Jar.Cookies(u) {
		if c.Name == "ws_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie after admin login")
	}
	code, out := adminCall(t, b, hs.URL, "WhoAmI", "{}", map[string]string{"Connect-Protocol-Version": "1"})
	if code != 200 || out["identity"] != "admin@example.com" || out["oidcEnabled"] != true {
		t.Fatalf("WhoAmI = %d %v", code, out)
	}

	// A valid login that isn't an admin gets no session.
	idp.as("someone@corp.example")
	nb := browser()
	resp, err = nb.Get(hs.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Not an admin") {
		t.Fatalf("non-admin login: %d %s", resp.StatusCode, body)
	}

	// Replaying a callback (state already used) is refused.
	resp, _ = nb.Get(hs.URL + "/auth/callback?state=bogus&code=x")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus state: %d", resp.StatusCode)
	}
}

func TestOIDCNodeLogin(t *testing.T) {
	idp := newFakeIdP(t)
	hs, st := newOIDCServer(t, idp)
	api := whalescalev1connect.NewControlServiceClient(http.DefaultClient, hs.URL)

	register := func() *v1.RegisterResponse {
		mk, _ := clientstate.NewMachineKey()
		pub, _ := (&clientstate.State{MachineKey: mk}).PublicKey()
		resp, err := api.Register(context.Background(), connect.NewRequest(&v1.RegisterRequest{MachineKey: pub, Hostname: "laptop"}))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Msg.AuthUrl == "" || resp.Msg.NodeToken != "" {
			t.Fatalf("expected a browser login, got %+v", resp.Msg)
		}
		return resp.Msg
	}

	// Allowed by domain: the device is added under an auto-created user.
	reg := register()
	idp.as("dev@corp.example")
	waitDone := make(chan *v1.WaitRegistrationResponse, 1)
	go func() {
		r, err := api.WaitRegistration(context.Background(), connect.NewRequest(&v1.WaitRegistrationRequest{RegistrationId: reg.RegistrationId}))
		if err != nil {
			t.Error(err)
			waitDone <- nil
			return
		}
		waitDone <- r.Msg
	}()
	resp, err := browser().Get(reg.AuthUrl)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Device added") {
		t.Fatalf("node login page: %d %s", resp.StatusCode, body)
	}
	select {
	case r := <-waitDone:
		if r == nil || r.NodeToken == "" || r.Node.User != "dev" {
			t.Fatalf("WaitRegistration = %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("WaitRegistration never returned")
	}

	// Not allowed: an outside email can't add devices.
	reg = register()
	idp.as("stranger@elsewhere.example")
	resp, _ = browser().Get(reg.AuthUrl)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider node login: %d", resp.StatusCode)
	}
	nodes, _ := st.ListNodes(context.Background(), "")
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}

	// Unknown registration ids are refused up front.
	resp, _ = browser().Get(hs.URL + "/auth/node?id=nope")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: %d", resp.StatusCode)
	}
}
