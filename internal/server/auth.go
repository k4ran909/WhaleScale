package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/k4ran909/whalescale/internal/control"
)

const sessionTTL = 12 * time.Hour

// OIDCConfig enables browser login with any OpenID Connect provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// Admins may sign in to the web console (matched by email).
	Admins []string
	// AllowedUsers and AllowedDomains may register nodes from a browser.
	// Admins always may. With both empty, only admins can.
	AllowedUsers   []string
	AllowedDomains []string
}

type authState struct {
	kind     string // "console" or "node"
	regID    string
	verifier string
	created  time.Time
}

type auth struct {
	srv      *Server
	cfg      *OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	secure   bool

	mu     sync.Mutex
	states map[string]authState
}

func newAuth(ctx context.Context, s *Server, cfg *OIDCConfig) (*auth, error) {
	a := &auth{srv: s, cfg: cfg, states: map[string]authState{}, secure: strings.HasPrefix(s.cfg.PublicURL, "https://")}
	if cfg == nil {
		return a, nil
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(pctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", cfg.Issuer, err)
	}
	a.provider = p
	a.verifier = p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	a.oauth = oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	return a, nil
}

func (a *auth) enabled() bool { return a.provider != nil }

func (a *auth) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/node", a.nodeLogin)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("POST /auth/apikey", a.apiKeyLogin)
	mux.HandleFunc("POST /auth/logout", a.logout)
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *auth) redirect(w http.ResponseWriter, r *http.Request, st authState) {
	if !a.enabled() {
		a.page(w, http.StatusNotFound, "Browser login is not configured", "Start the server with --oidc-issuer to enable it.")
		return
	}
	state := randToken()
	st.verifier = oauth2.GenerateVerifier()
	st.created = time.Now()
	a.mu.Lock()
	for k, v := range a.states {
		if time.Since(v.created) > 10*time.Minute {
			delete(a.states, k)
		}
	}
	a.states[state] = st
	a.mu.Unlock()
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(st.verifier)), http.StatusFound)
}

func (a *auth) login(w http.ResponseWriter, r *http.Request) {
	a.redirect(w, r, authState{kind: "console"})
}

func (a *auth) nodeLogin(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !a.srv.control.PendingExists(id) {
		a.page(w, http.StatusNotFound, "Login link expired", "Run 'ws login' again to get a fresh link.")
		return
	}
	a.redirect(w, r, authState{kind: "node", regID: id})
}

func (a *auth) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	st, ok := a.states[q.Get("state")]
	delete(a.states, q.Get("state"))
	a.mu.Unlock()
	if !ok || time.Since(st.created) > 10*time.Minute {
		a.page(w, http.StatusBadRequest, "Login expired", "Please start again.")
		return
	}
	if e := q.Get("error"); e != "" {
		a.page(w, http.StatusUnauthorized, "Login failed", "The identity provider said: "+e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.verifier))
	if err != nil {
		a.srv.log.Warn("oidc code exchange", "err", err)
		a.page(w, http.StatusUnauthorized, "Login failed", "Could not complete the login with the identity provider.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		a.page(w, http.StatusUnauthorized, "Login failed", "The identity token was not valid.")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil || claims.Email == "" {
		a.page(w, http.StatusForbidden, "No email address", "Your identity provider did not share a verified email address.")
		return
	}
	if claims.Verified != nil && !*claims.Verified {
		a.page(w, http.StatusForbidden, "Email not verified", "Verify your email address with your identity provider first.")
		return
	}
	email := strings.ToLower(claims.Email)

	switch st.kind {
	case "console":
		if !a.isAdmin(email) {
			a.srv.log.Warn("console login refused", "email", email)
			a.page(w, http.StatusForbidden, "Not an admin", email+" is not allowed to use the console.")
			return
		}
		if err := a.startSession(w, r.Context(), email); err != nil {
			a.page(w, http.StatusInternalServerError, "Login failed", "Could not create a session.")
			return
		}
		a.srv.log.Info("console login", "email", email)
		http.Redirect(w, r, "/", http.StatusFound)
	case "node":
		if !a.mayRegister(email) {
			a.srv.log.Warn("node login refused", "email", email)
			a.page(w, http.StatusForbidden, "Not allowed", email+" may not add devices to this network.")
			return
		}
		u, err := a.srv.store.UserForOIDC(r.Context(), idt.Subject, email)
		if err != nil {
			a.page(w, http.StatusInternalServerError, "Login failed", "Could not create your user.")
			return
		}
		n, err := a.srv.control.CompleteRegistration(r.Context(), st.regID, u.ID)
		if err != nil {
			a.page(w, http.StatusBadRequest, "Could not add device", err.Error())
			return
		}
		a.page(w, http.StatusOK, "Device added",
			fmt.Sprintf("%s is now on the network as %s (%s). You can close this tab.", n.Name, u.Name, n.IPv4))
	}
}

func (a *auth) isAdmin(email string) bool {
	return a.cfg != nil && slices.ContainsFunc(a.cfg.Admins, func(s string) bool { return strings.EqualFold(s, email) })
}

func (a *auth) mayRegister(email string) bool {
	if a.isAdmin(email) {
		return true
	}
	if slices.ContainsFunc(a.cfg.AllowedUsers, func(s string) bool { return strings.EqualFold(s, email) }) {
		return true
	}
	_, domain, _ := strings.Cut(email, "@")
	return slices.ContainsFunc(a.cfg.AllowedDomains, func(s string) bool { return strings.EqualFold(s, domain) })
}

func (a *auth) startSession(w http.ResponseWriter, ctx context.Context, identity string) error {
	tok, err := a.srv.store.CreateSession(ctx, identity, sessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: control.SessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()),
	})
	return nil
}

// apiKeyLogin trades an API key for a console session, so the console
// works without OIDC.
func (a *auth) apiKeyLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	prefix, err := a.srv.store.CheckAPIKey(r.Context(), strings.TrimSpace(body.Key))
	if err != nil {
		a.srv.log.Warn("console api-key login refused", "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired API key", http.StatusUnauthorized)
		return
	}
	if err := a.startSession(w, r.Context(), "api-key:"+prefix); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.log.Info("console login", "api_key", prefix)
	w.WriteHeader(http.StatusNoContent)
}

func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(control.SessionCookie); err == nil {
		a.srv.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: control.SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · Whalescale</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f4f6f8;color:#14202b}
main{max-width:30rem;padding:2rem;background:#fff;border-radius:12px;box-shadow:0 1px 3px #0002;margin:1rem}
h1{font-size:1.3rem;margin:0 0 .5rem}
@media (prefers-color-scheme:dark){body{background:#0e1419;color:#e3e9ee}main{background:#18212a}}
</style>
<main><h1>{{.Title}}</h1><p>{{.Body}}</p></main>`))

func (a *auth) page(w http.ResponseWriter, code int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pageTmpl.Execute(w, struct{ Title, Body string }{title, body})
}
