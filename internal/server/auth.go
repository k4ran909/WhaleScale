package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/k4ran909/whalescale/internal/passwd"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/totp"
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

// routes adds the login endpoints; limit wraps those anyone may call.
func (a *auth) routes(mux *http.ServeMux, limit func(http.Handler) http.Handler) {
	mux.Handle("GET /auth/status", limit(http.HandlerFunc(a.status)))
	mux.Handle("POST /auth/setup", limit(http.HandlerFunc(a.setup)))
	mux.Handle("POST /auth/password", limit(http.HandlerFunc(a.passwordLogin)))
	mux.Handle("POST /auth/password/change", limit(http.HandlerFunc(a.changePassword)))
	mux.Handle("GET /auth/2fa", limit(http.HandlerFunc(a.twoFactorStatus)))
	mux.Handle("POST /auth/2fa/setup", limit(http.HandlerFunc(a.twoFactorSetup)))
	mux.Handle("POST /auth/2fa/enable", limit(http.HandlerFunc(a.twoFactorEnable)))
	mux.Handle("POST /auth/2fa/disable", limit(http.HandlerFunc(a.twoFactorDisable)))
	mux.Handle("GET /auth/login", limit(http.HandlerFunc(a.login)))
	mux.Handle("GET /auth/node", limit(http.HandlerFunc(a.nodeLogin)))
	mux.Handle("GET /auth/callback", limit(http.HandlerFunc(a.callback)))
	mux.Handle("POST /auth/apikey", limit(http.HandlerFunc(a.apiKeyLogin)))
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
		a.srv.control.Audit(r.Context(), "oidc:"+email, "console sign-in")
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
	var body struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &body) {
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
	a.srv.control.Audit(r.Context(), "api-key:"+prefix, "console sign-in")
	w.WriteHeader(http.StatusNoContent)
}

// readJSON decodes a small JSON body into v, answering the error itself.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected JSON", http.StatusUnsupportedMediaType)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

// status tells the console how to sign in: whether the first admin account
// still has to be created, and whether OIDC is on.
func (a *auth) status(w http.ResponseWriter, r *http.Request) {
	setup, err := a.needsSetup(r.Context())
	if err != nil {
		a.srv.log.Error("auth status", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if setup {
		a.srv.announceSetup(r.Context()) // the setup page is open: put the code at the end of the log
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"setup": setup, "oidc": a.enabled(), "publicUrl": a.srv.cfg.PublicURL})
}

// needsSetup: no admin account yet, and no identity provider to sign in
// with instead.
func (a *auth) needsSetup(ctx context.Context) (bool, error) {
	if a.enabled() {
		return false, nil
	}
	n, err := a.srv.store.AdminCount(ctx)
	return n == 0, err
}

// setup creates the first admin account. It needs the setup code from the
// server's log, so whoever finds a fresh server first can't claim it, and
// closes for good once the account exists.
func (a *auth) setup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code     string `json:"code"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	if a.enabled() {
		http.Error(w, "this server signs admins in with its identity provider", http.StatusConflict)
		return
	}
	code, err := a.srv.store.SetupCode(ctx)
	if err != nil {
		a.srv.log.Error("setup code", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if code == "" {
		http.Error(w, "this server already has an admin account: sign in instead", http.StatusConflict)
		return
	}
	if subtle.ConstantTimeCompare([]byte(store.NormalizeCode(body.Code)), []byte(store.NormalizeCode(code))) != 1 {
		a.srv.log.Warn("console setup refused: wrong setup code", "remote", r.RemoteAddr)
		http.Error(w, "wrong setup code: copy it from the server's log (the line with setup_code)", http.StatusForbidden)
		return
	}
	name := strings.ToLower(strings.TrimSpace(body.Name))
	if !store.ValidName(name) {
		http.Error(w, "name: use lowercase letters, digits and '-', e.g. karan", http.StatusBadRequest)
		return
	}
	if err := passwd.Check(body.Password); err != nil {
		http.Error(w, "password: "+err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := passwd.Hash(body.Password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := a.srv.store.CreateFirstAdmin(ctx, name, hash); err != nil {
		if errors.Is(err, store.ErrSetupDone) {
			http.Error(w, "this server already has an admin account: sign in instead", http.StatusConflict)
			return
		}
		a.srv.log.Error("create first admin", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.store.ClearSetupCode(ctx)
	// Devices need an owner: the admin gets a user of the same name.
	if _, err := a.srv.store.CreateUser(ctx, name); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		a.srv.log.Warn("create the admin's user", "user", name, "err", err)
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "admin account created", "how", "first-run setup")
	a.srv.log.Info("first admin account created; setup is closed", "admin", name)
	if err := a.startSession(w, ctx, store.AdminIdentity(name)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// twoFactorHeader on a 401 from /auth/password tells the console that the
// password was right and the account needs a code from its authenticator
// app too. It's only sent after the password checks out, so it says
// nothing about accounts to someone guessing.
const twoFactorHeader = "X-Whalescale-Two-Factor"

// clock is the time two-factor codes are checked against (tests move it).
var clock = time.Now

// passwordLogin signs a console account in with its password, and its
// TOTP code when two-factor sign-in is on.
func (a *auth) passwordLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name := strings.ToLower(strings.TrimSpace(body.Name))
	hash, err := a.srv.store.AdminPasswordHash(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		err = passwd.VerifyNone(body.Password) // as slow as a real check
	case err == nil:
		err = passwd.Verify(body.Password, hash)
	}
	if err != nil {
		if !errors.Is(err, passwd.ErrMismatch) {
			a.srv.log.Error("password sign-in", "admin", name, "err", err)
		}
		a.srv.log.Warn("console sign-in refused", "admin", name, "remote", r.RemoteAddr)
		http.Error(w, "wrong name or password", http.StatusUnauthorized)
		return
	}
	secret, _, err := a.srv.store.AdminTOTP(ctx, name)
	if err != nil {
		a.srv.log.Error("password sign-in", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if secret != "" {
		if strings.TrimSpace(body.Code) == "" {
			w.Header().Set(twoFactorHeader, "required")
			http.Error(w, "enter the code from your authenticator app", http.StatusUnauthorized)
			return
		}
		if !a.useCode(ctx, name, secret, body.Code) {
			a.srv.log.Warn("console sign-in refused: wrong two-factor code", "admin", name, "remote", r.RemoteAddr)
			w.Header().Set(twoFactorHeader, "required")
			http.Error(w, "that code is wrong or was already used: wait for the next one", http.StatusUnauthorized)
			return
		}
	}
	if err := a.startSession(w, ctx, store.AdminIdentity(name)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "console sign-in")
	w.WriteHeader(http.StatusNoContent)
}

// changePassword sets a new password for the signed-in console account. It
// signs the account out everywhere else.
func (a *auth) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "only password accounts have a password to change")
	if !ok || !a.checkPassword(w, ctx, name, body.Current) {
		return
	}
	if err := passwd.Check(body.New); err != nil {
		http.Error(w, "new password: "+err.Error(), http.StatusBadRequest)
		return
	}
	newHash, err := passwd.Hash(body.New)
	if err == nil {
		err = a.srv.store.SetAdminPassword(ctx, name, newHash)
	}
	if err == nil {
		err = a.startSession(w, ctx, store.AdminIdentity(name)) // this browser stays signed in
	}
	if err != nil {
		a.srv.log.Error("change password", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "password changed")
	w.WriteHeader(http.StatusNoContent)
}

// account returns the password account signed in on r's session, or
// answers the request itself and returns false. notAccount is the error
// for sessions opened some other way (OIDC, an API key).
func (a *auth) account(w http.ResponseWriter, r *http.Request, notAccount string) (string, bool) {
	c, err := r.Cookie(control.SessionCookie)
	if err != nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return "", false
	}
	who, err := a.srv.store.SessionIdentity(r.Context(), c.Value)
	name, isAccount := strings.CutPrefix(who, "admin:")
	switch {
	case err != nil:
		http.Error(w, "session expired; sign in again", http.StatusUnauthorized)
		return "", false
	case !isAccount:
		http.Error(w, notAccount, http.StatusBadRequest)
		return "", false
	}
	return name, true
}

// checkPassword checks name's current password, answering 403 if it's
// wrong.
func (a *auth) checkPassword(w http.ResponseWriter, ctx context.Context, name, password string) bool {
	hash, err := a.srv.store.AdminPasswordHash(ctx, name)
	if err == nil {
		err = passwd.Verify(password, hash)
	}
	if err != nil {
		http.Error(w, "the current password is wrong", http.StatusForbidden)
		return false
	}
	return true
}

// useCode checks a TOTP code for name and uses it up: each code works
// once, on every server sharing the database.
func (a *auth) useCode(ctx context.Context, name, secret, code string) bool {
	_, last, err := a.srv.store.AdminTOTP(ctx, name)
	if err != nil {
		return false
	}
	step, ok := totp.Check(secret, code, clock(), last)
	if !ok {
		return false
	}
	ok, err = a.srv.store.UseAdminTOTPStep(ctx, name, step)
	return err == nil && ok
}

// twoFactorStatus tells the console whether the signed-in account uses
// two-factor sign-in ("available" is false for OIDC and API key sessions).
func (a *auth) twoFactorStatus(w http.ResponseWriter, r *http.Request) {
	var who string
	c, err := r.Cookie(control.SessionCookie)
	if err == nil {
		who, err = a.srv.store.SessionIdentity(r.Context(), c.Value)
	}
	if err != nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	out := map[string]bool{"available": false, "enabled": false}
	if name, isAccount := strings.CutPrefix(who, "admin:"); isAccount {
		secret, _, err := a.srv.store.AdminTOTP(r.Context(), name)
		out["available"], out["enabled"] = err == nil, secret != ""
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

// twoFactorSetup starts turning two-factor sign-in on: it needs the
// password, and returns a new secret (as text, an otpauth:// link and a QR
// code) that only takes effect once twoFactorEnable sees a code from it.
func (a *auth) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "two-factor sign-in is for password accounts; your identity provider handles it for OIDC")
	if !ok || !a.checkPassword(w, ctx, name, body.Password) {
		return
	}
	if secret, _, err := a.srv.store.AdminTOTP(ctx, name); err != nil || secret != "" {
		http.Error(w, "two-factor sign-in is already on: turn it off first to use a new phone", http.StatusConflict)
		return
	}
	secret := totp.NewSecret()
	uri := totp.URI("Whalescale", name+"@"+consoleHost(a.srv.cfg.PublicURL), secret)
	qr, err := totp.QRSVG(uri)
	if err == nil {
		err = a.srv.store.SetAdminTOTPPending(ctx, name, secret)
	}
	if err != nil {
		a.srv.log.Error("two-factor setup", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"secret": secret, "uri": uri, "qr": qr})
}

// twoFactorEnable turns two-factor sign-in on once a code from the new
// secret checks out, and signs the account out everywhere else.
func (a *auth) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "two-factor sign-in is for password accounts")
	if !ok {
		return
	}
	pending, err := a.srv.store.AdminTOTPPending(ctx, name)
	if err != nil || pending == "" {
		http.Error(w, "start the setup again", http.StatusConflict)
		return
	}
	step, ok := totp.Check(pending, body.Code, clock(), 0)
	if !ok {
		http.Error(w, "that code doesn't match: check the phone's clock, and type the code the app shows now", http.StatusForbidden)
		return
	}
	err = a.srv.store.EnableAdminTOTP(ctx, name, pending, step)
	if err == nil {
		err = a.srv.store.DeleteSessionsOf(ctx, store.AdminIdentity(name))
	}
	if err == nil {
		err = a.startSession(w, ctx, store.AdminIdentity(name)) // this browser stays signed in
	}
	if err != nil {
		a.srv.log.Error("two-factor enable", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "two-factor sign-in turned on")
	w.WriteHeader(http.StatusNoContent)
}

// twoFactorDisable turns two-factor sign-in off: it needs the password and
// a current code. (Lost the phone? 'whalescale admins reset-2fa NAME' on
// the server.)
func (a *auth) twoFactorDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "two-factor sign-in is for password accounts")
	if !ok || !a.checkPassword(w, ctx, name, body.Password) {
		return
	}
	secret, _, err := a.srv.store.AdminTOTP(ctx, name)
	if err != nil || secret == "" {
		http.Error(w, "two-factor sign-in is already off", http.StatusConflict)
		return
	}
	if !a.useCode(ctx, name, secret, body.Code) {
		http.Error(w, "that code is wrong or was already used: wait for the next one", http.StatusForbidden)
		return
	}
	if err := a.srv.store.DisableAdminTOTP(ctx, name); err != nil {
		a.srv.log.Error("two-factor disable", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "two-factor sign-in turned off")
	w.WriteHeader(http.StatusNoContent)
}

// consoleHost names the server in authenticator apps: "ws.example.com".
func consoleHost(publicURL string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(publicURL, "https://"), "http://")
	h, _, _ = strings.Cut(h, "/")
	if h == "" {
		return "whalescale"
	}
	return h
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
