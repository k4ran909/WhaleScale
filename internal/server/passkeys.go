package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/k4ran909/whalescale/internal/store"
)

// Passkeys sign a console account in with the device's own unlock (a
// fingerprint, the face, a PIN or a security key) instead of a password.
// They're WebAuthn credentials bound to the server's public URL, so a
// look-alike site can't use them. A passkey sign-in skips the password and
// the two-factor code: the passkey is both factors itself (something you
// have, unlocked by something you are or know).

const (
	// ceremonyTTL is how long a passkey ceremony may take, from the
	// server's challenge to the browser's answer.
	ceremonyTTL = 5 * time.Minute
	// passkeyBodyLimit: WebAuthn answers are bigger than other sign-in
	// requests (attestation, client data).
	passkeyBodyLimit = 64 << 10
)

// newPasskeys returns the WebAuthn relying party for the console at
// publicURL, or nil if passkeys can't work there: browsers only offer them
// on https:// pages, and on http://localhost.
func newPasskeys(publicURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return nil, nil
	}
	host := u.Hostname()
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost"))) {
		return nil, nil
	}
	return webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "Whalescale",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}

// passkeyUser is a console account as the WebAuthn library sees it.
type passkeyUser struct {
	id    uint64
	name  string
	creds []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return userHandle(u.id) }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userHandle identifies an account to its passkeys. Account IDs are never
// reused, so a deleted account's passkeys can't sign in a new one.
func userHandle(adminID uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte("wsadmin:"), adminID)
}

func credentialID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// passkeyUserFor loads a console account and its passkeys.
func (a *auth) passkeyUserFor(r *http.Request, name string) (*passkeyUser, error) {
	ctx := r.Context()
	id, err := a.srv.store.AdminID(ctx, name)
	if err != nil {
		return nil, err
	}
	keys, err := a.srv.store.AdminPasskeys(ctx, name)
	if err != nil {
		return nil, err
	}
	u := &passkeyUser{id: id, name: name}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Credential, &c); err != nil {
			return nil, fmt.Errorf("passkey %d: %w", k.ID, err)
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

// A ceremony is a passkey registration or sign-in between the server's
// challenge and the browser's answer. It's kept in the database, so the
// answer may reach any of several servers, and works once.
type ceremony struct {
	kind    string // "register" or "login"
	admin   string // the account adding a passkey
	session webauthn.SessionData
}

// saveCeremony stores c and returns its token; it answers the request
// itself and returns false when it can't.
func (a *auth) saveCeremony(w http.ResponseWriter, r *http.Request, c ceremony) (string, bool) {
	data, err := json.Marshal(c.session)
	tok := randToken()
	if err == nil {
		err = a.srv.store.SaveCeremony(r.Context(), tok, c.kind, c.admin, data, ceremonyTTL)
	}
	switch {
	case errors.Is(err, store.ErrTooManyCeremonies):
		http.Error(w, "too many passkey requests at once; try again in a few minutes", http.StatusServiceUnavailable)
		return "", false
	case err != nil:
		a.srv.log.Error("save passkey ceremony", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "", false
	}
	return tok, true
}

// takeCeremony returns the ceremony of kind stored under tok, once.
func (a *auth) takeCeremony(r *http.Request, tok, kind string) (ceremony, bool) {
	c := ceremony{kind: kind}
	admin, data, err := a.srv.store.TakeCeremony(r.Context(), tok, kind, ceremonyTTL)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.srv.log.Error("take passkey ceremony", "err", err)
		}
		return c, false
	}
	c.admin = admin
	return c, json.Unmarshal(data, &c.session) == nil
}

// passkeysOff answers for servers where passkeys can't work.
func (a *auth) passkeysOff(w http.ResponseWriter) bool {
	if a.passkeys == nil {
		http.Error(w, "passkeys need the server's public-url to be an https:// address", http.StatusNotFound)
		return true
	}
	return false
}

type passkeyInfo struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"lastUsed,omitempty"`
}

func infoOf(p store.Passkey) passkeyInfo {
	i := passkeyInfo{ID: p.ID, Name: p.Name, Created: p.CreatedAt.Unix()}
	if !p.LastUsed.IsZero() {
		i.LastUsed = p.LastUsed.Unix()
	}
	return i
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// passkeyList lists the signed-in account's passkeys ("available" is false
// where the server can't offer passkeys).
func (a *auth) passkeyList(w http.ResponseWriter, r *http.Request) {
	name, ok := a.account(w, r, "passkeys are for password accounts")
	if !ok {
		return
	}
	keys, err := a.srv.store.AdminPasskeys(r.Context(), name)
	if err != nil {
		a.srv.log.Error("list passkeys", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := []passkeyInfo{}
	for _, k := range keys {
		out = append(out, infoOf(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": a.passkeys != nil, "passkeys": out})
}

// passkeyRegisterBegin starts adding a passkey to the signed-in account. It
// needs the password, like turning on two-factor sign-in, so a session
// left open in a browser can't add one.
func (a *auth) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if a.passkeysOff(w) || !readJSON(w, r, &body) {
		return
	}
	name, ok := a.account(w, r, "passkeys are for password accounts; your identity provider handles sign-in for OIDC")
	if !ok || !a.checkPassword(w, r.Context(), name, body.Password) {
		return
	}
	user, err := a.passkeyUserFor(r, name)
	if err != nil {
		a.srv.log.Error("passkey registration", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(user.creds) >= store.MaxPasskeys {
		http.Error(w, store.ErrTooManyPasskeys.Error()+": remove one first", http.StatusConflict)
		return
	}
	creation, session, err := a.passkeys.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		// The same device twice would only be a second name for one key.
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()),
	)
	if err != nil {
		a.srv.log.Error("passkey registration", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tok, ok := a.saveCeremony(w, r, ceremony{kind: "register", admin: name, session: *session})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "options": creation})
}

// passkeyRegisterFinish checks the browser's new passkey and saves it.
func (a *auth) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string          `json:"token"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if a.passkeysOff(w) || !readJSONLimit(w, r, &body, passkeyBodyLimit) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "passkeys are for password accounts")
	if !ok {
		return
	}
	c, ok := a.takeCeremony(r, body.Token, "register")
	if !ok || c.admin != name {
		http.Error(w, "that took too long; add the passkey again", http.StatusConflict)
		return
	}
	label := strings.TrimSpace(body.Name)
	if label == "" {
		label = "Passkey"
	}
	if len([]rune(label)) > 60 {
		label = string([]rune(label)[:60])
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		http.Error(w, "the browser's answer isn't a passkey", http.StatusBadRequest)
		return
	}
	user, err := a.passkeyUserFor(r, name)
	if err != nil {
		a.srv.log.Error("passkey registration", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cred, err := a.passkeys.CreateCredential(user, c.session, parsed)
	if err != nil {
		a.srv.log.Warn("passkey registration refused", "admin", name, "err", webauthnError(err))
		http.Error(w, "the passkey couldn't be verified; try again", http.StatusBadRequest)
		return
	}
	data, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p, err := a.srv.store.AddAdminPasskey(ctx, name, label, credentialID(cred.ID), data)
	switch {
	case errors.Is(err, store.ErrTooManyPasskeys):
		http.Error(w, err.Error()+": remove one first", http.StatusConflict)
		return
	case errors.Is(err, store.ErrAlreadyExists):
		http.Error(w, "that passkey is added already", http.StatusConflict)
		return
	case err != nil:
		a.srv.log.Error("save passkey", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "passkey added", "passkey", label)
	writeJSON(w, http.StatusCreated, infoOf(*p))
}

// passkeyDelete removes one of the signed-in account's passkeys.
func (a *auth) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID uint64 `json:"id"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	name, ok := a.account(w, r, "passkeys are for password accounts")
	if !ok {
		return
	}
	var label string
	if keys, err := a.srv.store.AdminPasskeys(ctx, name); err == nil {
		for _, k := range keys {
			if k.ID == body.ID {
				label = k.Name
			}
		}
	}
	if err := a.srv.store.DeleteAdminPasskey(ctx, name, body.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no such passkey", http.StatusNotFound)
			return
		}
		a.srv.log.Error("delete passkey", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "passkey removed", "passkey", label)
	w.WriteHeader(http.StatusNoContent)
}

// passkeyLoginBegin starts a passkey sign-in. It asks for any passkey of
// this server, so nobody types a name: the browser offers the ones it has.
func (a *auth) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if a.passkeysOff(w) {
		return
	}
	assertion, session, err := a.passkeys.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		a.srv.log.Error("passkey sign-in", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tok, ok := a.saveCeremony(w, r, ceremony{kind: "login", session: *session})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "options": assertion})
}

// passkeyLoginFinish checks the passkey's signature and signs its account in.
func (a *auth) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string          `json:"token"`
		Credential json.RawMessage `json:"credential"`
	}
	if a.passkeysOff(w) || !readJSONLimit(w, r, &body, passkeyBodyLimit) {
		return
	}
	ctx := r.Context()
	c, ok := a.takeCeremony(r, body.Token, "login")
	if !ok {
		http.Error(w, "that took too long; try again", http.StatusUnauthorized)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		http.Error(w, "the browser's answer isn't a passkey sign-in", http.StatusBadRequest)
		return
	}
	var found *store.Passkey
	lookup := func(rawID, handle []byte) (webauthn.User, error) {
		p, err := a.srv.store.PasskeyByCredentialID(ctx, credentialID(rawID))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(handle, userHandle(p.AdminID)) {
			return nil, errors.New("the passkey belongs to another account")
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(p.Credential, &cred); err != nil {
			return nil, err
		}
		found = p
		return &passkeyUser{id: p.AdminID, name: p.Admin, creds: []webauthn.Credential{cred}}, nil
	}
	user, cred, err := a.passkeys.ValidatePasskeyLogin(lookup, c.session, parsed)
	if err != nil || found == nil {
		a.srv.log.Warn("passkey sign-in refused", "remote", r.RemoteAddr, "err", webauthnError(err))
		http.Error(w, "this passkey isn't one of this server's, or it was removed", http.StatusUnauthorized)
		return
	}
	name := user.WebAuthnName()
	if cred.Authenticator.CloneWarning {
		// The signature counter went backwards: two copies of the key exist.
		a.srv.log.Warn("passkey sign-in refused: its counter went backwards, so it may have been copied",
			"admin", name, "passkey", found.Name, "remote", r.RemoteAddr)
		http.Error(w, "this passkey may have been copied, so it's refused: sign in with your password, remove it and add it again", http.StatusUnauthorized)
		return
	}
	data, err := json.Marshal(cred)
	if err == nil {
		err = a.srv.store.UsePasskey(ctx, found.ID, data)
	}
	if err == nil {
		err = a.startSession(w, ctx, store.AdminIdentity(name))
	}
	if err != nil {
		a.srv.log.Error("passkey sign-in", "admin", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.srv.control.Audit(ctx, store.AdminIdentity(name), "console sign-in", "how", "passkey", "passkey", found.Name)
	w.WriteHeader(http.StatusNoContent)
}

// webauthnError adds the library's detail to an error for the log.
func webauthnError(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return strings.TrimSpace(pe.Details + " " + pe.DevInfo)
	}
	if err == nil {
		return "unknown passkey"
	}
	return err.Error()
}
