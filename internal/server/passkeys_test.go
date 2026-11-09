package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/k4ran909/whalescale/internal/control"
	"github.com/k4ran909/whalescale/internal/passwd"
)

var b64 = base64.RawURLEncoding

// softKey is a software passkey: an ES256 key pair and a signature
// counter, answering the server's WebAuthn options the way a browser and
// its authenticator would.
type softKey struct {
	t      *testing.T
	priv   *ecdsa.PrivateKey
	id     []byte
	handle []byte
	count  uint32
	origin string
	// What the next answer gets wrong, to test refusals.
	noUV        bool
	otherOrigin bool
}

func newSoftKey(t *testing.T, origin string) *softKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softKey{t: t, priv: priv, id: id, origin: origin}
}

type wireOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		UserVerification string `json:"userVerification"`
	} `json:"publicKey"`
}

func (k *softKey) clientData(typ, challenge string) []byte {
	origin := k.origin
	if k.otherOrigin {
		origin = "http://localhost.evil.example"
	}
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (k *softKey) authData(rpID string, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(0x01) // user present
	if !k.noUV {
		flags |= 0x04 // user verified
	}
	if attested != nil {
		flags |= 0x40
	}
	k.count++
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	return append(out, attested...)
}

// create answers registration options with a new credential.
func (k *softKey) create(options json.RawMessage) json.RawMessage {
	var o wireOptions
	if err := json.Unmarshal(options, &o); err != nil {
		k.t.Fatal(err)
	}
	handle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		k.t.Fatal(err)
	}
	k.handle = handle
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: k.priv.PublicKey.X.FillBytes(make([]byte, 32)), -3: k.priv.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		k.t.Fatal(err)
	}
	attested := make([]byte, 16) // AAGUID: none
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(k.id)))
	attested = append(append(attested, k.id...), cose...)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(o.PublicKey.RP.ID, attested)})
	if err != nil {
		k.t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(k.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		},
	})
	return b
}

// get answers sign-in options with a signed assertion.
func (k *softKey) get(options json.RawMessage) json.RawMessage {
	var o wireOptions
	if err := json.Unmarshal(options, &o); err != nil {
		k.t.Fatal(err)
	}
	auth := k.authData(o.PublicKey.RPID, nil)
	cd := k.clientData("webauthn.get", o.PublicKey.Challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(k.handle),
		},
	})
	return b
}

// call posts body (JSON) and returns the status, the body and the session
// cookie it set, if any.
func call(t *testing.T, c *http.Client, method, url string, body any, cookie *http.Cookie) (int, []byte, *http.Cookie) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, url, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == control.SessionCookie && ck.Value != "" {
			session = ck
		}
	}
	return resp.StatusCode, out, session
}

type ceremonyStart struct {
	Token   string          `json:"token"`
	Options json.RawMessage `json:"options"`
}

// Passkeys: adding one needs the password, then it signs the account in
// with no name, password or code. Each ceremony works once, and answers
// for another site, without user verification, from a copied key or from
// a removed passkey are refused.
func TestPasskeys(t *testing.T) {
	hs, st := newTestServerAt(t, func(addr string) string {
		_, port, _ := net.SplitHostPort(addr)
		return "http://localhost:" + port
	})
	origin := strings.Replace(hs.URL, "127.0.0.1", "localhost", 1)
	c := hs.Client()
	ctx := context.Background()
	const pw = "long enough password"
	hash, _ := passwd.Hash(pw)
	if _, err := st.CreateAdmin(ctx, "karan", hash); err != nil {
		t.Fatal(err)
	}

	code, body, _ := call(t, c, "GET", hs.URL+"/auth/status", nil, nil)
	if code != 200 || !strings.Contains(string(body), `"passkeys":true`) {
		t.Fatalf("status: %d %s", code, body)
	}
	code, _, session := call(t, c, "POST", hs.URL+"/auth/password", map[string]string{"name": "karan", "password": pw}, nil)
	if code != 204 || session == nil {
		t.Fatalf("password sign-in: %d", code)
	}

	// Adding a passkey needs the password, and a session.
	if code, _, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/register/begin", map[string]string{"password": "wrong password!"}, session); code != 403 {
		t.Fatalf("begin with a wrong password: %d", code)
	}
	if code, _, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/register/begin", map[string]string{"password": pw}, nil); code != 401 {
		t.Fatalf("begin without a session: %d", code)
	}
	var start ceremonyStart
	code, body, _ = call(t, c, "POST", hs.URL+"/auth/passkeys/register/begin", map[string]string{"password": pw}, session)
	if code != 200 || json.Unmarshal(body, &start) != nil {
		t.Fatalf("begin: %d %s", code, body)
	}
	var o wireOptions
	json.Unmarshal(start.Options, &o)
	if o.PublicKey.RP.ID != "localhost" || o.PublicKey.AuthenticatorSelection.ResidentKey != "required" ||
		o.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("registration options: %s", start.Options)
	}
	key := newSoftKey(t, origin)
	finish := map[string]any{"token": start.Token, "name": "Laptop", "credential": key.create(start.Options)}
	code, body, _ = call(t, c, "POST", hs.URL+"/auth/passkeys/register/finish", finish, session)
	if code != 201 || !strings.Contains(string(body), `"name":"Laptop"`) {
		t.Fatalf("finish: %d %s", code, body)
	}
	if code, _, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/register/finish", finish, session); code != 409 {
		t.Fatalf("finishing twice: %d", code)
	}
	code, body, _ = call(t, c, "GET", hs.URL+"/auth/passkeys", nil, session)
	var list struct {
		Available bool          `json:"available"`
		Passkeys  []passkeyInfo `json:"passkeys"`
	}
	if code != 200 || json.Unmarshal(body, &list) != nil || !list.Available || len(list.Passkeys) != 1 || list.Passkeys[0].LastUsed != 0 {
		t.Fatalf("list: %d %s", code, body)
	}

	// Signing in: no name, password or code.
	login := func(k *softKey) (int, *http.Cookie, ceremonyStart, json.RawMessage) {
		t.Helper()
		var s ceremonyStart
		code, body, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/login/begin", nil, nil)
		if code != 200 || json.Unmarshal(body, &s) != nil {
			t.Fatalf("login begin: %d %s", code, body)
		}
		answer := k.get(s.Options)
		code, _, cookie := call(t, c, "POST", hs.URL+"/auth/passkeys/login/finish", map[string]any{"token": s.Token, "credential": answer}, nil)
		return code, cookie, s, answer
	}
	code, cookie, s, answer := login(key)
	if code != 204 || cookie == nil {
		t.Fatalf("passkey sign-in: %d", code)
	}
	code, body, _ = call(t, c, "GET", hs.URL+"/auth/passkeys", nil, cookie)
	if code != 200 || !strings.Contains(string(body), `"lastUsed"`) {
		t.Fatalf("the passkey's session: %d %s", code, body)
	}
	if code, _, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/login/finish", map[string]any{"token": s.Token, "credential": answer}, nil); code != 401 {
		t.Fatalf("the same answer twice: %d", code)
	}

	// Refusals: another site's answer, no user verification, a copied key.
	key.otherOrigin = true
	if code, _, _, _ := login(key); code != 401 {
		t.Fatalf("an answer for another origin: %d", code)
	}
	key.otherOrigin, key.noUV = false, true
	if code, _, _, _ := login(key); code != 401 {
		t.Fatalf("an answer without user verification: %d", code)
	}
	key.noUV = false
	if code, _, _, _ := login(key); code != 204 {
		t.Fatalf("sign-in again: %d", code)
	}
	clone := *key
	clone.count = 1 // a copy of the key, behind the original's counter
	if code, _, _, _ := login(&clone); code != 401 {
		t.Fatalf("a copied key: %d", code)
	}
	stranger := newSoftKey(t, origin)
	stranger.handle = key.handle
	if code, _, _, _ := login(stranger); code != 401 {
		t.Fatalf("a passkey the server never saw: %d", code)
	}

	// Removing it: it no longer signs in.
	if code, _, _ := call(t, c, "POST", hs.URL+"/auth/passkeys/delete", map[string]any{"id": list.Passkeys[0].ID}, session); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _, _ := login(key); code != 401 {
		t.Fatalf("a removed passkey: %d", code)
	}
}

// Passkeys only work where browsers offer them: https://, or
// http://localhost.
func TestPasskeysNeedSecureOrigin(t *testing.T) {
	hs, _ := newTestServer(t) // http://127.0.0.1:port
	code, body, _ := call(t, hs.Client(), "GET", hs.URL+"/auth/status", nil, nil)
	if code != 200 || !strings.Contains(string(body), `"passkeys":false`) {
		t.Fatalf("status: %d %s", code, body)
	}
	if code, _, _ := call(t, hs.Client(), "POST", hs.URL+"/auth/passkeys/login/begin", nil, nil); code != 404 {
		t.Fatalf("login begin: %d", code)
	}
	for url, want := range map[string]bool{
		"https://ws.example.com": true, "http://localhost:8080": true, "http://ws.example.com": false, "": false,
	} {
		w, err := newPasskeys(url)
		if err != nil || (w != nil) != want {
			t.Errorf("%q: %v %v", url, w != nil, err)
		}
	}
}
