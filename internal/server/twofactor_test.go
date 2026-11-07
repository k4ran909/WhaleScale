package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/passwd"
	"github.com/k4ran909/whalescale/internal/totp"
)

// Two-factor sign-in: turning it on needs the password and a code from
// the new secret; then sign-in needs a code, each code works once, and
// turning it off needs the password and a code.
func TestTwoFactor(t *testing.T) {
	hs, st := newTestServer(t)
	c := hs.Client()
	ctx := context.Background()
	const pw = "long enough password"
	hash, _ := passwd.Hash(pw)
	if _, err := st.CreateAdmin(ctx, "karan", hash); err != nil {
		t.Fatal(err)
	}
	// Each step of the test happens 30 s after the last, so each needs a
	// fresh code.
	now := time.Unix(1_800_000_000, 0)
	defer func() { clock = time.Now }()
	clock = func() time.Time { return now }
	next := func() { now = now.Add(30 * time.Second) }
	code := func(secret string) string {
		s, err := totp.Code(secret, totp.Step(now))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	login := func(code string) (int, string, *http.Cookie, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": "karan", "password": pw, "code": code})
		req, _ := http.NewRequest("POST", hs.URL+"/auth/password", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		text, _ := io.ReadAll(resp.Body)
		var session *http.Cookie
		for _, ck := range resp.Cookies() {
			if ck.Name == "ws_session" {
				session = ck
			}
		}
		return resp.StatusCode, strings.TrimSpace(string(text)), session, resp.Header.Get(twoFactorHeader)
	}
	status := func(cookie *http.Cookie) map[string]bool {
		t.Helper()
		req, _ := http.NewRequest("GET", hs.URL+"/auth/2fa", nil)
		req.AddCookie(cookie)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]bool
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	got, _, session, hdr := login("")
	if got != 204 || hdr != "" {
		t.Fatalf("sign-in without two-factor: %d %q", got, hdr)
	}
	if s := status(session); !s["available"] || s["enabled"] {
		t.Fatalf("status before: %v", s)
	}

	// Setup needs the password.
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/setup", `{"password":"wrong password!!"}`, session); got != 403 {
		t.Fatalf("setup with the wrong password: %d", got)
	}
	req, _ := http.NewRequest("POST", hs.URL+"/auth/2fa/setup", strings.NewReader(`{"password":"`+pw+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(session)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var setup struct{ Secret, URI, QR string }
	err = json.NewDecoder(resp.Body).Decode(&setup)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || setup.Secret == "" || !strings.HasPrefix(setup.URI, "otpauth://totp/Whalescale:karan") ||
		!strings.HasPrefix(setup.QR, "<svg") {
		t.Fatalf("setup: %d %v %+v", resp.StatusCode, err, setup)
	}
	// Until a code from the new secret checks out, nothing changes.
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/enable", `{"code":"000000"}`, session); got != 403 {
		t.Fatalf("enable with a wrong code: %d", got)
	}
	if got, _, _, hdr := login(""); got != 204 || hdr != "" {
		t.Fatalf("sign-in while only pending: %d %q", got, hdr)
	}
	got, _, newSession := postJSON(t, c, hs.URL+"/auth/2fa/enable", `{"code":"`+code(setup.Secret)+`"}`, session)
	if got != 204 || newSession == nil {
		t.Fatalf("enable: %d", got)
	}
	if s := status(newSession); !s["enabled"] {
		t.Fatalf("status after: %v", s)
	}
	// Other sessions were signed out.
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/setup", `{"password":"`+pw+`"}`, session); got != 401 {
		t.Fatalf("old session after enabling: %d", got)
	}

	// Sign-in now needs a code, and says so only after the password.
	next()
	if got, _, _, hdr := login(""); got != 401 || hdr != "required" {
		t.Fatalf("sign-in without a code: %d %q", got, hdr)
	}
	body, _ := json.Marshal(map[string]string{"name": "karan", "password": "wrong password!", "code": ""})
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/password", string(body), nil); got != 401 {
		t.Fatalf("wrong password: %d", got)
	}
	if got, _, _, _ := login("123456"); got != 401 {
		t.Fatalf("wrong code: %d", got)
	}
	c1 := code(setup.Secret)
	if got, _, ck, _ := login(c1); got != 204 || ck == nil {
		t.Fatalf("sign-in with the code: %d", got)
	}
	if got, _, _, _ := login(c1); got != 401 {
		t.Fatalf("the same code twice: %d", got)
	}

	// Turning it off needs the password and a fresh code.
	next()
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/disable", `{"password":"`+pw+`","code":"`+c1+`"}`, newSession); got != 403 {
		t.Fatalf("disable with a used code: %d", got)
	}
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/disable", `{"password":"wrong password!!","code":"`+code(setup.Secret)+`"}`, newSession); got != 403 {
		t.Fatalf("disable with the wrong password: %d", got)
	}
	if got, _, _ := postJSON(t, c, hs.URL+"/auth/2fa/disable", `{"password":"`+pw+`","code":"`+code(setup.Secret)+`"}`, newSession); got != 204 {
		t.Fatalf("disable: %d", got)
	}
	if got, _, _, hdr := login(""); got != 204 || hdr != "" {
		t.Fatalf("sign-in after disabling: %d %q", got, hdr)
	}
}
