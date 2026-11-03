package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/k4ran909/whalescale/internal/joincode"
	"github.com/k4ran909/whalescale/internal/store"
)

// postJSON posts body and returns the status, the response text and the
// session cookie it set, if any.
func postJSON(t *testing.T, c *http.Client, url, body string, cookie *http.Cookie) (int, string, *http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var text strings.Builder
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	text.Write(buf[:n])
	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "ws_session" {
			session = ck
		}
	}
	return resp.StatusCode, strings.TrimSpace(text.String()), session
}

// The console's first run: the setup code from the log creates the only
// admin account, setup closes, and that account signs in with its
// password from then on.
func TestFirstRunSetup(t *testing.T) {
	hs, st := newTestServer(t)
	c := hs.Client()
	ctx := context.Background()

	status := func() map[string]any {
		t.Helper()
		resp, err := c.Get(hs.URL + "/auth/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	if s := status(); s["setup"] != true || s["oidc"] != false || s["publicUrl"] != "http://"+hs.Listener.Addr().String() {
		t.Fatalf("status before setup = %v", s)
	}
	code, err := st.SetupCode(ctx)
	if err != nil || len(code) != 9 {
		t.Fatalf("setup code %q, %v", code, err)
	}
	if again, _ := st.SetupCode(ctx); again != code {
		t.Fatal("setup code changed between reads")
	}

	setup := func(code, name, pw string) (int, string, *http.Cookie) {
		body, _ := json.Marshal(map[string]string{"code": code, "name": name, "password": pw})
		return postJSON(t, c, hs.URL+"/auth/setup", string(body), nil)
	}
	for name, tc := range map[string]struct {
		code, name, pw string
		want           int
	}{
		"no code":        {"", "karan", "long enough password", 403},
		"wrong code":     {"AAAA-AAAA", "karan", "long enough password", 403},
		"bad name":       {code, "Karan Singh", "long enough password", 400},
		"short password": {code, "karan", "short", 400},
	} {
		if got, text, _ := setup(tc.code, tc.name, tc.pw); got != tc.want {
			t.Errorf("%s: %d %q, want %d", name, got, text, tc.want)
		}
	}
	// Typed loosely (lower case, no dash) the code still works.
	got, text, session := setup(strings.ToLower(strings.ReplaceAll(code, "-", "")), " Karan ", "long enough password")
	if got != 204 || session == nil || !session.HttpOnly {
		t.Fatalf("setup: %d %q, cookie %+v", got, text, session)
	}

	// Signed in as the new account, which also got a user for its devices.
	ck := map[string]string{"Cookie": "ws_session=" + session.Value, "Connect-Protocol-Version": "1"}
	got, out := adminCall(t, c, hs.URL, "WhoAmI", "{}", ck)
	if got != 200 || out["method"] != "admin" || out["identity"] != "karan" {
		t.Fatalf("WhoAmI = %d %v", got, out)
	}
	if u, err := st.ListUsers(ctx); err != nil || len(u) != 1 || u[0].Name != "karan" {
		t.Fatalf("users = %+v, %v", u, err)
	}

	// Setup is closed for good.
	if s := status(); s["setup"] != false {
		t.Fatalf("status after setup = %v", s)
	}
	if got, _, _ := setup(code, "mallory", "long enough password"); got != 409 {
		t.Fatalf("second setup: %d", got)
	}
	if c, _ := st.SetupCode(ctx); c != "" {
		t.Fatalf("setup code after setup = %q", c)
	}

	// Password sign-in.
	login := func(name, pw string) (int, *http.Cookie) {
		body, _ := json.Marshal(map[string]string{"name": name, "password": pw})
		got, _, ck := postJSON(t, c, hs.URL+"/auth/password", string(body), nil)
		return got, ck
	}
	if got, _ := login("karan", "wrong password!"); got != 401 {
		t.Fatalf("wrong password: %d", got)
	}
	if got, _ := login("nobody", "long enough password"); got != 401 {
		t.Fatalf("unknown account: %d", got)
	}
	got, second := login("KARAN", "long enough password")
	if got != 204 || second == nil {
		t.Fatalf("sign-in: %d", got)
	}

	// A new pre-auth key comes with a join code for this server.
	got, out = adminCall(t, c, hs.URL, "CreatePreAuthKey", `{"user":"karan"}`, ck)
	if got != 200 {
		t.Fatalf("CreatePreAuthKey: %d %v", got, out)
	}
	server, key, err := joincode.Decode(out["joinCode"].(string))
	if err != nil || server != "http://"+hs.Listener.Addr().String() || key != out["secret"] {
		t.Fatalf("join code = %v: %q %q %v", out["joinCode"], server, key, err)
	}

	// Changing the password needs the current one, and signs the account
	// out everywhere but here.
	change := func(cookie *http.Cookie, current, next string) (int, *http.Cookie) {
		body, _ := json.Marshal(map[string]string{"current": current, "new": next})
		got, _, ck := postJSON(t, c, hs.URL+"/auth/password/change", string(body), cookie)
		return got, ck
	}
	if got, _ := change(second, "wrong current pw", "another long password"); got != 403 {
		t.Fatalf("wrong current password: %d", got)
	}
	if got, _ := change(second, "long enough password", "short"); got != 400 {
		t.Fatalf("short new password: %d", got)
	}
	got, third := change(second, "long enough password", "another long password")
	if got != 204 || third == nil {
		t.Fatalf("change password: %d", got)
	}
	if got, _ := adminCall(t, c, hs.URL, "WhoAmI", "{}", ck); got != 401 {
		t.Fatalf("old session after a password change: %d", got)
	}
	ck["Cookie"] = "ws_session=" + third.Value
	if got, _ := adminCall(t, c, hs.URL, "WhoAmI", "{}", ck); got != 200 {
		t.Fatalf("this browser's new session: %d", got)
	}
	if got, _ := login("karan", "another long password"); got != 204 {
		t.Fatalf("sign-in with the new password: %d", got)
	}

	// The audit log names the account.
	evs, _ := st.QueryAudit(ctx, store.AuditQuery{Actor: "admin:karan"})
	var actions []string
	for _, e := range evs {
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"admin account created", "console sign-in", "pre-auth key created", "password changed"} {
		if !strings.Contains(strings.Join(actions, ","), want) {
			t.Errorf("audit log lacks %q: %v", want, actions)
		}
	}
}
