package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/passwd"
	"github.com/k4ran909/whalescale/internal/store"
)

func settingOf(t *testing.T, out map[string]any, name string) map[string]any {
	t.Helper()
	list, _ := out["settings"].([]any)
	for _, s := range list {
		if m, _ := s.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no setting %q in %v", name, out)
	return nil
}

// TestConsoleSettings: settings changed through the admin API take effect
// at once (the gateway starts answering for its domain), override the
// config file, survive a reload, and go back to the config file's value on
// request. Read keys can look but not change.
func TestConsoleSettings(t *testing.T) {
	hs, st := newTestServer(t)
	ctx := context.Background()
	_, admin, err := st.CreateScopedAPIKey(ctx, time.Hour, store.ScopeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, read, err := st.CreateScopedAPIKey(ctx, time.Hour, store.ScopeRead)
	if err != nil {
		t.Fatal(err)
	}
	c := hs.Client()
	as := map[string]string{"Authorization": "Bearer " + admin}
	ro := map[string]string{"Authorization": "Bearer " + read}

	code, out := adminCall(t, c, hs.URL, "GetSettings", "{}", ro)
	if code != 200 || out["dnsSuffix"] != "whale.internal" {
		t.Fatalf("GetSettings = %d %v", code, out)
	}
	if g := settingOf(t, out, "gateway-domain"); g["value"] != nil || g["fromConsole"] != nil {
		t.Fatalf("gateway-domain before: %v", g)
	}
	if code, _ := adminCall(t, c, hs.URL, "UpdateSetting", `{"name":"flow-logs","value":"true"}`, ro); code != 403 {
		t.Fatalf("UpdateSetting with a read key: %d, want 403", code)
	}
	for _, bad := range []string{`{"name":"flow-logs","value":"maybe"}`, `{"name":"gateway-domain","value":"not a domain"}`, `{"name":"listen","value":":1"}`} {
		if code, out := adminCall(t, c, hs.URL, "UpdateSetting", bad, as); code != 400 {
			t.Errorf("UpdateSetting %s = %d %v, want 400", bad, code, out)
		}
	}

	if code, out := adminCall(t, c, hs.URL, "UpdateSetting", `{"name":"gateway-domain","value":"Apps.Example.com."}`, as); code != 200 {
		t.Fatalf("set gateway-domain: %d %v", code, out)
	} else if g := settingOf(t, out, "gateway-domain"); g["value"] != "apps.example.com" || g["fromConsole"] != true {
		t.Fatalf("gateway-domain after: %v", g)
	}
	// The gateway now owns <name>.apps.example.com: an unknown exposure there
	// is the gateway's answer, not the console's.
	req, _ := newHostRequest(hs.URL+"/", "nope.apps.example.com")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatalf("nope.apps.example.com served the console (%d); the gateway didn't pick up its domain", resp.StatusCode)
	}
	if code, out := adminCall(t, c, hs.URL, "ListExposures", "{}", as); code != 200 || out["gatewayDomain"] != "apps.example.com" {
		t.Fatalf("ListExposures = %d %v", code, out)
	}

	if code, out := adminCall(t, c, hs.URL, "UpdateSetting", `{"name":"gateway-domain","useConfig":true}`, as); code != 200 {
		t.Fatalf("reset gateway-domain: %d %v", code, out)
	} else if g := settingOf(t, out, "gateway-domain"); g["value"] != nil || g["fromConsole"] != nil {
		t.Fatalf("gateway-domain after reset: %v", g)
	}
	req, _ = newHostRequest(hs.URL+"/", "nope.apps.example.com")
	if resp, err = c.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("after reset, other hosts should reach the console again: %d", resp.StatusCode)
	}

	if code, out := adminCall(t, c, hs.URL, "UpdateSetting", `{"name":"post-quantum","value":"1"}`, as); code != 200 {
		t.Fatalf("set post-quantum: %d %v", code, out)
	} else if p := settingOf(t, out, "post-quantum"); p["value"] != "true" || p["configValue"] != "false" {
		t.Fatalf("post-quantum after: %v", p)
	}
	if saved, _ := st.ConsoleSettings(ctx); saved["post-quantum"] != "true" {
		t.Fatalf("saved settings: %v", saved)
	}
}

// TestConsoleAccounts: team members' console accounts are added and
// removed through the admin API; the new member gets a one-time password
// and a user for their machines; nobody deletes their own or the last
// account.
func TestConsoleAccounts(t *testing.T) {
	hs, st := newTestServer(t)
	ctx := context.Background()
	h, _ := passwd.Hash("first-admin-password")
	if _, err := st.CreateFirstAdmin(ctx, "owner", h); err != nil {
		t.Fatal(err)
	}
	_, admin, err := st.CreateScopedAPIKey(ctx, time.Hour, store.ScopeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	c := hs.Client()
	as := map[string]string{"Authorization": "Bearer " + admin}

	code, out := adminCall(t, c, hs.URL, "CreateConsoleAccount", `{"name":"Priya"}`, as)
	if code != 200 {
		t.Fatalf("CreateConsoleAccount = %d %v", code, out)
	}
	pw, _ := out["password"].(string)
	if len(pw) < 16 {
		t.Fatalf("password %q", pw)
	}
	hash, err := st.AdminPasswordHash(ctx, "priya")
	if err != nil || passwd.Verify(pw, hash) != nil {
		t.Fatalf("the returned password doesn't sign priya in: %v", err)
	}
	if users, _ := st.ListUsers(ctx); len(users) != 1 || users[0].Name != "priya" {
		t.Fatalf("users = %v, want priya", users)
	}
	if code, _ := adminCall(t, c, hs.URL, "CreateConsoleAccount", `{"name":"priya"}`, as); code != 409 {
		t.Fatalf("duplicate account: %d, want 409", code)
	}
	if code, _ := adminCall(t, c, hs.URL, "CreateConsoleAccount", `{"name":"no spaces"}`, as); code != 400 {
		t.Fatalf("bad name: %d, want 400", code)
	}

	// Priya signs in and can't delete herself.
	resp, err := c.Post(hs.URL+"/auth/password", "application/json", stringsReader(`{"name":"priya","password":"`+pw+`"}`))
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("priya's sign-in: %v %v", err, resp)
	}
	var cookie string
	for _, ck := range resp.Cookies() {
		if ck.Name == "ws_session" {
			cookie = ck.Value
		}
	}
	session := map[string]string{"Cookie": "ws_session=" + cookie, "Connect-Protocol-Version": "1"}
	code, out = adminCall(t, c, hs.URL, "ListConsoleAccounts", "{}", session)
	if code != 200 || out["you"] != "priya" || len(out["accounts"].([]any)) != 2 {
		t.Fatalf("ListConsoleAccounts = %d %v", code, out)
	}
	if code, _ := adminCall(t, c, hs.URL, "DeleteConsoleAccount", `{"name":"priya"}`, session); code != 400 {
		t.Fatalf("deleting yourself: %d, want 400 (failed precondition)", code)
	}
	if code, out := adminCall(t, c, hs.URL, "DeleteConsoleAccount", `{"name":"owner"}`, session); code != 200 {
		t.Fatalf("delete owner: %d %v", code, out)
	}
	if code, _ := adminCall(t, c, hs.URL, "DeleteConsoleAccount", `{"name":"priya"}`, as); code != 400 {
		t.Fatalf("deleting the last account: %d, want 400 (failed precondition)", code)
	}
}

func newHostRequest(url, host string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Host = host
	}
	return req, err
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
