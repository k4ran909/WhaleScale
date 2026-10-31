package policy

import (
	"net/netip"
	"strings"
	"testing"
)

var explainNodes = []Node{
	{ID: 1, Name: "laptop", User: "bob", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
	{ID: 2, Name: "nas", User: "karan", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
	{ID: 3, Name: "router", User: "karan", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		Routes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
}

const explainPolicy = `{
	"groups": {"group:admins": ["karan"]},
	"acls": [
		{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
		{"action": "accept", "src": ["bob"], "dst": ["node:nas:22,80"]},
		{"action": "accept", "src": ["bob"], "dst": ["192.168.1.0/24:443", "10.0.0.0/8:443"]}
	]
}`

func explain(t *testing.T, p *Policy, src, dst string) Explanation {
	t.Helper()
	s, err := Resolve(src, explainNodes)
	if err != nil {
		t.Fatal(err)
	}
	d, port, err := ResolveDst(dst, explainNodes)
	if err != nil {
		t.Fatal(err)
	}
	return p.Explain(s, d, port, explainNodes)
}

func TestExplain(t *testing.T) {
	p, err := Parse([]byte(explainPolicy))
	if err != nil {
		t.Fatal(err)
	}

	ex := explain(t, p, "bob", "node:nas:22")
	if !ex.Allowed || ex.Rule != 1 {
		t.Fatalf("bob→nas:22 = %+v", ex)
	}

	ex = explain(t, p, "bob", "node:nas:443")
	if ex.Allowed || !strings.Contains(strings.Join(ex.Reasons, "\n"), "only ports 22,80") {
		t.Fatalf("bob→nas:443 should be a near miss on ports: %+v", ex)
	}

	ex = explain(t, p, "node:laptop", "100.64.0.2:3389")
	if ex.Allowed || !strings.Contains(strings.Join(ex.Reasons, "\n"), "would allow it for sources group:admins") {
		t.Fatalf("laptop→nas:3389 should point at the admins rule: %+v", ex)
	}

	if ex := explain(t, p, "karan", "node:laptop:5900"); !ex.Allowed || ex.Rule != 0 {
		t.Fatalf("admin→anything = %+v", ex)
	}

	// Subnet addresses: allowed by the CIDR rule and served by the router.
	if ex := explain(t, p, "bob", "192.168.1.10:443"); !ex.Allowed || len(ex.Reasons) != 1 {
		t.Fatalf("bob→LAN:443 = %+v", ex)
	}
	// Allowed by policy, but nothing routes there.
	ex = explain(t, p, "bob", "10.1.2.3:443")
	if !ex.Allowed || !strings.Contains(strings.Join(ex.Reasons, "\n"), "no approved subnet router") {
		t.Fatalf("bob→unrouted:443 = %+v", ex)
	}

	if ex := explain(t, AllowAll(), "bob", "node:nas:1"); !ex.Allowed {
		t.Fatalf("allow-all denied: %+v", ex)
	}
}

func TestPolicyTests(t *testing.T) {
	good := explainPolicy[:strings.LastIndex(explainPolicy, "}")] + `,
	"tests": [
		{"src": "bob", "accept": ["node:nas:22", "192.168.1.5:443"], "deny": ["node:nas:443", "karan:22"]},
		{"src": "karan", "accept": ["node:laptop:22"]}
	]}`
	p, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if fails := p.RunTests(explainNodes); len(fails) != 0 {
		t.Fatalf("passing tests reported failures: %v", fails)
	}

	bad := explainPolicy[:strings.LastIndex(explainPolicy, "}")] + `,
	"tests": [
		{"src": "bob", "accept": ["node:nas:443"], "deny": ["node:nas:22"]},
		{"src": "node:ghost", "accept": ["node:nas:22"]}
	]}`
	p, err = Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	fails := strings.Join(p.RunTests(explainNodes), "\n")
	for _, want := range []string{"should reach node:nas:443", "should NOT reach node:nas:22", `unknown node "ghost"`} {
		if !strings.Contains(fails, want) {
			t.Errorf("missing failure %q in:\n%s", want, fails)
		}
	}

	if _, err := Parse([]byte(`{"acls":[], "tests":[{"src":"group:admins","accept":["x:1"]}]}`)); err == nil {
		t.Fatal("a group as test source should be rejected")
	}
	if _, err := Parse([]byte(`{"acls":[], "tests":[{"src":"bob"}]}`)); err == nil {
		t.Fatal("a test with no assertions should be rejected")
	}
}
