package policy

import (
	"net/netip"
	"strings"
	"testing"
)

var testNodes = []Node{
	{ID: 1, Name: "alice-pc", User: "alice", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
	{ID: 2, Name: "bob-pc", User: "bob", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
	{ID: 3, Name: "nas", User: "alice", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.3")}},
}

func TestParseErrors(t *testing.T) {
	for name, src := range map[string]string{
		"unknown field":   `{"acl": []}`,
		"bad action":      `{"acls":[{"action":"allow","src":["*"],"dst":["*:*"]}]}`,
		"undefined group": `{"acls":[{"action":"accept","src":["group:x"],"dst":["*:*"]}]}`,
		"missing ports":   `{"acls":[{"action":"accept","src":["*"],"dst":["alice"]}]}`,
		"bad port range":  `{"acls":[{"action":"accept","src":["*"],"dst":["*:90-80"]}]}`,
		"bad prefix":      `{"acls":[{"action":"accept","src":["tag:x"],"dst":["*:*"]}]}`,
		"bad cidr":        `{"acls":[{"action":"accept","src":["10.0.0.0/99"],"dst":["*:*"]}]}`,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCompile(t *testing.T) {
	p, err := Parse([]byte(`{
		"groups": {"group:admins": ["alice"]},
		"acls": [
			{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
			{"action": "accept", "src": ["bob"], "dst": ["node:nas:445,8000-8100"]}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	c := p.Compile(testNodes)

	if !c.Peers[2][3] || !c.Peers[3][2] {
		t.Fatal("bob and nas should be peers")
	}
	if !c.Peers[1][2] {
		t.Fatal("alice-pc should see bob-pc (admins -> *)")
	}

	// nas gets: admins rule (all ports) + bob rule (445, 8000-8100).
	rules := c.Rules[3]
	if len(rules) != 2 {
		t.Fatalf("nas rules = %+v", rules)
	}
	bobRule := rules[1]
	if bobRule.Src[0] != netip.MustParsePrefix("100.64.0.2/32") || len(bobRule.Ports) != 2 || bobRule.Ports[1] != (PortRange{8000, 8100}) {
		t.Fatalf("bob rule = %+v", bobRule)
	}
	// alice-pc only accepts from admins, so nothing from bob.
	for _, r := range c.Rules[1] {
		for _, s := range r.Src {
			if s.Contains(netip.MustParseAddr("100.64.0.2")) {
				t.Fatal("alice-pc must not accept from bob")
			}
		}
	}
}

func TestAllowAll(t *testing.T) {
	c := AllowAll().Compile(testNodes)
	for _, n := range testNodes {
		if len(c.Peers[n.ID]) != len(testNodes)-1 {
			t.Fatalf("node %d peers = %v", n.ID, c.Peers[n.ID])
		}
	}
}

func TestLint(t *testing.T) {
	p, _ := Parse([]byte(`{"groups":{"group:g":["carol"]},"acls":[{"action":"accept","src":["dave"],"dst":["*:*"]}]}`))
	w := strings.Join(p.Lint([]string{"alice"}), "\n")
	if !strings.Contains(w, `"carol"`) || !strings.Contains(w, `"dave"`) {
		t.Fatalf("lint = %s", w)
	}
}
