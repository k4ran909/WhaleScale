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

	if !c.CanTalk(2, 3) || !c.CanTalk(3, 2) {
		t.Fatal("bob and nas should be peers")
	}
	if !c.CanTalk(1, 2) {
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
		if len(c.Peers(n.ID)) != len(testNodes)-1 {
			t.Fatalf("node %d peers = %v", n.ID, c.Peers(n.ID))
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

func TestRoutedSubnets(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.1.0/24")
	nodes := []Node{
		{ID: 1, Name: "laptop", User: "bob", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{ID: 2, Name: "router", User: "alice", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}, Routes: []netip.Prefix{lan}},
	}
	p, err := Parse([]byte(`{"acls":[{"action":"accept","src":["bob"],"dst":["192.168.1.10/32:22"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := p.Compile(nodes)
	rules := c.Rules[2]
	if len(rules) != 1 || len(rules[0].Dst) != 1 || rules[0].Dst[0] != netip.MustParsePrefix("192.168.1.10/32") {
		t.Fatalf("router rules = %+v", rules)
	}
	if !c.CanTalk(1, 2) {
		t.Fatal("laptop must see the router to reach the subnet")
	}
	// A user selector grants the router's own addresses, not its subnet.
	p, _ = Parse([]byte(`{"acls":[{"action":"accept","src":["bob"],"dst":["alice:*"]}]}`))
	for _, r := range p.Compile(nodes).Rules[2] {
		if len(r.Dst) > 0 {
			t.Fatalf("user selector granted routed subnet: %+v", r)
		}
	}
	// Allow-all covers routed subnets.
	var sawRouted bool
	for _, r := range AllowAll().Compile(nodes).Rules[2] {
		sawRouted = sawRouted || (len(r.Dst) == 1 && r.Dst[0] == lan)
	}
	if !sawRouted {
		t.Fatal("allow-all should cover routed subnets")
	}
}

func TestSSHRules(t *testing.T) {
	p, err := Parse([]byte(`{
		"groups": {"group:admins": ["alice"]},
		"acls": [],
		"ssh": [{"action": "accept", "src": ["group:admins"], "dst": ["node:nas"], "users": ["root", "$user"], "record": true}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	c := p.Compile(testNodes)
	ssh := c.SSH[3] // nas
	if len(ssh) != 1 || !ssh[0].Record || ssh[0].Users[1] != SelfUser || ssh[0].Src[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("nas ssh rules = %+v", ssh)
	}
	if len(c.SSH[2]) != 0 {
		t.Fatal("bob-pc got an ssh rule it was not named in")
	}
	// The rule opens TCP 22 (only) from the admins, and makes them peers.
	var opened bool
	for _, r := range c.Rules[3] {
		opened = opened || (len(r.Ports) == 1 && r.Ports[0] == PortRange{First: 22, Last: 22})
	}
	if !opened || !c.CanTalk(1, 3) {
		t.Fatalf("ssh rule did not open port 22: %+v", c.Rules[3])
	}

	for name, src := range map[string]string{
		"cidr dst":   `{"acls":[],"ssh":[{"action":"accept","src":["*"],"dst":["10.0.0.0/8"],"users":["root"]}]}`,
		"no users":   `{"acls":[],"ssh":[{"action":"accept","src":["*"],"dst":["*"],"users":[]}]}`,
		"bad user":   `{"acls":[],"ssh":[{"action":"accept","src":["*"],"dst":["*"],"users":["Root; rm -rf"]}]}`,
		"bad action": `{"acls":[],"ssh":[{"action":"check","src":["*"],"dst":["*"],"users":["root"]}]}`,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
