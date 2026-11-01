package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"10.0.22631", "10.0.9200", 1}, {"0.10", "0.9", 1}, {"v1.2.3", "1.2.3", 0}, {"1.2", "1.2.0", 0},
		{"1.4.0-rc1", "1.4.0", 0}, {"13.6.1", "14", -1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPostures(t *testing.T) {
	p, err := Parse([]byte(`{
		"postures": {
			"posture:current": ["client_version >= 0.4.0", "os in [linux, macos]"],
			"posture:not-windows": ["os not in [windows]"]
		},
		"acls": [
			{"action": "accept", "src": ["*"], "dst": ["node:db:5432"], "src_posture": ["posture:current"]},
			{"action": "accept", "src": ["*"], "dst": ["node:db:22"], "src_posture": ["posture:not-windows"]}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	node := func(id uint64, name, os, client string) Node {
		return Node{ID: id, Name: name, User: "ann", Addrs: []netip.Addr{netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})},
			Posture: map[string]string{"os": os, "client_version": client}}
	}
	nodes := []Node{
		node(1, "db", "linux", "0.4.0"),
		node(2, "new-mac", "macos", "0.4.1"),
		node(3, "old-linux", "linux", "0.3.9"),
		node(4, "win", "windows", "0.5.0"),
		node(5, "unknown", "", ""),
	}
	c := p.Compile(nodes)
	allowed := map[netip.Addr]map[uint16]bool{}
	for _, r := range c.Rules[1] {
		for _, pfx := range r.Src {
			for _, n := range nodes {
				if pfx.Contains(n.Addrs[0]) {
					if allowed[n.Addrs[0]] == nil {
						allowed[n.Addrs[0]] = map[uint16]bool{}
					}
					allowed[n.Addrs[0]][r.Ports[0].First] = true
				}
			}
		}
	}
	for _, want := range []struct {
		id   int
		port uint16
		ok   bool
	}{
		{2, 5432, true}, {3, 5432, false}, {4, 5432, false}, {5, 5432, false},
		{3, 22, true}, {4, 22, false}, {5, 22, false},
	} {
		if got := allowed[nodes[want.id-1].Addrs[0]][want.port]; got != want.ok {
			t.Errorf("%s → db:%d allowed = %v, want %v", nodes[want.id-1].Name, want.port, got, want.ok)
		}
	}
	if !c.CanTalk(2, 1) || c.CanTalk(5, 1) {
		t.Error("peer visibility doesn't follow posture")
	}

	src, _ := Resolve("node:old-linux", nodes)
	dst, _ := Resolve("node:db", nodes)
	ex := p.Explain(src, dst, 5432, nodes)
	if ex.Allowed || !strings.Contains(ex.Reasons[0], "old-linux fails posture:current: its client_version is 0.3.9, not >= 0.4.0") {
		t.Fatalf("explain = %+v", ex)
	}

	for name, src := range map[string]string{
		"unknown attribute": `{"acls":[],"postures":{"posture:x":["disk >= 1"]}}`,
		"bad operator":      `{"acls":[],"postures":{"posture:x":["os ~ linux"]}}`,
		"undefined posture": `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"],"src_posture":["posture:nope"]}]}`,
		"list without []":   `{"acls":[],"postures":{"posture:x":["os in linux"]}}`,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
