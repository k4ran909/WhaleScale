package policy

import (
	"net/netip"
	"testing"
	"time"
)

// Policies come from admins, Git repositories and the API: whatever parses
// must compile, explain and answer access questions without panicking.
func FuzzPolicy(f *testing.F) {
	f.Add([]byte(`{"groups":{"group:admins":["alice"]},"acls":[{"action":"accept","src":["group:admins"],"dst":["*:*"]},{"action":"accept","src":["bob"],"dst":["node:nas:445,8000-8100"]}]}`))
	f.Add([]byte(`{"acls":[{"action":"accept","src":["10.0.0.0/8","node:nas"],"dst":["192.168.1.0/24:22","0.0.0.0/0:*"]}],"access_requests":[{"src":["alice"],"dst":["node:nas:7100"],"max_duration":"1h"}],"posture":{"recent":["os_version >= 10"]}}`))
	f.Add([]byte(`{"ssh":[{"action":"accept","src":["alice"],"dst":["node:nas"],"users":["root"]}],"tests":[{"src":"alice","accept":["nas:22"]}]}`))
	f.Fuzz(func(t *testing.T, src []byte) {
		p, err := Parse(src)
		if err != nil {
			return
		}
		nodes := append([]Node{{ID: 4, Name: "gw", User: "bob", Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
			Routes:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.0.0.0/8")},
			Posture: map[string]string{"os": "linux", "os_version": "6.1"}}}, testNodes...)
		p.Compile(nodes)
		alice := Identity{User: "alice", Node: "alice-pc", Addrs: testNodes[0].Addrs}
		nas := Identity{User: "alice", Node: "nas", Addrs: testNodes[2].Addrs}
		p.Explain(alice, nas, 22, nodes)
		p.Explain(nas, Identity{Addrs: []netip.Addr{netip.MustParseAddr("10.1.2.3")}}, 443, nodes)
		for _, n := range nodes {
			p.Requestable(n)
			p.MaxRequest(n, "node:nas:7100")
			p.MatchRequest(n, "node:nas:7100", time.Hour)
		}
		for i := range p.ACLs {
			p.RuleText(i)
		}
	})
}
