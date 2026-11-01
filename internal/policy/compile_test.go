package policy

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/israce"
)

func TestAggregate(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	for _, tc := range []struct{ in, want []netip.Prefix }{
		{pfx("100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32"), pfx("100.64.0.1/32", "100.64.0.2/31")},
		{pfx("10.0.0.0/25", "10.0.0.128/25", "10.0.0.7/32"), pfx("10.0.0.0/24")},
		{pfx("fd00::1/128", "100.64.0.0/32", "fd00::/128"), pfx("100.64.0.0/32", "fd00::/127")},
		{pfx("0.0.0.0/0", "1.2.3.4/32"), pfx("0.0.0.0/0")},
		{pfx("255.255.255.255/32", "255.255.255.254/32"), pfx("255.255.255.254/31")},
	} {
		if got := Aggregate(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("Aggregate(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// Random host sets: the result must cover exactly the same addresses.
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		in := map[netip.Addr]bool{}
		var ps []netip.Prefix
		for i := 0; i < r.Intn(64); i++ {
			a := netip.AddrFrom4([4]byte{100, 64, 0, byte(r.Intn(256))})
			in[a] = true
			ps = append(ps, netip.PrefixFrom(a, 32))
		}
		out := Aggregate(ps)
		for b := 0; b < 256; b++ {
			a := netip.AddrFrom4([4]byte{100, 64, 0, byte(b)})
			covered := false
			for _, p := range out {
				covered = covered || p.Contains(a)
			}
			if covered != in[a] {
				t.Fatalf("round %d: %v covered=%v, want %v (out %v)", round, a, covered, in[a], out)
			}
		}
	}
}

// naivePeers is the obvious pairwise definition the class-based compiler
// must agree with.
func naivePeers(p *Policy, nodes []Node) map[[2]uint64]bool {
	out := map[[2]uint64]bool{}
	link := func(a, b uint64) {
		if a != b {
			out[[2]uint64{a, b}], out[[2]uint64{b, a}] = true, true
		}
	}
	src := func(sels []string) []Node {
		var res []Node
		for _, n := range nodes {
			for _, s := range sels {
				if pfx, err := netip.ParsePrefix(s); err == nil {
					if coveredBy(n.Addrs, []netip.Prefix{pfx}) {
						res = append(res, n)
						break
					}
				} else if p.matches(s, n) {
					res = append(res, n)
					break
				}
			}
		}
		return res
	}
	for _, a := range p.ACLs {
		srcs := src(a.Src)
		for _, d := range a.Dst {
			sel, _, _ := splitDst(d)
			for _, dn := range nodes {
				if p.matchesDst(sel, dn) || len(routedDst(sel, dn.Routes)) > 0 {
					for _, sn := range srcs {
						link(sn.ID, dn.ID)
					}
				}
			}
		}
	}
	for _, r := range p.SSH {
		srcs := src(r.Src)
		for _, dn := range nodes {
			for _, sel := range r.Dst {
				if p.matches(sel, dn) {
					for _, sn := range srcs {
						link(sn.ID, dn.ID)
					}
					break
				}
			}
		}
	}
	return out
}

func TestCompilePeersMatchNaive(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	users := []string{"ann", "ben", "cat", "dan", "eve"}
	for round := 0; round < 100; round++ {
		var nodes []Node
		for i := 0; i < 2+r.Intn(30); i++ {
			n := Node{ID: uint64(i*3 + 1), Name: fmt.Sprintf("n%d", i), User: users[r.Intn(len(users))],
				Addrs: []netip.Addr{netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})}}
			if r.Intn(5) == 0 {
				n.Routes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			}
			nodes = append(nodes, n)
		}
		sels := []string{"*", "ann", "ben", "group:g1", "group:g2", "node:n1", "node:n4", "100.64.0.0/29", "10.0.0.0/16"}
		pick := func() []string {
			var out []string
			for i := 0; i <= r.Intn(2); i++ {
				out = append(out, sels[r.Intn(len(sels))])
			}
			return out
		}
		p := &Policy{Groups: map[string][]string{"group:g1": {"ann", "cat"}, "group:g2": {"eve"}}}
		for i := 0; i < 1+r.Intn(4); i++ {
			var dst []string
			for _, s := range pick() {
				dst = append(dst, s+":80")
			}
			p.ACLs = append(p.ACLs, ACL{Action: "accept", Src: pick(), Dst: dst})
		}
		if r.Intn(2) == 0 {
			p.SSH = append(p.SSH, SSHRule{Action: "accept", Src: pick(), Dst: []string{"node:n2", "ben"}, Users: []string{"root"}})
		}
		want := naivePeers(p, nodes)
		c := p.Compile(nodes)
		for _, a := range nodes {
			var ids []uint64
			for _, b := range nodes {
				if got := c.CanTalk(a.ID, b.ID); got != want[[2]uint64{a.ID, b.ID}] {
					t.Fatalf("round %d: CanTalk(%d, %d) = %v; policy %+v", round, a.ID, b.ID, got, p)
				}
				if want[[2]uint64{a.ID, b.ID}] {
					ids = append(ids, b.ID)
				}
			}
			if got := c.Peers(a.ID); !slices.Equal(got, ids) {
				t.Fatalf("round %d: Peers(%d) = %v, want %v", round, a.ID, got, ids)
			}
			var h uint64
			for _, id := range ids {
				h ^= mix(id)
			}
			if gh, gn := c.PeerSet(a.ID); gh != h || gn != len(ids) {
				t.Fatalf("round %d: PeerSet(%d) = %x/%d, want %x/%d", round, a.ID, gh, gn, h, len(ids))
			}
		}
	}
}

// scaleNodes makes n nodes spread over users in a few groups, with mesh
// addresses handed out in sequence like the store does.
func scaleNodes(n int) ([]Node, *Policy) {
	nodes := make([]Node, n)
	groups := map[string][]string{}
	for i := range nodes {
		user := fmt.Sprintf("user%d", i%500)
		v4 := netip.AddrFrom4([4]byte{100, 64 + byte(i>>16), byte(i >> 8), byte(i)})
		b := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}
		copy(b[12:], v4.AsSlice())
		nodes[i] = Node{ID: uint64(i + 1), Name: fmt.Sprintf("node%d", i), User: user,
			Addrs: []netip.Addr{v4, netip.AddrFrom16(b)}}
		if i < 500 {
			g := fmt.Sprintf("group:team%d", i%20)
			groups[g] = append(groups[g], user)
		}
	}
	acls := []ACL{{Action: "accept", Src: []string{"group:team0"}, Dst: []string{"*:*"}}}
	for t := 1; t < 20; t++ {
		g := fmt.Sprintf("group:team%d", t)
		acls = append(acls, ACL{Action: "accept", Src: []string{g}, Dst: []string{g + ":22,80,443", "node:node1:5432"}})
	}
	return nodes, &Policy{Groups: groups, ACLs: acls}
}

func TestCompileScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	nodes, team := scaleNodes(10000)
	for name, p := range map[string]*Policy{"allow-all": AllowAll(), "teams": team} {
		start := time.Now()
		c := p.Compile(nodes)
		took := time.Since(start)
		t.Logf("%s: compiled 10k nodes in %v, %d peer classes", name, took, len(c.peers))
		if !israce.Enabled && took > 500*time.Millisecond {
			t.Errorf("%s: compile took %v, want < 500ms", name, took)
		}
	}
	// "*" over 10k sequential nodes collapses to a few CIDRs per family.
	c := AllowAll().Compile(nodes)
	if r := c.Rules[1]; len(r) != 1 || len(r[0].Src) > 16 {
		t.Fatalf("allow-all source prefixes = %d, want a handful", len(r[0].Src))
	}
}

func BenchmarkCompile10k(b *testing.B) {
	nodes, p := scaleNodes(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Compile(nodes)
	}
}
