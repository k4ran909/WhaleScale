package policy

import (
	"math/bits"
	"net/netip"
	"strings"
)

// Compiled is the result of compiling a policy against a set of nodes.
//
// Peer visibility is stored per class of nodes rather than per pair: nodes
// that sit on the same sides of the same ACLs see the same peers, so a
// policy like "*" -> "*" costs one bitset, not N² map entries.
type Compiled struct {
	// Inbound rules for each node, keyed by node ID. Nodes matched by the
	// same ACL share their rules' slices; treat them as read-only.
	Rules map[uint64][]Rule
	// SSH logins each node accepts.
	SSH map[uint64][]CompiledSSH

	ids   []uint64       // node index -> ID
	index map[uint64]int // ID -> node index
	class []int          // node index -> class
	peers []bitset       // class -> node indexes its members may talk to
	hash  []uint64       // class -> set hash of its peers' IDs
	count []int          // class -> number of peers
}

// sshPorts is shared by every rule an SSH grant opens.
var sshPorts = []PortRange{{First: 22, Last: 22}}

// link says every node in a may exchange packets with every node in b.
type link struct{ a, b bitset }

// Compile evaluates the policy against the current set of nodes.
func (p *Policy) Compile(nodes []Node) *Compiled {
	c := &Compiled{Rules: map[uint64][]Rule{}, SSH: map[uint64][]CompiledSSH{},
		ids: make([]uint64, len(nodes)), index: make(map[uint64]int, len(nodes))}
	for i, n := range nodes {
		c.ids[i], c.index[n.ID] = n.ID, i
	}
	m := p.newMatcher(nodes)
	var links []link
	for _, a := range p.ACLs {
		srcSet, srcPrefixes := m.resolveSrc(a.Src, a.SrcPosture)
		if len(srcPrefixes) == 0 {
			continue
		}
		for _, d := range a.Dst {
			sel, portStr, _ := splitDst(d)
			ports, _ := parsePorts(portStr)
			dstSet := newBitset(len(nodes))
			// Per node: its own addresses first, then networks it routes.
			for _, i := range m.dstNodes(sel) {
				c.Rules[nodes[i].ID] = append(c.Rules[nodes[i].ID], Rule{Src: srcPrefixes, Ports: ports})
				dstSet.set(i)
			}
			for _, i := range m.routers {
				if routed := routedDst(sel, nodes[i].Routes); len(routed) > 0 {
					c.Rules[nodes[i].ID] = append(c.Rules[nodes[i].ID], Rule{Src: srcPrefixes, Dst: routed, Ports: ports})
					dstSet.set(i)
				}
			}
			links = addLink(links, srcSet, dstSet)
		}
	}
	// SSH rules: each grants logins and opens TCP 22 from its sources.
	for _, r := range p.SSH {
		srcSet, srcPrefixes := m.resolveSrc(r.Src, r.SrcPosture)
		if len(srcPrefixes) == 0 {
			continue
		}
		dstSet := newBitset(len(nodes))
		for _, sel := range r.Dst {
			for _, i := range m.nodes(sel) {
				dstSet.set(i)
			}
		}
		dstSet.each(func(i int) {
			id := nodes[i].ID
			c.SSH[id] = append(c.SSH[id], CompiledSSH{Src: srcPrefixes, Users: r.Users, Record: r.Record})
			c.Rules[id] = append(c.Rules[id], Rule{Src: srcPrefixes, Ports: sshPorts})
		})
		links = addLink(links, srcSet, dstSet)
	}
	c.buildPeers(links)
	return c
}

// addLink skips links that connect nobody, so they don't split classes.
func addLink(links []link, a, b bitset) []link {
	if a.empty() || b.empty() {
		return links
	}
	return append(links, link{a, b})
}

// buildPeers groups nodes by which side of which links they are on, and
// computes each group's peers once.
func (c *Compiled) buildPeers(links []link) {
	n := len(c.ids)
	c.class = make([]int, n)
	classOf := map[string]int{}
	sig := make([]byte, (2*len(links)+7)/8)
	var reps []int
	for i := 0; i < n; i++ {
		clear(sig)
		for j, l := range links {
			if l.a.has(i) {
				sig[2*j/8] |= 1 << (2 * j % 8)
			}
			if l.b.has(i) {
				sig[(2*j+1)/8] |= 1 << ((2*j + 1) % 8)
			}
		}
		k, ok := classOf[string(sig)]
		if !ok {
			k = len(reps)
			classOf[string(sig)] = k
			reps = append(reps, i)
		}
		c.class[i] = k
	}
	c.peers = make([]bitset, len(reps))
	c.hash = make([]uint64, len(reps))
	c.count = make([]int, len(reps))
	for k, r := range reps {
		set := newBitset(n)
		for _, l := range links {
			if l.a.has(r) {
				set.or(l.b)
			}
			if l.b.has(r) {
				set.or(l.a)
			}
		}
		c.peers[k] = set
		set.each(func(i int) {
			c.hash[k] ^= mix(c.ids[i])
			c.count[k]++
		})
	}
}

// Peers returns the IDs of the nodes id may exchange packets with, in the
// order the nodes were given to Compile.
func (c *Compiled) Peers(id uint64) []uint64 {
	i, ok := c.index[id]
	if !ok {
		return nil
	}
	var out []uint64
	c.peers[c.class[i]].each(func(j int) {
		if j != i {
			out = append(out, c.ids[j])
		}
	})
	return out
}

// CanTalk reports whether nodes a and b may exchange packets.
func (c *Compiled) CanTalk(a, b uint64) bool {
	i, ok1 := c.index[a]
	j, ok2 := c.index[b]
	return ok1 && ok2 && i != j && c.peers[c.class[i]].has(j)
}

// PeerSet summarizes Peers(id) as a count and an order-independent hash of
// the peer IDs, so callers can tell cheaply whether a node's peers changed.
func (c *Compiled) PeerSet(id uint64) (hash uint64, count int) {
	i, ok := c.index[id]
	if !ok {
		return 0, 0
	}
	k := c.class[i]
	hash, count = c.hash[k], c.count[k]
	if c.peers[k].has(i) {
		hash ^= mix(id)
		count--
	}
	return hash, count
}

// mix is splitmix64's finalizer: a cheap, well-spread hash of an ID.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// matcher resolves selectors to node indexes through indexes on user and
// name, so each selector costs what it matches rather than a pass over
// every node. Results are memoized per selector.
type matcher struct {
	p       *Policy
	all     []Node
	byUser  map[string][]int
	byName  map[string][]int
	routers []int // nodes with approved routes
	memo    map[string][]int
	passing map[string]bitset // posture name -> nodes meeting it
}

func (p *Policy) newMatcher(nodes []Node) *matcher {
	m := &matcher{p: p, all: nodes, byUser: map[string][]int{}, byName: map[string][]int{}, memo: map[string][]int{},
		passing: map[string]bitset{}}
	for i, n := range nodes {
		m.byUser[n.User] = append(m.byUser[n.User], i)
		m.byName[n.Name] = append(m.byName[n.Name], i)
		if len(n.Routes) > 0 {
			m.routers = append(m.routers, i)
		}
	}
	return m
}

// nodes returns, in index order, the nodes a user, group, node or "*"
// selector names.
func (m *matcher) nodes(sel string) []int {
	if r, ok := m.memo[sel]; ok {
		return r
	}
	var r []int
	switch {
	case sel == "*":
		r = make([]int, len(m.all))
		for i := range r {
			r[i] = i
		}
	case strings.HasPrefix(sel, "group:"):
		set := newBitset(len(m.all))
		for _, u := range m.p.Groups[sel] {
			for _, i := range m.byUser[u] {
				set.set(i)
			}
		}
		set.each(func(i int) { r = append(r, i) })
	case strings.HasPrefix(sel, "node:"):
		r = m.byName[sel[len("node:"):]]
	default:
		r = m.byUser[sel]
	}
	m.memo[sel] = r
	return r
}

// dstNodes is nodes, plus CIDR selectors matching nodes' own addresses.
func (m *matcher) dstNodes(sel string) []int {
	pfx, err := netip.ParsePrefix(sel)
	if err != nil {
		return m.nodes(sel)
	}
	var r []int
	for i, n := range m.all {
		if coveredBy(n.Addrs, []netip.Prefix{pfx}) {
			r = append(r, i)
		}
	}
	return r
}

// passes reports whether node i meets every named posture.
func (m *matcher) passes(i int, postures []string) bool {
	for _, name := range postures {
		set, ok := m.passing[name]
		if !ok {
			set = newBitset(len(m.all))
			for j, n := range m.all {
				if ok, _ := m.p.Passes(n, []string{name}); ok {
					set.set(j)
				}
			}
			m.passing[name] = set
		}
		if !set.has(i) {
			return false
		}
	}
	return true
}

// resolveSrc turns source selectors into the nodes they cover (named, or
// inside a source CIDR) and the prefixes packets from them may carry,
// merged into as few CIDRs as possible. Named machines that fail a
// posture are left out.
func (m *matcher) resolveSrc(sels, postures []string) (bitset, []netip.Prefix) {
	set := newBitset(len(m.all))
	var cidrs, prefixes []netip.Prefix
	for _, s := range sels {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			cidrs = append(cidrs, pfx.Masked())
			continue
		}
		for _, i := range m.nodes(s) {
			if !set.has(i) && m.passes(i, postures) {
				set.set(i)
				for _, ip := range m.all[i].Addrs {
					prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
		}
	}
	if len(cidrs) > 0 {
		for i, n := range m.all {
			if coveredBy(n.Addrs, cidrs) {
				set.set(i)
			}
		}
	}
	return set, Aggregate(append(prefixes, cidrs...))
}

func coveredBy(addrs []netip.Addr, pfxs []netip.Prefix) bool {
	for _, a := range addrs {
		for _, p := range pfxs {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// bitset is a set of node indexes.
type bitset []uint64

func newBitset(n int) bitset    { return make(bitset, (n+63)/64) }
func (b bitset) set(i int)      { b[i/64] |= 1 << (i % 64) }
func (b bitset) has(i int) bool { return b[i/64]&(1<<(i%64)) != 0 }

func (b bitset) empty() bool {
	for _, w := range b {
		if w != 0 {
			return false
		}
	}
	return true
}

func (b bitset) or(o bitset) {
	for i := range b {
		b[i] |= o[i]
	}
}

func (b bitset) each(f func(int)) {
	for w, word := range b {
		for word != 0 {
			t := bits.TrailingZeros64(word)
			f(w*64 + t)
			word &= word - 1
		}
	}
}
