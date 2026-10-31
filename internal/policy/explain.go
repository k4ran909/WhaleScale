package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Test asserts what a source may and may not reach. It lives in the
// policy file's "tests" list; a policy that fails its own tests is not
// applied.
//
//	{"src": "guest", "accept": ["node:nas:445"], "deny": ["karan:22"]}
//
// src is a user, node:NAME or an IP; accept and deny entries are
// "<user|node:NAME|IP>:<port>".
type Test struct {
	Src    string   `json:"src"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// Identity is one side of a connection, as specific as what is known:
// a user (any of their devices), a node, or a bare address.
type Identity struct {
	User  string
	Node  string
	Addrs []netip.Addr
}

func (id Identity) String() string {
	switch {
	case id.Node != "":
		return "node:" + id.Node
	case id.User != "":
		return id.User
	case len(id.Addrs) > 0:
		return id.Addrs[0].String()
	}
	return "?"
}

// Resolve turns "karan", "node:nas" or "100.64.0.5" into an identity,
// filling in a node's owner and addresses from nodes.
func Resolve(s string, nodes []Node) (Identity, error) {
	switch {
	case strings.HasPrefix(s, "node:"):
		name := s[len("node:"):]
		for _, n := range nodes {
			if n.Name == name {
				return Identity{User: n.User, Node: n.Name, Addrs: n.Addrs}, nil
			}
		}
		return Identity{}, fmt.Errorf("unknown node %q", name)
	case strings.HasPrefix(s, "group:"), s == "*", strings.Contains(s, "/"):
		return Identity{}, fmt.Errorf("%q is not a single source or destination; use a user, node:NAME or an IP", s)
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		for _, n := range nodes {
			for _, a := range n.Addrs {
				if a == ip {
					return Identity{User: n.User, Node: n.Name, Addrs: n.Addrs}, nil
				}
			}
		}
		return Identity{Addrs: []netip.Addr{ip}}, nil
	}
	if s == "" || strings.Contains(s, ":") {
		return Identity{}, fmt.Errorf("bad identity %q", s)
	}
	return Identity{User: s}, nil
}

// ResolveDst splits "<identity>:<port>" (IPv6 as "[addr]:port").
func ResolveDst(s string, nodes []Node) (Identity, uint16, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return Identity{}, 0, fmt.Errorf("%q must be <destination>:<port>", s)
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return Identity{}, 0, fmt.Errorf("%q: bad port", s)
	}
	id, err := Resolve(strings.Trim(s[:i], "[]"), nodes)
	return id, uint16(port), err
}

func (p *Policy) matchesIdentity(sel string, id Identity) bool {
	switch {
	case sel == "*":
		return true
	case strings.HasPrefix(sel, "group:"):
		for _, m := range p.Groups[sel] {
			if id.User != "" && m == id.User {
				return true
			}
		}
		return false
	case strings.HasPrefix(sel, "node:"):
		return id.Node != "" && id.Node == sel[len("node:"):]
	case strings.Contains(sel, "/"):
		pfx, err := netip.ParsePrefix(sel)
		if err != nil {
			return false
		}
		for _, a := range id.Addrs {
			if pfx.Contains(a) {
				return true
			}
		}
		return false
	default:
		return id.User != "" && id.User == sel
	}
}

// Explanation says whether src may open connections to dst:port, and why.
type Explanation struct {
	Allowed bool
	// Rule is the index in acls of the granting rule, or -1.
	Rule int
	// Reasons explains the verdict: the granting rule, or near misses.
	Reasons []string
}

// RuleText renders acls[i] for messages.
func (p *Policy) RuleText(i int) string {
	a := p.ACLs[i]
	return fmt.Sprintf("acls[%d]: %s → %s", i, strings.Join(a.Src, ", "), strings.Join(a.Dst, ", "))
}

// Explain evaluates the policy for one connection. nodes are used to
// check that a subnet address is actually served by an approved router.
func (p *Policy) Explain(src, dst Identity, port uint16, nodes []Node) Explanation {
	ex := Explanation{Rule: -1}
	// Near misses: a rule for this pair on other ports is the most likely
	// fix, so those come before rules that only lack the source.
	var portMiss, srcMiss []string
	for i, a := range p.ACLs {
		srcOK := false
		for _, s := range a.Src {
			srcOK = srcOK || p.matchesIdentity(s, src)
		}
		for _, d := range a.Dst {
			sel, portStr, err := splitDst(d)
			if err != nil {
				continue
			}
			ports, _ := parsePorts(portStr)
			dstOK := p.matchesIdentity(sel, dst)
			portOK := false
			for _, pr := range ports {
				portOK = portOK || (port >= pr.First && port <= pr.Last)
			}
			switch {
			case srcOK && dstOK && portOK:
				if !ex.Allowed {
					ex.Allowed, ex.Rule = true, i
					ex.Reasons = []string{"allowed by " + p.RuleText(i) + " (destination " + d + ")"}
				}
			case srcOK && dstOK:
				portMiss = append(portMiss, fmt.Sprintf("%s covers %s → %s but only ports %s", p.RuleText(i), src, dst, portStr))
			case !srcOK && dstOK && portOK:
				srcMiss = append(srcMiss, fmt.Sprintf("%s would allow it for sources %s", p.RuleText(i), strings.Join(a.Src, ", ")))
			}
		}
	}
	if ex.Allowed {
		ex.Reasons = ex.Reasons[:1]
		if dst.Node == "" && len(dst.Addrs) > 0 && !servedByRouter(dst.Addrs[0], nodes) {
			ex.Reasons = append(ex.Reasons, fmt.Sprintf("but no approved subnet router or exit node serves %s, so packets have nowhere to go", dst.Addrs[0]))
		}
		return ex
	}
	ex.Reasons = append(portMiss, srcMiss...)
	if len(ex.Reasons) == 0 {
		ex.Reasons = []string{fmt.Sprintf("no rule lets %s reach %s on port %d", src, dst, port)}
	}
	ex.Reasons = append(ex.Reasons, "replies to connections "+dst.String()+" opens to "+src.String()+" are still allowed")
	return ex
}

func servedByRouter(a netip.Addr, nodes []Node) bool {
	for _, n := range nodes {
		for _, r := range n.Routes {
			if r.Contains(a) {
				return true
			}
		}
	}
	return false
}

func (t Test) validate() error {
	if t.Src == "" || len(t.Accept)+len(t.Deny) == 0 {
		return errors.New("needs src and at least one accept or deny entry")
	}
	if _, err := Resolve(t.Src, nil); err != nil && !strings.HasPrefix(t.Src, "node:") {
		return err
	}
	for _, d := range append(append([]string{}, t.Accept...), t.Deny...) {
		if _, _, err := ResolveDst(d, nil); err != nil && !strings.HasPrefix(d, "node:") {
			return err
		}
	}
	return nil
}

// RunTests evaluates the policy's own tests against the current nodes and
// returns one message per failure.
func (p *Policy) RunTests(nodes []Node) []string {
	var fails []string
	for i, t := range p.Tests {
		where := fmt.Sprintf("tests[%d]", i)
		src, err := Resolve(t.Src, nodes)
		if err != nil {
			fails = append(fails, fmt.Sprintf("%s src: %v", where, err))
			continue
		}
		check := func(entry string, want bool) {
			dst, port, err := ResolveDst(entry, nodes)
			if err != nil {
				fails = append(fails, fmt.Sprintf("%s %q: %v", where, entry, err))
				return
			}
			ex := p.Explain(src, dst, port, nodes)
			switch {
			case want && !ex.Allowed:
				fails = append(fails, fmt.Sprintf("%s: %s should reach %s, but %s", where, t.Src, entry, ex.Reasons[0]))
			case !want && ex.Allowed:
				fails = append(fails, fmt.Sprintf("%s: %s should NOT reach %s, but it is %s", where, t.Src, entry, ex.Reasons[0]))
			}
		}
		for _, a := range t.Accept {
			check(a, true)
		}
		for _, d := range t.Deny {
			check(d, false)
		}
	}
	return fails
}
