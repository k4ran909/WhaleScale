// Package policy parses access policies and compiles them into per-node
// packet filters and peer visibility.
//
// Policy file (JSON):
//
//	{
//	  "groups": { "group:admins": ["alice"] },
//	  "acls": [
//	    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
//	    { "action": "accept", "src": ["bob"], "dst": ["node:nas:445,8000-8100"] }
//	  ]
//	}
//
// Selectors: "*", a user name, "group:NAME", "node:NAME" or an IPv4/IPv6
// CIDR. A dst entry is "<selector>:<ports>" where ports is "*", "22",
// "80-90" or a comma-separated list. Without a policy everything is allowed.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type Policy struct {
	Groups map[string][]string `json:"groups,omitempty"`
	ACLs   []ACL               `json:"acls"`
	Tests  []Test              `json:"tests,omitempty"`
	SSH    []SSHRule           `json:"ssh,omitempty"`
	// DeviceLimits caps how many machines a user may register, keyed by
	// user, "group:NAME" or "*". See DeviceLimit.
	DeviceLimits map[string]int `json:"device_limits,omitempty"`
}

// SSHRule lets sources log in to destination machines over SSH as the
// listed local users, with no keys or passwords: the mesh identity is the
// credential. "$user" means the connecting person's own mesh user name.
//
//	{"action": "accept", "src": ["group:admins"], "dst": ["node:nas"],
//	 "users": ["karan", "root"], "record": true}
type SSHRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Users  []string `json:"users"`
	// Record captures sessions and uploads them to the server.
	Record bool `json:"record,omitempty"`
}

// SelfUser in SSHRule.Users stands for the connecting mesh user's name.
const SelfUser = "$user"

var localUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// CompiledSSH is an SSH rule as it applies to one destination node.
type CompiledSSH struct {
	Src    []netip.Prefix
	Users  []string
	Record bool
}

type ACL struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// AllowAll is the default policy when none is configured.
func AllowAll() *Policy {
	return &Policy{ACLs: []ACL{{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}}}}
}

// Parse decodes and validates a policy. Unknown fields are rejected so that
// typos fail loudly instead of silently granting or denying access.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	var errs []error
	for g, members := range p.Groups {
		if !strings.HasPrefix(g, "group:") || len(g) == len("group:") {
			errs = append(errs, fmt.Errorf("group %q: name must look like group:NAME", g))
		}
		for _, m := range members {
			if strings.Contains(m, ":") {
				errs = append(errs, fmt.Errorf("group %q: member %q must be a user name", g, m))
			}
		}
	}
	for i, a := range p.ACLs {
		where := fmt.Sprintf("acls[%d]", i)
		if a.Action != "accept" {
			errs = append(errs, fmt.Errorf("%s: action must be \"accept\", got %q", where, a.Action))
		}
		if len(a.Src) == 0 || len(a.Dst) == 0 {
			errs = append(errs, fmt.Errorf("%s: src and dst must not be empty", where))
		}
		for _, s := range a.Src {
			if err := p.checkSelector(s); err != nil {
				errs = append(errs, fmt.Errorf("%s src %q: %w", where, s, err))
			}
		}
		for _, d := range a.Dst {
			sel, ports, err := splitDst(d)
			if err == nil {
				err = p.checkSelector(sel)
			}
			if err == nil {
				_, err = parsePorts(ports)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s dst %q: %w", where, d, err))
			}
		}
	}
	for i, t := range p.Tests {
		if err := t.validate(); err != nil {
			errs = append(errs, fmt.Errorf("tests[%d]: %w", i, err))
		}
	}
	for i, r := range p.SSH {
		where := fmt.Sprintf("ssh[%d]", i)
		if r.Action != "accept" {
			errs = append(errs, fmt.Errorf("%s: action must be \"accept\", got %q", where, r.Action))
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 || len(r.Users) == 0 {
			errs = append(errs, fmt.Errorf("%s: src, dst and users must not be empty", where))
		}
		for _, sel := range r.Src {
			if err := p.checkSelector(sel); err != nil {
				errs = append(errs, fmt.Errorf("%s src %q: %w", where, sel, err))
			}
		}
		for _, sel := range r.Dst {
			if strings.Contains(sel, "/") {
				errs = append(errs, fmt.Errorf("%s dst %q: SSH destinations are machines (a user, group:NAME, node:NAME or *), not networks", where, sel))
			} else if err := p.checkSelector(sel); err != nil {
				errs = append(errs, fmt.Errorf("%s dst %q: %w", where, sel, err))
			}
		}
		for _, u := range r.Users {
			if u != SelfUser && !localUserRe.MatchString(u) {
				errs = append(errs, fmt.Errorf("%s user %q: not a valid local user name (or \"$user\")", where, u))
			}
		}
	}
	for sel, n := range p.DeviceLimits {
		where := fmt.Sprintf("device_limits[%q]", sel)
		switch {
		case n < 0:
			errs = append(errs, fmt.Errorf("%s: must not be negative", where))
		case strings.HasPrefix(sel, "node:") || strings.Contains(sel, "/"):
			errs = append(errs, fmt.Errorf("%s: limits apply to users, groups or \"*\"", where))
		default:
			if err := p.checkSelector(sel); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", where, err))
			}
		}
	}
	return errors.Join(errs...)
}

// DeviceLimit returns how many machines user may register: their own
// entry if there is one, else the most generous of their groups', else
// "*". ok is false when no limit applies.
func (p *Policy) DeviceLimit(user string) (limit int, ok bool) {
	if n, found := p.DeviceLimits[user]; found {
		return n, true
	}
	limit = -1
	for sel, n := range p.DeviceLimits {
		if strings.HasPrefix(sel, "group:") && n > limit && slices.Contains(p.Groups[sel], user) {
			limit = n
		}
	}
	if limit >= 0 {
		return limit, true
	}
	n, found := p.DeviceLimits["*"]
	return n, found
}

func (p *Policy) checkSelector(s string) error {
	switch {
	case s == "*":
	case strings.HasPrefix(s, "group:"):
		if _, ok := p.Groups[s]; !ok {
			return errors.New("undefined group")
		}
	case strings.HasPrefix(s, "node:"):
		if len(s) == len("node:") {
			return errors.New("empty node name")
		}
	case strings.Contains(s, "/"):
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("bad CIDR: %w", err)
		}
	case strings.Contains(s, ":"):
		return errors.New("unknown selector prefix")
	case s == "":
		return errors.New("empty selector")
	}
	return nil
}

// Lint reports references that are valid syntax but match nothing today,
// such as a user with no account. They are warnings, not errors.
func (p *Policy) Lint(users []string) []string {
	known := map[string]bool{}
	for _, u := range users {
		known[u] = true
	}
	var warn []string
	check := func(where, sel string) {
		if sel == "*" || strings.Contains(sel, ":") || strings.Contains(sel, "/") {
			return
		}
		if !known[sel] {
			warn = append(warn, fmt.Sprintf("%s: user %q does not exist", where, sel))
		}
	}
	for g, members := range p.Groups {
		for _, m := range members {
			check("groups."+g, m)
		}
	}
	for sel := range p.DeviceLimits {
		check("device_limits", sel)
	}
	for i, a := range p.ACLs {
		for _, s := range a.Src {
			check(fmt.Sprintf("acls[%d].src", i), s)
		}
		for _, d := range a.Dst {
			sel, _, _ := splitDst(d)
			check(fmt.Sprintf("acls[%d].dst", i), sel)
		}
	}
	sort.Strings(warn)
	return warn
}

// splitDst splits "selector:ports" at the last colon, so IPv6 CIDRs work:
// "fd00::/8:443".
func splitDst(d string) (sel, ports string, err error) {
	i := strings.LastIndexByte(d, ':')
	if i <= 0 || i == len(d)-1 {
		return "", "", errors.New(`must be "<selector>:<ports>"`)
	}
	return d[:i], d[i+1:], nil
}

type PortRange struct{ First, Last uint16 }

var AllPorts = []PortRange{{0, 65535}}

func parsePorts(s string) ([]PortRange, error) {
	if s == "*" {
		return AllPorts, nil
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		last := first
		if isRange {
			if last, err = strconv.ParseUint(hi, 10, 16); err != nil || last < first {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		out = append(out, PortRange{uint16(first), uint16(last)})
	}
	return out, nil
}

// Node is the subset of node data the compiler needs.
type Node struct {
	ID    uint64
	Name  string
	User  string
	Addrs []netip.Addr
	// Routes are approved subnets (or 0.0.0.0/0, ::/0) the node forwards to.
	Routes []netip.Prefix
}

// Rule allows packets from any Src prefix to the listed ports. Dst empty
// means the node's own addresses; otherwise the routed prefixes listed.
type Rule struct {
	Src   []netip.Prefix
	Dst   []netip.Prefix
	Ports []PortRange
}

func (p *Policy) matches(sel string, n Node) bool {
	switch {
	case sel == "*":
		return true
	case strings.HasPrefix(sel, "group:"):
		for _, m := range p.Groups[sel] {
			if m == n.User {
				return true
			}
		}
		return false
	case strings.HasPrefix(sel, "node:"):
		return n.Name == sel[len("node:"):]
	default:
		return n.User == sel
	}
}

func (p *Policy) matchesDst(sel string, n Node) bool {
	if pfx, err := netip.ParsePrefix(sel); err == nil {
		for _, a := range n.Addrs {
			if pfx.Contains(a) {
				return true
			}
		}
		return false
	}
	return p.matches(sel, n)
}

// routedDst returns the part of a node's routes a dst selector grants: all
// of them for "*", the overlap for a CIDR, none for user/group/node
// selectors (those name devices, not the networks behind them).
func routedDst(sel string, routes []netip.Prefix) []netip.Prefix {
	if len(routes) == 0 {
		return nil
	}
	if sel == "*" {
		return routes
	}
	cidr, err := netip.ParsePrefix(sel)
	if err != nil {
		return nil
	}
	cidr = cidr.Masked()
	var out []netip.Prefix
	for _, r := range routes {
		if !r.Overlaps(cidr) {
			continue
		}
		if r.Bits() >= cidr.Bits() {
			out = append(out, r)
		} else {
			out = append(out, cidr)
		}
	}
	return out
}
