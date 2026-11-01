package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Postures are named lists of conditions a machine must meet, used by
// rules' src_posture:
//
//	"postures": {"posture:current": ["client_version >= 0.4.0", "os in [linux, macos, windows]"]}
//
// A condition is "<attribute> <op> <value>". Attributes are what machines
// report: os, os_version, client_version. Ops are ==, !=, >=, >, <=, <
// (versions compare numerically, part by part) and in / not in with a
// [list]. A machine that doesn't report an attribute fails every
// condition on it.

// PostureAttrs are the attributes conditions may test.
var PostureAttrs = []string{"os", "os_version", "client_version"}

type condition struct {
	attr, op string
	values   []string
}

func parseCondition(s string) (condition, error) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return condition{}, fmt.Errorf("condition %q must look like \"client_version >= 0.4.0\"", s)
	}
	c := condition{attr: f[0], op: f[1]}
	rest := f[2:]
	if c.op == "not" && f[2] == "in" {
		c.op, rest = "not in", f[3:]
	}
	if !slices.Contains(PostureAttrs, c.attr) {
		return condition{}, fmt.Errorf("condition %q: unknown attribute %q (known: %s)", s, c.attr, strings.Join(PostureAttrs, ", "))
	}
	value := strings.Join(rest, " ")
	switch c.op {
	case "==", "!=", ">=", ">", "<=", "<":
		if value == "" {
			return condition{}, fmt.Errorf("condition %q: missing value", s)
		}
		c.values = []string{value}
	case "in", "not in":
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			return condition{}, fmt.Errorf("condition %q: %s needs a [list]", s, c.op)
		}
		for _, v := range strings.Split(value[1:len(value)-1], ",") {
			if v = strings.TrimSpace(v); v != "" {
				c.values = append(c.values, v)
			}
		}
		if len(c.values) == 0 {
			return condition{}, fmt.Errorf("condition %q: empty list", s)
		}
	default:
		return condition{}, fmt.Errorf("condition %q: unknown operator %q", s, c.op)
	}
	return c, nil
}

// eval reports whether n meets c, and if not, why.
func (c condition) eval(n Node) (bool, string) {
	have := n.Posture[c.attr]
	if have == "" {
		return false, fmt.Sprintf("it doesn't report %s", c.attr)
	}
	var ok bool
	switch c.op {
	case "in":
		ok = slices.Contains(c.values, have)
	case "not in":
		ok = !slices.Contains(c.values, have)
	case "==":
		ok = have == c.values[0]
	case "!=":
		ok = have != c.values[0]
	default:
		cmp := compareVersions(have, c.values[0])
		ok = map[string]bool{">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0}[c.op]
	}
	if ok {
		return true, ""
	}
	want := strings.Join(c.values, ", ")
	if strings.HasSuffix(c.op, "in") {
		want = "[" + want + "]"
	}
	return false, fmt.Sprintf("its %s is %s, not %s %s", c.attr, have, c.op, want)
}

// compareVersions compares dotted versions numerically: "10.0.22631" >
// "10.0.9200", "0.10" > "0.9". Non-numeric parts ("-rc1", a leading "v")
// are ignored; missing parts count as 0.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func (p *Policy) validatePostures() []error {
	var errs []error
	for name, conds := range p.Postures {
		if !strings.HasPrefix(name, "posture:") || name == "posture:" {
			errs = append(errs, fmt.Errorf("posture %q: name must look like posture:NAME", name))
		}
		if len(conds) == 0 {
			errs = append(errs, fmt.Errorf("posture %q: no conditions", name))
		}
		for _, c := range conds {
			if _, err := parseCondition(c); err != nil {
				errs = append(errs, fmt.Errorf("posture %q: %w", name, err))
			}
		}
	}
	check := func(where string, names []string) {
		for _, n := range names {
			if _, ok := p.Postures[n]; !ok {
				errs = append(errs, fmt.Errorf("%s src_posture: undefined posture %q", where, n))
			}
		}
	}
	for i, a := range p.ACLs {
		check(fmt.Sprintf("acls[%d]", i), a.SrcPosture)
	}
	for i, r := range p.SSH {
		check(fmt.Sprintf("ssh[%d]", i), r.SrcPosture)
	}
	return errs
}

// Passes reports whether n meets every named posture, and if not, why.
func (p *Policy) Passes(n Node, postures []string) (bool, string) {
	for _, name := range postures {
		for _, s := range p.Postures[name] {
			c, err := parseCondition(s)
			if err != nil {
				return false, err.Error()
			}
			if ok, why := c.eval(n); !ok {
				return false, fmt.Sprintf("%s fails %s: %s", n.Name, name, why)
			}
		}
	}
	return true, ""
}
