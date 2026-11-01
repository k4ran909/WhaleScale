package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// AccessRule lets sources request temporary access to any of its
// destinations, for up to MaxDuration. Each request is approved by an
// admin unless AutoApprove is set (break-glass access: granted at once,
// but still audited). Approved grants expire on their own.
//
//	{"src": ["group:eng"], "dst": ["node:prod-db:5432"], "max_duration": "4h"}
type AccessRule struct {
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	MaxDuration string   `json:"max_duration,omitempty"`
	AutoApprove bool     `json:"auto_approve,omitempty"`
}

const (
	// DefaultAccessDuration applies when a rule sets no max_duration.
	DefaultAccessDuration = time.Hour
	// MaxAccessDuration caps any rule's max_duration.
	MaxAccessDuration = 7 * 24 * time.Hour
)

// Max is the longest grant the rule allows.
func (r AccessRule) Max() time.Duration {
	if d, err := time.ParseDuration(r.MaxDuration); err == nil && d > 0 {
		return d
	}
	return DefaultAccessDuration
}

func (p *Policy) validateAccessRules() []error {
	var errs []error
	for i, r := range p.AccessRequests {
		where := fmt.Sprintf("access_requests[%d]", i)
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			errs = append(errs, fmt.Errorf("%s: src and dst must not be empty", where))
		}
		for _, s := range r.Src {
			if strings.Contains(s, "/") {
				errs = append(errs, fmt.Errorf("%s src %q: requests come from people and machines, not networks", where, s))
			} else if err := p.checkSelector(s); err != nil {
				errs = append(errs, fmt.Errorf("%s src %q: %w", where, s, err))
			}
		}
		for _, d := range r.Dst {
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
		if r.MaxDuration != "" {
			d, err := time.ParseDuration(r.MaxDuration)
			if err != nil || d <= 0 || d > MaxAccessDuration {
				errs = append(errs, fmt.Errorf("%s: max_duration %q must be a duration like \"4h\", at most %v", where, r.MaxDuration, MaxAccessDuration))
			}
		}
	}
	return errs
}

// Requestable lists the rules node n may make requests under.
func (p *Policy) Requestable(n Node) []AccessRule {
	var out []AccessRule
	for _, r := range p.AccessRequests {
		for _, s := range r.Src {
			if p.matches(s, n) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// covering returns the rules that let node n request dst ("selector:ports"):
// rules listing the selector with ports that include the requested ones.
func (p *Policy) covering(n Node, dst string) ([]AccessRule, error) {
	sel, ports, err := splitDst(dst)
	if err != nil {
		return nil, err
	}
	want, err := parsePorts(ports)
	if err != nil {
		return nil, err
	}
	var out []AccessRule
	for _, r := range p.Requestable(n) {
		for _, rd := range r.Dst {
			rsel, rports, _ := splitDst(rd)
			if have, _ := parsePorts(rports); rsel == sel && portsWithin(want, have) {
				out = append(out, r)
				break
			}
		}
	}
	return out, nil
}

// MaxRequest is the longest grant node n may request for dst, or 0.
func (p *Policy) MaxRequest(n Node, dst string) time.Duration {
	rules, _ := p.covering(n, dst)
	var longest time.Duration
	for _, r := range rules {
		longest = max(longest, r.Max())
	}
	return longest
}

// MatchRequest finds the rule that lets node n request dst for d,
// preferring one that approves automatically.
func (p *Policy) MatchRequest(n Node, dst string, d time.Duration) (AccessRule, error) {
	rules, err := p.covering(n, dst)
	if err != nil {
		return AccessRule{}, err
	}
	var longest time.Duration
	var found *AccessRule
	for i, r := range rules {
		longest = max(longest, r.Max())
		if d <= r.Max() && (found == nil || r.AutoApprove && !found.AutoApprove) {
			found = &rules[i]
		}
	}
	if found != nil {
		return *found, nil
	}
	if longest > 0 {
		return AccessRule{}, fmt.Errorf("%s can be requested for at most %v", dst, longest)
	}
	return AccessRule{}, errors.New("the access policy doesn't let you request " + dst)
}

func portsWithin(want, have []PortRange) bool {
	for _, w := range want {
		ok := false
		for _, h := range have {
			ok = ok || (w.First >= h.First && w.Last <= h.Last)
		}
		if !ok {
			return false
		}
	}
	return true
}
