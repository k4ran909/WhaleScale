package policy

import (
	"net/netip"
	"sort"
)

// Aggregate returns the smallest list of CIDRs covering exactly the same
// addresses as in. Mesh addresses are handed out in sequence, so a source
// like "*" over 10,000 nodes collapses from 20,000 host prefixes to a
// handful, which keeps packet filters and network maps small.
func Aggregate(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	type span struct{ from, to netip.Addr }
	spans := make([]span, 0, len(in))
	for _, p := range in {
		p = p.Masked()
		spans = append(spans, span{p.Addr(), lastAddr(p)})
	}
	// Addr.Less sorts IPv4 before IPv6, so families never interleave.
	sort.Slice(spans, func(i, j int) bool { return spans[i].from.Less(spans[j].from) })
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.from.BitLen() == last.to.BitLen() && (s.from.Compare(last.to) <= 0 || last.to.Next() == s.from) {
			if s.to.Compare(last.to) > 0 {
				last.to = s.to
			}
			continue
		}
		merged = append(merged, s)
	}
	var out []netip.Prefix
	for _, s := range merged {
		out = appendRange(out, s.from, s.to)
	}
	return out
}

// appendRange appends the minimal CIDRs covering from..to (inclusive).
func appendRange(out []netip.Prefix, from, to netip.Addr) []netip.Prefix {
	for {
		// The biggest block that starts at from and ends by to.
		p := netip.PrefixFrom(from, from.BitLen())
		for b := 0; b < from.BitLen(); b++ {
			c := netip.PrefixFrom(from, b)
			if c.Masked().Addr() == from && lastAddr(c).Compare(to) <= 0 {
				p = c
				break
			}
		}
		out = append(out, p)
		end := lastAddr(p)
		if end.Compare(to) >= 0 {
			return out
		}
		from = end.Next()
	}
}

// lastAddr is the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
