// Package dnsserver answers MagicDNS queries for names under the mesh's
// suffix. The OS is configured to send only that suffix here (split DNS),
// so other names are refused rather than forwarded.
package dnsserver

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const ttl = 60

type Server struct {
	log *slog.Logger

	mu      sync.RWMutex
	suffix  string                  // "whale.internal." (lowercase, trailing dot)
	records map[string][]netip.Addr // fqdn with trailing dot -> addrs
}

func New(log *slog.Logger) *Server {
	return &Server{log: log, records: map[string][]netip.Addr{}}
}

// SetRecords replaces the zone. Names are bare node names; suffix is the
// MagicDNS domain.
func (s *Server) SetRecords(suffix string, names map[string][]netip.Addr) {
	suffix = canonical(suffix)
	recs := make(map[string][]netip.Addr, len(names))
	for n, addrs := range names {
		recs[canonical(n)+suffix] = addrs
	}
	s.mu.Lock()
	s.suffix, s.records = suffix, recs
	s.mu.Unlock()
}

func canonical(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" {
		return ""
	}
	return s + "."
}

// Lookup resolves a name, with or without the suffix.
func (s *Server) Lookup(name string) ([]netip.Addr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := canonical(name)
	if a, ok := s.records[n]; ok {
		return a, true
	}
	a, ok := s.records[n+s.suffix]
	return a, ok
}

// Serve answers queries on pc until it is closed.
func (s *Server) Serve(pc net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		resp, ok := s.Handle(buf[:n])
		if ok {
			pc.WriteTo(resp, from)
		}
	}
}

// Handle answers one DNS query message.
func (s *Server) Handle(query []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired}
	name := strings.ToLower(q.Name.String())

	s.mu.RLock()
	inZone := s.suffix != "" && (name == s.suffix || strings.HasSuffix(name, "."+s.suffix))
	addrs, found := s.records[name]
	s.mu.RUnlock()

	switch {
	case !inZone:
		rh.Authoritative = false
		rh.RCode = dnsmessage.RCodeRefused
	case !found && name != s.suffix:
		rh.RCode = dnsmessage.RCodeNameError
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), rh)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	b.Question(q)
	if found && q.Class == dnsmessage.ClassINET {
		b.StartAnswers()
		rrh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		for _, a := range addrs {
			switch {
			case q.Type == dnsmessage.TypeA && a.Is4():
				b.AResource(rrh, dnsmessage.AResource{A: a.As4()})
			case q.Type == dnsmessage.TypeAAAA && a.Is6():
				b.AAAAResource(rrh, dnsmessage.AAAAResource{AAAA: a.As16()})
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}
