// Package dnsserver answers MagicDNS queries for names under the mesh's
// suffix. Usually the OS sends only that suffix here (split DNS) and other
// names are refused; with a Forwarder (a machine using an exit node, or an
// exit node answering for its clients) they are forwarded.
package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const ttl = 60

// maxInFlight bounds queries being answered at once; more are dropped
// (clients retry).
const maxInFlight = 64

type Server struct {
	log *slog.Logger

	mu      sync.RWMutex
	suffix  string                  // "whale.internal." (lowercase, trailing dot)
	records map[string][]netip.Addr // fqdn with trailing dot -> addrs
	fwd     Forwarder
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
	sem := make(chan struct{}, maxInFlight)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			continue
		}
		query := slices.Clone(buf[:n])
		var src netip.Addr
		if ua, ok := from.(*net.UDPAddr); ok {
			src = ua.AddrPort().Addr().Unmap()
		}
		// Forwarded queries take a round trip: answer each on its own.
		go func() {
			defer func() { <-sem }()
			if resp, ok := s.HandleFrom(context.Background(), src, query); ok {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

// Handle answers one DNS query message.
func (s *Server) Handle(query []byte) ([]byte, bool) {
	return s.HandleFrom(context.Background(), netip.Addr{}, query)
}

// meshReverse reports whether name is a reverse lookup (PTR) inside the
// mesh range 100.64.0.0/10, e.g. "1.0.64.100.in-addr.arpa.". Those are
// answered here (as unknown names) rather than forwarded: no outside
// server knows them, and waiting for one to time out makes tools that look
// up every address (ping) stall. This matters where every lookup comes
// here, as on Android.
func meshReverse(name string) bool {
	rest, ok := strings.CutSuffix(name, ".in-addr.arpa.")
	if !ok {
		return false
	}
	labels := strings.Split(rest, ".")
	n := len(labels)
	if n < 2 || labels[n-1] != "100" {
		return false
	}
	second := 0
	for _, c := range labels[n-2] {
		if c < '0' || c > '9' || second > 255 {
			return false
		}
		second = second*10 + int(c-'0')
	}
	return second >= 64 && second <= 127
}

// HandleFrom answers one DNS query message from src, forwarding names
// outside the mesh if there is a Forwarder.
func (s *Server) HandleFrom(ctx context.Context, src netip.Addr, query []byte) ([]byte, bool) {
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
	inZone := s.suffix != "" && (name == s.suffix || strings.HasSuffix(name, "."+s.suffix)) || meshReverse(name)
	addrs, found := s.records[name]
	fwd := s.fwd
	s.mu.RUnlock()

	if !inZone && fwd != nil {
		resp, err := fwd(ctx, src, query)
		if err == nil {
			return resp, true
		}
		if !errors.Is(err, ErrRefused) {
			s.log.Debug("forward DNS query", "name", name, "err", err)
			rh.Authoritative, rh.RecursionAvailable = false, true
			rh.RCode = dnsmessage.RCodeServerFailure
			return s.empty(rh, q)
		}
	}
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

// empty is a response with no answers.
func (s *Server) empty(rh dnsmessage.Header, q dnsmessage.Question) ([]byte, bool) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), rh)
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	b.Question(q)
	out, err := b.Finish()
	return out, err == nil
}
