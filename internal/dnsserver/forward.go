package dnsserver

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Forwarder resolves a query for a name outside the mesh, asked by from.
// ErrRefused refuses the query; any other error answers SERVFAIL.
type Forwarder func(ctx context.Context, from netip.Addr, query []byte) ([]byte, error)

// ErrRefused makes the server refuse a query instead of forwarding it.
var ErrRefused = errors.New("refused")

// forwardTimeout bounds one exchange with an upstream server.
const forwardTimeout = 3 * time.Second

// SetForwarder sets where names outside the mesh go; nil refuses them.
func (s *Server) SetForwarder(f Forwarder) {
	s.mu.Lock()
	s.fwd = f
	s.mu.Unlock()
}

// Exchange sends a query over a datagram connection from dial and returns
// the response with the query's ID.
func Exchange(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short query")
	}
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 12 && buf[0] == query[0] && buf[1] == query[1] {
			return slices.Clone(buf[:n]), nil
		}
	}
}

// UDP dials a DNS server at addr (host:port) over UDP.
func UDP(addr string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}
}

// Upstream forwards queries to servers (host:port), trying each in turn.
// With none, it uses the system's resolvers: those in /etc/resolv.conf, read
// for each query (they change with the network), or where there is no such
// file (Windows), the OS resolver for A and AAAA questions.
func Upstream(servers []string) func(ctx context.Context, query []byte) ([]byte, error) {
	return func(ctx context.Context, query []byte) ([]byte, error) {
		list := servers
		if len(list) == 0 {
			list = systemResolvers("/etc/resolv.conf")
		}
		if len(list) == 0 {
			return resolveViaOS(ctx, query)
		}
		var last error
		for _, s := range list {
			resp, err := Exchange(ctx, UDP(s), query)
			if err == nil {
				return resp, nil
			}
			last = err
		}
		return nil, last
	}
}

// systemResolvers lists a resolv.conf's nameservers as host:53 (at most
// three, as the resolver library uses).
func systemResolvers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < 3 {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		// Zone suffixes ("fe80::1%eth0") are kept: Dial understands them.
		host := fields[1]
		if _, err := netip.ParseAddr(strings.SplitN(host, "%", 2)[0]); err != nil {
			continue
		}
		out = append(out, net.JoinHostPort(host, "53"))
	}
	return out
}

// resolveViaOS answers A and AAAA questions with the OS resolver.
func resolveViaOS(ctx context.Context, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	network := map[dnsmessage.Type]string{dnsmessage.TypeA: "ip4", dnsmessage.TypeAAAA: "ip6"}[q.Type]
	if network == "" || q.Class != dnsmessage.ClassINET {
		return nil, errors.New("only A and AAAA questions can be resolved without a resolv.conf")
	}
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, strings.TrimSuffix(q.Name.String(), "."))
	rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		rh.RCode = dnsmessage.RCodeNameError
	case err != nil:
		return nil, err
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), rh)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rrh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
	for _, a := range addrs {
		a = a.Unmap()
		switch {
		case q.Type == dnsmessage.TypeA && a.Is4():
			b.AResource(rrh, dnsmessage.AResource{A: a.As4()})
		case q.Type == dnsmessage.TypeAAAA && a.Is6():
			b.AAAAResource(rrh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	return b.Finish()
}
