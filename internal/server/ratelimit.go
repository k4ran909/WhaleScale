package server

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRateLimit is how many unauthenticated requests (registrations,
// browser logins, API key logins) one client may make per minute.
const DefaultRateLimit = 60

// maxTracked bounds the clients a limiter remembers. Past it (many
// addresses at once) it starts over rather than grow without limit.
const maxTracked = 100_000

// limiter is a per-client token bucket: perMin requests a minute, in
// bursts of up to perMin. IPv6 clients are grouped by /64, which one
// machine usually has to itself.
type limiter struct {
	perMin  float64
	trusted []netip.Prefix
	now     func() time.Time
	limited atomic.Uint64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// newLimiter allows perMin requests a minute per client; trusted proxies'
// X-Forwarded-For headers name the client. perMin < 0 disables limiting.
func newLimiter(perMin int, trusted []netip.Prefix) *limiter {
	if perMin == 0 {
		perMin = DefaultRateLimit
	}
	return &limiter{perMin: float64(perMin), trusted: trusted, now: time.Now, buckets: map[netip.Addr]*bucket{}}
}

// wrap refuses requests over the client's limit with 429.
func (l *limiter) wrap(h http.Handler) http.Handler {
	if l.perMin < 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wait := l.take(l.client(r)); wait > 0 {
			l.limited.Add(1)
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			http.Error(w, "too many requests; try again later", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// client is the address a request comes from: the peer, or if the peer is
// a trusted proxy, the last address in X-Forwarded-For it didn't add
// itself. Loopback clients are this machine and aren't limited (zero).
func (l *limiter) client(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := ap.Addr().Unmap()
	if l.isTrusted(ip) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break // garbage: trust nothing further left
			}
			ip = hop.Unmap()
			if !l.isTrusted(ip) {
				break
			}
		}
	}
	if ip.IsLoopback() {
		return netip.Addr{}
	}
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

func (l *limiter) isTrusted(ip netip.Addr) bool {
	return ip.IsLoopback() || slices.ContainsFunc(l.trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// take spends a token for ip and returns zero, or how long until one is
// available.
func (l *limiter) take(ip netip.Addr) time.Duration {
	if !ip.IsValid() {
		return 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > time.Minute {
		// Buckets that have refilled are the same as none.
		for k, b := range l.buckets {
			if now.Sub(b.at) > time.Minute {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= maxTracked {
			clear(l.buckets)
		}
		b = &bucket{tokens: l.perMin, at: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.perMin, b.tokens+now.Sub(b.at).Minutes()*l.perMin)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration((1 - b.tokens) / l.perMin * float64(time.Minute))
}

// ParsePrefixes parses comma-separated addresses or CIDR prefixes (for
// --trusted-proxies).
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, &net.ParseError{Type: "IP address or CIDR prefix", Text: f}
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
