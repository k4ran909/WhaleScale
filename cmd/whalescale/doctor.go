package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/k4ran909/whalescale/internal/relay"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/stun"
)

type checker struct{ fails, warns int }

func (c *checker) ok(format string, a ...any) { fmt.Printf("✔ "+format+"\n", a...) }
func (c *checker) warn(format string, a ...any) {
	c.warns++
	fmt.Printf("! "+format+"\n", a...)
}
func (c *checker) fail(format string, a ...any) {
	c.fails++
	fmt.Printf("✘ "+format+"\n", a...)
}

// cmdDoctor checks configuration and a running server from the outside:
// what a node or browser would hit.
func cmdDoctor(args []string) error {
	o, _, err := loadServeConfig(args, false)
	if err != nil {
		return err
	}
	c := &checker{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if errs := o.resolve(); len(errs) > 0 {
		for _, e := range errs {
			c.fail("config: %v", e)
		}
	} else {
		c.ok("config is valid (public URL %s)", o.publicURL)
	}

	dbName := store.Redact(o.db)
	if _, err := os.Stat(o.db); err != nil && !store.IsPostgres(o.db) {
		c.warn("database %s does not exist yet (it is created on first start)", o.db)
	} else if cur, latest, err := store.Inspect(ctx, o.db); err != nil {
		c.fail("database %s: %v", dbName, err)
	} else if cur < latest {
		c.warn("database schema %d, this binary has %d: migrations run on next start (back up %s first)", cur, latest, dbName)
	} else if cur > latest {
		c.fail("database schema %d is newer than this binary (%d): upgrade whalescale", cur, latest)
	} else {
		c.ok("database schema is current (version %d)", cur)
	}

	hc := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(o.publicURL, "/")
	resp, err := hc.Get(base + "/healthz")
	if err != nil {
		c.fail("server not reachable at %s: %v (is it running, and does DNS/firewall allow it?)", base, err)
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			c.ok("server answers at %s/healthz", base)
		} else {
			c.fail("%s/healthz returned %d: %s", base, resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}

	if u, _ := url.Parse(o.publicURL); u != nil && u.Scheme == "https" {
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{ServerName: u.Hostname()})
		if err != nil {
			c.fail("TLS to %s: %v", host, err)
		} else {
			cert := conn.ConnectionState().PeerCertificates[0]
			left := time.Until(cert.NotAfter)
			switch {
			case left < 7*24*time.Hour:
				c.fail("TLS certificate expires in %s (%s)", left.Round(time.Hour), cert.NotAfter.Format(time.DateOnly))
			case left < 21*24*time.Hour:
				c.warn("TLS certificate expires in %d days", int(left.Hours()/24))
			default:
				c.ok("TLS certificate valid until %s", cert.NotAfter.Format(time.DateOnly))
			}
			conn.Close()
		}
	} else if !isLoopbackURL(o.publicURL) {
		c.warn("public URL is plain http: node tokens cross the network unencrypted")
	}

	if resp, err := hc.Get(base + "/relay"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			c.ok("relay endpoint reachable (%s/relay)", base)
		} else {
			c.warn("relay endpoint returned %d (expected 401 without credentials); check reverse-proxy WebSocket support", resp.StatusCode)
		}
	}

	pu, _ := url.Parse(o.publicURL)
	for _, a := range splitList(o.stunListen) {
		_, port, _ := net.SplitHostPort(a)
		target := net.JoinHostPort(pu.Hostname(), port)
		if mapped, err := stunProbe(target); err != nil {
			c.fail("STUN %s: %v (open UDP %s in the firewall)", target, err, port)
		} else {
			c.ok("STUN %s answers (you are %s)", target, mapped)
		}
	}
	if len(splitList(o.stunListen)) == 1 {
		c.warn("only one STUN port: nodes can't detect symmetric NAT; use stun-listen: \":3478,:3479\"")
	}

	if o.relayQUICListen != "" {
		_, port, _ := net.SplitHostPort(o.relayQUICListen)
		target := net.JoinHostPort(pu.Hostname(), port)
		if st, err := store.Open(ctx, o.db); err != nil {
			c.warn("QUIC relay: cannot read its certificate: %v", err)
		} else {
			pin, err := server.QUICRelayPin(st)
			st.Close()
			if err == nil {
				err = relay.ProbeQUIC(ctx, target, pin)
			}
			if err != nil {
				c.warn("QUIC relay %s: %v (open UDP %s; nodes fall back to the slower WebSocket relay)", target, err, port)
			} else {
				c.ok("QUIC relay %s answers with the pinned certificate", target)
			}
		}
	}

	if o.gatewayDomain != "" {
		// Any name under the gateway domain must reach this server.
		probe := "doctor-check." + strings.Trim(o.gatewayDomain, ".")
		want, err1 := net.LookupHost(pu.Hostname())
		got, err2 := net.LookupHost(probe)
		switch {
		case err2 != nil:
			c.fail("gateway: %s does not resolve; add a wildcard DNS record *.%s pointing at this server", probe, o.gatewayDomain)
		case err1 == nil && !overlaps(want, got):
			c.fail("gateway: *.%s resolves to %v but %s resolves to %v", o.gatewayDomain, got, pu.Hostname(), want)
		default:
			c.ok("gateway: *.%s resolves to this server", o.gatewayDomain)
		}
		if !o.tlsACME && o.certFile != "" {
			c.warn("gateway: with tls-cert, the certificate must cover *.%s (or use tls-acme, or Caddy on-demand TLS)", o.gatewayDomain)
		}
	}

	if o.oidcIssuer != "" {
		r, err := hc.Get(strings.TrimRight(o.oidcIssuer, "/") + "/.well-known/openid-configuration")
		if err != nil || r.StatusCode != http.StatusOK {
			c.fail("OIDC discovery at %s failed: %v", o.oidcIssuer, err)
		} else {
			c.ok("OIDC issuer %s reachable; register redirect URL %s/auth/callback", o.oidcIssuer, base)
		}
		if r != nil {
			r.Body.Close()
		}
	}

	fmt.Printf("\n%d problem(s), %d warning(s)\n", c.fails, c.warns)
	if c.fails > 0 {
		return fmt.Errorf("doctor found %d problem(s)", c.fails)
	}
	return nil
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func stunProbe(target string) (netip.AddrPort, error) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer conn.Close()
	tx := stun.NewTxID()
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 3; attempt++ {
		conn.Write(stun.Request(tx))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if gotTx, mapped, err := stun.ParseResponse(buf[:n]); err == nil && gotTx == tx {
			return mapped, nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("no response")
}
