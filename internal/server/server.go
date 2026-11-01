// Package server assembles the Whalescale server: control and admin APIs,
// web console, browser login, relay, STUN, metrics and the background
// watcher that reloads policy and notices admin changes.
package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/control"
	"github.com/k4ran909/whalescale/internal/gateway"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/relay"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/stun"
	"github.com/k4ran909/whalescale/internal/version"
)

type Config struct {
	// PublicURL is how nodes and browsers reach this server.
	PublicURL string
	// STUN lists host:port values advertised to nodes.
	STUN       []string
	DNSSuffix  string
	PolicyFile string
	// PolicySync follows a policy in a Git repository instead.
	PolicySync *PolicySyncConfig
	OIDC       *OIDCConfig
	// GatewayDomain enables the gateway: <name>.<GatewayDomain> must resolve
	// to this server (a wildcard DNS record).
	GatewayDomain string
	// RecordingsDir stores recorded SSH sessions (default: next to the DB).
	RecordingsDir string
	// FlowLogs turns on connection logging; records older than
	// FlowRetention are pruned.
	FlowLogs      bool
	FlowRetention time.Duration
	// RelayQUICAddr (host:port) advertises a QUIC relay; the caller then
	// runs ServeRelayQUIC on the matching UDP socket.
	RelayQUICAddr string
	// Console is the built web console (web/dist). Nil disables it.
	Console fs.FS
	Log     *slog.Logger
}

type Server struct {
	cfg     Config
	store   *store.Store
	control *control.Service
	admin   *control.Admin
	relay   *relay.Server
	auth    *auth
	gateway *gateway.Server
	log     *slog.Logger
	started time.Time

	policyMod time.Time
	psync     *policySync
	quicCert  tls.Certificate
}

func New(st *store.Store, cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	relayURL, err := relayURL(cfg.PublicURL)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st, log: cfg.Log, started: time.Now()}
	ccfg := control.Config{
		DNSSuffix: cfg.DNSSuffix, Relays: []string{relayURL}, STUN: cfg.STUN,
		PublicURL: cfg.PublicURL, OIDC: cfg.OIDC != nil, RecordingsDir: cfg.RecordingsDir, FlowLogs: cfg.FlowLogs,
	}
	if cfg.GatewayDomain != "" {
		s.gateway = gateway.NewServer(cfg.GatewayDomain, st, func(ctx context.Context, tok string) (*store.Node, error) {
			return st.NodeByToken(ctx, tok)
		}, cfg.Log)
		ccfg.GatewayDomain = s.gateway.Domain()
		ccfg.GatewayURL = strings.TrimSuffix(relayURL, "/relay") + "/gateway"
		ccfg.GatewayConnected = s.gateway.Connected
	}
	if cfg.RelayQUICAddr != "" {
		cert, pin, err := loadQUICCert(st)
		if err != nil {
			return nil, fmt.Errorf("QUIC relay certificate: %w", err)
		}
		s.quicCert = cert
		ccfg.QUICRelay, ccfg.QUICRelayPin = cfg.RelayQUICAddr, hex.EncodeToString(pin)
	}
	s.control = control.New(st, cfg.Log, ccfg)
	s.admin = control.NewAdmin(s.control)
	s.relay = relay.NewServer(s.control.RelayAuth, cfg.Log)
	if s.auth, err = newAuth(context.Background(), s, cfg.OIDC); err != nil {
		return nil, err
	}
	if cfg.PolicySync != nil {
		if cfg.PolicyFile != "" {
			return nil, errors.New("use either a policy file or a policy URL, not both")
		}
		if s.psync, err = newPolicySync(s, *cfg.PolicySync); err != nil {
			return nil, err
		}
		s.control.SetPolicyStatus(func() control.PolicyStatus {
			st := s.psync.Status()
			return control.PolicyStatus{URL: st.URL, LastSync: st.LastSync, Revision: st.Revision, Error: st.Error}
		})
		if err := s.psync.start(context.Background()); err != nil {
			return nil, err
		}
	} else if err := s.loadInitialPolicy(); err != nil {
		return nil, err
	}
	if err := s.control.RefreshGrants(context.Background()); err != nil {
		return nil, fmt.Errorf("load access grants: %w", err)
	}
	return s, nil
}

func relayURL(public string) (string, error) {
	u, err := url.Parse(public)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid public URL %q", public)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("public URL must be http(s), got %q", public)
	}
	u.Path = "/relay"
	return u.String(), nil
}

// Handler serves the APIs, relay, browser login, console and health check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Generous for recording uploads; everything else is tiny.
	path, h := whalescalev1connect.NewControlServiceHandler(s.control, connect.WithReadMaxBytes(control.MaxRecording+(1<<20)))
	mux.Handle(path, h)
	mux.Handle(whalescalev1connect.ControlServiceStreamNetworkMapProcedure, longLived(h))
	mux.Handle(whalescalev1connect.ControlServiceWaitRegistrationProcedure, longLived(h))
	apath, ah := whalescalev1connect.NewAdminServiceHandler(s.admin)
	mux.Handle(apath, ah)
	mux.Handle("/relay", longLived(s.relay))
	if s.gateway != nil {
		mux.Handle("/gateway", longLived(s.gateway.TunnelHandler()))
		mux.Handle("GET /gateway/ask", s.gateway.AskHandler())
	}
	s.auth.routes(mux)
	if s.psync != nil && s.psync.cfg.WebhookSecret != "" {
		mux.HandleFunc("POST /policy/sync", s.psync.webhook)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.store.SchemaVersion(r.Context()); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	if s.cfg.Console != nil {
		// Method-less: "GET /" conflicts with the API prefixes in ServeMux.
		mux.Handle("/", consoleHandler(s.cfg.Console))
	}
	if s.gateway == nil {
		return mux
	}
	// Requests for <name>.<gateway domain> are public traffic for a node;
	// everything else is the server itself.
	public := longLived(s.gateway)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.gateway.Match(r.Host); ok {
			public.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// AllowTLSHost decides which names automatic TLS may get certificates for:
// the server's own host and live gateway exposures.
func (s *Server) AllowTLSHost(ctx context.Context, host string) error {
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && strings.EqualFold(host, u.Hostname()) {
		return nil
	}
	if s.gateway != nil {
		return s.gateway.AllowHost(ctx, host)
	}
	return fmt.Errorf("host %q is not served here", host)
}

// consoleHandler serves the single-page console, falling back to
// index.html for client-side routes.
func consoleHandler(dist fs.FS) http.Handler {
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(dist, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// longLived lifts the server's read/write timeouts for streams and relay
// connections, which stay open for hours.
func longLived(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Time{})
		rc.SetWriteDeadline(time.Time{})
		h.ServeHTTP(w, r)
	})
}

// quicCertKey stores the QUIC relay's self-signed certificate, so its pin
// stays the same across restarts.
const quicCertKey = "relay_quic_cert"

func loadQUICCert(st *store.Store) (tls.Certificate, []byte, error) {
	ctx := context.Background()
	text, ok, err := st.Setting(ctx, quicCertKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if !ok {
		b, err := relay.NewQUICCert()
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		if err := st.SetSetting(ctx, quicCertKey, string(b)); err != nil {
			return tls.Certificate{}, nil, err
		}
		text = string(b)
	}
	return relay.ParseQUICCert([]byte(text))
}

// QUICRelayPin returns the QUIC relay certificate's pin from the database,
// creating the certificate if needed (for 'whalescale doctor').
func QUICRelayPin(st *store.Store) ([]byte, error) {
	_, pin, err := loadQUICCert(st)
	return pin, err
}

// ServeRelayQUIC runs the QUIC relay on pc until ctx is done.
func (s *Server) ServeRelayQUIC(ctx context.Context, pc net.PacketConn) error {
	return s.relay.ServeQUIC(ctx, pc, s.quicCert)
}

// ServeSTUN answers STUN on pc until ctx is done.
func (s *Server) ServeSTUN(ctx context.Context, pc net.PacketConn) error {
	return stun.Serve(ctx, pc, s.log)
}

// MetricsHandler serves Prometheus text-format metrics.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		nodes, _ := s.store.ListNodes(ctx, "")
		users, _ := s.store.ListUsers(ctx)
		direct, relayed, none := 0, 0, 0
		for _, p := range s.control.Topology() {
			switch p.Path {
			case "direct":
				direct++
			case "relay":
				relayed++
			default:
				none++
			}
		}
		st := s.control.Stats()
		rs := s.relay.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m := func(name, typ, help string, v any, labels ...string) {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
			l := ""
			if len(labels) > 0 {
				l = "{" + strings.Join(labels, ",") + "}"
			}
			fmt.Fprintf(w, "%s%s %v\n", name, l, v)
		}
		m("whalescale_build_info", "gauge", "Build information.", 1, `version="`+version.Version+`"`, `commit="`+version.Commit+`"`)
		m("whalescale_uptime_seconds", "gauge", "Seconds since the server started.", int64(time.Since(s.started).Seconds()))
		m("whalescale_users", "gauge", "Number of users.", len(users))
		m("whalescale_nodes", "gauge", "Number of registered nodes.", len(nodes))
		m("whalescale_nodes_online", "gauge", "Nodes holding a network map stream.", s.control.OnlineCount())
		fmt.Fprintf(w, "# HELP whalescale_peer_paths Peer paths reported by nodes, by kind.\n# TYPE whalescale_peer_paths gauge\n")
		fmt.Fprintf(w, "whalescale_peer_paths{path=\"direct\"} %d\nwhalescale_peer_paths{path=\"relay\"} %d\nwhalescale_peer_paths{path=\"none\"} %d\n", direct, relayed, none)
		m("whalescale_registrations_total", "counter", "Nodes registered since start.", st.Registrations.Load())
		m("whalescale_netmaps_sent_total", "counter", "Network map updates (full or delta) pushed to nodes.", st.MapsSent.Load())
		m("whalescale_snapshots_total", "counter", "Network snapshots built, one per batch of changes.", st.Snapshots.Load())
		m("whalescale_policy_compiles_total", "counter", "Policy compilations.", st.Compiles.Load())
		m("whalescale_relay_clients", "gauge", "Nodes connected to the relay.", rs.Clients)
		m("whalescale_relay_packets_total", "counter", "Packets forwarded by the relay.", rs.Packets)
		m("whalescale_relay_bytes_total", "counter", "Bytes forwarded by the relay.", rs.Bytes)
		m("whalescale_relay_dropped_total", "counter", "Relay packets dropped (unknown or slow peer).", rs.Dropped)
	})
}

// Watch polls for changes made outside the API (admin CLI deletes, policy
// file edits) and pushes new maps when something changed.
func (s *Server) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	last, _ := s.store.Fingerprint(ctx)
	var lastPrune time.Time
	if s.psync != nil {
		go s.psync.run(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(lastPrune) > time.Hour {
			lastPrune = time.Now()
			if n, err := s.store.PruneFlows(ctx, time.Now().Add(-s.flowRetention())); err == nil && n > 0 {
				s.log.Info("pruned old flow logs", "rows", n)
			}
		}
		if fp, err := s.store.Fingerprint(ctx); err == nil && fp != last {
			last = fp
			s.control.NotifyAll()
		}
		// Expires grants on time, and picks up CLI decisions.
		if err := s.control.RefreshGrants(ctx); err != nil {
			s.log.Error("refresh access grants", "err", err)
		}
		if s.cfg.PolicyFile != "" {
			if fi, err := os.Stat(s.cfg.PolicyFile); err == nil && !fi.ModTime().Equal(s.policyMod) {
				if err := s.loadPolicyFile(false); err != nil {
					s.log.Error("policy reload failed; keeping the previous policy", "err", err)
				}
			}
		}
	}
}

func (s *Server) flowRetention() time.Duration {
	if s.cfg.FlowRetention > 0 {
		return s.cfg.FlowRetention
	}
	return 7 * 24 * time.Hour
}

// loadInitialPolicy picks the policy source: a --policy file wins, then a
// policy saved from the console, then allow-all.
func (s *Server) loadInitialPolicy() error {
	if s.cfg.PolicyFile != "" {
		return s.loadPolicyFile(true)
	}
	text, ok, err := s.store.Setting(context.Background(), control.PolicySettingKey)
	if err != nil || !ok {
		return err
	}
	p, err := policy.Parse([]byte(text))
	if err != nil {
		return fmt.Errorf("stored policy is invalid (fix it with the console or 'whalescale policy'): %w", err)
	}
	s.warnFailingTests(p)
	s.control.SetPolicy(p, text, "database")
	s.log.Info("policy loaded from database", "acls", len(p.ACLs))
	return nil
}

// warnFailingTests logs a policy's failing tests. At startup that is all
// it does: nodes come and go, and an outdated test must not lock anyone out.
func (s *Server) warnFailingTests(p *policy.Policy) []string {
	nodes, err := s.store.ListNodes(context.Background(), "")
	if err != nil {
		return nil
	}
	fails := p.RunTests(control.PolicyNodes(nodes))
	for _, f := range fails {
		s.log.Warn("policy test failing", "failure", f)
	}
	return fails
}

// loadPolicyFile applies the policy file. On reloads (not at startup) a
// policy that fails its own tests is refused and the previous one kept.
func (s *Server) loadPolicyFile(startup bool) error {
	fi, err := os.Stat(s.cfg.PolicyFile)
	if err != nil {
		return err
	}
	s.policyMod = fi.ModTime()
	b, err := os.ReadFile(s.cfg.PolicyFile)
	if err != nil {
		return err
	}
	p, err := policy.Parse(b)
	if err != nil {
		return err
	}
	if users, err := s.store.ListUsers(context.Background()); err == nil {
		names := make([]string, len(users))
		for i, u := range users {
			names[i] = u.Name
		}
		for _, w := range p.Lint(names) {
			s.log.Warn("policy", "warning", w)
		}
	}
	if fails := s.warnFailingTests(p); len(fails) > 0 && !startup {
		return fmt.Errorf("policy file fails %d of its tests; not applied", len(fails))
	}
	s.control.SetPolicy(p, string(b), "file")
	if startup {
		s.log.Info("policy loaded", "file", s.cfg.PolicyFile, "acls", len(p.ACLs))
	} else {
		s.control.Audit(context.Background(), "file:"+s.cfg.PolicyFile, "policy reloaded", "acls", len(p.ACLs))
	}
	return nil
}
