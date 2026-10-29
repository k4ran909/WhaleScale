// Package server assembles the Whalescale server: control and admin APIs,
// web console, browser login, relay, STUN, metrics and the background
// watcher that reloads policy and notices admin changes.
package server

import (
	"context"
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

	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/control"
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
	OIDC       *OIDCConfig
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
	log     *slog.Logger
	started time.Time

	policyMod time.Time
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
	s.control = control.New(st, cfg.Log, control.Config{
		DNSSuffix: cfg.DNSSuffix, Relays: []string{relayURL}, STUN: cfg.STUN,
		PublicURL: cfg.PublicURL, OIDC: cfg.OIDC != nil,
	})
	s.admin = control.NewAdmin(s.control)
	s.relay = relay.NewServer(s.control.RelayAuth, cfg.Log)
	if s.auth, err = newAuth(context.Background(), s, cfg.OIDC); err != nil {
		return nil, err
	}
	if err := s.loadInitialPolicy(); err != nil {
		return nil, err
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
	path, h := whalescalev1connect.NewControlServiceHandler(s.control)
	mux.Handle(path, h)
	mux.Handle(whalescalev1connect.ControlServiceStreamNetworkMapProcedure, longLived(h))
	mux.Handle(whalescalev1connect.ControlServiceWaitRegistrationProcedure, longLived(h))
	apath, ah := whalescalev1connect.NewAdminServiceHandler(s.admin)
	mux.Handle(apath, ah)
	mux.Handle("/relay", longLived(s.relay))
	s.auth.routes(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.store.SchemaVersion(r.Context()); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	if s.cfg.Console != nil {
		mux.Handle("GET /", consoleHandler(s.cfg.Console))
	}
	return mux
}

// consoleHandler serves the single-page console, falling back to
// index.html for client-side routes.
func consoleHandler(dist fs.FS) http.Handler {
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		m("whalescale_netmaps_sent_total", "counter", "Network maps pushed to nodes.", st.MapsSent.Load())
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if fp, err := s.store.Fingerprint(ctx); err == nil && fp != last {
			last = fp
			s.control.NotifyAll()
		}
		if s.cfg.PolicyFile != "" {
			if fi, err := os.Stat(s.cfg.PolicyFile); err == nil && !fi.ModTime().Equal(s.policyMod) {
				if err := s.loadPolicyFile(); err != nil {
					s.log.Error("policy reload failed; keeping the previous policy", "err", err)
				}
			}
		}
	}
}

// loadInitialPolicy picks the policy source: a --policy file wins, then a
// policy saved from the console, then allow-all.
func (s *Server) loadInitialPolicy() error {
	if s.cfg.PolicyFile != "" {
		return s.loadPolicyFile()
	}
	text, ok, err := s.store.Setting(context.Background(), control.PolicySettingKey)
	if err != nil || !ok {
		return err
	}
	p, err := policy.Parse([]byte(text))
	if err != nil {
		return fmt.Errorf("stored policy is invalid (fix it with the console or 'whalescale policy'): %w", err)
	}
	s.control.SetPolicy(p, text, "database")
	s.log.Info("policy loaded from database", "acls", len(p.ACLs))
	return nil
}

func (s *Server) loadPolicyFile() error {
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
	s.control.SetPolicy(p, string(b), "file")
	s.log.Info("policy loaded", "file", s.cfg.PolicyFile, "acls", len(p.ACLs))
	return nil
}

