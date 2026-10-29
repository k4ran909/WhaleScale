// Package server assembles the Whalescale server: control API, relay, STUN
// and the background watcher that reloads policy and notices admin changes.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/control"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/relay"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/stun"
)

type Config struct {
	// PublicURL is how nodes reach this server, e.g. https://ws.example.com.
	PublicURL string
	// STUN lists host:port values advertised to nodes.
	STUN       []string
	DNSSuffix  string
	PolicyFile string
	Log        *slog.Logger
}

type Server struct {
	cfg     Config
	store   *store.Store
	control *control.Service
	relay   *relay.Server
	log     *slog.Logger

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
	s := &Server{cfg: cfg, store: st, log: cfg.Log}
	s.control = control.New(st, cfg.Log, control.Config{
		DNSSuffix: cfg.DNSSuffix, Relays: []string{relayURL}, STUN: cfg.STUN,
	})
	s.relay = relay.NewServer(s.control.RelayAuth, cfg.Log)
	if cfg.PolicyFile != "" {
		if err := s.loadPolicy(); err != nil {
			return nil, err
		}
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

// Handler serves the control API, relay and health check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	path, h := whalescalev1connect.NewControlServiceHandler(s.control)
	mux.Handle(path, h)
	mux.Handle(whalescalev1connect.ControlServiceStreamNetworkMapProcedure, longLived(h))
	mux.Handle("/relay", longLived(s.relay))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.store.SchemaVersion(r.Context()); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
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
				if err := s.loadPolicy(); err != nil {
					s.log.Error("policy reload failed; keeping the previous policy", "err", err)
				}
			}
		}
	}
}

func (s *Server) loadPolicy() error {
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
	s.control.SetPolicy(p)
	s.log.Info("policy loaded", "file", s.cfg.PolicyFile, "acls", len(p.ACLs))
	return nil
}
