// Package gateway publishes nodes' local HTTP services on the internet
// through the Whalescale server, a self-hosted counterpart to Tailscale
// Funnel.
//
// A node with exposures keeps one WebSocket to the server's /gateway
// endpoint and runs yamux over it. For each public request to
// https://<name>.<domain>, the server opens a stream, writes a header line
// naming the exposure, and proxies HTTP over the stream. The node accepts
// only names it chose to expose and dials only its own localhost, so the
// server can never steer it at other ports or hosts.
package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/k4ran909/whalescale/internal/store"
)

// streamMagic starts every stream's header line: "WSGW1 <name>\n".
const streamMagic = "WSGW1 "

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 25 * time.Second
	cfg.StreamOpenTimeout = 15 * time.Second
	return cfg
}

// NodeAuth maps a node token to the node it belongs to.
type NodeAuth func(ctx context.Context, token string) (*store.Node, error)

// Server routes public traffic to nodes' tunnels.
type Server struct {
	domain string // "apps.example.com", lowercase, no dots at either end
	store  *store.Store
	auth   NodeAuth
	log    *slog.Logger
	proxy  *httputil.ReverseProxy

	mu       sync.Mutex
	sessions map[uint64]*yamux.Session
}

func NewServer(domain string, st *store.Store, auth NodeAuth, log *slog.Logger) *Server {
	s := &Server{domain: strings.Trim(strings.ToLower(domain), "."), store: st, auth: auth, log: log,
		sessions: map[uint64]*yamux.Session{}}
	tr := &http.Transport{
		DialContext:           s.dialExposure,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			name, _ := s.Match(pr.In.Host)
			// The URL host carries the exposure name to dialExposure; the
			// Host header stays what the visitor sent.
			pr.SetURL(&url.URL{Scheme: "http", Host: name})
			pr.Out.Host = pr.In.Host
			// ReverseProxy drops inbound X-Forwarded-* headers, which is
			// right for direct visitors. A reverse proxy on this host or a
			// private network (Caddy in Docker) is trusted to set them, so
			// the app still sees the real visitor address.
			if fromPrivateProxy(pr.In.RemoteAddr) {
				for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
					if v := pr.In.Header.Values(h); len(v) > 0 {
						pr.Out.Header[h] = v
					}
				}
			}
			pr.SetXForwarded()
			if fromPrivateProxy(pr.In.RemoteAddr) && pr.In.Header.Get("X-Forwarded-Proto") != "" {
				pr.Out.Header.Set("X-Forwarded-Proto", pr.In.Header.Get("X-Forwarded-Proto"))
			}
		},
		Transport:     tr,
		FlushInterval: -1, // stream responses (server-sent events, long polls)
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Debug("gateway proxy", "host", r.Host, "err", err)
			http.Error(w, "The service behind this address is not reachable right now.", http.StatusBadGateway)
		},
	}
	return s
}

// Domain is the gateway's DNS suffix.
func (s *Server) Domain() string { return s.domain }

// URL is an exposure's public address.
func (s *Server) URL(name string) string { return "https://" + name + "." + s.domain }

// Match reports whether host (with or without a port) is <name>.<domain>.
func (s *Server) Match(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	name, ok := strings.CutSuffix(host, "."+s.domain)
	if !ok || name == "" || strings.Contains(name, ".") || !store.ValidExposureName(name) {
		return "", false
	}
	return name, true
}

// Connected reports whether a node holds a gateway tunnel.
func (s *Server) Connected(nodeID uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[nodeID]
	return sess != nil && !sess.IsClosed()
}

// live returns the exposure for name if it may receive traffic.
func (s *Server) live(ctx context.Context, name string) (*store.Exposure, error) {
	e, err := s.store.ExposureByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !e.Live() {
		return nil, store.ErrNotFound
	}
	return e, nil
}

// AllowHost decides whether a TLS certificate may be issued for host:
// only for live exposures, so strangers can't make us request certificates
// for arbitrary names.
func (s *Server) AllowHost(ctx context.Context, host string) error {
	name, ok := s.Match(host)
	if !ok {
		return errors.New("not a gateway host")
	}
	_, err := s.live(ctx, name)
	return err
}

// ServeHTTP handles public traffic for <name>.<domain>.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := s.Match(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := s.live(r.Context(), name); err != nil {
		http.Error(w, "Nothing is published at this address.", http.StatusNotFound)
		return
	}
	s.proxy.ServeHTTP(w, r)
}

// AskHandler answers Caddy's on-demand TLS "ask": 200 for live exposures.
func (s *Server) AskHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.AllowHost(r.Context(), r.URL.Query().Get("domain")); err != nil {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// dialExposure opens a stream to the node behind addr ("<name>:80").
func (s *Server) dialExposure(ctx context.Context, _, addr string) (net.Conn, error) {
	name, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	e, err := s.live(ctx, name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	sess := s.sessions[e.NodeID]
	s.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		return nil, fmt.Errorf("%s is not connected to the gateway", e.NodeName)
	}
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(st, streamMagic+name+"\n"); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// TunnelHandler accepts nodes' gateway tunnels.
func (s *Server) TunnelHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		node, err := s.auth(r.Context(), tok)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(-1) // yamux frames its own data
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sess, err := yamux.Client(websocket.NetConn(ctx, c, websocket.MessageBinary), yamuxConfig())
		if err != nil {
			c.CloseNow()
			return
		}
		s.mu.Lock()
		if old := s.sessions[node.ID]; old != nil {
			old.Close()
		}
		s.sessions[node.ID] = sess
		s.mu.Unlock()
		s.log.Info("gateway tunnel up", "node", node.Name)
		<-sess.CloseChan()
		s.mu.Lock()
		if s.sessions[node.ID] == sess {
			delete(s.sessions, node.ID)
		}
		s.mu.Unlock()
		s.log.Info("gateway tunnel down", "node", node.Name)
	})
}

// Client keeps a node's gateway tunnel up and proxies streams to the
// node's own localhost.
type Client struct {
	url   string
	token string
	hc    *http.Client
	log   *slog.Logger

	mu    sync.Mutex
	ports map[string]uint16
}

func NewClient(url, token string, hc *http.Client, log *slog.Logger) *Client {
	return &Client{url: url, token: token, hc: hc, log: log, ports: map[string]uint16{}}
}

// SetExposures replaces the names this node serves and their local ports.
func (c *Client) SetExposures(ports map[string]uint16) {
	c.mu.Lock()
	c.ports = ports
	c.mu.Unlock()
}

func (c *Client) port(name string) (uint16, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.ports[name]
	return p, ok
}

// Run connects and reconnects until ctx is done.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		c.log.Warn("gateway tunnel down", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) session(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dctx, c.url, &websocket.DialOptions{
		HTTPClient: c.hc,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.token}},
	})
	cancel()
	if err != nil {
		return err
	}
	conn.SetReadLimit(-1)
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	sess, err := yamux.Server(websocket.NetConn(sctx, conn, websocket.MessageBinary), yamuxConfig())
	if err != nil {
		conn.CloseNow()
		return err
	}
	defer sess.Close()
	go func() { <-sctx.Done(); sess.Close() }()
	c.log.Info("gateway tunnel up", "url", c.url)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go c.handle(st)
	}
}

// handle proxies one public connection to the exposed local port.
func (c *Client) handle(st net.Conn) {
	defer st.Close()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(st, 512)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, streamMagic) {
		return
	}
	st.SetReadDeadline(time.Time{})
	name := strings.TrimSpace(strings.TrimPrefix(line, streamMagic))
	port, ok := c.port(name)
	if !ok {
		c.log.Warn("gateway stream for a name this node does not expose", "name", name)
		return
	}
	local, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 5*time.Second)
	if err != nil {
		local, err = net.DialTimeout("tcp", net.JoinHostPort("::1", fmt.Sprint(port)), 5*time.Second)
	}
	if err != nil {
		c.log.Warn("exposed service not reachable", "name", name, "port", port, "err", err)
		return
	}
	defer local.Close()
	// HTTP doesn't half-close: once either side is done, the connection
	// is, so the deferred Closes end the other copy.
	done := make(chan struct{}, 2)
	go func() { io.Copy(local, br); done <- struct{}{} }()
	go func() { io.Copy(st, local); done <- struct{}{} }()
	<-done
}

// fromPrivateProxy reports whether a request came from loopback or a
// private network, where a trusted reverse proxy would sit.
func fromPrivateProxy(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate()
}
