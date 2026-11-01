// Package relay forwards packets between nodes that can't reach each other
// directly. It only ever sees WireGuard ciphertext and sealed disco messages.
//
// Two transports carry the same frames: QUIC datagrams over UDP (fast, no
// TCP-over-TCP slowdown for tunneled TCP), and WebSocket binary messages,
// which work through proxies and on networks that only allow HTTPS. Clients
// use QUIC when the server offers it and fall back to WebSocket. Frames:
//
//	client -> server: dst node key(32) | payload
//	server -> client: src node key(32) | payload
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/k4ran909/whalescale/internal/key"
)

const (
	MaxPacket  = 64 << 10
	sendQueue  = 512
	pingPeriod = 25 * time.Second
)

// Authenticator maps a bearer token to the node key it may send as.
type Authenticator func(ctx context.Context, token string) (key.Public, error)

type Server struct {
	auth Authenticator
	log  *slog.Logger

	mu      sync.Mutex
	clients map[key.Public]*client

	packets, bytes, dropped atomic.Uint64
}

// Stats is a snapshot of relay counters.
type Stats struct {
	Clients                 int
	Packets, Bytes, Dropped uint64
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	n := len(s.clients)
	s.mu.Unlock()
	return Stats{Clients: n, Packets: s.packets.Load(), Bytes: s.bytes.Load(), Dropped: s.dropped.Load()}
}

// client is one connected node, whichever transport it uses.
type client struct {
	key  key.Public
	out  chan []byte
	kick func() // closes the connection, e.g. when a newer one replaces it
}

// register makes c the node's current connection, replacing an older one.
func (s *Server) register(c *client) {
	s.mu.Lock()
	old := s.clients[c.key]
	s.clients[c.key] = c
	s.mu.Unlock()
	if old != nil {
		old.kick()
	}
	s.log.Debug("relay client connected", "node", c.key.ShortString())
}

func (s *Server) unregister(c *client) {
	s.mu.Lock()
	if s.clients[c.key] == c {
		delete(s.clients, c.key)
	}
	s.mu.Unlock()
	s.log.Debug("relay client gone", "node", c.key.ShortString())
}

// route forwards a frame (dst key | payload) from src, reusing its buffer.
func (s *Server) route(src key.Public, msg []byte) {
	if len(msg) < 32 {
		return
	}
	dst := key.Public(msg[:32])
	s.mu.Lock()
	peer := s.clients[dst]
	s.mu.Unlock()
	if peer == nil {
		s.dropped.Add(1)
		return
	}
	copy(msg[:32], src[:]) // the authenticated source, never a claimed one
	select {
	case peer.out <- msg:
		s.packets.Add(1)
		s.bytes.Add(uint64(len(msg) - 32))
	default: // peer is slow; drop rather than block everyone
		s.dropped.Add(1)
	}
}

func NewServer(auth Authenticator, log *slog.Logger) *Server {
	return &Server{auth: auth, log: log, clients: map[key.Public]*client{}}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	k, err := s.auth(r.Context(), tok)
	if err != nil || k.IsZero() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxPacket + 32)
	c := &client{key: k, out: make(chan []byte, sendQueue),
		kick: func() { conn.Close(websocket.StatusPolicyViolation, "replaced by newer connection") }}
	s.register(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		s.unregister(c)
		conn.CloseNow()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-c.out:
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Write(wctx, websocket.MessageBinary, m)
				wcancel()
				if err != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()

	for {
		typ, msg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageBinary {
			s.route(k, msg)
		}
	}
}

// Connected reports whether a node currently holds a relay connection.
func (s *Server) Connected(k key.Public) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[k] != nil
}

func bearer(h string) (string, bool) {
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):], true
	}
	return "", false
}

// Packet is one packet received from the relay.
type Packet struct {
	Src  key.Public
	Data []byte
}

// Client keeps a connection to one relay server, reconnecting as needed.
type Client struct {
	url   string
	token string
	log   *slog.Logger

	hc   *http.Client
	recv chan Packet
	send chan []byte

	// QUIC transport, when the server offers one.
	quicAddr   string
	quicPin    []byte
	listenUDP  func() (net.PacketConn, error)
	quicFails  int
	quicFailed time.Time

	mu        sync.Mutex
	connected bool
	transport string
}

// NewClient makes a relay client. hc may be nil for the default client.
func NewClient(url, token string, hc *http.Client, log *slog.Logger) *Client {
	return &Client{url: url, token: token, log: log, hc: hc,
		recv: make(chan Packet, sendQueue), send: make(chan []byte, sendQueue)}
}

// Recv delivers packets from other nodes.
func (c *Client) Recv() <-chan Packet { return c.recv }

// Send queues a packet for dst. It never blocks; packets are dropped while
// disconnected or when the queue is full.
func (c *Client) Send(dst key.Public, pkt []byte) error {
	if len(pkt) > MaxPacket {
		return errors.New("packet too large for relay")
	}
	if !c.Connected() {
		return errors.New("relay not connected")
	}
	b := make([]byte, 32+len(pkt))
	copy(b, dst[:])
	copy(b[32:], pkt)
	select {
	case c.send <- b:
		return nil
	default:
		return errors.New("relay send queue full")
	}
}

func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Client) setConnected(v bool, transport string) {
	c.mu.Lock()
	c.connected, c.transport = v, transport
	c.mu.Unlock()
}

// Transport reports "quic", "websocket" or "" when disconnected.
func (c *Client) Transport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return ""
	}
	return c.transport
}

// SetQUIC offers the server's QUIC transport at addr (host:port), whose
// certificate must hash (SHA-256) to pin. listen opens the client's UDP
// socket (nil: an ordinary one). Call before Run.
func (c *Client) SetQUIC(addr string, pin []byte, listen func() (net.PacketConn, error)) {
	c.quicAddr, c.quicPin, c.listenUDP = addr, pin, listen
}

const (
	quicRetryAfter = 5 * time.Minute  // after QUIC failed twice in a row
	wsUpgradeAfter = 10 * time.Minute // a WebSocket fallback session then retries QUIC
)

// Run connects and reconnects until ctx is done, preferring QUIC.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		var err error
		if c.quicAddr != "" && (c.quicFails < 2 || time.Since(c.quicFailed) > quicRetryAfter) {
			err = c.sessionQUIC(ctx)
			c.setConnected(false, "")
			if ctx.Err() != nil {
				return
			}
			if time.Since(start) < 30*time.Second {
				c.quicFails++
				c.quicFailed = time.Now()
				c.log.Info("QUIC relay unavailable; trying WebSocket", "addr", c.quicAddr, "err", err)
				continue // straight to the next transport, no backoff
			}
			c.quicFails = 0
		} else {
			sctx, cancel := ctx, context.CancelFunc(func() {})
			if c.quicAddr != "" {
				sctx, cancel = context.WithTimeout(ctx, wsUpgradeAfter)
			}
			err = c.session(sctx)
			cancel()
			c.setConnected(false, "")
			if ctx.Err() != nil {
				return
			}
			if errors.Is(sctx.Err(), context.DeadlineExceeded) {
				c.quicFails = 0 // planned: go back and try QUIC
				continue
			}
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		c.log.Warn("relay disconnected", "url", c.url, "err", err, "retry_in", backoff)
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
	defer conn.CloseNow()
	conn.SetReadLimit(MaxPacket + 32)
	c.setConnected(true, "websocket")
	c.log.Info("relay connected", "url", c.url, "transport", "websocket")

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(pingPeriod)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case b := <-c.send:
				wctx, cancel := context.WithTimeout(sctx, 10*time.Second)
				err := conn.Write(wctx, websocket.MessageBinary, b)
				cancel()
				if err != nil {
					conn.CloseNow()
					return
				}
			case <-t.C:
				pctx, cancel := context.WithTimeout(sctx, 10*time.Second)
				err := conn.Ping(pctx)
				cancel()
				if err != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()

	for {
		typ, msg, err := conn.Read(sctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary || len(msg) < 32 {
			continue
		}
		select {
		case c.recv <- Packet{Src: key.Public(msg[:32]), Data: msg[32:]}:
		default:
		}
	}
}
