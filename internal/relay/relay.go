// Package relay forwards packets between nodes that can't reach each other
// directly. It only ever sees WireGuard ciphertext and sealed disco messages.
//
// Transport is WebSocket (binary messages), so it works through proxies and
// on networks that only allow HTTPS. Frames:
//
//	client -> server: dst node key(32) | payload
//	server -> client: src node key(32) | payload
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
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
}

type client struct {
	key  key.Public
	conn *websocket.Conn
	out  chan []byte
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
	c := &client{key: k, conn: conn, out: make(chan []byte, sendQueue)}

	s.mu.Lock()
	if old := s.clients[k]; old != nil {
		old.conn.Close(websocket.StatusPolicyViolation, "replaced by newer connection")
	}
	s.clients[k] = c
	s.mu.Unlock()
	s.log.Debug("relay client connected", "node", k.ShortString())

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		s.mu.Lock()
		if s.clients[k] == c {
			delete(s.clients, k)
		}
		s.mu.Unlock()
		conn.CloseNow()
		s.log.Debug("relay client gone", "node", k.ShortString())
	}()
	go c.writeLoop(ctx)

	for {
		typ, msg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary || len(msg) < 32 {
			continue
		}
		dst := key.Public(msg[:32])
		s.mu.Lock()
		peer := s.clients[dst]
		s.mu.Unlock()
		if peer == nil {
			continue
		}
		// Reuse the buffer: overwrite the dst key with the src key.
		copy(msg[:32], k[:])
		select {
		case peer.out <- msg:
		default: // peer is slow; drop rather than block everyone
		}
	}
}

func (c *client) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-c.out:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.conn.Write(wctx, websocket.MessageBinary, m)
			cancel()
			if err != nil {
				c.conn.CloseNow()
				return
			}
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

	recv chan Packet
	send chan []byte

	mu        sync.Mutex
	connected bool
}

func NewClient(url, token string, log *slog.Logger) *Client {
	return &Client{url: url, token: token, log: log,
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

func (c *Client) setConnected(v bool) {
	c.mu.Lock()
	c.connected = v
	c.mu.Unlock()
}

// Run connects and reconnects until ctx is done.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		c.setConnected(false)
		if ctx.Err() != nil {
			return
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
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.token}},
	})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(MaxPacket + 32)
	c.setConnected(true)
	c.log.Info("relay connected", "url", c.url)

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
