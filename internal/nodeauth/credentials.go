package nodeauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"connectrpc.com/connect"
)

// Authority normalizes a host[:port] (or a URL's host) the way both ends
// name a server in proofs: lower case, without a default port.
func Authority(host string) string {
	host = strings.ToLower(host)
	for _, p := range []string{":443", ":80"} {
		host = strings.TrimSuffix(host, p)
	}
	return host
}

// Credential makes the Authorization value for a request with this method
// to rawURL. Relay and gateway clients take one.
type Credential func(method, rawURL string) string

// Bearer is a Credential that always sends the node token.
func Bearer(token string) Credential {
	return func(string, string) string { return "Bearer " + token }
}

// Credentials makes a node's Authorization values: proofs once it knows the
// server key, its bearer token until then.
type Credentials struct {
	machine, token string

	mu     sync.Mutex
	signer *Signer
	server string
}

// NewCredentials takes the machine's private key (base64) and node token.
func NewCredentials(machinePriv, token string) *Credentials {
	return &Credentials{machine: machinePriv, token: token}
}

// SetServerKey starts signing requests against the server's key (base64).
func (c *Credentials) SetServerKey(serverKey string) error {
	s, err := NewSigner(c.machine, serverKey)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.signer, c.server = s, serverKey
	c.mu.Unlock()
	return nil
}

// ServerKey is the key requests are signed against, or "" before one is set.
func (c *Credentials) ServerKey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.server
}

// Header returns the Authorization value for a request with this method to
// path on authority.
func (c *Credentials) Header(method, authority, path string) string {
	c.mu.Lock()
	s := c.signer
	c.mu.Unlock()
	if s == nil {
		return "Bearer " + c.token
	}
	return s.Header(method, Authority(authority), path)
}

// ForURL is Header for a request to rawURL; it is a Credential.
func (c *Credentials) ForURL(method, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "Bearer " + c.token
	}
	return c.Header(method, u.Host, u.Path)
}

// Interceptor authenticates every call a Connect client makes, each proof
// naming the procedure it is for.
func (c *Credentials) Interceptor() connect.Interceptor { return interceptor{c} }

type interceptor struct{ c *Credentials }

func (i interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			req.Header().Set("Authorization", i.c.Header(http.MethodPost, req.Peer().Addr, req.Spec().Procedure))
		}
		return next(ctx, req)
	}
}

func (i interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", i.c.Header(http.MethodPost, conn.Peer().Addr, spec.Procedure))
		return conn
	}
}

func (i interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
