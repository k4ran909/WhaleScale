// Package mcp serves the Model Context Protocol over stdio, so AI agents
// (Claude Desktop, Claude Code and other MCP clients) can look after a
// Whalescale network through the admin API.
//
// Every tool is an admin API call made with the API key the server was
// started with, so the key's scope is the boundary: with a read-only key
// the change tools aren't even listed, and the server refuses them anyway.
// Everything an agent changes lands in the audit log under that key.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
)

// ProtocolVersion is the MCP revision this server speaks.
const ProtocolVersion = "2025-06-18"

// Server answers MCP requests with admin API calls.
type Server struct {
	admin   whalescalev1connect.AdminServiceClient
	apiKey  string
	version string

	once  sync.Once
	scope string // the key's scope, fetched on first need
}

// New makes a server that calls admin with apiKey.
func New(admin whalescalev1connect.AdminServiceClient, apiKey, version string) *Server {
	return &Server{admin: admin, apiKey: apiKey, version: version}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC messages from r and writes
// replies to w until r ends or ctx is done.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 16<<20) // policies can be large
	enc := json.NewEncoder(w)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		result, rerr := s.handle(ctx, &req)
		if len(req.ID) == 0 {
			continue // a notification: no reply
		}
		resp := response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req *request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		version := ProtocolVersion
		if p.ProtocolVersion != "" && p.ProtocolVersion < ProtocolVersion {
			version = p.ProtocolVersion // speak the client's older revision
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "whalescale", "title": "Whalescale", "version": s.version},
			"instructions": "Tools for a Whalescale mesh VPN: machines, users, the access policy (JSON), routes, " +
				"temporary access requests, connection logs and the audit log. Use explain_access to find out why one " +
				"machine can or can't reach another. check_policy validates a policy before set_policy applies it.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		var list []map[string]any
		for _, t := range s.tools(ctx) {
			list = append(list, t.describe())
		}
		return map[string]any{"tools": list}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		for _, t := range tools {
			if t.name == p.Name {
				return s.call(ctx, t, p.Arguments), nil
			}
		}
		return nil, &rpcError{-32602, "unknown tool " + p.Name}
	}
	if len(req.ID) == 0 {
		return nil, nil // unknown notifications are ignored
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

// readOnlyKey reports whether the API key may only read.
func (s *Server) readOnlyKey(ctx context.Context) bool {
	s.once.Do(func() {
		resp, err := s.admin.WhoAmI(ctx, s.authed(connect.NewRequest(&v1.WhoAmIRequest{})))
		if err == nil {
			s.scope = resp.Msg.Scope
		}
	})
	return s.scope != "admin"
}

// tools lists what the key may use.
func (s *Server) tools(ctx context.Context) []*tool {
	ro := s.readOnlyKey(ctx)
	var out []*tool
	for _, t := range tools {
		if !t.write || !ro {
			out = append(out, t)
		}
	}
	return out
}

func authed[T any](s *Server, r *connect.Request[T]) *connect.Request[T] {
	r.Header().Set("Authorization", "Bearer "+s.apiKey)
	return r
}

func (s *Server) authed(r *connect.Request[v1.WhoAmIRequest]) *connect.Request[v1.WhoAmIRequest] {
	return authed(s, r)
}

// call runs a tool. Failures are tool results with isError set, so the
// agent sees why and can adjust, rather than protocol errors.
func (s *Server) call(ctx context.Context, t *tool, args map[string]any) map[string]any {
	var err error
	for _, p := range t.params {
		if v, ok := args[p.name]; p.required && (!ok || v == nil) {
			err = fmt.Errorf("missing argument %q", p.name)
			break
		}
	}
	var text string
	if err == nil {
		a := argReader(args)
		if text, err = t.run(ctx, s, a); err == nil {
			err = a.err
		}
	}
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) {
			err = fmt.Errorf("%s: %s", ce.Code(), ce.Message())
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}
