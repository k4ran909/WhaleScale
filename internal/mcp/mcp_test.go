package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/gen/whalescale/v1/whalescalev1connect"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

// session is an MCP client talking to a Server through pipes.
type session struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Scanner
	next int
}

func newSession(t *testing.T, url, apiKey string) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := New(whalescalev1connect.NewAdminServiceClient(&http.Client{Timeout: 10 * time.Second}, url), apiKey, "test")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		srv.Serve(ctx, inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() { cancel(); inW.Close() })
	return &session{t: t, in: inW, out: bufio.NewScanner(outR)}
}

func (s *session) call(method string, params any) map[string]any {
	s.t.Helper()
	s.next++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": s.next, "method": method, "params": params})
	fmt.Fprintf(s.in, "%s\n", b)
	if !s.out.Scan() {
		s.t.Fatalf("%s: no reply", method)
	}
	var resp map[string]any
	if err := json.Unmarshal(s.out.Bytes(), &resp); err != nil {
		s.t.Fatal(err)
	}
	if resp["id"] != float64(s.next) {
		s.t.Fatalf("%s: reply for id %v", method, resp["id"])
	}
	if e, ok := resp["error"]; ok {
		s.t.Fatalf("%s: %v", method, e)
	}
	return resp["result"].(map[string]any)
}

func (s *session) notify(method string) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	fmt.Fprintf(s.in, "%s\n", b)
}

func (s *session) tool(name string, args map[string]any) (string, bool) {
	s.t.Helper()
	r := s.call("tools/call", map[string]any{"name": name, "arguments": args})
	text := r["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := r["isError"].(bool)
	return text, isErr
}

func (s *session) toolNames() []string {
	s.t.Helper()
	var names []string
	for _, t := range s.call("tools/list", map[string]any{})["tools"].([]any) {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	return names
}

func TestMCP(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	t.Cleanup(hs.Close)
	srv, err := server.New(st, server.Config{PublicURL: hs.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	st.CreateUser(ctx, "ann")
	st.SeedNodes(ctx, []string{"ann"}, 2, "")
	_, adminKey, _ := st.CreateAPIKey(ctx, time.Hour)
	_, readKey, _ := st.CreateScopedAPIKey(ctx, time.Hour, store.ScopeRead)

	// A read-only agent.
	r := newSession(t, hs.URL, readKey)
	init := r.call("initialize", map[string]any{"protocolVersion": ProtocolVersion, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "1"}})
	if init["protocolVersion"] != ProtocolVersion || init["serverInfo"].(map[string]any)["name"] != "whalescale" {
		t.Fatalf("initialize = %v", init)
	}
	r.notify("notifications/initialized") // gets no reply; the next call's reply must still match
	names := strings.Join(r.toolNames(), ",")
	if !strings.Contains(names, "list_machines") || strings.Contains(names, "set_policy") {
		t.Fatalf("read-only key sees tools %s", names)
	}
	if text, isErr := r.tool("list_machines", nil); isErr || !strings.Contains(text, "ann-0") || strings.Contains(text, "machine_key") {
		t.Fatalf("list_machines = %v %s", isErr, text)
	}
	if text, isErr := r.tool("explain_access", map[string]any{"src": "node:ann-0", "dst": "node:ann-1:22"}); isErr || !strings.HasPrefix(text, "ALLOWED") {
		t.Fatalf("explain_access = %v %s", isErr, text)
	}
	if text, isErr := r.tool("explain_access", map[string]any{"src": "node:ann-0"}); !isErr || !strings.Contains(text, `"dst"`) {
		t.Fatalf("missing argument: %v %s", isErr, text)
	}
	// Called anyway (it isn't listed), the server refuses it.
	if text, isErr := r.tool("set_policy", map[string]any{"policy": `{"acls":[]}`}); !isErr || !strings.Contains(text, "read-only") {
		t.Fatalf("set_policy with a read key = %v %s", isErr, text)
	}

	// An admin agent can change things, and it's all audited.
	a := newSession(t, hs.URL, adminKey)
	a.call("initialize", map[string]any{"protocolVersion": "2025-03-26"})
	if !strings.Contains(strings.Join(a.toolNames(), ","), "set_policy") {
		t.Fatal("admin key doesn't see set_policy")
	}
	policy := `{"acls":[{"action":"accept","src":["ann"],"dst":["node:ann-1:443"]}]}`
	if text, isErr := a.tool("check_policy", map[string]any{"policy": policy}); isErr || !strings.HasPrefix(text, "valid") {
		t.Fatalf("check_policy = %v %s", isErr, text)
	}
	if text, isErr := a.tool("set_policy", map[string]any{"policy": policy}); isErr {
		t.Fatalf("set_policy = %s", text)
	}
	if text, _ := r.tool("explain_access", map[string]any{"src": "node:ann-0", "dst": "node:ann-1:22"}); !strings.HasPrefix(text, "DENIED") {
		t.Fatalf("after the new policy, explain_access = %s", text)
	}
	if text, isErr := a.tool("list_audit_events", map[string]any{"action": "policy"}); isErr || !strings.Contains(text, "api-key:") {
		t.Fatalf("audit = %v %s", isErr, text)
	}
	if _, isErr := a.tool("delete_machine", map[string]any{"machine": "no-such-machine"}); !isErr {
		t.Fatal("deleting an unknown machine succeeded")
	}
}
