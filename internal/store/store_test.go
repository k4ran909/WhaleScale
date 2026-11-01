package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/k4ran909/whalescale/internal/store/storetest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	path := storetest.DSN(t, t.TempDir())
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := s.IPv6Prefix(ctx)
	s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	v, err := s.SchemaVersion(ctx)
	if err != nil || v < 1 {
		t.Fatalf("schema version = %d, %v", v, err)
	}
	if p2, _ := s.IPv6Prefix(ctx); p1 != p2 {
		t.Fatalf("ipv6 prefix changed across reopen: %v -> %v", p1, p2)
	}
	if p1.Bits() != 48 || p1.Addr().As16()[0] != 0xfd {
		t.Fatalf("prefix %v is not a ULA /48", p1)
	}
}

func TestRegisterFlow(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.CreateUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate user: got %v", err)
	}

	_, oneShot, err := s.CreatePreAuthKey(ctx, "alice", false, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n1, tok1, err := s.RegisterNode(ctx, RegisterParams{AuthKey: oneShot, MachineKey: "mk1", Hostname: "My-Laptop.local", OS: "windows"})
	if err != nil {
		t.Fatal(err)
	}
	if n1.Name != "my-laptop" || n1.IPv4.String() != "100.64.0.1" {
		t.Fatalf("node1 = %s %s", n1.Name, n1.IPv4)
	}
	if _, _, err := s.RegisterNode(ctx, RegisterParams{AuthKey: oneShot, MachineKey: "mk2", Hostname: "x"}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("reused one-shot key: got %v", err)
	}

	_, reusable, _ := s.CreatePreAuthKey(ctx, "alice", true, false, time.Hour)
	n2, _, err := s.RegisterNode(ctx, RegisterParams{AuthKey: reusable, MachineKey: "mk2", Hostname: "my-laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if n2.Name != "my-laptop-1" || n2.IPv4.String() != "100.64.0.2" {
		t.Fatalf("node2 = %s %s", n2.Name, n2.IPv4)
	}
	// Names are unique across users too.
	s.CreateUser(ctx, "bob")
	_, bobKey, _ := s.CreatePreAuthKey(ctx, "bob", false, false, time.Hour)
	n3, _, err := s.RegisterNode(ctx, RegisterParams{AuthKey: bobKey, MachineKey: "mk3", Hostname: "my-laptop"})
	if err != nil || n3.Name != "my-laptop-2" {
		t.Fatalf("node3 = %+v, %v", n3, err)
	}
	changed, err := s.UpdateNodeInfo(ctx, n1.ID, NodeInfo{NodeKey: "nk1", DiscoKey: "dk1", Endpoints: []string{"1.2.3.4:41641"}, OS: "windows"})
	if err != nil || !changed {
		t.Fatalf("UpdateNodeInfo = %v, %v", changed, err)
	}
	if changed, _ := s.UpdateNodeInfo(ctx, n1.ID, NodeInfo{NodeKey: "nk1", DiscoKey: "dk1", Endpoints: []string{"1.2.3.4:41641"}, OS: "windows"}); changed {
		t.Fatal("identical update reported a change")
	}
	if _, err := s.UpdateNodeInfo(ctx, n2.ID, NodeInfo{NodeKey: "nk1"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate node key: got %v", err)
	}
	if _, _, err := s.RegisterNode(ctx, RegisterParams{AuthKey: reusable, MachineKey: "mk2", Hostname: "dup"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate machine key: got %v", err)
	}

	got, err := s.NodeByToken(ctx, tok1)
	if err != nil || got.ID != n1.ID {
		t.Fatalf("NodeByToken = %+v, %v", got, err)
	}
	if _, err := s.NodeByToken(ctx, "wsnode-bogus"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bogus token: got %v", err)
	}

	nodes, err := s.ListNodes(ctx, "alice")
	if err == nil && (len(nodes[0].Endpoints) != 1 || nodes[0].NodeKey != "nk1") {
		t.Fatalf("node1 info not persisted: %+v", nodes[0])
	}
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ListNodes = %d, %v", len(nodes), err)
	}
}

func TestExpiredKey(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.CreateUser(ctx, "bob")
	k, plain, _ := s.CreatePreAuthKey(ctx, "bob", true, false, time.Hour)
	if err := s.ExpirePreAuthKey(ctx, k.Prefix); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RegisterNode(ctx, RegisterParams{AuthKey: plain, MachineKey: "mk", Hostname: "h"}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expired key: got %v", err)
	}
}

func TestSanitizeHostname(t *testing.T) {
	for in, want := range map[string]string{
		"DESKTOP-ABC123":   "desktop-abc123",
		"my laptop!!":      "my-laptop",
		"host.example.com": "host",
		"___":              "node",
		"":                 "node",
	} {
		if got := sanitizeHostname(in); got != want {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

// Queries cancelled mid-flight must not leave statements behind. Before
// v1.40.1, modernc.org/sqlite dropped the rows of a query cancelled after its
// first step without finalizing them: the statement kept a read transaction
// open, which stalls WAL checkpoints, and kept the file open after Close.
func TestCancelledQueriesReleaseDB(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateUser(ctx, "alice")
	for i := 0; i < 2000; i++ {
		qctx, cancel := context.WithCancel(ctx)
		go cancel()
		s.ListUsers(qctx)
	}

	// A leaked statement is an open reader, so a truncating checkpoint from
	// another connection reports busy.
	other, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var busy, logFrames, done int
	if err := other.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done); err != nil {
		t.Fatal(err)
	}
	if busy != 0 {
		t.Error("checkpoint blocked by a statement left open by a cancelled query")
	}
	other.Close()

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Windows can't delete a file that is still open.
	if err := os.Remove(path); err != nil {
		t.Errorf("database still open after Close: %v", err)
	}
}
