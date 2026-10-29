package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
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
