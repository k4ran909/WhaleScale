package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAdmins(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if n, err := s.AdminCount(ctx); err != nil || n != 0 {
		t.Fatalf("AdminCount = %d, %v", n, err)
	}

	// Racing first-run setups: exactly one wins.
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for _, name := range []string{"ann", "bob", "cat", "dan"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.CreateFirstAdmin(ctx, name, "hash-"+name)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrSetupDone):
			t.Fatalf("losing setup: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d first admins created", won)
	}

	admins, err := s.ListAdmins(ctx)
	if err != nil || len(admins) != 1 {
		t.Fatalf("ListAdmins = %+v, %v", admins, err)
	}
	first := admins[0].Name
	if _, err := s.CreateFirstAdmin(ctx, "eve", "x"); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("setup after the first admin: %v", err)
	}
	// The CLI can add more.
	if _, err := s.CreateAdmin(ctx, "eve", "hash-eve"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, "eve", "x"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate admin: %v", err)
	}
	if _, err := s.CreateAdmin(ctx, "Not Valid", "x"); err == nil {
		t.Fatal("invalid name accepted")
	}
	if h, err := s.AdminPasswordHash(ctx, "eve"); err != nil || h != "hash-eve" {
		t.Fatalf("hash = %q, %v", h, err)
	}
	if _, err := s.AdminPasswordHash(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown admin: %v", err)
	}

	// A new password, and deleting the account, sign it out everywhere.
	tok, _ := s.CreateSession(ctx, AdminIdentity("eve"), time.Hour)
	other, _ := s.CreateSession(ctx, AdminIdentity(first), time.Hour)
	if err := s.SetAdminPassword(ctx, "eve", "hash-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionIdentity(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session after a password change: %v", err)
	}
	if id, err := s.SessionIdentity(ctx, other); err != nil || id != AdminIdentity(first) {
		t.Fatalf("another admin's session = %q, %v", id, err)
	}
	if err := s.SetAdminPassword(ctx, "nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password for an unknown admin: %v", err)
	}
	if err := s.DeleteAdmin(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionIdentity(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session after deletion: %v", err)
	}
	if ok, _ := s.AdminExists(ctx, first); ok {
		t.Fatal("deleted admin still exists")
	}
	if ok, _ := s.AdminExists(ctx, "eve"); !ok {
		t.Fatal("remaining admin missing")
	}
}
