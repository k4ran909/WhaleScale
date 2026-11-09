package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Passkeys belong to one account: listed oldest first, found by credential
// ID, at most MaxPasskeys each, never two with one ID, and gone with
// their account.
func TestAdminPasskeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for _, name := range []string{"karan", "ann"} {
		if _, err := s.CreateAdmin(ctx, name, "hash"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddAdminPasskey(ctx, "nobody", "x", "id0", []byte("{}")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("passkey for a missing account: %v", err)
	}
	p, err := s.AddAdminPasskey(ctx, "karan", "Laptop", "id1", []byte(`{"a":1}`))
	if err != nil || p.Admin != "karan" || p.ID == 0 {
		t.Fatalf("add: %+v %v", p, err)
	}
	if _, err := s.AddAdminPasskey(ctx, "ann", "Phone", "id1", []byte("{}")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("the same credential twice: %v", err)
	}
	got, err := s.PasskeyByCredentialID(ctx, "id1")
	if err != nil || got.Admin != "karan" || got.Name != "Laptop" || string(got.Credential) != `{"a":1}` || !got.LastUsed.IsZero() {
		t.Fatalf("by credential ID: %+v %v", got, err)
	}
	if err := s.UsePasskey(ctx, p.ID, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PasskeyByCredentialID(ctx, "id1"); string(got.Credential) != `{"a":2}` || got.LastUsed.IsZero() {
		t.Fatalf("after use: %+v", got)
	}

	// Only its own account can remove it.
	if err := s.DeleteAdminPasskey(ctx, "ann", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account's passkey: %v", err)
	}
	for i := 2; i <= MaxPasskeys; i++ {
		if _, err := s.AddAdminPasskey(ctx, "karan", "key", fmt.Sprint("id", i), []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddAdminPasskey(ctx, "karan", "one too many", "idx", []byte("{}")); !errors.Is(err, ErrTooManyPasskeys) {
		t.Fatalf("over the limit: %v", err)
	}
	admins, _ := s.ListAdmins(ctx)
	if admins[0].Passkeys != MaxPasskeys || admins[1].Passkeys != 0 {
		t.Fatalf("ListAdmins: %+v", admins)
	}
	if err := s.DeleteAdminPasskey(ctx, "karan", p.ID); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.AdminPasskeys(ctx, "karan"); len(keys) != MaxPasskeys-1 || keys[0].CredentialID != "id2" {
		t.Fatalf("after delete: %d", len(keys))
	}

	if _, err := s.AddAdminPasskey(ctx, "ann", "Phone", "ann1", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteAdminPasskeys(ctx, "ann"); err != nil || n != 1 {
		t.Fatalf("reset: %d %v", n, err)
	}
	if err := s.DeleteAdmin(ctx, "karan"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PasskeyByCredentialID(ctx, "id2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted account's passkey: %v", err)
	}
}

// A passkey ceremony is taken once, by any server sharing the database,
// and only as the kind it was saved as, while it's young enough.
func TestCeremonies(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if err := s.SaveCeremony(ctx, "t1", "register", "karan", []byte(`{"challenge":"x"}`), time.Minute); err != nil {
		t.Fatal(err)
	}
	admin, data, err := s.TakeCeremony(ctx, "t1", "register", time.Minute)
	if err != nil || admin != "karan" || string(data) != `{"challenge":"x"}` {
		t.Fatalf("take: %q %s %v", admin, data, err)
	}
	if _, _, err := s.TakeCeremony(ctx, "t1", "register", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("taken twice: %v", err)
	}
	s.SaveCeremony(ctx, "t2", "login", "", []byte("{}"), time.Minute)
	if _, _, err := s.TakeCeremony(ctx, "t2", "register", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another kind: %v", err)
	}
	if _, _, err := s.TakeCeremony(ctx, "t2", "login", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after a wrong-kind take, it's gone: %v", err)
	}
	s.SaveCeremony(ctx, "t3", "login", "", []byte("{}"), time.Minute)
	if _, _, err := s.TakeCeremony(ctx, "t3", "login", -time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
}
