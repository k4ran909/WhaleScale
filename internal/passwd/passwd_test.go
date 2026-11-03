package passwd

import (
	"errors"
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") || strings.Contains(h, "horse") {
		t.Fatalf("hash %q", h)
	}
	if err := Verify("correct horse battery staple", h); err != nil {
		t.Fatalf("right password: %v", err)
	}
	if err := Verify("correct horse battery stapl", h); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	// Salted: the same password hashes differently each time.
	if h2, _ := Hash("correct horse battery staple"); h2 == h {
		t.Fatal("hash isn't salted")
	}
	if !errors.Is(VerifyNone("x"), ErrMismatch) {
		t.Fatal("VerifyNone accepted")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=0,t=1,p=1$AA$AA",
		"$argon2id$v=19$m=99999999,t=1,p=1$AA$AA", "$argon2id$v=19$m=1,t=1,p=1$!!$AA"} {
		if err := Verify("x", bad); err == nil || errors.Is(err, ErrMismatch) {
			t.Errorf("hash %q: %v", bad, err)
		}
	}
}

func TestCheck(t *testing.T) {
	if Check("short") == nil || Check(strings.Repeat("x", MaxLength+1)) == nil || Check("long enough pw") != nil {
		t.Fatal("password rules")
	}
}
