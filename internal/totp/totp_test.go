package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238's SHA-1 test vectors (appendix B), last six digits.
func TestRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		got, err := Code(secret, Step(time.Unix(tc.unix, 0)))
		if err != nil || got != tc.want {
			t.Errorf("at %d: %q %v, want %q", tc.unix, got, err, tc.want)
		}
	}
}

func TestCheck(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := Code(secret, Step(now))
	step, ok := Check(secret, code[:3]+" "+code[3:], now, 0)
	if !ok || step != Step(now) {
		t.Fatalf("current code refused")
	}
	if _, ok := Check(secret, code, now, step); ok {
		t.Fatal("a used code was accepted again")
	}
	prev, _ := Code(secret, Step(now)-1)
	if _, ok := Check(secret, prev, now, 0); !ok {
		t.Fatal("the previous step's code (clock drift) refused")
	}
	old, _ := Code(secret, Step(now)-3)
	if _, ok := Check(secret, old, now, 0); ok {
		t.Fatal("a code 90 s old was accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Check(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestURIAndQR(t *testing.T) {
	u := URI("Whalescale", "karan", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/Whalescale:karan?") || !strings.Contains(u, "secret=ABC") || !strings.Contains(u, "issuer=Whalescale") {
		t.Fatalf("URI %q", u)
	}
	svg, err := QRSVG(URI("Whalescale", "karan", NewSecret()))
	if err != nil || !strings.HasPrefix(svg, "<svg") || strings.Count(svg, "h1v1") < 100 {
		t.Fatalf("QR: %v %.80s", err, svg)
	}
}
