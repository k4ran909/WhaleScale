package nodeauth

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func keys(t testing.TB) (machinePriv, machinePub string, server *ecdh.PrivateKey) {
	t.Helper()
	m, _ := ecdh.X25519().GenerateKey(rand.Reader)
	s, _ := GenerateKey()
	return base64.StdEncoding.EncodeToString(m.Bytes()), base64.StdEncoding.EncodeToString(m.PublicKey().Bytes()), s
}

func TestSignVerify(t *testing.T) {
	mPriv, mPub, srv := keys(t)
	signer, err := NewSigner(mPriv, base64.StdEncoding.EncodeToString(srv.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(srv, []string{"ws.example.com"})
	now := time.Now()
	const path = "/whalescale.v1.ControlService/UpdateNode"

	h := signer.Header("POST", "ws.example.com", path)
	if !IsProof(h) || strings.Contains(h, mPriv) {
		t.Fatalf("header %q", h)
	}
	got, err := v.Verify(h, "POST", path, now)
	if err != nil || got != mPub {
		t.Fatalf("Verify = %q, %v", got, err)
	}
	// Seen once: a copy from a log is refused.
	if _, err := v.Verify(h, "POST", path, now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}

	for name, tc := range map[string]struct {
		header, method, path string
		now                  time.Time
		want                 error
	}{
		"other path":   {signer.Header("POST", "ws.example.com", path), "POST", "/whalescale.v1.ControlService/Logout", now, ErrBadProof},
		"other method": {signer.Header("POST", "ws.example.com", path), "GET", path, now, ErrBadProof},
		"other server": {signer.Header("POST", "ws2.example.com", path), "POST", path, now, ErrElsewhere},
		"too old":      {signer.Header("POST", "ws.example.com", path), "POST", path, now.Add(MaxSkew + time.Minute), ErrStale},
		"from future":  {signer.Header("POST", "ws.example.com", path), "POST", path, now.Add(-MaxSkew - time.Minute), ErrStale},
		"bearer":       {"Bearer wsnode-abc", "POST", path, now, ErrMalformed},
		"garbage":      {Scheme + "a,b,c", "POST", path, now, ErrMalformed},
	} {
		if _, err := v.Verify(tc.header, tc.method, tc.path, tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// Another machine claiming this machine key can't make the MAC.
	otherPriv, _, _ := keys(t)
	forger, _ := NewSigner(otherPriv, base64.StdEncoding.EncodeToString(srv.PublicKey().Bytes()))
	forged := forger.Header("POST", "ws.example.com", path)
	parts := strings.Split(strings.TrimPrefix(forged, Scheme), ",")
	mine := strings.Split(strings.TrimPrefix(h, Scheme), ",")
	parts[0] = mine[0] // swap in the victim's public key
	if _, err := v.Verify(Scheme+strings.Join(parts, ","), "POST", path, now); !errors.Is(err, ErrBadProof) {
		t.Fatalf("forged proof: %v", err)
	}
	// A proof made for another server key doesn't verify here.
	_, _, otherSrv := keys(t)
	wrong, _ := NewSigner(mPriv, base64.StdEncoding.EncodeToString(otherSrv.PublicKey().Bytes()))
	if _, err := v.Verify(wrong.Header("POST", "ws.example.com", path), "POST", path, now); !errors.Is(err, ErrBadProof) {
		t.Fatalf("proof for another server key: %v", err)
	}
}
