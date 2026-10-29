// Package key provides Curve25519 key types shared by WireGuard and
// path discovery.
package key

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type Public [32]byte

type Private [32]byte

func NewPrivate() (Private, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Private{}, err
	}
	return Private(k.Bytes()), nil
}

func (k Private) Public() Public {
	pk, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		panic(err) // any 32 bytes are a valid X25519 scalar
	}
	return Public(pk.PublicKey().Bytes())
}

func (k Private) IsZero() bool { return k == Private{} }
func (k Public) IsZero() bool  { return k == Public{} }

// String is the base64 form used in the control API.
func (k Public) String() string  { return base64.StdEncoding.EncodeToString(k[:]) }
func (k Private) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex is the form WireGuard's UAPI expects.
func (k Public) Hex() string  { return hex.EncodeToString(k[:]) }
func (k Private) Hex() string { return hex.EncodeToString(k[:]) }

// ShortString is a short prefix for logs.
func (k Public) ShortString() string { return "[" + k.String()[:5] + "]" }

func ParsePublic(s string) (Public, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return Public{}, fmt.Errorf("invalid public key %q", s)
	}
	return Public(b), nil
}

func ParsePrivate(s string) (Private, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return Private{}, fmt.Errorf("invalid private key")
	}
	return Private(b), nil
}

func ParsePublicHex(s string) (Public, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return Public{}, fmt.Errorf("invalid hex public key %q", s)
	}
	return Public(b), nil
}
