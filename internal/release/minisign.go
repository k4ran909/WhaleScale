// Package release signs and verifies release files, and writes the SBOM.
//
// Signatures use minisign's format (https://jedisct1.github.io/minisign/),
// so anyone can check a download with the standard tool:
//
//	minisign -Vm checksums.txt -P <PublicKey>
//
// The release key's private half is a Woodpecker secret
// (release_signing_key); PublicKey below is its public half, which the
// tray's updater trusts.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// PublicKey is the release key in minisign's format (the second line of
// packaging/release-key.pub).
const PublicKey = "RWQTDZ8OU3crgX88ZlDbLDwo0k+eu+ZQJMQ/DF3FsOwAoYXbEWqs6Jz5"

// Key is a release signing key. Its text form (Encode) is what the
// release_signing_key secret holds.
type Key struct {
	ID   [8]byte
	Priv ed25519.PrivateKey
}

const keyPrefix = "whalescale-release-key:"

// NewKey makes a random key.
func NewKey() (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k := &Key{Priv: priv}
	if _, err := rand.Read(k.ID[:]); err != nil {
		return nil, err
	}
	return k, nil
}

// Encode returns the key as one line of text: keep it secret.
func (k *Key) Encode() string {
	return keyPrefix + base64.StdEncoding.EncodeToString(append(k.ID[:], k.Priv.Seed()...))
}

// ParseKey reads Encode's form.
func ParseKey(s string) (*Key, error) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if !strings.HasPrefix(s, keyPrefix) || err != nil || len(b) != 8+ed25519.SeedSize {
		return nil, errors.New("not a whalescale release key")
	}
	k := &Key{Priv: ed25519.NewKeyFromSeed(b[8:])}
	copy(k.ID[:], b[:8])
	return k, nil
}

// PublicKey returns the key's public half in minisign's one-line form.
func (k *Key) PublicKey() string {
	pub := k.Priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), k.ID[:]...), pub...))
}

// PublicKeyFile returns a minisign .pub file.
func (k *Key) PublicKeyFile() string {
	return fmt.Sprintf("untrusted comment: minisign public key %016X\n%s\n", binary.LittleEndian.Uint64(k.ID[:]), k.PublicKey())
}

// Sign returns a minisign signature file for msg, named file in its
// trusted comment. It signs the BLAKE2b-512 hash ("prehashed"), as
// minisign does by default.
func (k *Key) Sign(msg []byte, file string, now time.Time) string {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(k.Priv, h[:])
	trusted := fmt.Sprintf("timestamp:%d\tfile:%s\thashed", now.Unix(), file)
	global := ed25519.Sign(k.Priv, append(append([]byte(nil), sig...), trusted...))
	blob := append(append([]byte("ED"), k.ID[:]...), sig...)
	return fmt.Sprintf("untrusted comment: signature from the Whalescale release key\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(blob), trusted, base64.StdEncoding.EncodeToString(global))
}

// Verify checks a minisign signature file over msg against a public key
// in minisign's one-line form, including the trusted comment's signature.
func Verify(publicKey string, msg []byte, sigFile string) error {
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(pk) != 2+8+ed25519.PublicKeySize || string(pk[:2]) != "Ed" {
		return errors.New("bad public key")
	}
	lines := strings.Split(strings.ReplaceAll(sigFile, "\r\n", "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment: ") || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return errors.New("not a minisign signature")
	}
	blob, err1 := base64.StdEncoding.DecodeString(lines[1])
	global, err2 := base64.StdEncoding.DecodeString(lines[3])
	if err1 != nil || err2 != nil || len(blob) != 2+8+ed25519.SignatureSize || len(global) != ed25519.SignatureSize {
		return errors.New("malformed signature")
	}
	if !bytes.Equal(blob[2:10], pk[2:10]) {
		return errors.New("signed with a different key")
	}
	pub := ed25519.PublicKey(pk[10:])
	sig := blob[10:]
	signed := msg
	switch string(blob[:2]) {
	case "ED":
		h := blake2b.Sum512(msg)
		signed = h[:]
	case "Ed": // legacy: the message itself
	default:
		return errors.New("unknown signature algorithm")
	}
	if !ed25519.Verify(pub, signed, sig) {
		return errors.New("signature doesn't match")
	}
	trusted := strings.TrimPrefix(lines[2], "trusted comment: ")
	if !ed25519.Verify(pub, append(append([]byte(nil), sig...), trusted...), global) {
		return errors.New("trusted comment signature doesn't match")
	}
	return nil
}
