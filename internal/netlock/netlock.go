// Package netlock implements the network lock: admins hold ed25519 keys on
// their own machines and sign which keys are trusted and which node keys
// belong on the network. Nodes check those signatures themselves, so a
// compromised control server can't add machines or change who is trusted.
package netlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

const (
	pubPrefix  = "wslock:"
	privPrefix = "wslock-private:"
)

// GenerateKey makes a new lock key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// EncodePublic renders a public key as "wslock:BASE64".
func EncodePublic(k ed25519.PublicKey) string {
	return pubPrefix + base64.RawURLEncoding.EncodeToString(k)
}

// ParsePublic reads "wslock:BASE64".
func ParsePublic(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), pubPrefix))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(s), pubPrefix) || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a lock public key (wslock:...): %q", s)
	}
	return ed25519.PublicKey(b), nil
}

// EncodePrivate renders a private key for a key file.
func EncodePrivate(k ed25519.PrivateKey) string {
	return privPrefix + base64.RawURLEncoding.EncodeToString(k.Seed()) + "\n"
}

// ParsePrivate reads a key file's contents.
func ParsePrivate(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, privPrefix))
	if err != nil || !strings.HasPrefix(s, privPrefix) || len(b) != ed25519.SeedSize {
		return nil, errors.New("not a lock private key file")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func stateDigest(st *v1.LockState) []byte {
	var b bytes.Buffer
	b.WriteString("whalescale lock state v1\x00")
	binary.Write(&b, binary.BigEndian, st.Version)
	if st.Disabled {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	binary.Write(&b, binary.BigEndian, uint32(len(st.Keys)))
	for _, k := range st.Keys {
		b.Write(k)
	}
	return b.Bytes()
}

// SignState fills in st's signer and signature.
func SignState(st *v1.LockState, priv ed25519.PrivateKey) {
	st.Signer = priv.Public().(ed25519.PublicKey)
	st.Signature = ed25519.Sign(priv, stateDigest(st))
}

func trusts(st *v1.LockState, k []byte) bool {
	for _, t := range st.Keys {
		if bytes.Equal(t, k) {
			return true
		}
	}
	return false
}

func checkKeys(st *v1.LockState) error {
	if len(st.Keys) == 0 {
		return fmt.Errorf("lock version %d trusts no keys", st.Version)
	}
	for _, k := range st.Keys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("lock version %d has a malformed key", st.Version)
		}
	}
	return nil
}

// Next checks that next may follow prev (prev nil: next is the first
// version): one version later, and signed by a key prev trusts (the first
// by one of its own).
func Next(prev, next *v1.LockState) error {
	if err := checkKeys(next); err != nil {
		return err
	}
	signers := next
	want := uint64(1)
	if prev != nil {
		signers, want = prev, prev.Version+1
	}
	if next.Version != want {
		return fmt.Errorf("lock version %d where %d was expected", next.Version, want)
	}
	if !trusts(signers, next.Signer) || !ed25519.Verify(next.Signer, stateDigest(next), next.Signature) {
		return fmt.Errorf("lock version %d is not signed by a trusted key", next.Version)
	}
	return nil
}

// VerifyChain checks a whole chain from version 1.
func VerifyChain(chain []*v1.LockState) error {
	var prev *v1.LockState
	for _, st := range chain {
		if err := Next(prev, st); err != nil {
			return err
		}
		prev = st
	}
	return nil
}

// Advance returns the newest state in chain that follows from local, which
// the node already trusts. With local nil (trust on first use) the whole
// chain must verify; pinned, if any, must include the key that signed
// version 1. A chain that doesn't contain local exactly, or breaks after
// it, is an error and local stays in force: the server can delay lock
// changes but never undo or forge them.
func Advance(local *v1.LockState, chain []*v1.LockState, pinned [][]byte) (*v1.LockState, error) {
	if local == nil {
		if len(chain) == 0 {
			return nil, nil
		}
		if err := VerifyChain(chain); err != nil {
			return nil, err
		}
		if len(pinned) > 0 && !trusts(&v1.LockState{Keys: pinned}, chain[0].Signer) {
			return nil, errors.New("the network lock was not set up with a key this machine was told to trust")
		}
		return chain[len(chain)-1], nil
	}
	start := -1
	for i, st := range chain {
		if st.Version == local.Version {
			start = i
		}
	}
	if start < 0 || !proto.Equal(chain[start], local) {
		return local, fmt.Errorf("the server's lock history doesn't include the version this machine trusts (%d)", local.Version)
	}
	head := local
	for _, st := range chain[start+1:] {
		if err := Next(head, st); err != nil {
			return head, err
		}
		head = st
	}
	return head, nil
}

func nodeDigest(nodeKey []byte) []byte {
	return append([]byte("whalescale lock node v1\x00"), nodeKey...)
}

// SignNode signs a node's WireGuard public key (32 bytes).
func SignNode(priv ed25519.PrivateKey, nodeKey []byte) *v1.NodeSignature {
	return &v1.NodeSignature{Signer: priv.Public().(ed25519.PublicKey), Signature: ed25519.Sign(priv, nodeDigest(nodeKey))}
}

// NodeSigned reports whether sig is a valid signature over nodeKey by a key
// head trusts.
func NodeSigned(head *v1.LockState, nodeKey []byte, sig *v1.NodeSignature) bool {
	return sig != nil && len(nodeKey) == 32 && trusts(head, sig.Signer) && len(sig.Signer) == ed25519.PublicKeySize &&
		ed25519.Verify(sig.Signer, nodeDigest(nodeKey), sig.Signature)
}

// Enforced reports whether head filters peers.
func Enforced(head *v1.LockState) bool { return head != nil && !head.Disabled }
