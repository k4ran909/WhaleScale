package netlock

import (
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func state(version uint64, signer ed25519.PrivateKey, keys ...ed25519.PrivateKey) *v1.LockState {
	st := &v1.LockState{Version: version}
	for _, k := range keys {
		st.Keys = append(st.Keys, pub(k))
	}
	SignState(st, signer)
	return st
}

func TestKeyEncoding(t *testing.T) {
	k := mustKey(t)
	p, err := ParsePublic(EncodePublic(pub(k)))
	if err != nil || !p.Equal(ed25519.PublicKey(pub(k))) {
		t.Fatalf("public round trip: %v", err)
	}
	k2, err := ParsePrivate(EncodePrivate(k))
	if err != nil || !k2.Equal(k) {
		t.Fatalf("private round trip: %v", err)
	}
	if _, err := ParsePublic("wsapi-nope"); err == nil {
		t.Fatal("bad public key accepted")
	}
}

func TestChainAndAdvance(t *testing.T) {
	alice, bob, mallory := mustKey(t), mustKey(t), mustKey(t)
	v1s := state(1, alice, alice)
	v2 := state(2, alice, alice, bob) // alice adds bob
	v3 := state(3, bob, bob)          // bob removes alice
	chain := []*v1.LockState{v1s, v2, v3}
	if err := VerifyChain(chain); err != nil {
		t.Fatal(err)
	}

	// First use: adopt the head; with a pin, only if version 1 was signed by it.
	if head, err := Advance(nil, chain, nil); err != nil || head.Version != 3 {
		t.Fatalf("TOFU: %v %v", head, err)
	}
	if _, err := Advance(nil, chain, [][]byte{pub(mallory)}); err == nil {
		t.Fatal("pin ignored")
	}

	// From v2 we may move to v3; a forged v4 by mallory stops at v3.
	forged := state(4, mallory, mallory)
	head, err := Advance(v2, append(chain, forged), nil)
	if err == nil || head.Version != 3 {
		t.Fatalf("forged extension: head %v, err %v", head, err)
	}
	// alice was removed in v3, so she can't sign v4 either.
	if _, err := Advance(v3, []*v1.LockState{v1s, v2, v3, state(4, alice, alice)}, nil); err == nil {
		t.Fatal("removed key signed a new version")
	}
	// The server can't roll a node back or swap its history.
	if head, err := Advance(v3, chain[:2], nil); err == nil || head != v3 {
		t.Fatal("rollback accepted")
	}
	other := []*v1.LockState{state(1, mallory, mallory), state(2, mallory, mallory)}
	if head, err := Advance(v2, other, nil); err == nil || head != v2 {
		t.Fatal("replaced history accepted")
	}
	// A tampered copy of the trusted version doesn't match.
	tampered := proto.Clone(v2).(*v1.LockState)
	tampered.Keys = append(tampered.Keys, pub(mallory))
	if _, err := Advance(v2, []*v1.LockState{v1s, tampered}, nil); err == nil {
		t.Fatal("tampered state accepted")
	}

	// Node signatures count only from keys the head trusts.
	nodeKey := make([]byte, 32)
	nodeKey[0] = 7
	if !NodeSigned(v3, nodeKey, SignNode(bob, nodeKey)) {
		t.Fatal("bob's signature refused")
	}
	if NodeSigned(v3, nodeKey, SignNode(alice, nodeKey)) {
		t.Fatal("removed key's signature accepted")
	}
	other7 := append([]byte{}, nodeKey...)
	other7[1] = 1
	if NodeSigned(v3, other7, SignNode(bob, nodeKey)) {
		t.Fatal("signature transferred to another node key")
	}
}
