package control

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/netlock"
)

func TestLockAdminValidation(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	_, apiKey, _ := st.CreateAPIKey(ctx, time.Hour)
	a := NewAdmin(s)
	authed := func(r connect.AnyRequest) { r.Header().Set("Authorization", "Bearer "+apiKey) }
	update := func(state *v1.LockState) error {
		r := connect.NewRequest(&v1.UpdateLockRequest{State: state})
		authed(r)
		_, err := a.UpdateLock(ctx, r)
		return err
	}
	alice, _ := netlock.GenerateKey()
	mallory, _ := netlock.GenerateKey()
	mk := func(version uint64, signer ed25519.PrivateKey, keys ...ed25519.PrivateKey) *v1.LockState {
		ls := &v1.LockState{Version: version}
		for _, k := range keys {
			ls.Keys = append(ls.Keys, k.Public().(ed25519.PublicKey))
		}
		netlock.SignState(ls, signer)
		return ls
	}

	if err := update(mk(2, alice, alice)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("version 2 first: %v", err)
	}
	if err := update(mk(1, alice, alice)); err != nil {
		t.Fatal(err)
	}
	if err := update(mk(2, mallory, mallory)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("untrusted signer: %v", err)
	}
	if err := update(mk(2, alice, alice, mallory)); err != nil {
		t.Fatal(err)
	}

	// Signatures must come from a trusted key and cover the node key given.
	st.CreateUser(ctx, "ann")
	st.SeedNodes(ctx, []string{"ann"}, 1, "")
	nodes, _ := st.ListNodes(ctx, "")
	nk := nodes[0].NodeKey
	sign := func(sig *v1.NodeSignature) error {
		r := connect.NewRequest(&v1.SignNodesRequest{Signatures: []*v1.SignedNodeKey{{NodeKey: nk, Signature: sig}}})
		authed(r)
		_, err := a.SignNodes(ctx, r)
		return err
	}
	outsider, _ := netlock.GenerateKey()
	if err := sign(netlock.SignNode(outsider, make([]byte, 32))); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad signature accepted: %v", err)
	}
	key, _ := nodeKeyBytes(nk)
	if err := sign(netlock.SignNode(alice, key)); err != nil {
		t.Fatal(err)
	}
	nodes, _ = st.ListNodes(ctx, "")
	if len(nodes[0].LockSignature) == 0 {
		t.Fatal("signature not stored")
	}
}
