package control

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/netlock"
	"github.com/k4ran909/whalescale/internal/store"
)

// lockChain loads the network lock history from the store.
func lockChain(ctx context.Context, st *store.Store) ([]*v1.LockState, error) {
	raw, err := st.LockChain(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*v1.LockState, len(raw))
	for i, b := range raw {
		out[i] = &v1.LockState{}
		if err := proto.Unmarshal(b, out[i]); err != nil {
			return nil, fmt.Errorf("lock state %d: %w", i+1, err)
		}
	}
	return out, nil
}

func lockSignature(b []byte) *v1.NodeSignature {
	if len(b) == 0 {
		return nil
	}
	sig := &v1.NodeSignature{}
	if proto.Unmarshal(b, sig) != nil {
		return nil
	}
	return sig
}

func (a *Admin) GetLock(ctx context.Context, req *connect.Request[v1.GetLockRequest]) (*connect.Response[v1.GetLockResponse], error) {
	if _, err := a.auth(ctx, req); err != nil {
		return nil, err
	}
	chain, err := lockChain(ctx, a.svc.store)
	if err != nil {
		return nil, internal(a, "load lock chain", err)
	}
	return connect.NewResponse(&v1.GetLockResponse{Chain: chain}), nil
}

func (a *Admin) UpdateLock(ctx context.Context, req *connect.Request[v1.UpdateLockRequest]) (*connect.Response[v1.UpdateLockResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	st := req.Msg.State
	if st == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("state is required"))
	}
	chain, err := lockChain(ctx, a.svc.store)
	if err != nil {
		return nil, internal(a, "load lock chain", err)
	}
	var head *v1.LockState
	if len(chain) > 0 {
		head = chain[len(chain)-1]
	}
	// Nodes check this themselves; checking here too just refuses garbage
	// early with a useful error.
	if err := netlock.Next(head, st); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	b, _ := proto.Marshal(st)
	if err := a.svc.store.AppendLockState(ctx, st.Version, b); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, connect.NewError(connect.CodeAborted, errors.New("another lock change landed first; fetch it and sign again"))
		}
		return nil, internal(a, "store lock state", err)
	}
	keys := make([]string, len(st.Keys))
	for i, k := range st.Keys {
		keys[i] = netlock.EncodePublic(k)
	}
	a.audit(ctx, id, "network lock updated", "version", st.Version, "disabled", st.Disabled,
		"keys", keys, "signed_by", netlock.EncodePublic(st.Signer))
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.UpdateLockResponse{}), nil
}

func (a *Admin) SignNodes(ctx context.Context, req *connect.Request[v1.SignNodesRequest]) (*connect.Response[v1.SignNodesResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	chain, err := lockChain(ctx, a.svc.store)
	if err != nil {
		return nil, internal(a, "load lock chain", err)
	}
	if len(chain) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the network lock isn't set up; run 'ws lock init' first"))
	}
	head := chain[len(chain)-1]
	signers := map[string]bool{}
	for _, s := range req.Msg.Signatures {
		key, err := nodeKeyBytes(s.NodeKey)
		if err != nil || !netlock.NodeSigned(head, key, s.Signature) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("signature for node key %s is not valid under lock version %d", s.NodeKey, head.Version))
		}
		signers[netlock.EncodePublic(s.Signature.Signer)] = true
	}
	for _, s := range req.Msg.Signatures {
		b, _ := proto.Marshal(s.Signature)
		if err := a.svc.store.SetLockSignature(ctx, s.NodeKey, b); err != nil {
			return nil, internal(a, "store lock signature", err)
		}
	}
	for signer := range signers {
		a.audit(ctx, id, "nodes signed", "count", len(req.Msg.Signatures), "signed_by", signer)
	}
	a.svc.NotifyAll()
	return connect.NewResponse(&v1.SignNodesResponse{}), nil
}

func nodeKeyBytes(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
