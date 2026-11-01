package engine

import (
	"crypto/ed25519"
	"encoding/base64"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/netlock"
	"github.com/k4ran909/whalescale/internal/netmap"
)

// LockStatus is this node's view of the network lock.
type LockStatus struct {
	Enabled     bool     `json:"enabled"`
	Version     uint64   `json:"version,omitempty"`
	TrustedKeys []string `json:"trusted_keys,omitempty"`
	// SelfSigned: peers will accept this node.
	SelfSigned bool `json:"self_signed"`
	// LockedOut are peers the server lists that no trusted key signed.
	LockedOut []string `json:"locked_out,omitempty"`
	// Error is set when the server sent lock data that didn't verify.
	Error string `json:"error,omitempty"`
}

func (e *Engine) loadLockHead() *v1.LockState {
	b, err := base64.StdEncoding.DecodeString(e.opts.State.LockHead)
	if err != nil || len(b) == 0 {
		return nil
	}
	st := &v1.LockState{}
	if proto.Unmarshal(b, st) != nil {
		return nil
	}
	return st
}

// enforceLock checks the map's lock history against the state this node
// already trusts, remembers any verified newer state, and returns the map
// without the peers (and peer relays) no trusted key signed. Everything
// downstream (WireGuard, routes, DNS, relays) only ever sees what's left.
func (e *Engine) enforceLock(nm *v1.NetworkMap) *v1.NetworkMap {
	local := e.lockHead
	var pinned [][]byte
	for _, s := range e.opts.State.LockTrust {
		if k, err := netlock.ParsePublic(s); err == nil {
			pinned = append(pinned, k)
		}
	}
	head, err := netlock.Advance(local, nm.LockChain, pinned)
	ls := &LockStatus{}
	if err != nil {
		ls.Error = err.Error()
		e.log.Error("network lock: refusing the server's lock data", "err", err)
	}
	if head != nil && (local == nil || head.Version != local.Version) {
		e.lockHead = head
		b, _ := proto.Marshal(head)
		e.opts.State.LockHead = base64.StdEncoding.EncodeToString(b)
		if e.opts.StatePath != "" {
			if err := clientstate.Save(e.opts.StatePath, e.opts.State); err != nil {
				e.log.Error("save network lock state", "err", err)
			}
		}
		e.log.Info("network lock state updated", "version", head.Version, "enabled", !head.Disabled)
	}
	defer func() {
		e.mu.Lock()
		e.lockStatus = ls
		e.mu.Unlock()
	}()
	if !netlock.Enforced(head) {
		return nm
	}
	ls.Enabled, ls.Version = true, head.Version
	for _, k := range head.Keys {
		ls.TrustedKeys = append(ls.TrustedKeys, netlock.EncodePublic(ed25519.PublicKey(k)))
	}
	signed := func(n *v1.Node) bool {
		k, err := base64.StdEncoding.DecodeString(n.GetNodeKey())
		return err == nil && netlock.NodeSigned(head, k, n.GetLockSignature())
	}
	ls.SelfSigned = signed(nm.Self)
	keys := map[string]bool{}
	var peers []*v1.Node
	for _, p := range nm.Peers {
		if signed(p) {
			peers = append(peers, p)
			keys[p.NodeKey] = true
		} else {
			ls.LockedOut = append(ls.LockedOut, p.Name)
		}
	}
	out := netmap.WithPeers(nm, peers)
	out.PeerRelays = nil
	for _, r := range nm.PeerRelays {
		if keys[r.NodeKey] {
			out.PeerRelays = append(out.PeerRelays, r)
		}
	}
	out.RelayClients = nil
	for _, c := range nm.RelayClients {
		if keys[c.NodeKey] {
			out.RelayClients = append(out.RelayClients, c)
		}
	}
	return out
}
