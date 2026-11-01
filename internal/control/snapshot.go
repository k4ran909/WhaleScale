package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/maphash"
	"maps"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

// snapshot is the whole network at one map version. It is built once per
// change and shared by every map stream, so a change costs one database
// read and at most one policy compile, not one of each per connected node.
// Snapshots are immutable once built.
type snapshot struct {
	version     uint64
	prevVersion uint64 // version of the snapshot this one was built from
	nodes       []store.Node
	index       map[uint64]int
	// protos[i] is nodes[i] as sent to peers. A node whose entry didn't
	// change keeps the previous snapshot's pointer, so streams detect
	// changes by pointer comparison.
	protos  []*v1.Node
	hashes  []uint64
	wire    [][]byte // protos[i] encoded, for pack
	changed []uint64 // nodes added, changed or removed since prevVersion

	policy    *policy.Policy
	policyKey uint64
	compiled  *policy.Compiled
	filters   map[uint64]*nodeFilter

	dns          *v1.DNSConfig
	lockChain    []*v1.LockState
	exposures    map[uint64][]store.Exposure
	taken        map[uint64][]string
	peerRelays   []relayEntry[*v1.PeerRelay]
	relayClients []relayEntry[*v1.RelayClient]
}

type relayEntry[T any] struct {
	id    uint64
	proto T
}

// nodeFilter is one node's compiled access rules in wire form.
type nodeFilter struct {
	rules []*v1.FilterRule
	hash  uint64
	ssh   []*v1.SSHRule
}

// hashSeed is fixed for the process so hashes compare across snapshots.
var hashSeed = maphash.MakeSeed()

var deterministic = proto.MarshalOptions{Deterministic: true}

// snapshot returns the network as of the current version, building it if
// something changed. Concurrent callers share one build.
func (s *Service) snapshot() (*snapshot, error) {
	v := s.version.Load()
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if s.snap != nil && s.snap.version >= v {
		return s.snap, nil
	}
	// Not the caller's context: one stream going away must not fail a
	// build the others are waiting for.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snap, err := s.buildSnapshot(ctx, s.snap)
	if err != nil {
		s.log.Error("build network snapshot", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	s.snap = snap
	s.stats.Snapshots.Add(1)

	return snap, nil
}

func (s *Service) buildSnapshot(ctx context.Context, prev *snapshot) (*snapshot, error) {
	// Read the version first: a change landing during the build bumps it
	// again and causes another build.
	version := s.version.Load()
	var nodes []store.Node
	var exposures map[uint64][]store.Exposure
	var chain []*v1.LockState
	// Cleared before reading, so a write landing mid-read marks it again.
	if s.storeDirty.Swap(false) || prev == nil {
		var err error
		if nodes, err = s.store.ListNodes(ctx, ""); err != nil {
			s.storeDirty.Store(true)
			return nil, err
		}
		list, err := s.store.ListExposures(ctx)
		if err != nil {
			s.storeDirty.Store(true)
			return nil, err
		}
		exposures = map[uint64][]store.Exposure{}
		for _, e := range list {
			exposures[e.NodeID] = append(exposures[e.NodeID], e)
		}
		if chain, err = lockChain(ctx, s.store); err != nil {
			s.storeDirty.Store(true)
			return nil, err
		}
	} else {
		nodes, exposures, chain = prev.nodes, prev.exposures, prev.lockChain
	}
	s.mu.Lock()
	online := maps.Clone(s.online)
	taken := maps.Clone(s.taken)
	s.mu.Unlock()
	s.policyMu.RLock()
	pol := s.policy
	s.policyMu.RUnlock()

	snap := &snapshot{version: version, nodes: nodes, index: make(map[uint64]int, len(nodes)),
		protos: make([]*v1.Node, len(nodes)), hashes: make([]uint64, len(nodes)), wire: make([][]byte, len(nodes)),
		dns: &v1.DNSConfig{Suffix: s.cfg.DNSSuffix}, exposures: exposures, taken: taken, lockChain: chain}
	if prev != nil {
		snap.prevVersion = prev.version
	}
	for i := range nodes {
		n := &nodes[i]
		snap.index[n.ID] = i
		p := s.mapNode(n, online[n.ID] > 0)
		b, err := deterministic.Marshal(p)
		if err != nil {
			return nil, err
		}
		h := maphash.Bytes(hashSeed, b)
		if prev != nil {
			if j, ok := prev.index[n.ID]; ok && prev.hashes[j] == h {
				p, b = prev.protos[j], prev.wire[j]
			} else {
				snap.changed = append(snap.changed, n.ID)
			}
		}
		snap.protos[i], snap.hashes[i], snap.wire[i] = p, h, b

		if n.NodeKey == "" || n.DiscoKey == "" {
			continue
		}
		if n.RelayOffered && n.RelayApproved {
			snap.peerRelays = append(snap.peerRelays, relayEntry[*v1.PeerRelay]{n.ID,
				&v1.PeerRelay{Name: n.Name, NodeKey: n.NodeKey, DiscoKey: n.DiscoKey, Endpoints: n.Endpoints}})
		}
		// A relay serves every node: it only forwards ciphertext, and who
		// may talk to whom is still enforced by WireGuard and the filter.
		snap.relayClients = append(snap.relayClients, relayEntry[*v1.RelayClient]{n.ID,
			&v1.RelayClient{NodeKey: n.NodeKey, DiscoKey: n.DiscoKey}})
	}
	if prev != nil {
		for _, n := range prev.nodes {
			if _, ok := snap.index[n.ID]; !ok {
				snap.changed = append(snap.changed, n.ID)
			}
		}
	}

	// Recompile only when the policy or something it looks at changed;
	// endpoint and key updates, the bulk of all changes, don't qualify.
	snap.policy, snap.policyKey = pol, policyKey(nodes)
	if prev != nil && prev.policy == pol && prev.policyKey == snap.policyKey {
		snap.compiled, snap.filters = prev.compiled, prev.filters
	} else {
		start := time.Now()
		snap.compiled = pol.Compile(PolicyNodes(nodes))
		snap.filters = buildFilters(snap.compiled, nodes)
		s.stats.Compiles.Add(1)
		s.log.Debug("policy compiled", "nodes", len(nodes), "took", time.Since(start))
	}
	return snap, nil
}

// mapNode is a node as network maps carry it: what peers need to reach and
// name it. Console details (machine key, timestamps, routes waiting for
// approval) stay out, keeping maps small and free of churn.
func (s *Service) mapNode(n *store.Node, online bool) *v1.Node {
	p := s.nodeProto(n, online)
	p.MachineKey, p.CreatedAt, p.LastSeen, p.Ephemeral, p.AdvertisedRoutes = "", nil, nil, false, nil
	return p
}

// policyKey hashes the node data the policy compiler reads.
func policyKey(nodes []store.Node) uint64 {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	var b [8]byte
	for i := range nodes {
		n := &nodes[i]
		binary.LittleEndian.PutUint64(b[:], n.ID)
		h.Write(b[:])
		h.WriteString(n.Name)
		h.WriteByte(0)
		h.WriteString(n.User)
		h.WriteByte(0)
		for _, a := range []netip.Addr{n.IPv4, n.IPv6} {
			ab, _ := a.MarshalBinary()
			h.Write(ab)
		}
		for _, r := range n.Routes {
			rb, _ := r.MarshalBinary()
			h.Write(rb)
		}
		h.WriteByte(0xff)
	}
	return h.Sum64()
}

// buildFilters converts compiled rules to wire form. Nodes matched by the
// same ACL share rule slices, so each distinct rule is converted and
// hashed once, however many nodes it applies to.
func buildFilters(c *policy.Compiled, nodes []store.Node) map[uint64]*nodeFilter {
	type sliceKey struct {
		p *netip.Prefix
		n int
	}
	strs := map[sliceKey][]string{}
	prefixStrings := func(ps []netip.Prefix) []string {
		if len(ps) == 0 {
			return nil
		}
		k := sliceKey{&ps[0], len(ps)}
		if s, ok := strs[k]; ok {
			return s
		}
		s := make([]string, len(ps))
		for i, p := range ps {
			s[i] = p.String()
		}
		strs[k] = s
		return s
	}
	type ruleKey struct {
		src, dst sliceKey
		ports    *policy.PortRange
		nports   int
	}
	type wireRule struct {
		rule *v1.FilterRule
		hash uint64
	}
	rules := map[ruleKey]wireRule{}
	out := make(map[uint64]*nodeFilter, len(nodes))
	var hb [8]byte
	for i := range nodes {
		id := nodes[i].ID
		// Non-nil and empty means deny all inbound.
		f := &nodeFilter{rules: []*v1.FilterRule{}}
		var h maphash.Hash
		h.SetSeed(hashSeed)
		for _, r := range c.Rules[id] {
			k := ruleKey{nports: len(r.Ports)}
			if len(r.Src) > 0 {
				k.src = sliceKey{&r.Src[0], len(r.Src)}
			}
			if len(r.Dst) > 0 {
				k.dst = sliceKey{&r.Dst[0], len(r.Dst)}
			}
			if len(r.Ports) > 0 {
				k.ports = &r.Ports[0]
			}
			w, ok := rules[k]
			if !ok {
				fr := &v1.FilterRule{SrcPrefixes: prefixStrings(r.Src), DstPrefixes: prefixStrings(r.Dst)}
				for _, pr := range r.Ports {
					fr.Ports = append(fr.Ports, &v1.PortRange{First: uint32(pr.First), Last: uint32(pr.Last)})
				}
				b, _ := deterministic.Marshal(fr)
				w = wireRule{fr, maphash.Bytes(hashSeed, b)}
				rules[k] = w
			}
			f.rules = append(f.rules, w.rule)
			binary.LittleEndian.PutUint64(hb[:], w.hash)
			h.Write(hb[:])
		}
		f.hash = h.Sum64()
		for _, r := range c.SSH[id] {
			f.ssh = append(f.ssh, &v1.SSHRule{SrcPrefixes: prefixStrings(r.Src), Users: r.Users, Record: r.Record})
		}
		out[id] = f
	}
	return out
}

// settings is everything in node i's map apart from self, peers, the
// packet filter and the version.
func (s *Service) settings(snap *snapshot, i int) *v1.NetworkMap {
	n := &snap.nodes[i]
	nm := &v1.NetworkMap{
		Dns:           snap.dns,
		Relays:        s.cfg.Relays,
		Stun:          s.cfg.STUN,
		RelayOffered:  n.RelayOffered,
		RelayApproved: n.RelayApproved,
		FlowLogs:      s.cfg.FlowLogs,
		QuicRelay:     s.cfg.QUICRelay,
		SshRules:      snap.filters[n.ID].ssh,
		LockChain:     snap.lockChain,
	}
	nm.QuicRelayCertSha256 = s.cfg.QUICRelayPin
	for _, r := range snap.peerRelays {
		if r.id != n.ID {
			nm.PeerRelays = append(nm.PeerRelays, r.proto)
		}
	}
	if n.RelayOffered && n.RelayApproved {
		for _, c := range snap.relayClients {
			if c.id != n.ID {
				nm.RelayClients = append(nm.RelayClients, c.proto)
			}
		}
	}
	if s.cfg.GatewayDomain != "" {
		nm.GatewayUrl = s.cfg.GatewayURL
	}
	for _, e := range snap.exposures[n.ID] {
		if !e.Advertised {
			continue
		}
		x := &v1.Exposure{Name: e.Name, Port: uint32(e.Port), Approved: e.Approved, Url: s.exposureURL(e.Name)}
		switch {
		case s.cfg.GatewayDomain == "":
			x.Problem = "the server has no gateway domain configured"
		case !e.Approved:
			x.Problem = "waiting for an admin to approve it"
		}
		nm.Exposures = append(nm.Exposures, x)
	}
	for _, name := range snap.taken[n.ID] {
		nm.Exposures = append(nm.Exposures, &v1.Exposure{Name: name, Problem: "name taken by another machine"})
	}
	return nm
}

// fullMap completes node i's settings into its whole network map.
func fullMap(snap *snapshot, i int, nm *v1.NetworkMap) *v1.NetworkMap {
	id := snap.nodes[i].ID
	nm.Self, nm.Version, nm.PacketFilter = snap.protos[i], snap.version, snap.filters[id].rules
	// Peers come out in node ID order, the order Apply keeps on the client.
	for _, pid := range snap.compiled.Peers(id) {
		nm.Peers = append(nm.Peers, snap.protos[snap.index[pid]])
	}
	return nm
}

// mapStream is what one node's stream has sent so far.
type mapStream struct {
	id     uint64
	deltas bool
	// The snapshot the client's current map was built from, and the
	// settings it was sent.
	snap     *snapshot
	settings []byte
}

// next returns the message that brings the client up to date with snap,
// or nil when nothing relevant to this node changed.
func (s *Service) next(m *mapStream, snap *snapshot) (*v1.StreamNetworkMapResponse, error) {
	i, ok := snap.index[m.id]
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("node was deleted"))
	}
	old := m.snap
	if old == snap {
		return nil, nil
	}
	settings := s.settings(snap, i)
	sb, err := deterministic.Marshal(settings)
	if err != nil {
		return nil, err
	}
	prevSettings := m.settings
	m.snap, m.settings = snap, sb
	oi, known := 0, false
	if old != nil {
		oi, known = old.index[m.id]
	}
	if !known {
		return &v1.StreamNetworkMapResponse{NetworkMap: fullMap(snap, i, settings)}, nil
	}
	d := &v1.NetworkMapDelta{Version: snap.version}
	if snap.protos[i] != old.protos[oi] {
		d.Self = snap.protos[i]
	}
	if nf, of := snap.filters[m.id], old.filters[m.id]; nf.hash != of.hash {
		d.PacketFilter = &v1.PacketFilter{Rules: nf.rules}
	}
	if !bytes.Equal(sb, prevSettings) {
		d.Settings = settings
	}
	diffPeers(old, snap, m.id, d)
	if d.Self == nil && d.PacketFilter == nil && d.Settings == nil && len(d.PeersChanged) == 0 && len(d.PeersRemoved) == 0 {
		return nil, nil
	}
	if !m.deltas {
		return &v1.StreamNetworkMapResponse{NetworkMap: fullMap(snap, i, s.settings(snap, i))}, nil
	}
	return &v1.StreamNetworkMapResponse{Delta: d}, nil
}

// diffPeers adds node id's peer changes between two snapshots to d.
func diffPeers(old, snap *snapshot, id uint64, d *v1.NetworkMapDelta) {
	nh, nn := snap.compiled.PeerSet(id)
	oh, on := old.compiled.PeerSet(id)
	if old.version == snap.prevVersion && nh == oh && nn == on {
		// Same peers as before: only entries that changed need a look,
		// usually a handful however big the network is.
		for _, pid := range snap.changed {
			if snap.compiled.CanTalk(id, pid) {
				d.PeersChanged = append(d.PeersChanged, snap.protos[snap.index[pid]])
			}
		}
		return
	}
	// The peer set changed (or the stream skipped versions): merge the two
	// ID-ordered lists.
	np, op := snap.compiled.Peers(id), old.compiled.Peers(id)
	for len(np) > 0 || len(op) > 0 {
		switch {
		case len(op) == 0 || len(np) > 0 && np[0] < op[0]:
			d.PeersChanged = append(d.PeersChanged, snap.protos[snap.index[np[0]]])
			np = np[1:]
		case len(np) == 0 || op[0] < np[0]:
			d.PeersRemoved = append(d.PeersRemoved, op[0])
			op = op[1:]
		default:
			if p := snap.protos[snap.index[np[0]]]; p != old.protos[old.index[op[0]]] {
				d.PeersChanged = append(d.PeersChanged, p)
			}
			np, op = np[1:], op[1:]
		}
	}
}

var (
	peersField        = (&v1.NetworkMap{}).ProtoReflect().Descriptor().Fields().ByName("peers").Number()
	peersChangedField = (&v1.NetworkMapDelta{}).ProtoReflect().Descriptor().Fields().ByName("peers_changed").Number()
)

// pack switches a message's peer entries to their encodings from the
// snapshot, made once when it was built, instead of encoding the same peer
// again for every stream it goes to. The bytes go in the message's unknown
// fields, which protobuf writes out verbatim: the wire format is exactly
// what encoding the entries would produce.
func pack(r *v1.StreamNetworkMapResponse, snap *snapshot) {
	switch {
	case r.NetworkMap != nil:
		if packNodes(r.NetworkMap, peersField, r.NetworkMap.Peers, snap) {
			r.NetworkMap.Peers = nil
		}
	case r.Delta != nil:
		if packNodes(r.Delta, peersChangedField, r.Delta.PeersChanged, snap) {
			r.Delta.PeersChanged = nil
		}
	}
}

func packNodes(m proto.Message, field protowire.Number, nodes []*v1.Node, snap *snapshot) bool {
	size := 0
	for _, n := range nodes {
		i, ok := snap.index[n.Id]
		if !ok || snap.protos[i] != n {
			return false
		}
		size += protowire.SizeTag(field) + protowire.SizeBytes(len(snap.wire[i]))
	}
	raw := make([]byte, 0, size)
	for _, n := range nodes {
		raw = protowire.AppendTag(raw, field, protowire.BytesType)
		raw = protowire.AppendBytes(raw, snap.wire[snap.index[n.Id]])
	}
	pr := m.ProtoReflect()
	pr.SetUnknown(append(pr.GetUnknown(), raw...))
	return true
}
