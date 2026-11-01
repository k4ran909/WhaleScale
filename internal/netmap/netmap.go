// Package netmap applies incremental network map updates on the client.
package netmap

import (
	"errors"
	"sort"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
)

// Apply returns the map that results from applying d to cur. cur is not
// modified; unchanged peers are shared between the two.
func Apply(cur *v1.NetworkMap, d *v1.NetworkMapDelta) (*v1.NetworkMap, error) {
	if cur == nil {
		return nil, errors.New("network map delta before any full map")
	}
	var next *v1.NetworkMap
	if d.Settings != nil {
		next = proto.Clone(d.Settings).(*v1.NetworkMap)
	} else {
		next = shallowCopy(cur)
	}
	next.Self, next.PacketFilter, next.Version = cur.Self, cur.PacketFilter, d.Version
	if d.Self != nil {
		next.Self = d.Self
	}
	if d.PacketFilter != nil {
		next.PacketFilter = d.PacketFilter.Rules
		if next.PacketFilter == nil {
			// Empty and non-nil: deny all inbound.
			next.PacketFilter = []*v1.FilterRule{}
		}
	}
	next.Peers = cur.Peers
	if len(d.PeersChanged) > 0 || len(d.PeersRemoved) > 0 {
		peers := make(map[uint64]*v1.Node, len(cur.Peers)+len(d.PeersChanged))
		for _, p := range cur.Peers {
			peers[p.Id] = p
		}
		for _, id := range d.PeersRemoved {
			delete(peers, id)
		}
		for _, p := range d.PeersChanged {
			peers[p.Id] = p
		}
		next.Peers = make([]*v1.Node, 0, len(peers))
		for _, p := range peers {
			next.Peers = append(next.Peers, p)
		}
		sort.Slice(next.Peers, func(i, j int) bool { return next.Peers[i].Id < next.Peers[j].Id })
	}
	return next, nil
}

// WithPeers returns a copy of m with a different peer list, sharing
// everything else.
func WithPeers(m *v1.NetworkMap, peers []*v1.Node) *v1.NetworkMap {
	out := shallowCopy(m)
	out.Self, out.PacketFilter, out.Version, out.Peers = m.Self, m.PacketFilter, m.Version, peers
	return out
}

// shallowCopy copies the settings fields of a map, sharing their contents.
func shallowCopy(m *v1.NetworkMap) *v1.NetworkMap {
	return &v1.NetworkMap{
		Dns:                 m.Dns,
		Relays:              m.Relays,
		Stun:                m.Stun,
		Exposures:           m.Exposures,
		GatewayUrl:          m.GatewayUrl,
		PeerRelays:          m.PeerRelays,
		RelayClients:        m.RelayClients,
		RelayOffered:        m.RelayOffered,
		RelayApproved:       m.RelayApproved,
		SshRules:            m.SshRules,
		FlowLogs:            m.FlowLogs,
		QuicRelay:           m.QuicRelay,
		QuicRelayCertSha256: m.QuicRelayCertSha256,
		LockChain:           m.LockChain,
		ControlUrls:         m.ControlUrls,
	}
}
