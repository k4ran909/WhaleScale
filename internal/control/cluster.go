package control

import (
	"context"
	"slices"
	"time"
)

// Member is a running server as network maps advertise it: where nodes
// can reach its control API, relay and QUIC relay.
type Member struct {
	PublicURL, RelayURL, QUICAddr string
}

// SetMembers updates the servers sharing this database, oldest first.
// Nodes get them as control URLs to fail over to, and use the oldest
// server's relay, so everyone meets on the same one. window is how long a
// silent server still counts as alive.
func (s *Service) SetMembers(ms []Member, window time.Duration) {
	s.mu.Lock()
	s.clusterWindow = window
	same := slices.Equal(ms, s.members)
	if !same {
		s.members = slices.Clone(ms)
	}
	s.mu.Unlock()
	if !same {
		s.notify(false)
	}
}

// Changed marks that this server changed shared state, so the server tells
// the others.
func (s *Service) Changed() { s.localChange.Store(true) }

// TakeChanged reports, and clears, whether Changed was called.
func (s *Service) TakeChanged() bool { return s.localChange.Swap(false) }

// NotifyRemote rebuilds maps after a change made elsewhere: by another
// server or a command run against the database. Unlike NotifyAll it
// doesn't pass the news on.
func (s *Service) NotifyRemote() { s.notify(true) }

// SyncPresence writes which nodes hold a map stream on this server, so
// other servers show them online. Changes are batched: during a connect
// storm this is one transaction, not one per node. It reports whether
// anything was written.
func (s *Service) SyncPresence(ctx context.Context) (bool, error) {
	if s.cfg.ServerID == "" {
		return false, nil
	}
	s.mu.Lock()
	cur := make(map[uint64]bool, len(s.online))
	for id := range s.online {
		cur[id] = true
	}
	s.mu.Unlock()
	var add, remove []uint64
	for id := range cur {
		if !s.presence[id] {
			add = append(add, id)
		}
	}
	for id := range s.presence {
		if !cur[id] {
			remove = append(remove, id)
		}
	}
	if len(add) == 0 && len(remove) == 0 {
		return false, nil
	}
	if err := s.store.SetPresence(ctx, s.cfg.ServerID, add, remove); err != nil {
		return false, err
	}
	s.presence = cur
	return true, nil
}

// clusterInfo returns what maps advertise about the servers.
func (s *Service) clusterInfo() (relays, controls []string, quic string) {
	s.mu.Lock()
	ms := s.members
	s.mu.Unlock()
	if len(ms) == 0 {
		return s.cfg.Relays, nil, s.cfg.QUICRelay
	}
	for _, m := range ms {
		relays = append(relays, m.RelayURL)
		controls = append(controls, m.PublicURL)
	}
	return relays, controls, ms[0].QUICAddr
}
