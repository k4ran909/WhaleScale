package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/k4ran909/whalescale/internal/control"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

// Several servers can share one database (an SQLite file on one host, for
// rolling restarts; a shared database for separate hosts). Each heartbeats
// a row; nodes learn every live server's control URL and fail over between
// them, and all use the oldest server's relay so they meet on the same
// one. One server at a time holds the leader lease and runs the periodic
// jobs (grant expiry, flow log pruning, Git policy sync). Changes spread
// through a change counter in the database that every server polls.

const leaderLease = "leader"

func randomServerID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// clusterWindow is how long a silent server still counts as alive.
func clusterWindow(every time.Duration) time.Duration {
	return max(3*every, 2*time.Second)
}

// clusterTick heartbeats, renews or takes the leader lease, and refreshes
// the member list nodes see.
func (s *Server) clusterTick(ctx context.Context, every time.Duration) {
	window := clusterWindow(every)
	if err := s.store.Heartbeat(ctx, store.Member{ID: s.id, PublicURL: s.cfg.PublicURL, RelayURL: s.relayURL,
		QUICAddr: s.cfg.RelayQUICAddr, StartedAt: s.started}); err != nil {
		s.log.Error("cluster heartbeat", "err", err)
		return
	}
	leader, err := s.store.AcquireLease(ctx, leaderLease, s.id, window)
	if err != nil {
		s.log.Error("leader lease", "err", err)
		leader = false
	}
	if was := s.leader.Swap(leader); was != leader {
		s.log.Info("leader changed", "this_server_leads", leader, "server", s.id)
	}
	members, err := s.store.LiveMembers(ctx, window)
	if err != nil {
		s.log.Error("cluster members", "err", err)
		return
	}
	ms := make([]control.Member, len(members))
	for i, m := range members {
		ms[i] = control.Member{PublicURL: m.PublicURL, RelayURL: m.RelayURL, QUICAddr: m.QUICAddr}
	}
	s.control.SetMembers(ms, window)
	if leader {
		if err := s.store.PruneMembers(ctx, 10*window); err != nil {
			s.log.Error("prune cluster members", "err", err)
		}
	}
}

// Leader reports whether this server holds the leader lease.
func (s *Server) Leader() bool { return s.leader.Load() }

// leaveCluster runs at shutdown so the others take over at once.
func (s *Server) leaveCluster() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.store.ReleaseLease(ctx, leaderLease, s.id)
	s.store.LeaveCluster(ctx, s.id)
	s.store.BumpChangeSeq(ctx)
}

// syncLoop shares this server's changes and presence with the others and
// picks up theirs.
func (s *Server) syncLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	last, _ := s.store.ChangeSeq(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if changed, err := s.control.SyncPresence(ctx); err != nil {
			s.log.Error("write presence", "err", err)
		} else if changed {
			s.control.Changed()
		}
		bumped := false
		if s.control.TakeChanged() {
			if err := s.store.BumpChangeSeq(ctx); err != nil {
				s.log.Error("announce change", "err", err)
				s.control.Changed() // try again next tick
			} else {
				bumped = true
			}
		}
		seq, err := s.store.ChangeSeq(ctx)
		if err != nil || seq == last {
			continue
		}
		remote := !bumped || seq != last+1
		last = seq
		if remote {
			s.control.NotifyRemote()
			s.reloadSharedPolicy(ctx)
			if err := s.control.RefreshGrants(ctx, false); err != nil {
				s.log.Error("refresh access grants", "err", err)
			}
		}
	}
}

// reloadSharedPolicy picks up a policy another server stored: one saved in
// the console, or synced from Git by the leader. A policy file is each
// server's own.
func (s *Server) reloadSharedPolicy(ctx context.Context) {
	text, source := s.control.Policy()
	key := ""
	switch source {
	case "database", "default":
		if s.cfg.PolicyFile == "" && s.psync == nil {
			key, source = control.PolicySettingKey, "database"
		}
	case "url":
		key = syncedPolicyKey
	}
	if key == "" {
		return
	}
	stored, ok, err := s.store.Setting(ctx, key)
	if err != nil || !ok || stored == text {
		return
	}
	p, err := policy.Parse([]byte(stored))
	if err != nil {
		s.log.Error("policy stored by another server is invalid; keeping the current one", "err", err)
		return
	}
	s.control.SetPolicy(p, stored, source)
	s.log.Info("policy updated by another server", "source", source, "acls", len(p.ACLs))
}
