package control

import (
	"context"
	"time"
)

// DefaultEphemeralTimeout is how long an ephemeral node may stay offline
// before it is removed.
const DefaultEphemeralTimeout = 10 * time.Minute

// RemoveStaleEphemeral deletes ephemeral nodes (registered with an
// ephemeral pre-auth key: CI runners, containers) that have been offline
// longer than timeout, and reports how many went. Nodes holding a map
// stream here are kept whatever their last_seen says.
func (s *Service) RemoveStaleEphemeral(ctx context.Context, timeout time.Duration) (int, error) {
	stale, err := s.store.StaleEphemeralNodes(ctx, time.Now().Add(-timeout))
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, n := range stale {
		s.mu.Lock()
		online := s.online[n.ID] > 0
		s.mu.Unlock()
		if online {
			continue
		}
		if err := s.store.DeleteNode(ctx, n.ID); err != nil {
			return removed, err
		}
		removed++
		s.Audit(ctx, "system", "ephemeral node removed", "node", n.Name, "user", n.User,
			"offline_since", n.LastSeen.UTC().Format(time.RFC3339))
	}
	if removed > 0 {
		s.NotifyAll()
	}
	return removed, nil
}
