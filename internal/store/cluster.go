package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Member is a running server in a cluster sharing this database.
type Member struct {
	ID        string
	PublicURL string
	RelayURL  string
	QUICAddr  string
	StartedAt time.Time
	LastSeen  time.Time
}

// Heartbeat records that server m is alive.
func (s *Store) Heartbeat(ctx context.Context, m Member) error {
	now := time.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `INSERT INTO servers(id, public_url, relay_url, quic_addr, started_at, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET public_url = excluded.public_url, relay_url = excluded.relay_url,
			quic_addr = excluded.quic_addr, last_seen = excluded.last_seen`,
		m.ID, m.PublicURL, m.RelayURL, m.QUICAddr, m.StartedAt.UnixMilli(), now)
	return err
}

// LiveMembers returns servers that heartbeat within window, oldest first:
// the order nodes prefer their relays in.
func (s *Store) LiveMembers(ctx context.Context, window time.Duration) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, public_url, relay_url, quic_addr, started_at, last_seen FROM servers
		WHERE last_seen >= ? ORDER BY started_at, id`, time.Now().Add(-window).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var started, seen int64
		if err := rows.Scan(&m.ID, &m.PublicURL, &m.RelayURL, &m.QUICAddr, &started, &seen); err != nil {
			return nil, err
		}
		m.StartedAt, m.LastSeen = time.UnixMilli(started), time.UnixMilli(seen)
		out = append(out, m)
	}
	return out, rows.Err()
}

// LeaveCluster removes a server and its presence rows, on clean shutdown.
func (s *Store) LeaveCluster(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM presence WHERE server_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, id)
	return err
}

// PruneMembers drops servers silent for longer than maxAge, and presence
// rows of servers no longer listed.
func (s *Store) PruneMembers(ctx context.Context, maxAge time.Duration) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE last_seen < ?`, time.Now().Add(-maxAge).UnixMilli()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM presence WHERE server_id NOT IN (SELECT id FROM servers)`)
	return err
}

// SetPresence adds and removes server's presence rows in one transaction.
func (s *Store) SetPresence(ctx context.Context, server string, add, remove []uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range add {
		if _, err := tx.ExecContext(ctx, `INSERT INTO presence(node_id, server_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, id, server); err != nil {
			return err
		}
	}
	for _, id := range remove {
		if _, err := tx.ExecContext(ctx, `DELETE FROM presence WHERE node_id = ? AND server_id = ?`, id, server); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Presence returns nodes with a map stream on a live server other than
// self.
func (s *Store) Presence(ctx context.Context, self string, window time.Duration) (map[uint64]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.node_id FROM presence p JOIN servers v ON v.id = p.server_id
		WHERE v.id != ? AND v.last_seen >= ?`, self, time.Now().Add(-window).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64]bool{}
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// AcquireLease takes or renews the named lease for holder until ttl from
// now. It reports whether holder has it: someone else's unexpired lease
// wins.
func (s *Store) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO leases(name, holder, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
		WHERE leases.holder = excluded.holder OR leases.expires_at < ?`,
		name, holder, now.Add(ttl).UnixMilli(), now.UnixMilli()); err != nil {
		return false, err
	}
	var got string
	err := s.db.QueryRowContext(ctx, `SELECT holder FROM leases WHERE name = ?`, name).Scan(&got)
	return got == holder, err
}

// ReleaseLease gives up holder's lease, so another server takes over at
// once instead of waiting for it to expire.
func (s *Store) ReleaseLease(ctx context.Context, name, holder string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM leases WHERE name = ? AND holder = ?`, name, holder)
	return err
}

// BumpChangeSeq tells other servers that something changed.
func (s *Store) BumpChangeSeq(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE change_seq SET seq = seq + 1 WHERE id = 1`)
	return err
}

// ChangeSeq reads the change counter.
func (s *Store) ChangeSeq(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT seq FROM change_seq WHERE id = 1`).Scan(&n)
	return n, err
}

// LeaseHolder returns who holds the named lease and until when ("" if
// nobody does).
func (s *Store) LeaseHolder(ctx context.Context, name string) (string, time.Time, error) {
	var holder string
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT holder, expires_at FROM leases WHERE name = ? AND expires_at >= ?`,
		name, time.Now().UnixMilli()).Scan(&holder, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	return holder, time.UnixMilli(exp), err
}
