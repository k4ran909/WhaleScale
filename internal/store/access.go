package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Access request states.
const (
	AccessPending  = "pending"
	AccessApproved = "approved"
	AccessDenied   = "denied"
	AccessRevoked  = "revoked"
	AccessExpired  = "expired"
)

// PendingAccessTTL is how long a request waits for a decision.
const PendingAccessTTL = 24 * time.Hour

// AccessRequest is a request for temporary access from one node. While
// approved and unexpired it is a grant.
type AccessRequest struct {
	ID          uint64
	NodeID      uint64
	NodeName    string
	User        string
	Dst         string
	Duration    time.Duration
	Reason      string
	Status      string
	RequestedAt time.Time
	DecidedBy   string
	DecidedAt   time.Time
	ExpiresAt   time.Time
}

// ErrNotPending refuses a decision on a request that was already decided.
var ErrNotPending = errors.New("request is no longer pending")

// ErrNotActive refuses revoking something that isn't an active grant.
var ErrNotActive = errors.New("not an active grant")

const accessColumns = `a.id, a.node_id, n.name, u.name, a.dst, a.duration, a.reason, a.status, a.requested_at,
	a.decided_by, a.decided_at, a.expires_at`

const accessFrom = ` FROM access_requests a JOIN nodes n ON n.id = a.node_id JOIN users u ON u.id = n.user_id`

func scanAccess(r scanner) (*AccessRequest, error) {
	var a AccessRequest
	var dur, req, dec, exp int64
	if err := r.Scan(&a.ID, &a.NodeID, &a.NodeName, &a.User, &a.Dst, &dur, &a.Reason, &a.Status, &req,
		&a.DecidedBy, &dec, &exp); err != nil {
		return nil, err
	}
	a.Duration, a.RequestedAt = time.Duration(dur)*time.Second, time.Unix(req, 0)
	if dec > 0 {
		a.DecidedAt = time.Unix(dec, 0)
	}
	if exp > 0 {
		a.ExpiresAt = time.Unix(exp, 0)
	}
	return &a, nil
}

func (s *Store) accessByID(ctx context.Context, q querier, id uint64) (*AccessRequest, error) {
	a, err := scanAccess(q.QueryRowContext(ctx, `SELECT `+accessColumns+accessFrom+` WHERE a.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("access request %d: %w", id, ErrNotFound)
	}
	return a, err
}

// CreateAccessRequest records a request. With autoApprove it is granted at
// once, decided by "policy".
func (s *Store) CreateAccessRequest(ctx context.Context, nodeID uint64, dst string, d time.Duration, reason string, autoApprove bool) (*AccessRequest, error) {
	now := time.Now()
	status, by, decided, expires := AccessPending, "", int64(0), int64(0)
	if autoApprove {
		status, by, decided, expires = AccessApproved, "policy", now.Unix(), now.Add(d).Unix()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO access_requests(node_id, dst, duration, reason, status, requested_at, decided_by, decided_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, nodeID, dst, int64(d/time.Second), reason, status, now.Unix(), by, decided, expires)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.accessByID(ctx, s.db, uint64(id))
}

// AccessFilter selects access requests. Zero values match everything.
type AccessFilter struct {
	NodeID uint64
	// Open limits the list to pending requests and active grants.
	Open  bool
	Limit int
}

// ListAccessRequests returns requests, newest first.
func (s *Store) ListAccessRequests(ctx context.Context, f AccessFilter) ([]AccessRequest, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	q := `SELECT ` + accessColumns + accessFrom + ` WHERE (? = 0 OR a.node_id = ?)`
	args := []any{f.NodeID, f.NodeID}
	if f.Open {
		q += ` AND (a.status = 'pending' OR (a.status = 'approved' AND a.expires_at > ?))`
		args = append(args, time.Now().Unix())
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY a.id DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		a, err := scanAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// ActiveGrants returns approved, unexpired requests, oldest first.
func (s *Store) ActiveGrants(ctx context.Context) ([]AccessRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accessColumns+accessFrom+
		` WHERE a.status = 'approved' AND a.expires_at > ? ORDER BY a.id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		a, err := scanAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DecideAccessRequest approves or denies a pending request. An approved
// grant runs for the requested duration from now.
func (s *Store) DecideAccessRequest(ctx context.Context, id uint64, approve bool, by string) (*AccessRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := s.accessByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != AccessPending {
		return nil, fmt.Errorf("request %d is %s: %w", id, a.Status, ErrNotPending)
	}
	now := time.Now()
	status, expires := AccessDenied, int64(0)
	if approve {
		status, expires = AccessApproved, now.Add(a.Duration).Unix()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE access_requests SET status = ?, decided_by = ?, decided_at = ?, expires_at = ? WHERE id = ?`,
		status, by, now.Unix(), expires, id); err != nil {
		return nil, err
	}
	if a, err = s.accessByID(ctx, tx, id); err != nil {
		return nil, err
	}
	return a, tx.Commit()
}

// RevokeAccessGrant ends an active grant early.
func (s *Store) RevokeAccessGrant(ctx context.Context, id uint64, by string) (*AccessRequest, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE access_requests SET status = 'revoked', decided_by = ?, decided_at = ?
		WHERE id = ? AND status = 'approved' AND expires_at > ?`, by, time.Now().Unix(), id, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.accessByID(ctx, s.db, id); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("request %d: %w", id, ErrNotActive)
	}
	return s.accessByID(ctx, s.db, id)
}

// ExpireAccessRequests marks grants past their end, and requests left
// pending longer than PendingAccessTTL, as expired, and returns them.
func (s *Store) ExpireAccessRequests(ctx context.Context) ([]AccessRequest, error) {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+accessColumns+accessFrom+`
		WHERE (a.status = 'approved' AND a.expires_at <= ?) OR (a.status = 'pending' AND a.requested_at <= ?)`,
		now.Unix(), now.Add(-PendingAccessTTL).Unix())
	if err != nil {
		return nil, err
	}
	var out []AccessRequest
	for rows.Next() {
		a, err := scanAccess(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, a := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE access_requests SET status = 'expired' WHERE id = ?`, a.ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}
