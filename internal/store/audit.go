package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AuditEvent is one entry in the audit log: who did what, and when.
type AuditEvent struct {
	ID     uint64
	At     time.Time
	Actor  string // "oidc:alice@example.com", "api-key:ab12cd", "cli:root", "user:alice", "git", ...
	Action string // "user created", "policy updated", ...
	Detail string // key=value pairs
}

// Audit appends an event. kv are alternating keys and values, formatted
// like log fields. Each entry's hash covers the previous entry's hash and
// its own fields, so VerifyAudit detects edited or deleted rows.
func (s *Store) Audit(ctx context.Context, actor, action string, kv ...any) error {
	e := AuditEvent{At: time.Now().Truncate(time.Second), Actor: actor, Action: action, Detail: formatKV(kv)}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// One writer at a time, or two servers would both chain onto the same
	// entry.
	if err := tx.lock(ctx, "audit-log"); err != nil {
		return err
	}
	prev := make([]byte, sha256.Size)
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO audit_log(at, actor, action, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		e.At.Unix(), e.Actor, e.Action, e.Detail, prev, []byte{}).Scan(&id)
	if err != nil {
		return err
	}
	e.ID = uint64(id)
	if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET hash = ? WHERE id = ?`, auditHash(prev, e), id); err != nil {
		return err
	}
	return tx.Commit()
}

// auditHash chains an entry to the one before it. The ID is included so
// rows can't be renumbered or reordered.
func auditHash(prev []byte, e AuditEvent) []byte {
	h := sha256.New()
	h.Write(prev)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], e.ID)
	binary.BigEndian.PutUint64(b[8:], uint64(e.At.Unix()))
	h.Write(b[:])
	for _, f := range []string{e.Actor, e.Action, e.Detail} {
		binary.BigEndian.PutUint64(b[:8], uint64(len(f)))
		h.Write(b[:8])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

func formatKV(kv []any) string {
	var sb strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		v := fmt.Sprint(kv[i+1])
		if v == "" || strings.ContainsAny(v, " \t\n\"=") {
			v = strconv.Quote(v)
		}
		fmt.Fprintf(&sb, "%v=%s", kv[i], v)
	}
	return sb.String()
}

// AuditQuery filters QueryAudit. Zero values match everything.
type AuditQuery struct {
	Since  time.Time
	Actor  string // substring
	Action string // substring
	Limit  int
}

// QueryAudit returns matching events, newest first.
func (s *Store) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, error) {
	if q.Limit <= 0 || q.Limit > 10000 {
		q.Limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, detail FROM audit_log
		WHERE at >= ? AND `+s.db.contains("actor")+` AND `+s.db.contains("action")+` ORDER BY id DESC LIMIT ?`,
		q.Since.Unix(), q.Actor, q.Action, q.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrAuditTampered means the audit log's hash chain is broken.
var ErrAuditTampered = errors.New("audit log hash chain broken")

// VerifyAudit walks the whole log and checks the hash chain. It returns the
// number of entries checked and the newest entry's hash, or on a break the
// ID of the first entry that doesn't match. The chain can't reveal that the
// newest entries were removed; recording the head hash elsewhere from time
// to time can.
func (s *Store) VerifyAudit(ctx context.Context) (n int, head []byte, badID uint64, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, detail, prev_hash, hash FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, nil, 0, err
	}
	defer rows.Close()
	prev := make([]byte, sha256.Size)
	for rows.Next() {
		var e AuditEvent
		var at int64
		var p, h []byte
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail, &p, &h); err != nil {
			return n, nil, 0, err
		}
		e.At = time.Unix(at, 0)
		if !bytes.Equal(p, prev) || !bytes.Equal(h, auditHash(prev, e)) {
			return n, nil, e.ID, ErrAuditTampered
		}
		prev = h
		n++
	}
	return n, prev, 0, rows.Err()
}
