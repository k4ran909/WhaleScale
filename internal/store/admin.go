package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- settings ---

func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- users ---

// UserDetail adds admin-facing fields to User.
type UserDetail struct {
	User
	Email     string
	NodeCount int
}

func (s *Store) ListUserDetails(ctx context.Context) ([]UserDetail, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.name, u.email, u.created_at,
		(SELECT COUNT(*) FROM nodes n WHERE n.user_id = u.id) FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserDetail
	for rows.Next() {
		var u UserDetail
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &created, &u.NodeCount); err != nil {
			return nil, err
		}
		u.CreatedAt = time.Unix(created, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ErrUserHasNodes stops a user with nodes from being deleted by accident.
var ErrUserHasNodes = errors.New("user still has nodes; delete them first")

func (s *Store) DeleteUser(ctx context.Context, name string) error {
	uid, err := s.userID(ctx, s.db, name)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE user_id = ?`, uid).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%q has %d node(s): %w", name, n, ErrUserHasNodes)
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, uid)
	return err
}

// UserForOIDC returns the user linked to an OIDC subject, creating one on
// first login. The user name comes from the email's local part, made unique.
func (s *Store) UserForOIDC(ctx context.Context, subject, email string) (*User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, created_at FROM users WHERE oidc_subject = ?`, subject).
		Scan(&u.ID, &u.Name, &created)
	if err == nil {
		u.CreatedAt = time.Unix(created, 0)
		s.db.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, email, u.ID)
		return &u, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	local, _, _ := strings.Cut(email, "@")
	base := sanitizeHostname(local)
	if base == "node" && local == "" {
		base = "user"
	}
	now := time.Now()
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		var id int64
		err := s.db.QueryRowContext(ctx, `INSERT INTO users(name, email, oidc_subject, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
			name, email, subject, now.Unix()).Scan(&id)
		if isUniqueErr(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &User{ID: uint64(id), Name: name, CreatedAt: now}, nil
	}
	return nil, errors.New("could not pick a unique user name")
}

// --- API keys ---

type APIKey struct {
	ID        uint64
	Prefix    string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
	Scope     string
}

// API key scopes.
const (
	// ScopeAdmin keys can do everything.
	ScopeAdmin = "admin"
	// ScopeRead keys can look but not change anything: for monitoring and
	// AI agents.
	ScopeRead = "read"
)

// ValidScope reports whether s names a scope.
func ValidScope(s string) bool { return s == ScopeAdmin || s == ScopeRead }

func (k APIKey) Valid() bool { return time.Now().Before(k.ExpiresAt) }

// CreateAPIKey makes an admin-scope key.
func (s *Store) CreateAPIKey(ctx context.Context, ttl time.Duration) (*APIKey, string, error) {
	return s.CreateScopedAPIKey(ctx, ttl, ScopeAdmin)
}

// CreateScopedAPIKey makes a key with the given scope.
func (s *Store) CreateScopedAPIKey(ctx context.Context, ttl time.Duration, scope string) (*APIKey, string, error) {
	if !ValidScope(scope) {
		return nil, "", fmt.Errorf("unknown API key scope %q (admin or read)", scope)
	}
	prefix, err := randHex(6)
	if err != nil {
		return nil, "", err
	}
	secret, err := randHex(24)
	if err != nil {
		return nil, "", err
	}
	plain := "wsapi-" + prefix + "-" + secret
	now := time.Now()
	k := &APIKey{Prefix: prefix, CreatedAt: now, ExpiresAt: now.Add(ttl), Scope: scope}
	var id int64
	err = s.db.QueryRowContext(ctx, `INSERT INTO api_keys(prefix, hash, created_at, expires_at, scope) VALUES (?, ?, ?, ?, ?) RETURNING id`,
		prefix, hashSecret(plain), now.Unix(), k.ExpiresAt.Unix(), scope).Scan(&id)
	if err != nil {
		return nil, "", err
	}
	k.ID = uint64(id)
	return k, plain, nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, prefix, created_at, expires_at, last_used, scope FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var c, e, l int64
		if err := rows.Scan(&k.ID, &k.Prefix, &c, &e, &l, &k.Scope); err != nil {
			return nil, err
		}
		k.CreatedAt, k.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
		if l > 0 {
			k.LastUsed = time.Unix(l, 0)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) ExpireAPIKey(ctx context.Context, prefix string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET expires_at = ? WHERE prefix = ?`, time.Now().Unix(), prefix)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("api key %q: %w", prefix, ErrNotFound)
	}
	return nil
}

// CheckAPIKey validates a key and returns its prefix for audit logs.
func (s *Store) CheckAPIKey(ctx context.Context, plain string) (string, error) {
	var prefix string
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT prefix, expires_at FROM api_keys WHERE hash = ?`, hashSecret(plain)).Scan(&prefix, &exp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && time.Now().Unix() >= exp) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	s.db.ExecContext(ctx, `UPDATE api_keys SET last_used = ? WHERE prefix = ?`, time.Now().Unix(), prefix)
	return prefix, nil
}

// APIKeyScope returns a key's scope by prefix (for console sessions opened
// with a key). An unknown key gets the read scope.
func (s *Store) APIKeyScope(ctx context.Context, prefix string) string {
	var scope string
	if err := s.db.QueryRowContext(ctx, `SELECT scope FROM api_keys WHERE prefix = ?`, prefix).Scan(&scope); err != nil {
		return ScopeRead
	}
	return scope
}

// --- console sessions ---

func (s *Store) CreateSession(ctx context.Context, identity string, ttl time.Duration) (string, error) {
	tok, err := randHex(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now.Unix())
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(hash, identity, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashSecret(tok), identity, now.Unix(), now.Add(ttl).Unix())
	return tok, err
}

func (s *Store) SessionIdentity(ctx context.Context, tok string) (string, error) {
	var id string
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT identity, expires_at FROM sessions WHERE hash = ?`, hashSecret(tok)).Scan(&id, &exp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && time.Now().Unix() >= exp) {
		return "", ErrNotFound
	}
	return id, err
}

func (s *Store) DeleteSession(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hashSecret(tok))
	return err
}

// --- routes ---

type Route struct {
	NodeID     uint64
	NodeName   string
	Prefix     netip.Prefix
	Advertised bool
	Approved   bool
}

func (r Route) IsExit() bool { return r.Prefix.Bits() == 0 }

// SetAdvertisedRoutes records what a node currently offers. It reports
// whether the set changed.
func (s *Store) SetAdvertisedRoutes(ctx context.Context, nodeID uint64, prefixes []netip.Prefix) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT prefix FROM routes WHERE node_id = ? AND advertised = TRUE`, nodeID)
	if err != nil {
		return false, err
	}
	before := map[string]bool{}
	for rows.Next() {
		var p string
		rows.Scan(&p)
		before[p] = true
	}
	rows.Close()
	after := map[string]bool{}
	for _, p := range prefixes {
		after[p.Masked().String()] = true
	}
	changed := len(before) != len(after)
	for p := range after {
		if !before[p] {
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET advertised = FALSE WHERE node_id = ?`, nodeID); err != nil {
		return false, err
	}
	for p := range after {
		if _, err := tx.ExecContext(ctx, `INSERT INTO routes(node_id, prefix, advertised) VALUES (?, ?, TRUE)
			ON CONFLICT(node_id, prefix) DO UPDATE SET advertised = TRUE`, nodeID, p); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.node_id, n.name, r.prefix, r.advertised, r.approved
		FROM routes r JOIN nodes n ON n.id = r.node_id ORDER BY n.name, r.prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		var p string
		if err := rows.Scan(&r.NodeID, &r.NodeName, &p, &r.Advertised, &r.Approved); err != nil {
			return nil, err
		}
		if r.Prefix, err = netip.ParsePrefix(p); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetRouteApproved(ctx context.Context, nodeID uint64, prefix netip.Prefix, approved bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE routes SET approved = ? WHERE node_id = ? AND prefix = ?`,
		approved, nodeID, prefix.Masked().String())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d has never advertised %s: %w", nodeID, prefix, ErrNotFound)
	}
	return nil
}

// attachRoutes fills each node's advertised and active (approved and still
// advertised) routes.
func (s *Store) attachRoutes(ctx context.Context, nodes []Node) error {
	if len(nodes) == 0 {
		return nil
	}
	routes, err := s.ListRoutes(ctx)
	if err != nil {
		return err
	}
	idx := map[uint64]*Node{}
	for i := range nodes {
		idx[nodes[i].ID] = &nodes[i]
	}
	for _, r := range routes {
		n := idx[r.NodeID]
		if n == nil || !r.Advertised {
			continue
		}
		n.AdvertisedRoutes = append(n.AdvertisedRoutes, r.Prefix)
		if r.Approved {
			n.Routes = append(n.Routes, r.Prefix)
		}
	}
	return nil
}

// --- peer relays ---

// SetRelayOffered records whether a node volunteers as a peer relay. It
// reports whether that changed.
func (s *Store) SetRelayOffered(ctx context.Context, nodeID uint64, offered bool) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET relay_offered = ? WHERE id = ? AND relay_offered != ?`,
		offered, nodeID, offered)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetRelayApproved lets (or stops) a node relay for others.
func (s *Store) SetRelayApproved(ctx context.Context, nodeID uint64, approved bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET relay_approved = ? WHERE id = ?`, approved, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", nodeID, ErrNotFound)
	}
	return nil
}

// --- SSH recordings ---

// Recording describes a recorded SSH session; the contents are a file in
// the recordings directory.
type Recording struct {
	ID        uint64
	NodeName  string
	LocalUser string
	SrcNode   string
	SrcUser   string
	StartedAt time.Time
	EndedAt   time.Time
	Size      int64
	File      string
}

// SaveRecording writes data under dir and records it.
func (s *Store) SaveRecording(ctx context.Context, dir string, r Recording, data []byte) (*Recording, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	suffix, err := randHex(4)
	if err != nil {
		return nil, err
	}
	r.File = fmt.Sprintf("%s-%s-%s.cast", r.StartedAt.UTC().Format("20060102T150405Z"), sanitizeHostname(r.NodeName), suffix)
	if err := os.WriteFile(filepath.Join(dir, r.File), data, 0o600); err != nil {
		return nil, err
	}
	r.Size = int64(len(data))
	var id int64
	err = s.db.QueryRowContext(ctx, `INSERT INTO recordings(node_name, local_user, src_node, src_user, started_at, ended_at, size, file)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, r.NodeName, r.LocalUser, r.SrcNode, r.SrcUser, r.StartedAt.Unix(), r.EndedAt.Unix(), r.Size, r.File).Scan(&id)
	if err != nil {
		os.Remove(filepath.Join(dir, r.File))
		return nil, err
	}
	r.ID = uint64(id)
	return &r, nil
}

func scanRecording(sc interface{ Scan(...any) error }) (Recording, error) {
	var r Recording
	var started, ended int64
	err := sc.Scan(&r.ID, &r.NodeName, &r.LocalUser, &r.SrcNode, &r.SrcUser, &started, &ended, &r.Size, &r.File)
	r.StartedAt, r.EndedAt = time.Unix(started, 0), time.Unix(ended, 0)
	return r, err
}

const recordingColumns = `id, node_name, local_user, src_node, src_user, started_at, ended_at, size, file`

// ListRecordings returns the newest recordings first.
func (s *Store) ListRecordings(ctx context.Context, limit int) ([]Recording, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordingColumns+` FROM recordings ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Recording
	for rows.Next() {
		r, err := scanRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordingByID returns a recording and its contents.
func (s *Store) RecordingByID(ctx context.Context, dir string, id uint64) (*Recording, []byte, error) {
	r, err := scanRecording(s.db.QueryRowContext(ctx, `SELECT `+recordingColumns+` FROM recordings WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("recording %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.Base(r.File)))
	return &r, data, err
}
