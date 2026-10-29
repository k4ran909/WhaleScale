// Package store persists control-plane state in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidKey    = errors.New("invalid, expired or already used auth key")
	ErrPoolExhausted = errors.New("address pool exhausted")
)

// Node address pool: the CGNAT range, like Tailscale. 100.100.100.100 is kept
// free for the future MagicDNS resolver.
var (
	ipv4Pool     = netip.MustParsePrefix("100.64.0.0/10")
	reservedIPv4 = netip.MustParseAddr("100.100.100.100")
)

type Store struct {
	db *sql.DB
}

type User struct {
	ID        uint64
	Name      string
	CreatedAt time.Time
}

type PreAuthKey struct {
	ID        uint64
	User      string
	Prefix    string
	Reusable  bool
	Ephemeral bool
	Used      bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Node struct {
	ID         uint64
	UserID     uint64
	User       string
	Name       string
	MachineKey string
	IPv4       netip.Addr
	IPv6       netip.Addr
	OS         string
	Ephemeral  bool
	CreatedAt  time.Time
	LastSeen   time.Time
	NodeKey    string
	DiscoKey   string
	Endpoints  []string
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if _, err := s.IPv6Prefix(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// IPv6Prefix returns this deployment's ULA /48, generating a random one on
// first use (RFC 4193) so separate deployments don't collide.
func (s *Store) IPv6Prefix(ctx context.Context) (netip.Prefix, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ipv6_prefix'`).Scan(&v)
	if err == nil {
		return netip.ParsePrefix(v)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return netip.Prefix{}, err
	}
	var b [16]byte
	b[0] = 0xfd
	if _, err := rand.Read(b[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	p := netip.PrefixFrom(netip.AddrFrom16(b), 48)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES ('ipv6_prefix', ?)`, p.String()); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

// --- users ---

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (s *Store) CreateUser(ctx context.Context, name string) (*User, error) {
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid user name %q: use lowercase letters, digits and '-'", name)
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(name, created_at) VALUES (?, ?)`, name, now.Unix())
	if err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("user %q: %w", name, ErrAlreadyExists)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: uint64(id), Name: name, CreatedAt: now}, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = time.Unix(created, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) userID(ctx context.Context, q querier, name string) (uint64, error) {
	var id uint64
	err := q.QueryRowContext(ctx, `SELECT id FROM users WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	return id, err
}

// --- pre-auth keys ---

// CreatePreAuthKey returns the stored key and the plaintext secret, which is
// never stored and cannot be recovered later.
func (s *Store) CreatePreAuthKey(ctx context.Context, user string, reusable, ephemeral bool, ttl time.Duration) (*PreAuthKey, string, error) {
	uid, err := s.userID(ctx, s.db, user)
	if err != nil {
		return nil, "", err
	}
	prefix, err := randHex(6)
	if err != nil {
		return nil, "", err
	}
	secret, err := randHex(24)
	if err != nil {
		return nil, "", err
	}
	plain := "wskey-" + prefix + "-" + secret
	now := time.Now()
	k := &PreAuthKey{User: user, Prefix: prefix, Reusable: reusable, Ephemeral: ephemeral,
		ExpiresAt: now.Add(ttl), CreatedAt: now}
	res, err := s.db.ExecContext(ctx, `INSERT INTO preauth_keys(user_id, prefix, hash, reusable, ephemeral, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, uid, prefix, hashSecret(plain), reusable, ephemeral, k.ExpiresAt.Unix(), now.Unix())
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	k.ID = uint64(id)
	return k, plain, nil
}

func (s *Store) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT k.id, u.name, k.prefix, k.reusable, k.ephemeral, k.used, k.expires_at, k.created_at
		FROM preauth_keys k JOIN users u ON u.id = k.user_id ORDER BY k.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PreAuthKey
	for rows.Next() {
		var k PreAuthKey
		var exp, created int64
		if err := rows.Scan(&k.ID, &k.User, &k.Prefix, &k.Reusable, &k.Ephemeral, &k.Used, &exp, &created); err != nil {
			return nil, err
		}
		k.ExpiresAt, k.CreatedAt = time.Unix(exp, 0), time.Unix(created, 0)
		out = append(out, k)
	}
	return out, rows.Err()
}

// ExpirePreAuthKey makes a key unusable immediately.
func (s *Store) ExpirePreAuthKey(ctx context.Context, prefix string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE preauth_keys SET expires_at = ? WHERE prefix = ?`, time.Now().Unix(), prefix)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("key %q: %w", prefix, ErrNotFound)
	}
	return nil
}

// --- nodes ---

type RegisterParams struct {
	AuthKey    string
	MachineKey string
	Hostname   string
	OS         string
}

// RegisterNode consumes a pre-auth key and creates a node, returning it and
// its plaintext node token.
func (s *Store) RegisterNode(ctx context.Context, p RegisterParams) (*Node, string, error) {
	// Read outside the transaction: the pool has one connection, which the
	// transaction holds until it ends.
	prefix, err := s.IPv6Prefix(ctx)
	if err != nil {
		return nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	var (
		keyID, uid          uint64
		reusable, ephemeral bool
		used                bool
		exp                 int64
		userName            string
	)
	err = tx.QueryRowContext(ctx, `SELECT k.id, k.user_id, u.name, k.reusable, k.ephemeral, k.used, k.expires_at
		FROM preauth_keys k JOIN users u ON u.id = k.user_id WHERE k.hash = ?`, hashSecret(p.AuthKey)).
		Scan(&keyID, &uid, &userName, &reusable, &ephemeral, &used, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrInvalidKey
	}
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	if now.Unix() >= exp || (used && !reusable) {
		return nil, "", ErrInvalidKey
	}

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE machine_key = ?`, p.MachineKey).Scan(&exists); err != nil {
		return nil, "", err
	}
	if exists > 0 {
		return nil, "", fmt.Errorf("machine key: %w", ErrAlreadyExists)
	}

	name, err := uniqueNodeName(ctx, tx, sanitizeHostname(p.Hostname))
	if err != nil {
		return nil, "", err
	}
	v4, err := allocateIPv4(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	v6 := ipv6For(prefix, v4)

	token, err := randHex(32)
	if err != nil {
		return nil, "", err
	}
	token = "wsnode-" + token

	res, err := tx.ExecContext(ctx, `INSERT INTO nodes(user_id, name, machine_key, ipv4, ipv6, os, token_hash, ephemeral, preauth_key_id, created_at, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uid, name, p.MachineKey, v4.String(), v6.String(), p.OS, hashSecret(token), ephemeral, keyID, now.Unix(), now.Unix())
	if err != nil {
		return nil, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE preauth_keys SET used = 1 WHERE id = ?`, keyID); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	return &Node{ID: uint64(id), UserID: uid, User: userName, Name: name, MachineKey: p.MachineKey,
		IPv4: v4, IPv6: v6, OS: p.OS, Ephemeral: ephemeral, CreatedAt: now, LastSeen: now}, token, nil
}

const nodeColumns = `n.id, n.user_id, u.name, n.name, n.machine_key, n.ipv4, n.ipv6, n.os, n.ephemeral, n.created_at, n.last_seen, n.node_key, n.disco_key, n.endpoints`

// NodeByToken authenticates a node token and bumps last_seen.
func (s *Store) NodeByToken(ctx context.Context, token string) (*Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes n JOIN users u ON u.id = n.user_id WHERE n.token_hash = ?`, hashSecret(token))
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `UPDATE nodes SET last_seen = ? WHERE id = ?`, now.Unix(), n.ID); err != nil {
		return nil, err
	}
	n.LastSeen = now
	return n, nil
}

// ListNodes returns all nodes, optionally filtered to one user.
func (s *Store) ListNodes(ctx context.Context, user string) ([]Node, error) {
	q := `SELECT ` + nodeColumns + ` FROM nodes n JOIN users u ON u.id = n.user_id`
	var args []any
	if user != "" {
		q += ` WHERE u.name = ?`
		args = append(args, user)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY n.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// NodeInfo is what an agent reports about itself after registering.
type NodeInfo struct {
	NodeKey   string
	DiscoKey  string
	Endpoints []string
	OS        string
}

// UpdateNodeInfo stores agent-reported keys and endpoints. It reports
// whether anything changed, so callers can skip redundant map updates.
func (s *Store) UpdateNodeInfo(ctx context.Context, id uint64, info NodeInfo) (bool, error) {
	if info.Endpoints == nil {
		info.Endpoints = []string{}
	}
	eps, err := json.Marshal(info.Endpoints)
	if err != nil {
		return false, err
	}
	if info.NodeKey != "" {
		var other int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE node_key = ? AND id != ?`, info.NodeKey, id).Scan(&other); err != nil {
			return false, err
		}
		if other > 0 {
			return false, fmt.Errorf("node key: %w", ErrAlreadyExists)
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET node_key = ?, disco_key = ?, endpoints = ?, os = ?, last_seen = ?
		WHERE id = ? AND (node_key != ? OR disco_key != ? OR endpoints != ? OR os != ?)`,
		info.NodeKey, info.DiscoKey, string(eps), info.OS, time.Now().Unix(), id,
		info.NodeKey, info.DiscoKey, string(eps), info.OS)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) DeleteNode(ctx context.Context, id uint64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d: %w", id, ErrNotFound)
	}
	return nil
}

// --- helpers ---

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type scanner interface{ Scan(dest ...any) error }

func scanNode(r scanner) (*Node, error) {
	var n Node
	var v4, v6 string
	var created, seen int64
	var eps string
	if err := r.Scan(&n.ID, &n.UserID, &n.User, &n.Name, &n.MachineKey, &v4, &v6, &n.OS, &n.Ephemeral, &created, &seen,
		&n.NodeKey, &n.DiscoKey, &eps); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(eps), &n.Endpoints); err != nil {
		return nil, fmt.Errorf("node %d endpoints: %w", n.ID, err)
	}
	n.IPv4, _ = netip.ParseAddr(v4)
	n.IPv6, _ = netip.ParseAddr(v6)
	n.CreatedAt, n.LastSeen = time.Unix(created, 0), time.Unix(seen, 0)
	return &n, nil
}

func allocateIPv4(ctx context.Context, q querier) (netip.Addr, error) {
	rows, err := q.QueryContext(ctx, `SELECT ipv4 FROM nodes`)
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			used[a] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}
	// Skip the network address; stop before the broadcast address.
	for a := ipv4Pool.Addr().Next(); ipv4Pool.Contains(a.Next()); a = a.Next() {
		if a != reservedIPv4 && !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

// ipv6For embeds the IPv4 address in the low 32 bits of the deployment prefix,
// so a node's two addresses are easy to correlate.
func ipv6For(prefix netip.Prefix, v4 netip.Addr) netip.Addr {
	b := prefix.Addr().As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b)
}

var hostnameStrip = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	h = strings.Trim(hostnameStrip.ReplaceAllString(h, "-"), "-")
	if len(h) > 50 {
		h = strings.TrimRight(h[:50], "-")
	}
	if h == "" {
		h = "node"
	}
	return h
}

// uniqueNodeName picks a name unique across all users, because MagicDNS names
// are <node>.<suffix>.
func uniqueNodeName(ctx context.Context, q querier, base string) (string, error) {
	name := base
	for i := 1; ; i++ {
		var n int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE name = ?`, name).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return name, nil
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// Fingerprint changes whenever nodes are added or removed, including by
// admin commands run against the database while the server is up.
func (s *Store) Fingerprint(ctx context.Context) (string, error) {
	var count, sum int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(id), 0) FROM nodes`).Scan(&count, &sum)
	return fmt.Sprintf("%d/%d", count, sum), err
}
