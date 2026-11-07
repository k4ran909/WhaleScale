package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Admin is a console account that signs in with a password.
type Admin struct {
	ID        uint64
	Name      string
	CreatedAt time.Time
	TwoFactor bool // signs in with a TOTP code too
}

// ValidName reports whether name is a valid user or admin name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// ErrSetupDone: an admin account exists, so first-run setup is closed.
var ErrSetupDone = errors.New("this server already has an admin account")

// AdminCount is how many console accounts exist.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// CreateFirstAdmin creates the first console account, or returns
// ErrSetupDone if there already is one. Racing callers can't both succeed.
func (s *Store) CreateFirstAdmin(ctx context.Context, name, passwordHash string) (*Admin, error) {
	return s.createAdmin(ctx, name, passwordHash, true)
}

// CreateAdmin adds a console account (from the CLI).
func (s *Store) CreateAdmin(ctx context.Context, name, passwordHash string) (*Admin, error) {
	return s.createAdmin(ctx, name, passwordHash, false)
}

func (s *Store) createAdmin(ctx context.Context, name, hash string, first bool) (*Admin, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid name %q: use lowercase letters, digits and '-'", name)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := tx.lock(ctx, "admin-accounts"); err != nil {
		return nil, err
	}
	if first {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, ErrSetupDone
		}
	}
	now := time.Now()
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO admins(name, password_hash, created_at) VALUES (?, ?, ?) RETURNING id`,
		name, hash, now.Unix()).Scan(&id)
	if isUniqueErr(err) {
		return nil, fmt.Errorf("admin %q: %w", name, ErrAlreadyExists)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Admin{ID: uint64(id), Name: name, CreatedAt: now}, nil
}

// AdminPasswordHash returns a console account's password hash.
func (s *Store) AdminPasswordHash(ctx context.Context, name string) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE name = ?`, name).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// AdminExists reports whether a console account exists.
func (s *Store) AdminExists(ctx context.Context, name string) (bool, error) {
	_, err := s.AdminPasswordHash(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// SetAdminPassword changes a console account's password and signs it out
// everywhere.
func (s *Store) SetAdminPassword(ctx context.Context, name, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET password_hash = ? WHERE name = ?`, hash, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.DeleteSessionsOf(ctx, AdminIdentity(name))
}

// DeleteAdmin removes a console account and its sessions.
func (s *Store) DeleteAdmin(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admins WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.DeleteSessionsOf(ctx, AdminIdentity(name))
}

// ListAdmins returns the console accounts, oldest first.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, totp_secret <> '' FROM admins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		var a Admin
		var created int64
		if err := rows.Scan(&a.ID, &a.Name, &created, &a.TwoFactor); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(created, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AdminTOTP returns a console account's TOTP secret ("" when two-factor
// sign-in is off) and the time step of the last code it used.
func (s *Store) AdminTOTP(ctx context.Context, name string) (secret string, last int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT totp_secret, totp_last FROM admins WHERE name = ?`, name).Scan(&secret, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	return secret, last, err
}

// SetAdminTOTPPending stores the secret being set up, until EnableAdminTOTP.
func (s *Store) SetAdminTOTPPending(ctx context.Context, name, secret string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_pending = ? WHERE name = ?`, secret, name)
}

// AdminTOTPPending returns the secret being set up ("" when none).
func (s *Store) AdminTOTPPending(ctx context.Context, name string) (string, error) {
	var p string
	err := s.db.QueryRowContext(ctx, `SELECT totp_pending FROM admins WHERE name = ?`, name).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return p, err
}

// EnableAdminTOTP turns two-factor sign-in on with the pending secret,
// if it's still pending; step is the code that confirmed it.
func (s *Store) EnableAdminTOTP(ctx context.Context, name, pending string, step int64) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_secret = totp_pending, totp_pending = '', totp_last = ?
		WHERE name = ? AND totp_pending = ? AND totp_pending <> ''`, step, name, pending)
}

// DisableAdminTOTP turns two-factor sign-in off.
func (s *Store) DisableAdminTOTP(ctx context.Context, name string) error {
	return s.updateAdmin(ctx, `UPDATE admins SET totp_secret = '', totp_pending = '', totp_last = 0 WHERE name = ?`, name)
}

// UseAdminTOTPStep records that a code from step was used, and reports
// false if one from that step or later already was: across every server
// sharing the database, a code works once.
func (s *Store) UseAdminTOTPStep(ctx context.Context, name string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET totp_last = ? WHERE name = ? AND totp_last < ?`, step, name, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) updateAdmin(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminIdentity is a console account's session identity.
func AdminIdentity(name string) string { return "admin:" + name }

// DeleteSessionsOf signs an identity out of every console session.
func (s *Store) DeleteSessionsOf(ctx context.Context, identity string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE identity = ?`, identity)
	return err
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

const setupCodeKey = "setup_code"

// SetupCode returns the one-time code that lets the first admin account be
// created in the console, creating it if needed, or "" once an admin
// exists. It lives in the database, so every server of a cluster (and the
// CLI) shows the same one.
func (s *Store) SetupCode(ctx context.Context) (string, error) {
	n, err := s.AdminCount(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	return s.SettingOrCreate(ctx, setupCodeKey, RandomCode(8))
}

// ClearSetupCode forgets the setup code once setup is done.
func (s *Store) ClearSetupCode(ctx context.Context) error { return s.DeleteSetting(ctx, setupCodeKey) }

// codeAlphabet has 31 characters that can't be confused when read aloud or
// copied from a log (no 0/O, 1/I/L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// RandomCode returns n random characters from codeAlphabet in groups of
// four, e.g. "K7QM-2XRA" (about 5 bits each).
func RandomCode(n int) string {
	var out strings.Builder
	buf := make([]byte, 1)
	for i := 0; i < n; {
		rand.Read(buf)
		// Rejection sampling: bytes past the largest multiple of the
		// alphabet's size would make some characters likelier.
		if int(buf[0]) >= 256/len(codeAlphabet)*len(codeAlphabet) {
			continue
		}
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(codeAlphabet[int(buf[0])%len(codeAlphabet)])
		i++
	}
	return out.String()
}

// NormalizeCode makes a typed code comparable: case and dashes don't matter.
func NormalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, strings.TrimSpace(s))
}
