package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Passkey is a WebAuthn credential that signs a console account in.
type Passkey struct {
	ID           uint64
	AdminID      uint64
	Admin        string
	Name         string
	CredentialID string // base64url
	Credential   []byte // the WebAuthn library's record, JSON
	CreatedAt    time.Time
	LastUsed     time.Time // zero until first used
}

// MaxPasskeys is how many passkeys one account may have.
const MaxPasskeys = 20

// ErrTooManyPasskeys: the account has MaxPasskeys already.
var ErrTooManyPasskeys = fmt.Errorf("an account can have at most %d passkeys", MaxPasskeys)

// AdminID returns a console account's ID.
func (s *Store) AdminID(ctx context.Context, name string) (uint64, error) {
	var id uint64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM admins WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// AddAdminPasskey saves a new passkey for a console account.
func (s *Store) AddAdminPasskey(ctx context.Context, admin, name, credentialID string, credential []byte) (*Passkey, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := tx.lock(ctx, "admin-accounts"); err != nil {
		return nil, err
	}
	var adminID uint64
	err = tx.QueryRowContext(ctx, `SELECT id FROM admins WHERE name = ?`, admin).Scan(&adminID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_passkeys WHERE admin_id = ?`, adminID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= MaxPasskeys {
		return nil, ErrTooManyPasskeys
	}
	now := time.Now()
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO admin_passkeys(admin_id, credential_id, name, credential, created_at)
		VALUES (?, ?, ?, ?, ?) RETURNING id`, adminID, credentialID, name, string(credential), now.Unix()).Scan(&id)
	if isUniqueErr(err) {
		return nil, fmt.Errorf("passkey: %w", ErrAlreadyExists)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Passkey{ID: uint64(id), AdminID: adminID, Admin: admin, Name: name, CredentialID: credentialID,
		Credential: credential, CreatedAt: now}, nil
}

const passkeyColumns = `p.id, p.admin_id, a.name, p.name, p.credential_id, p.credential, p.created_at, p.last_used`

func scanPasskey(row interface{ Scan(...any) error }) (*Passkey, error) {
	var p Passkey
	var cred string
	var created, used int64
	if err := row.Scan(&p.ID, &p.AdminID, &p.Admin, &p.Name, &p.CredentialID, &cred, &created, &used); err != nil {
		return nil, err
	}
	p.Credential = []byte(cred)
	p.CreatedAt = time.Unix(created, 0)
	if used > 0 {
		p.LastUsed = time.Unix(used, 0)
	}
	return &p, nil
}

// AdminPasskeys returns a console account's passkeys, oldest first.
func (s *Store) AdminPasskeys(ctx context.Context, admin string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+passkeyColumns+` FROM admin_passkeys p JOIN admins a ON a.id = p.admin_id
		WHERE a.name = ? ORDER BY p.id`, admin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PasskeyByCredentialID finds a passkey by its credential ID (base64url).
func (s *Store) PasskeyByCredentialID(ctx context.Context, credentialID string) (*Passkey, error) {
	p, err := scanPasskey(s.db.QueryRowContext(ctx, `SELECT `+passkeyColumns+` FROM admin_passkeys p
		JOIN admins a ON a.id = p.admin_id WHERE p.credential_id = ?`, credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// UsePasskey records a sign-in with a passkey: its updated record (the new
// sign count) and the time.
func (s *Store) UsePasskey(ctx context.Context, id uint64, credential []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admin_passkeys SET credential = ?, last_used = ? WHERE id = ?`,
		string(credential), time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAdminPasskey removes one of a console account's passkeys.
func (s *Store) DeleteAdminPasskey(ctx context.Context, admin string, id uint64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_passkeys
		WHERE id = ? AND admin_id = (SELECT id FROM admins WHERE name = ?)`, id, admin)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MaxCeremonies bounds the passkey ceremonies waiting for an answer.
const MaxCeremonies = 10000

// ErrTooManyCeremonies: MaxCeremonies are waiting already.
var ErrTooManyCeremonies = errors.New("too many passkey ceremonies at once")

// SaveCeremony stores a passkey ceremony (the library's session data) under
// token until TakeCeremony, dropping ceremonies older than ttl.
func (s *Store) SaveCeremony(ctx context.Context, token, kind, admin string, session []byte, ttl time.Duration) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_ceremonies WHERE created_at < ?`, now.Add(-ttl).Unix()); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_ceremonies`).Scan(&n); err != nil {
		return err
	}
	if n >= MaxCeremonies {
		return ErrTooManyCeremonies
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_ceremonies(token, kind, admin, session, created_at) VALUES (?, ?, ?, ?, ?)`,
		token, kind, admin, string(session), now.Unix())
	return err
}

// TakeCeremony removes and returns the ceremony stored under token, if it
// is of kind and younger than ttl. Of several servers sharing the
// database, only one can take it.
func (s *Store) TakeCeremony(ctx context.Context, token, kind string, ttl time.Duration) (admin string, session []byte, err error) {
	var gotKind, data string
	var created int64
	err = s.db.QueryRowContext(ctx, `DELETE FROM webauthn_ceremonies WHERE token = ? RETURNING kind, admin, session, created_at`,
		token).Scan(&gotKind, &admin, &data, &created)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (gotKind != kind || time.Since(time.Unix(created, 0)) > ttl)) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	return admin, []byte(data), nil
}

// DeleteAdminPasskeys removes all of a console account's passkeys, and
// returns how many there were.
func (s *Store) DeleteAdminPasskeys(ctx context.Context, admin string) (int, error) {
	if _, err := s.AdminID(ctx, admin); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_passkeys
		WHERE admin_id = (SELECT id FROM admins WHERE name = ?)`, admin)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
