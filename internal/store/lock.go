package store

import (
	"context"
	"fmt"
)

// LockChain returns every network lock state (encoded LockState), oldest
// first.
func (s *Store) LockChain(ctx context.Context) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state FROM lock_chain ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// AppendLockState stores the next lock version. The caller checks that it
// follows from the current head; the primary key stops two versions with
// the same number.
func (s *Store) AppendLockState(ctx context.Context, version uint64, state []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO lock_chain(version, state) VALUES (?, ?)`, version, state)
	if isUniqueErr(err) {
		return fmt.Errorf("lock version %d: %w", version, ErrAlreadyExists)
	}
	return err
}

// SetLockSignature stores a signature (encoded NodeSignature) over a node key.
func (s *Store) SetLockSignature(ctx context.Context, nodeKey string, sig []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO lock_signatures(node_key, signature) VALUES (?, ?)
		ON CONFLICT(node_key) DO UPDATE SET signature = excluded.signature`, nodeKey, sig)
	return err
}

// attachLockSignatures fills each node's LockSignature.
func (s *Store) attachLockSignatures(ctx context.Context, nodes []Node) error {
	rows, err := s.db.QueryContext(ctx, `SELECT node_key, signature FROM lock_signatures`)
	if err != nil {
		return err
	}
	defer rows.Close()
	sigs := map[string][]byte{}
	for rows.Next() {
		var k string
		var b []byte
		if err := rows.Scan(&k, &b); err != nil {
			return err
		}
		sigs[k] = b
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range nodes {
		if nodes[i].NodeKey != "" {
			nodes[i].LockSignature = sigs[nodes[i].NodeKey]
		}
	}
	return nil
}
