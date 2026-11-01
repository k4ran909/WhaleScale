package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"time"
)

// SeedNodes adds perUser nodes for each of the given existing users in one
// transaction, named <prefix><user>-<k>, with sequential addresses and node
// and disco keys set, as if each had registered and connected. It is for
// load tests and benchmarks: registering 10,000 nodes one at a time takes
// minutes. It returns the new node IDs in order.
func (s *Store) SeedNodes(ctx context.Context, users []string, perUser int, prefix string) ([]uint64, error) {
	v6, err := s.IPv6Prefix(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := tx.lock(ctx, "node-allocation"); err != nil {
		return nil, err
	}
	used := map[netip.Addr]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT ipv4 FROM nodes`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return nil, err
		}
		used[netip.MustParseAddr(a)] = true
	}
	rows.Close()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO nodes(user_id, name, machine_key, ipv4, ipv6, os, token_hash,
		created_at, last_seen, node_key, disco_key, endpoints) VALUES (?, ?, ?, ?, ?, 'linux', ?, ?, ?, ?, ?, ?) RETURNING id`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	randKey := func() string {
		b := make([]byte, 32)
		rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	now := time.Now().Unix()
	var ids []uint64
	a := ipv4Pool.Addr()
	for _, user := range users {
		uid, err := s.userID(ctx, tx, user)
		if err != nil {
			return nil, err
		}
		for k := 0; k < perUser; k++ {
			for a = a.Next(); used[a] || a == reservedIPv4; a = a.Next() {
			}
			if !ipv4Pool.Contains(a.Next()) {
				return nil, ErrPoolExhausted
			}
			ep := fmt.Sprintf(`["192.0.2.%d:41641"]`, len(ids)%250+1)
			var id int64
			if err := stmt.QueryRowContext(ctx, uid, fmt.Sprintf("%s%s-%d", prefix, user, k), randKey(), a.String(),
				ipv6For(v6, a).String(), hashSecret(randKey()), now, now, randKey(), randKey(), ep).Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, uint64(id))
		}
	}
	return ids, tx.Commit()
}
