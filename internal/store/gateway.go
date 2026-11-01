package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

// Exposure is a node's local service published through the gateway.
type Exposure struct {
	NodeID     uint64
	NodeName   string
	Name       string
	Port       uint16
	Advertised bool
	Approved   bool
}

// Live reports whether the exposure should receive public traffic.
func (e Exposure) Live() bool { return e.Advertised && e.Approved }

// ExposureRequest is what a node asks to publish.
type ExposureRequest struct {
	Name string
	Port uint16
}

// ValidExposureName reports whether name works as a single DNS label.
func ValidExposureName(name string) bool { return nameRe.MatchString(name) }

// SetExposures records what a node currently wants published. Names other
// nodes hold are refused and returned in taken. Changing an exposure's
// port withdraws its approval: it is a different service now.
func (s *Store) SetExposures(ctx context.Context, nodeID uint64, reqs []ExposureRequest) (changed bool, taken []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, err
	}
	defer tx.Rollback()
	// Names are first come, first served across all nodes and servers.
	if err := tx.lock(ctx, "exposure-names"); err != nil {
		return false, nil, err
	}

	type row struct {
		port       uint16
		advertised bool
	}
	before := map[string]row{}
	rows, err := tx.QueryContext(ctx, `SELECT name, port, advertised FROM exposures WHERE node_id = ?`, nodeID)
	if err != nil {
		return false, nil, err
	}
	for rows.Next() {
		var name string
		var r row
		if err := rows.Scan(&name, &r.port, &r.advertised); err != nil {
			rows.Close()
			return false, nil, err
		}
		before[name] = r
	}
	rows.Close()

	if _, err := tx.ExecContext(ctx, `UPDATE exposures SET advertised = FALSE WHERE node_id = ?`, nodeID); err != nil {
		return false, nil, err
	}
	wanted := map[string]bool{}
	for _, r := range reqs {
		if !ValidExposureName(r.Name) || r.Port == 0 || wanted[r.Name] {
			continue
		}
		wanted[r.Name] = true
		old, mine := before[r.Name]
		switch {
		case mine && old.port == r.Port:
			_, err = tx.ExecContext(ctx, `UPDATE exposures SET advertised = TRUE WHERE node_id = ? AND name = ?`, nodeID, r.Name)
		case mine:
			changed = true
			_, err = tx.ExecContext(ctx, `UPDATE exposures SET advertised = TRUE, port = ?, approved = FALSE WHERE node_id = ? AND name = ?`,
				r.Port, nodeID, r.Name)
		default:
			// Checked first rather than caught: PostgreSQL abandons a
			// transaction after any failed statement.
			var holders int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM exposures WHERE name = ?`, r.Name).Scan(&holders); err != nil {
				return false, nil, err
			}
			if holders > 0 {
				taken = append(taken, r.Name)
				continue
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO exposures(node_id, name, port) VALUES (?, ?, ?)`, nodeID, r.Name, r.Port)
			changed = true
		}
		if err != nil {
			return false, nil, err
		}
		if mine && !old.advertised {
			changed = true
		}
	}
	for name, r := range before {
		if r.advertised && !wanted[name] {
			changed = true
		}
	}
	sort.Strings(taken)
	return changed, taken, tx.Commit()
}

const exposureColumns = `e.node_id, n.name, e.name, e.port, e.advertised, e.approved`

func scanExposures(rows *sql.Rows) ([]Exposure, error) {
	defer rows.Close()
	var out []Exposure
	for rows.Next() {
		var e Exposure
		if err := rows.Scan(&e.NodeID, &e.NodeName, &e.Name, &e.Port, &e.Advertised, &e.Approved); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListExposures returns every exposure, advertised or not.
func (s *Store) ListExposures(ctx context.Context) ([]Exposure, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+exposureColumns+`
		FROM exposures e JOIN nodes n ON n.id = e.node_id ORDER BY e.name`)
	if err != nil {
		return nil, err
	}
	return scanExposures(rows)
}

// NodeExposures returns one node's exposures.
func (s *Store) NodeExposures(ctx context.Context, nodeID uint64) ([]Exposure, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+exposureColumns+`
		FROM exposures e JOIN nodes n ON n.id = e.node_id WHERE e.node_id = ? ORDER BY e.name`, nodeID)
	if err != nil {
		return nil, err
	}
	return scanExposures(rows)
}

// ExposureByName finds an exposure for routing public traffic.
func (s *Store) ExposureByName(ctx context.Context, name string) (*Exposure, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+exposureColumns+`
		FROM exposures e JOIN nodes n ON n.id = e.node_id WHERE e.name = ?`, name)
	if err != nil {
		return nil, err
	}
	list, err := scanExposures(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

func (s *Store) SetExposureApproved(ctx context.Context, nodeID uint64, name string, approved bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE exposures SET approved = ? WHERE node_id = ? AND name = ?`, approved, nodeID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("node %d has no exposure %q: %w", nodeID, name, ErrNotFound)
	}
	return nil
}
