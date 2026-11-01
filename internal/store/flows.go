package store

import (
	"context"
	"time"
)

// Flow is one connection's traffic over a reporting window.
type Flow struct {
	NodeName                 string
	Proto                    uint8
	Client, Server           string
	Port                     uint16
	Outbound, Denied         bool
	Start, End               time.Time
	BytesSent, BytesRecv     uint64
	PacketsSent, PacketsRecv uint64
}

// InsertFlows stores a node's report in one transaction.
func (s *Store) InsertFlows(ctx context.Context, flows []Flow) error {
	if len(flows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO flow_logs(node_name, proto, client, server, port, outbound, denied,
		started_at, ended_at, bytes_sent, bytes_recv, packets_sent, packets_recv) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range flows {
		if _, err := stmt.ExecContext(ctx, f.NodeName, f.Proto, f.Client, f.Server, f.Port, f.Outbound, f.Denied,
			f.Start.Unix(), f.End.Unix(), f.BytesSent, f.BytesRecv, f.PacketsSent, f.PacketsRecv); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FlowQuery filters QueryFlows.
type FlowQuery struct {
	Node       string
	Since      time.Time
	DeniedOnly bool
	Limit      int
}

// QueryFlows returns matching flows, newest first.
func (s *Store) QueryFlows(ctx context.Context, q FlowQuery) ([]Flow, error) {
	sqlq := `SELECT node_name, proto, client, server, port, outbound, denied, started_at, ended_at,
		bytes_sent, bytes_recv, packets_sent, packets_recv FROM flow_logs WHERE ended_at >= ?`
	args := []any{q.Since.Unix()}
	if q.Node != "" {
		sqlq += ` AND node_name = ?`
		args = append(args, q.Node)
	}
	if q.DeniedOnly {
		sqlq += ` AND denied = TRUE`
	}
	sqlq += ` ORDER BY ended_at DESC, id DESC LIMIT ?`
	args = append(args, q.Limit)
	rows, err := s.db.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Flow
	for rows.Next() {
		var f Flow
		var start, end int64
		if err := rows.Scan(&f.NodeName, &f.Proto, &f.Client, &f.Server, &f.Port, &f.Outbound, &f.Denied, &start, &end,
			&f.BytesSent, &f.BytesRecv, &f.PacketsSent, &f.PacketsRecv); err != nil {
			return nil, err
		}
		f.Start, f.End = time.Unix(start, 0), time.Unix(end, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

// PruneFlows deletes flows that ended before cutoff.
func (s *Store) PruneFlows(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM flow_logs WHERE ended_at < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
