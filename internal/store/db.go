package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// db wraps the connection pool so queries written once, with ? placeholders,
// run on both SQLite and PostgreSQL (which wants $1, $2, ...). Everything
// else about the two dialects that differs is kept to a few helpers here;
// the queries themselves stick to SQL both understand.
type db struct {
	*sql.DB
	pg bool
}

// rebind turns ? placeholders into $n for PostgreSQL. Queries in this
// package never put a ? inside a string literal.
func (d *db) rebind(q string) string {
	if !d.pg || !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func (d *db) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.rebind(q), args...)
}

func (d *db) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.rebind(q), args...)
}

func (d *db) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.rebind(q), args...)
}

func (d *db) BeginTx(ctx context.Context, opts *sql.TxOptions) (*tx, error) {
	t, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &tx{Tx: t, d: d}, nil
}

// tx is a transaction with the same placeholder handling.
type tx struct {
	*sql.Tx
	d *db
}

func (t *tx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, t.d.rebind(q), args...)
}

func (t *tx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, t.d.rebind(q), args...)
}

func (t *tx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, t.d.rebind(q), args...)
}

func (t *tx) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return t.Tx.PrepareContext(ctx, t.d.rebind(q))
}

// lock serializes transactions that read before they write (the audit
// chain, address allocation) across servers. SQLite needs nothing: every
// transaction already holds the write lock (BEGIN IMMEDIATE). PostgreSQL
// takes a transaction-scoped advisory lock on the name.
func (t *tx) lock(ctx context.Context, name string) error {
	if !t.d.pg {
		return nil
	}
	_, err := t.Tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, name)
	return err
}

// contains is a SQL expression true when column contains the next bound
// string.
func (d *db) contains(column string) string {
	if d.pg {
		return "strpos(" + column + ", ?) > 0"
	}
	return "instr(" + column + ", ?) > 0"
}
