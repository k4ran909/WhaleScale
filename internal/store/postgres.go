package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
)

// openPostgres opens a PostgreSQL database, the choice when servers on
// different hosts share one network.
func openPostgres(ctx context.Context, dsn string) (*Store, error) {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(16)
	if err := sqldb.PingContext(ctx); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	d := &db{DB: sqldb, pg: true}
	if err := migrate(ctx, d); err != nil {
		sqldb.Close()
		return nil, err
	}
	s := &Store{db: d}
	if _, err := s.IPv6Prefix(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	return s, nil
}

// Redact returns a db setting safe to log: a PostgreSQL URL loses its
// password.
func Redact(dsn string) string {
	if !IsPostgres(dsn) {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://<unparseable>"
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "redacted")
	}
	return u.String()
}

// DataDir is where files that sit beside the database by default (ACME
// certificates, SSH recordings) go: the SQLite file's directory, or the
// working directory for PostgreSQL.
func DataDir(dsn string) string {
	if IsPostgres(dsn) {
		return "."
	}
	return filepath.Dir(dsn)
}
