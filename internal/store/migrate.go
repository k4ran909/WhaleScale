package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql migrations_pg/*.sql
var migrationFS embed.FS

// migrationDir holds each dialect's migrations. PostgreSQL support starts
// at version 12 with a baseline schema.
func migrationDir(pg bool) string {
	if pg {
		return "migrations_pg"
	}
	return "migrations"
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations(pg bool) ([]migration, error) {
	dir := migrationDir(pg)
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		return nil, err
	}
	var ms []migration
	seen := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		num, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: name must be NNNN_description.sql", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %q: bad version number", name)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, name, v)
		}
		seen[v] = name
		body, err := migrationFS.ReadFile(dir + "/" + name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

// migrate applies every pending migration, each in its own transaction.
// Jumping across many versions at once is supported: migrations are applied
// in order from whatever version the database is at.
func migrate(ctx context.Context, db *db) error {
	if db.pg {
		// Servers starting together must not migrate at the same time.
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('whalescale-migrate'))`); err != nil {
			return err
		}
		defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('whalescale-migrate'))`)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    BIGINT PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at BIGINT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	ms, err := loadMigrations(db.pg)
	if err != nil {
		return err
	}

	var current int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if n := len(ms); n > 0 && current > ms[n-1].version {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d); upgrade whalescale", current, ms[n-1].version)
	}

	for _, m := range ms {
		if m.version <= current {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
			m.version, m.name, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion reports the latest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

// Inspect reports a database's schema version and the latest this binary
// knows, without applying migrations (for 'whalescale doctor').
func Inspect(ctx context.Context, path string) (current, latest int, err error) {
	ms, err := loadMigrations(IsPostgres(path))
	if err != nil {
		return 0, 0, err
	}
	if len(ms) > 0 {
		latest = ms[len(ms)-1].version
	}
	driver, dsn := "sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)"
	if IsPostgres(path) {
		driver, dsn = "pgx", path
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return 0, latest, err
	}
	defer db.Close()
	err = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current)
	return current, latest, err
}
