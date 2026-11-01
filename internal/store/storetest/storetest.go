// Package storetest gives tests a fresh database to open with store.Open:
// an SQLite file, or, with WHALESCALE_TEST_POSTGRES set to a postgres://
// URL of a server tests may create databases on, a new PostgreSQL
// database that is dropped afterwards.
package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// DSN returns where a test's database lives: dir/ws.db, or a new
// PostgreSQL database. Open it after calling DSN, so the store is closed
// before the database is dropped.
func DSN(t testing.TB, dir string) string {
	t.Helper()
	admin := os.Getenv("WHALESCALE_TEST_POSTGRES")
	if admin == "" {
		return filepath.Join(dir, "ws.db")
	}
	b := make([]byte, 6)
	rand.Read(b)
	name := "ws_test_" + hex.EncodeToString(b)
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
		db.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		defer db.Close()
		if _, err := db.ExecContext(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop test database %s: %v", name, err)
		}
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// Postgres reports whether tests run against PostgreSQL.
func Postgres() bool { return os.Getenv("WHALESCALE_TEST_POSTGRES") != "" }
