package store

import "testing"

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://ws:s3cret@db.internal:5432/whalescale?sslmode=require": "postgres://ws:redacted@db.internal:5432/whalescale?sslmode=require",
		"postgresql://ws@db/whalescale":                                    "postgresql://ws@db/whalescale",
		"/var/lib/whalescale/whalescale.db":                                "/var/lib/whalescale/whalescale.db",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if DataDir("postgres://db/x") != "." || DataDir("/var/lib/whalescale/ws.db") == "." {
		t.Error("DataDir")
	}
}

func TestRebind(t *testing.T) {
	d := &db{pg: true}
	if got := d.rebind("SELECT a FROM t WHERE b = ? AND c IN (?, ?)"); got != "SELECT a FROM t WHERE b = $1 AND c IN ($2, $3)" {
		t.Fatalf("rebind = %q", got)
	}
	if got := (&db{}).rebind("x = ?"); got != "x = ?" {
		t.Fatalf("sqlite rebind changed the query: %q", got)
	}
}
