package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, _, _, err := st.VerifyAudit(ctx); err != nil || n != 0 {
		t.Fatalf("empty log: %d, %v", n, err)
	}
	st.Audit(ctx, "cli:root", "user created", "user", "alice")
	st.Audit(ctx, "oidc:bob@example.com", "policy updated", "note", "two words", "acls", 3)
	st.Audit(ctx, "api-key:ab12", "node deleted", "node", "pc-a")

	evs, err := st.QueryAudit(ctx, AuditQuery{Since: time.Now().Add(-time.Hour)})
	if err != nil || len(evs) != 3 || evs[0].Action != "node deleted" {
		t.Fatalf("query = %+v, %v", evs, err)
	}
	if evs[1].Detail != `note="two words" acls=3` {
		t.Fatalf("detail = %q", evs[1].Detail)
	}
	if evs, _ := st.QueryAudit(ctx, AuditQuery{Actor: "oidc:"}); len(evs) != 1 {
		t.Fatalf("actor filter: %+v", evs)
	}
	n, head, _, err := st.VerifyAudit(ctx)
	if err != nil || n != 3 || len(head) != 32 {
		t.Fatalf("verify: %d %x %v", n, head, err)
	}

	// Rewriting history breaks the chain at that entry.
	st.db.ExecContext(ctx, `UPDATE audit_log SET actor = 'cli:someone-else' WHERE id = 2`)
	if _, _, bad, err := st.VerifyAudit(ctx); !errors.Is(err, ErrAuditTampered) || bad != 2 {
		t.Fatalf("edited row: bad=%d err=%v", bad, err)
	}
	st.db.ExecContext(ctx, `UPDATE audit_log SET actor = 'oidc:bob@example.com' WHERE id = 2`)
	st.db.ExecContext(ctx, `DELETE FROM audit_log WHERE id = 2`)
	if _, _, bad, err := st.VerifyAudit(ctx); !errors.Is(err, ErrAuditTampered) || bad != 3 {
		t.Fatalf("deleted row: bad=%d err=%v", bad, err)
	}
}
