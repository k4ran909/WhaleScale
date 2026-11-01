package control

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/store"
)

func TestAccessRequestLifecycle(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ann")
	st.CreateUser(ctx, "ops")
	ids, _ := st.SeedNodes(ctx, []string{"ann", "ops"}, 1, "")
	dev, db := ids[0], ids[1]
	// Nobody can reach anybody, but ann may ask for the database, and ops
	// may break glass on the same machine without waiting for anyone.
	s.SetPolicy(mustPolicy(t, `{"acls":[],
		"access_requests":[
			{"src":["ann"],"dst":["node:ops-0:5432,5433"],"max_duration":"2h"},
			{"src":["ops"],"dst":["node:ops-0:22"],"auto_approve":true}]}`), "", "test")
	canTalk := func() bool {
		t.Helper()
		snap, err := s.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		return snap.compiled.CanTalk(dev, db)
	}
	ask := func(id uint64, dst string, d time.Duration) (*v1.AccessRequest, error) {
		nodes, _ := st.ListNodes(ctx, "")
		for i := range nodes {
			if nodes[i].ID == id {
				return s.requestAccess(ctx, &nodes[i], &v1.RequestAccessRequest{Dst: dst, DurationSeconds: uint64(d / time.Second), Reason: "ticket 7"})
			}
		}
		t.Fatalf("no node %d", id)
		return nil, nil
	}

	// Outside the rules: wrong port, too long, or nothing at all.
	for _, bad := range []struct {
		dst string
		d   time.Duration
	}{{"node:ops-0:22", time.Hour}, {"node:ops-0:5432", 3 * time.Hour}, {"node:ops-0:5432,8080", time.Hour}} {
		if _, err := ask(dev, bad.dst, bad.d); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("request %s for %v: %v", bad.dst, bad.d, err)
		}
	}

	r, err := ask(dev, "node:ops-0:5432", 0) // 0: the longest allowed
	if err != nil || r.Status != store.AccessPending || r.DurationSeconds != 7200 {
		t.Fatalf("request = %v, %v", r, err)
	}
	if canTalk() {
		t.Fatal("access before approval")
	}
	if _, err := st.DecideAccessRequest(ctx, r.Id, true, "oidc:boss@example.com"); err != nil {
		t.Fatal(err)
	}
	s.RefreshGrants(ctx, true)
	if !canTalk() {
		t.Fatal("no access after approval")
	}
	if _, err := st.DecideAccessRequest(ctx, r.Id, false, "x"); err == nil {
		t.Fatal("decided twice")
	}
	if _, err := st.RevokeAccessGrant(ctx, r.Id, "oidc:boss@example.com"); err != nil {
		t.Fatal(err)
	}
	s.RefreshGrants(ctx, true)
	if canTalk() {
		t.Fatal("access after revocation")
	}

	// Auto-approved, short grants expire by themselves.
	r, err = ask(db, "node:ops-0:22", time.Second)
	if err != nil || r.Status != store.AccessApproved {
		t.Fatalf("break-glass request = %v, %v", r, err)
	}
	if g, _ := st.ActiveGrants(ctx); len(g) != 1 {
		t.Fatalf("active grants = %+v", g)
	}
	time.Sleep(2100 * time.Millisecond)
	s.RefreshGrants(ctx, true)
	if g, _ := st.ActiveGrants(ctx); len(g) != 0 || len(s.CurrentPolicy().ACLs) != 0 {
		t.Fatalf("grant outlived its time: %+v", g)
	}

	var actions []string
	evs, _ := st.QueryAudit(ctx, store.AuditQuery{Action: "access"})
	for i := len(evs) - 1; i >= 0; i-- {
		actions = append(actions, evs[i].Actor+" "+evs[i].Action)
	}
	want := []string{"user:ann access requested", "user:ops access requested", "policy access granted", "system access grant expired"}
	if len(actions) != len(want) {
		t.Fatalf("audit = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("audit = %v, want %v", actions, want)
		}
	}
}
