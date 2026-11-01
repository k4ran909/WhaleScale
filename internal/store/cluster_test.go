package store

import (
	"context"
	"github.com/k4ran909/whalescale/internal/store/storetest"
	"testing"
	"time"
)

// Two servers on one database file, as the cluster runs them.
func TestClusterPrimitives(t *testing.T) {
	ctx := context.Background()
	path := storetest.DSN(t, t.TempDir())
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// Leases: one holder at a time; renewable; taken over when expired or released.
	if ok, err := a.AcquireLease(ctx, "leader", "srv-a", time.Second); !ok || err != nil {
		t.Fatalf("a acquire: %v %v", ok, err)
	}
	if ok, _ := b.AcquireLease(ctx, "leader", "srv-b", time.Second); ok {
		t.Fatal("b took a held lease")
	}
	if ok, _ := a.AcquireLease(ctx, "leader", "srv-a", 50*time.Millisecond); !ok {
		t.Fatal("a couldn't renew")
	}
	time.Sleep(80 * time.Millisecond)
	if ok, _ := b.AcquireLease(ctx, "leader", "srv-b", time.Second); !ok {
		t.Fatal("b didn't take an expired lease")
	}
	b.ReleaseLease(ctx, "leader", "srv-b")
	if ok, _ := a.AcquireLease(ctx, "leader", "srv-a", time.Second); !ok {
		t.Fatal("a didn't take a released lease")
	}

	// Members and presence.
	start := time.Now()
	a.Heartbeat(ctx, Member{ID: "srv-a", PublicURL: "https://a", RelayURL: "wss://a/relay", StartedAt: start})
	b.Heartbeat(ctx, Member{ID: "srv-b", PublicURL: "https://b", RelayURL: "wss://b/relay", StartedAt: start.Add(time.Second)})
	ms, err := b.LiveMembers(ctx, time.Minute)
	if err != nil || len(ms) != 2 || ms[0].ID != "srv-a" {
		t.Fatalf("members = %+v, %v", ms, err)
	}
	a.CreateUser(ctx, "ann")
	ids, _ := a.SeedNodes(ctx, []string{"ann"}, 2, "")
	if err := a.SetPresence(ctx, "srv-a", ids, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := b.Presence(ctx, "srv-b", time.Minute); len(p) != 2 {
		t.Fatalf("b sees presence %v", p)
	}
	if p, _ := a.Presence(ctx, "srv-a", time.Minute); len(p) != 0 {
		t.Fatalf("a's own presence counted as remote: %v", p)
	}
	a.SetPresence(ctx, "srv-a", nil, ids[:1])
	if p, _ := b.Presence(ctx, "srv-b", time.Minute); len(p) != 1 {
		t.Fatalf("after removal: %v", p)
	}
	// A dead server's presence stops counting.
	if p, _ := b.Presence(ctx, "srv-b", time.Nanosecond); len(p) != 0 {
		t.Fatalf("stale presence counted: %v", p)
	}

	before, _ := b.ChangeSeq(ctx)
	a.BumpChangeSeq(ctx)
	if after, _ := b.ChangeSeq(ctx); after != before+1 {
		t.Fatalf("change seq %d -> %d", before, after)
	}
	a.LeaveCluster(ctx, "srv-a")
	if ms, _ := b.LiveMembers(ctx, time.Minute); len(ms) != 1 {
		t.Fatalf("after leaving: %+v", ms)
	}
}
