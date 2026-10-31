package store

import (
	"context"
	"testing"
	"time"
)

func TestFlows(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	old := now.Add(-10 * 24 * time.Hour)
	err := s.InsertFlows(ctx, []Flow{
		{NodeName: "nas", Proto: 6, Client: "100.64.0.2", Server: "100.64.0.1", Port: 22, Start: now.Add(-time.Minute), End: now, BytesRecv: 500, PacketsRecv: 5},
		{NodeName: "nas", Proto: 6, Client: "100.64.0.9", Server: "100.64.0.1", Port: 22, Denied: true, Start: now, End: now, PacketsRecv: 2},
		{NodeName: "laptop", Proto: 6, Client: "100.64.0.2", Server: "100.64.0.1", Port: 22, Outbound: true, Start: now, End: now, BytesSent: 500},
		{NodeName: "nas", Proto: 17, Client: "100.64.0.2", Server: "100.64.0.1", Port: 53, Start: old, End: old},
	})
	if err != nil {
		t.Fatal(err)
	}
	all, _ := s.QueryFlows(ctx, FlowQuery{Since: now.Add(-time.Hour), Limit: 100})
	if len(all) != 3 {
		t.Fatalf("last hour: %d flows", len(all))
	}
	nas, _ := s.QueryFlows(ctx, FlowQuery{Node: "nas", Since: now.Add(-time.Hour), Limit: 100})
	if len(nas) != 2 {
		t.Fatalf("nas: %d flows", len(nas))
	}
	denied, _ := s.QueryFlows(ctx, FlowQuery{Since: now.Add(-time.Hour), DeniedOnly: true, Limit: 100})
	if len(denied) != 1 || denied[0].Client != "100.64.0.9" {
		t.Fatalf("denied: %+v", denied)
	}
	if n, err := s.PruneFlows(ctx, now.Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if rest, _ := s.QueryFlows(ctx, FlowQuery{Since: time.Unix(0, 0), Limit: 100}); len(rest) != 3 {
		t.Fatalf("after prune: %d flows", len(rest))
	}
}
