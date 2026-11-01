package control

import (
	"context"
	"fmt"
	"testing"

	"github.com/k4ran909/whalescale/internal/policy"
)

func BenchmarkSnapshotPolicyChange10k(b *testing.B) {
	ctx := context.Background()
	s, st := newTestService(b, Config{})
	var users []string
	groups := map[string][]string{}
	for i := 0; i < 1000; i++ {
		users = append(users, fmt.Sprintf("u%d", i))
		st.CreateUser(ctx, users[i])
		g := fmt.Sprintf("group:team%d", i/10)
		groups[g] = append(groups[g], users[i])
	}
	st.SeedNodes(ctx, users, 10, "")
	mk := func(ports string) *policy.Policy {
		p := &policy.Policy{Groups: groups}
		for tm := 0; tm < 100; tm++ {
			g := fmt.Sprintf("group:team%d", tm)
			p.ACLs = append(p.ACLs, policy.ACL{Action: "accept", Src: []string{g}, Dst: []string{g + ":" + ports}})
		}
		return p
	}
	pols := []*policy.Policy{mk("*"), mk("22,80")}
	s.snapshot()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.SetPolicy(pols[i%2], "", "test")
		if _, err := s.snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}
