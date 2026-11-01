package control

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/store"
)

func TestDeviceLimitEnforced(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ann")
	_, authKey, _ := st.CreatePreAuthKey(ctx, "ann", true, false, time.Hour)
	s.SetPolicy(mustPolicy(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"device_limits":{"ann":2}}`), "", "test")

	register := func(host string) error {
		priv, _ := clientstate.NewMachineKey()
		pub, _ := (&clientstate.State{MachineKey: priv}).PublicKey()
		_, err := s.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: authKey, MachineKey: pub, Hostname: host}))
		return err
	}
	for _, h := range []string{"one", "two"} {
		if err := register(h); err != nil {
			t.Fatalf("register %s: %v", h, err)
		}
	}
	err := register("three")
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("third device: %v", err)
	}
	evs, _ := st.QueryAudit(ctx, store.AuditQuery{Action: "registration refused"})
	if len(evs) != 1 || evs[0].Actor != "user:ann" {
		t.Fatalf("refusal not audited: %+v", evs)
	}

	// Raising the limit takes effect at once.
	s.SetPolicy(mustPolicy(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"device_limits":{"*":3}}`), "", "test")
	if err := register("three"); err != nil {
		t.Fatalf("after raising the limit: %v", err)
	}
}

func TestMapStreamLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ann")
	ids, _ := st.SeedNodes(ctx, []string{"ann"}, 1, "")
	started := make(chan struct{}, maxStreamsPerNode)
	for i := 0; i < maxStreamsPerNode; i++ {
		go s.runMapStream(ctx, ids[0], true, func(*v1.StreamNetworkMapResponse) error {
			started <- struct{}{}
			return nil
		})
	}
	for i := 0; i < maxStreamsPerNode; i++ {
		<-started
	}
	err := s.runMapStream(ctx, ids[0], true, func(*v1.StreamNetworkMapResponse) error { return nil })
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("stream %d: %v", maxStreamsPerNode+1, err)
	}
}
