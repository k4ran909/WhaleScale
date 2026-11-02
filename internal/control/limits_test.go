package control

import (
	"context"
	"strings"
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

// Ephemeral machines (CI runners, containers) are removed once offline
// past the timeout; online ones and ordinary ones stay.
func TestRemoveStaleEphemeral(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ci")
	_, ephKey, _ := st.CreatePreAuthKey(ctx, "ci", true, true, time.Hour)
	_, normalKey, _ := st.CreatePreAuthKey(ctx, "ci", true, false, time.Hour)
	register := func(key, host string) uint64 {
		t.Helper()
		priv, _ := clientstate.NewMachineKey()
		pub, _ := (&clientstate.State{MachineKey: priv}).PublicKey()
		resp, err := s.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: pub, Hostname: host}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.Node.Id
	}
	gone := register(ephKey, "runner-1")
	online := register(ephKey, "runner-2")
	register(normalKey, "laptop")
	s.mu.Lock()
	s.online[online] = 1
	s.mu.Unlock()

	// Within the timeout nothing goes.
	if n, err := s.RemoveStaleEphemeral(ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("fresh: removed %d, %v", n, err)
	}
	// A negative timeout puts the cutoff in the future: every ephemeral
	// node counts as long gone.
	if n, err := s.RemoveStaleEphemeral(ctx, -time.Hour); err != nil || n != 1 {
		t.Fatalf("stale: removed %d, %v", n, err)
	}
	nodes, _ := st.ListNodes(ctx, "")
	var names []string
	for _, n := range nodes {
		if n.ID == gone {
			t.Fatal("the offline ephemeral node is still there")
		}
		names = append(names, n.Name)
	}
	if strings.Join(names, ",") != "runner-2,laptop" {
		t.Fatalf("left: %v", names)
	}
	if evs, _ := st.QueryAudit(ctx, store.AuditQuery{Action: "ephemeral node removed"}); len(evs) != 1 || evs[0].Actor != "system" {
		t.Fatalf("audit: %+v", evs)
	}
}

// Logout removes the node and its token stops working.
func TestLogout(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ann")
	_, key, _ := st.CreatePreAuthKey(ctx, "ann", false, false, time.Hour)
	priv, _ := clientstate.NewMachineKey()
	pub, _ := (&clientstate.State{MachineKey: priv}).PublicKey()
	reg, err := s.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: pub, Hostname: "laptop"}))
	if err != nil {
		t.Fatal(err)
	}
	authed := func(r connect.AnyRequest) { r.Header().Set("Authorization", "Bearer "+reg.Msg.NodeToken) }
	req := connect.NewRequest(&v1.LogoutRequest{})
	authed(req)
	if _, err := s.Logout(ctx, req); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := st.ListNodes(ctx, ""); len(nodes) != 0 {
		t.Fatalf("node still there: %+v", nodes)
	}
	again := connect.NewRequest(&v1.GetNetworkMapRequest{})
	authed(again)
	if _, err := s.GetNetworkMap(ctx, again); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("token after logout: %v", err)
	}
	if evs, _ := st.QueryAudit(ctx, store.AuditQuery{Action: "logged out"}); len(evs) != 1 || evs[0].Actor != "user:ann" {
		t.Fatalf("audit: %+v", evs)
	}
}
