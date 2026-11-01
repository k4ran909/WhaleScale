package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/netmap"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/store"
)

func newTestService(t testing.TB, cfg Config) (*Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg), st
}

func mustPolicy(t testing.TB, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A client following a delta stream must always end up with exactly the
// map the server would send it from scratch, through every kind of change,
// including streams that skip versions.
func TestDeltasMatchFullMaps(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{STUN: []string{"stun.example:3478"}, GatewayDomain: "apps.example", GatewayURL: "wss://gw"})
	for _, u := range []string{"ann", "ben", "cat"} {
		st.CreateUser(ctx, u)
	}
	ids, err := st.SeedNodes(ctx, []string{"ann", "ben", "cat"}, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	policies := []*policy.Policy{
		policy.AllowAll(),
		mustPolicy(t, `{"groups":{"group:g":["ann","ben"]},"acls":[{"action":"accept","src":["group:g"],"dst":["group:g:*"]},{"action":"accept","src":["cat"],"dst":["ann:22"]}]}`),
		mustPolicy(t, `{"acls":[{"action":"accept","src":["ann"],"dst":["*:443"]},{"action":"accept","src":["10.0.0.0/8"],"dst":["ben:80"]}],
			"ssh":[{"action":"accept","src":["ann"],"dst":["cat"],"users":["root"]}]}`),
		mustPolicy(t, `{"acls":[{"action":"accept","src":["ben"],"dst":["ben:*","node:cat-1:5432"]}]}`),
	}

	type client struct {
		m  *mapStream
		nm *v1.NetworkMap
	}
	var clients []*client
	for i, id := range []uint64{ids[0], ids[5], ids[9], ids[17], ids[20]} {
		clients = append(clients, &client{m: &mapStream{id: id, deltas: i != 0}})
	}
	r := rand.New(rand.NewSource(3))
	check := func(step string) {
		t.Helper()
		snap, err := s.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range clients {
			// Sometimes skip a stream so it falls behind by a few versions.
			if c.nm != nil && r.Intn(4) == 0 {
				continue
			}
			resp, err := s.next(c.m, snap)
			if err != nil {
				t.Fatalf("%s: node %d: %v", step, c.m.id, err)
			}
			if resp != nil {
				// What goes on the wire, packed, must decode to the same.
				packed := proto.Clone(resp).(*v1.StreamNetworkMapResponse)
				pack(packed, snap)
				pb, _ := proto.Marshal(packed)
				ub, _ := proto.Marshal(resp)
				x, y := &v1.StreamNetworkMapResponse{}, &v1.StreamNetworkMapResponse{}
				proto.Unmarshal(pb, x)
				proto.Unmarshal(ub, y)
				if !proto.Equal(x, y) || len(pb) != len(ub) {
					t.Fatalf("%s: packed message decodes differently", step)
				}
			}
			switch {
			case resp == nil:
			case resp.NetworkMap != nil:
				c.nm = resp.NetworkMap
			case !c.m.deltas:
				t.Fatalf("%s: node %d got a delta without asking", step, c.m.id)
			default:
				if c.nm, err = netmap.Apply(c.nm, resp.Delta); err != nil {
					t.Fatal(err)
				}
			}
			// Round-trip through the wire format, as a real client sees it.
			b, _ := proto.Marshal(c.nm)
			got := &v1.NetworkMap{}
			proto.Unmarshal(b, got)
			i := snap.index[c.m.id]
			want := fullMap(snap, i, s.settings(snap, i))
			got.Version, want = 0, proto.Clone(want).(*v1.NetworkMap)
			want.Version = 0
			if !proto.Equal(got, want) {
				t.Fatalf("%s: node %d map diverged\n got: %v\nwant: %v", step, c.m.id, got, want)
			}
		}
	}

	check("initial")
	for step := 0; step < 300; step++ {
		id := ids[r.Intn(len(ids))]
		var what string
		switch r.Intn(7) {
		case 0:
			what = "policy"
			pol := policies[r.Intn(len(policies))]
			s.SetPolicy(pol, "", "test")
		case 1:
			what = "endpoints"
			st.UpdateNodeInfo(ctx, id, store.NodeInfo{NodeKey: fmt.Sprintf("%044d", step)[:43] + "=", DiscoKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{fmt.Sprintf("198.51.100.%d:41641", step%250)}})
		case 2:
			what = "online"
			s.mu.Lock()
			if s.online[id] > 0 {
				delete(s.online, id)
			} else {
				s.online[id] = 1
			}
			s.mu.Unlock()
		case 3:
			what = "routes"
			p := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", step%200))
			st.SetAdvertisedRoutes(ctx, id, []netip.Prefix{p})
			st.SetRouteApproved(ctx, id, p, r.Intn(2) == 0)
		case 4:
			what = "relay"
			st.SetRelayOffered(ctx, id, true)
			st.SetRelayApproved(ctx, id, r.Intn(2) == 0)
		case 5:
			what = "exposure"
			st.SetExposures(ctx, id, []store.ExposureRequest{{Name: fmt.Sprintf("svc%d", id), Port: uint16(8000 + step)}})
		case 6:
			what = "add/remove node"
			if r.Intn(2) == 0 {
				got, err := st.SeedNodes(ctx, []string{"cat"}, 1, fmt.Sprintf("new%d-", step))
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, got...)
			} else if victim := ids[len(ids)-1]; victim > ids[23] {
				st.DeleteNode(ctx, victim)
				ids = ids[:len(ids)-1]
			}
		}
		s.NotifyAll()
		check(fmt.Sprintf("step %d (%s)", step, what))
	}
}

// Changes elsewhere in the network that don't concern a node send it
// nothing, and an endpoint change sends peers just that one entry.
func TestDeltasAreMinimal(t *testing.T) {
	ctx := context.Background()
	s, st := newTestService(t, Config{})
	st.CreateUser(ctx, "ann")
	st.CreateUser(ctx, "ben")
	a, _ := st.SeedNodes(ctx, []string{"ann"}, 50, "")
	b, _ := st.SeedNodes(ctx, []string{"ben"}, 50, "")
	// ann's machines see each other; ben's see each other.
	s.SetPolicy(mustPolicy(t, `{"acls":[{"action":"accept","src":["ann"],"dst":["ann:*"]},{"action":"accept","src":["ben"],"dst":["ben:*"]}]}`), "", "test")

	m := &mapStream{id: a[0], deltas: true}
	next := func() *v1.StreamNetworkMapResponse {
		t.Helper()
		s.NotifyAll()
		snap, err := s.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := s.next(m, snap)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if first := next(); first.NetworkMap == nil || len(first.NetworkMap.Peers) != 49 {
		t.Fatalf("first message: %v", first)
	}
	st.UpdateNodeInfo(ctx, b[3], store.NodeInfo{NodeKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", DiscoKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="})
	if resp := next(); resp != nil {
		t.Fatalf("a change to an invisible node sent %v", resp)
	}
	compiles := s.Stats().Compiles.Load()
	st.UpdateNodeInfo(ctx, a[7], store.NodeInfo{NodeKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", DiscoKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="})
	resp := next()
	if d := resp.GetDelta(); d == nil || len(d.PeersChanged) != 1 || d.PeersChanged[0].Id != a[7] ||
		d.Self != nil || d.PacketFilter != nil || d.Settings != nil || len(d.PeersRemoved) != 0 {
		t.Fatalf("endpoint change delta = %v", resp)
	}
	if c := s.Stats().Compiles.Load(); c != compiles {
		t.Fatalf("an endpoint change recompiled the policy (%d -> %d compiles)", compiles, c)
	}
	// A policy change that only touches ports sends the filter alone.
	s.SetPolicy(mustPolicy(t, `{"acls":[{"action":"accept","src":["ann"],"dst":["ann:22"]},{"action":"accept","src":["ben"],"dst":["ben:*"]}]}`), "", "test")
	resp = next()
	if d := resp.GetDelta(); d == nil || d.PacketFilter == nil || len(d.PeersChanged)+len(d.PeersRemoved) != 0 || d.Settings != nil {
		t.Fatalf("port change delta = %v", resp)
	}
}
