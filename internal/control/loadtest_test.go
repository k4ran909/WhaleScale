package control

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/israce"
	"github.com/k4ran909/whalescale/internal/policy"
)

// TestLoad10k connects 10,000 simulated nodes (WHALESCALE_LOADTEST_NODES
// overrides the count) to one control service and measures how long policy
// pushes take to reach all of them. Each simulated stream runs the real
// server path, snapshot, delta and protobuf encoding, minus the network.
//
// The network: 100 teams of 10 users with 10 machines each, plus 10 shared
// infrastructure machines every team can reach on 443.
func TestLoad10k(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	n := 10000
	if israce.Enabled {
		n = 1000
	}
	if v, err := strconv.Atoi(os.Getenv("WHALESCALE_LOADTEST_NODES")); err == nil && v >= 100 {
		n = v
	}
	teams := n / 100
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, st := newTestService(t, Config{STUN: []string{"stun.example:3478"}, Relays: []string{"wss://ws.example/relay"}})

	start := time.Now()
	var users []string
	groups := map[string][]string{}
	for tm := 0; tm < teams; tm++ {
		for u := 0; u < 10; u++ {
			name := fmt.Sprintf("t%du%d", tm, u)
			users = append(users, name)
			groups[fmt.Sprintf("group:team%d", tm)] = append(groups[fmt.Sprintf("group:team%d", tm)], name)
		}
	}
	for _, u := range append(users, "infra") {
		if _, err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := st.SeedNodes(ctx, users, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	infra, err := st.SeedNodes(ctx, []string{"infra"}, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, infra...)
	t.Logf("seeded %d nodes in %v", len(ids), time.Since(start).Round(time.Millisecond))

	teamPolicy := func(teamPorts, infraPorts string, extra ...policy.ACL) *policy.Policy {
		p := &policy.Policy{Groups: groups, ACLs: extra}
		for tm := 0; tm < teams; tm++ {
			g := fmt.Sprintf("group:team%d", tm)
			p.ACLs = append(p.ACLs, policy.ACL{Action: "accept", Src: []string{g},
				Dst: []string{g + ":" + teamPorts, "infra:" + infraPorts}})
		}
		return p
	}
	s.SetPolicy(teamPolicy("*", "443"), "", "test")

	// One simulated client per node: it encodes every message as the real
	// stream would and records the newest map version it has.
	versions := make([]atomic.Uint64, len(ids))
	var bytesSent, msgs atomic.Int64
	var wg sync.WaitGroup
	start = time.Now()
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runMapStream(ctx, id, true, func(r *v1.StreamNetworkMapResponse) error {
				b, err := proto.Marshal(r)
				if err != nil {
					return err
				}
				bytesSent.Add(int64(len(b)))
				msgs.Add(1)
				v := r.GetNetworkMap().GetVersion()
				if r.Delta != nil {
					v = r.Delta.Version
				}
				versions[i].Store(v)
				return nil
			})
		}()
	}
	// waitAll waits until every node has a map at least as new as v.
	waitAll := func(what string, v uint64, limit time.Duration) time.Duration {
		t.Helper()
		began := time.Now()
		for {
			behind := 0
			for i := range versions {
				if versions[i].Load() < v {
					behind++
				}
			}
			if behind == 0 {
				return time.Since(began)
			}
			if time.Since(began) > limit {
				t.Fatalf("%s: %d of %d nodes still behind after %v", what, behind, len(ids), limit)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	// Connecting: every node announces itself to its peers. Streams that
	// connect together may get a first map that already includes later
	// announcements, and then rightly get nothing more, so wait for every
	// node to have a map and the stream of updates to go quiet.
	waitAll("connect", 1, 5*time.Minute)
	for last := int64(-1); last != msgs.Load(); {
		last = msgs.Load()
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("connected %d streams in %v: %d messages, %s", len(ids), time.Since(start).Round(time.Millisecond),
		msgs.Load(), mb(bytesSent.Load()))

	push := func(name string, p *policy.Policy) time.Duration {
		t.Helper()
		runtime.GC()
		bytesSent.Store(0)
		msgs.Store(0)
		began := time.Now()
		s.SetPolicy(p, "", "test")
		v := s.version.Load()
		waitAll(name, v, time.Minute)
		took := time.Since(began)
		t.Logf("%s: reached all %d nodes in %v: %d messages, %s", name, len(ids), took.Round(time.Millisecond),
			msgs.Load(), mb(bytesSent.Load()))
		return took
	}
	// Every node's packet filter changes; nobody's peers do.
	ports := push("policy push (ports)", teamPolicy("22,80,443", "443,8443"))
	// Every node's peers change: team 0 can now reach every machine on 22,
	// so each node gains (or, for team 0, keeps) 100 more peers.
	push("policy push (visibility)", teamPolicy("22,80,443", "443,8443",
		policy.ACL{Action: "accept", Src: []string{"group:team0"}, Dst: []string{"*:22"}}))

	// The target: a policy push reaches 10k nodes in under a second. It's
	// checked when the test has the machine to itself (make loadtest);
	// next to every other package's tests it only reports. The visibility
	// push moves ~390 MB of peer entries, so its time follows the
	// machine's load and is reported, not checked.
	if os.Getenv("WHALESCALE_LOADTEST_STRICT") != "" && !israce.Enabled && n <= 10000 && ports > time.Second {
		t.Errorf("policy push to %d nodes took %v, want < 1s", len(ids), ports)
	}
	cancel()
	wg.Wait()
}

func mb(n int64) string {
	return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/(1<<20)), ".0") + " MB"
}
