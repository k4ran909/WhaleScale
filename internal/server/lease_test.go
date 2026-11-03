package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

// A leader that stalls (no ticks: CPU starved, paused) must stop leading
// when its lease runs out, on its own, so it never leads at the same time
// as the server that takes over.
func TestLeaderStepsDownWhenLeaseLapses(t *testing.T) {
	ctx := context.Background()
	dsn := storetest.DSN(t, t.TempDir())
	open := func() *Server {
		t.Helper()
		st, err := store.Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		srv, err := New(st, Config{PublicURL: "http://127.0.0.1:1", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}
	s1, s2 := open(), open()
	const every = 100 * time.Millisecond // a 2 s lease
	s1.clusterTick(ctx, every)
	s2.clusterTick(ctx, every)
	if !s1.Leader() || s2.Leader() {
		t.Fatalf("leaders: s1 %v, s2 %v", s1.Leader(), s2.Leader())
	}

	// s1 stalls; s2 keeps ticking and takes over once the lease lapses.
	for deadline := time.Now().Add(clusterWindow(every) + 2*time.Second); !s2.Leader(); time.Sleep(every / 2) {
		if time.Now().After(deadline) {
			t.Fatal("s2 never took over the lapsed lease")
		}
		s2.clusterTick(ctx, every)
		if s1.Leader() && s2.Leader() {
			t.Fatal("two leaders")
		}
	}
	if s1.Leader() {
		t.Fatal("the stalled server still leads after its lease ran out")
	}
	// When s1 wakes up, its tick finds the lease taken.
	s1.clusterTick(ctx, every)
	if s1.Leader() || !s2.Leader() {
		t.Fatalf("after s1 wakes: s1 %v, s2 %v", s1.Leader(), s2.Leader())
	}
}
