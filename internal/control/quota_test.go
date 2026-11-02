package control

import (
	"context"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/clientstate"
)

// A machine over its recording quota gets new recordings refused; its old
// ones stay, and other machines are unaffected.
func TestRecordingQuota(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, st := newTestService(t, Config{RecordingsDir: dir, RecordingQuota: 100})
	st.CreateUser(ctx, "ann")
	_, key, _ := st.CreatePreAuthKey(ctx, "ann", true, false, time.Hour)
	register := func(host string) string {
		priv, _ := clientstate.NewMachineKey()
		pub, _ := (&clientstate.State{MachineKey: priv}).PublicKey()
		reg, err := s.Register(ctx, connect.NewRequest(&v1.RegisterRequest{AuthKey: key, MachineKey: pub, Hostname: host}))
		if err != nil {
			t.Fatal(err)
		}
		return reg.Msg.NodeToken
	}
	upload := func(token string, size int) error {
		now := timestamppb.Now()
		req := connect.NewRequest(&v1.UploadRecordingRequest{Data: make([]byte, size), LocalUser: "root", StartedAt: now, EndedAt: now})
		req.Header().Set("Authorization", "Bearer "+token)
		_, err := s.UploadRecording(ctx, req)
		return err
	}
	nas, web := register("nas"), register("web")
	if err := upload(nas, 60); err != nil {
		t.Fatal(err)
	}
	if err := upload(nas, 60); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("upload past the quota: %v", err)
	}
	if err := upload(nas, 40); err != nil {
		t.Fatalf("upload that fits: %v", err)
	}
	if err := upload(web, 90); err != nil {
		t.Fatalf("another machine's upload: %v", err)
	}
	if list, _ := st.ListRecordings(ctx, 10); len(list) != 3 {
		t.Fatalf("recordings: %+v", list)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 3 {
		t.Fatalf("%d files stored", len(files))
	}
}

func TestFlowBudget(t *testing.T) {
	s, _ := newTestService(t, Config{})
	now := time.Unix(1_800_000_000, 0)
	if got := s.takeFlows(1, flowBurst+500, now); got != flowBurst {
		t.Fatalf("first report: %d stored", got)
	}
	if got := s.takeFlows(1, 10, now); got != 0 {
		t.Fatalf("over budget: %d stored", got)
	}
	if got := s.takeFlows(2, 10, now); got != 10 {
		t.Fatalf("another node: %d stored", got)
	}
	// An honest busy node: a full report every 30 seconds always fits.
	for i := 1; i <= 5; i++ {
		if got := s.takeFlows(1, maxFlowsPerReport, now.Add(time.Duration(i)*30*time.Second)); got != maxFlowsPerReport {
			t.Fatalf("report %d: %d stored", i, got)
		}
	}
}
