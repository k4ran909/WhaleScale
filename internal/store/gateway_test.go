package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExposures(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.CreateUser(ctx, "karan")
	_, key, _ := s.CreatePreAuthKey(ctx, "karan", true, false, time.Hour)
	a, _, _ := s.RegisterNode(ctx, RegisterParams{AuthKey: key, MachineKey: "mk-a", Hostname: "nas"})
	b, _, _ := s.RegisterNode(ctx, RegisterParams{AuthKey: key, MachineKey: "mk-b", Hostname: "pi"})

	changed, taken, err := s.SetExposures(ctx, a.ID, []ExposureRequest{{"ha", 8123}, {"Bad Name", 80}, {"files", 0}})
	if err != nil || !changed || len(taken) != 0 {
		t.Fatalf("first set: %v %v %v", changed, taken, err)
	}
	list, _ := s.NodeExposures(ctx, a.ID)
	if len(list) != 1 || list[0].Name != "ha" || list[0].Port != 8123 || list[0].Live() {
		t.Fatalf("invalid entries must be skipped and new ones start unapproved: %+v", list)
	}
	if changed, _, _ := s.SetExposures(ctx, a.ID, []ExposureRequest{{"ha", 8123}}); changed {
		t.Fatal("identical set reported as changed")
	}

	// Another node can't take the name.
	_, taken, err = s.SetExposures(ctx, b.ID, []ExposureRequest{{"ha", 9000}, {"grafana", 3000}})
	if err != nil || len(taken) != 1 || taken[0] != "ha" {
		t.Fatalf("name collision: taken=%v err=%v", taken, err)
	}

	before, _ := s.Fingerprint(ctx)
	if err := s.SetExposureApproved(ctx, a.ID, "ha", true); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.Fingerprint(ctx); after == before {
		t.Fatal("fingerprint unchanged after approval")
	}
	e, err := s.ExposureByName(ctx, "ha")
	if err != nil || !e.Live() || e.NodeName != "nas" {
		t.Fatalf("ExposureByName = %+v, %v", e, err)
	}

	// Pointing the name at a different port needs approval again.
	s.SetExposures(ctx, a.ID, []ExposureRequest{{"ha", 9999}})
	if e, _ := s.ExposureByName(ctx, "ha"); e.Live() || e.Port != 9999 {
		t.Fatalf("port change kept approval: %+v", e)
	}
	// Withdrawing keeps the row (and name) but takes it offline.
	s.SetExposureApproved(ctx, a.ID, "ha", true)
	s.SetExposures(ctx, a.ID, nil)
	if e, _ := s.ExposureByName(ctx, "ha"); e.Live() {
		t.Fatal("withdrawn exposure still live")
	}
	s.SetExposures(ctx, a.ID, []ExposureRequest{{"ha", 9999}})
	if e, _ := s.ExposureByName(ctx, "ha"); !e.Live() {
		t.Fatal("re-advertised exposure lost its approval")
	}
	if _, err := s.ExposureByName(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown name: %v", err)
	}
}
