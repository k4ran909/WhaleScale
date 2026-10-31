package store

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIKeysAndSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	k, plain, err := s.CreateAPIKey(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.CheckAPIKey(ctx, plain); err != nil || p != k.Prefix {
		t.Fatalf("CheckAPIKey = %q, %v", p, err)
	}
	if _, err := s.CheckAPIKey(ctx, plain+"x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad key accepted: %v", err)
	}
	s.ExpireAPIKey(ctx, k.Prefix)
	if _, err := s.CheckAPIKey(ctx, plain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired key accepted: %v", err)
	}

	tok, err := s.CreateSession(ctx, "karan@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := s.SessionIdentity(ctx, tok); err != nil || id != "karan@example.com" {
		t.Fatalf("SessionIdentity = %q, %v", id, err)
	}
	s.DeleteSession(ctx, tok)
	if _, err := s.SessionIdentity(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted session still valid")
	}
}

func TestOIDCUsers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.CreateUser(ctx, "karan")
	u1, err := s.UserForOIDC(ctx, "sub-1", "Karan@example.com")
	if err != nil || u1.Name != "karan-1" {
		t.Fatalf("first OIDC user = %+v, %v", u1, err)
	}
	u2, _ := s.UserForOIDC(ctx, "sub-1", "karan@example.com")
	if u2.ID != u1.ID {
		t.Fatal("same subject mapped to a different user")
	}
	n, _, err := s.RegisterNodeForUser(ctx, u1.ID, RegisterParams{MachineKey: "mk", Hostname: "phone"})
	if err != nil || n.User != "karan-1" {
		t.Fatalf("RegisterNodeForUser = %+v, %v", n, err)
	}
	if err := s.DeleteUser(ctx, "karan-1"); !errors.Is(err, ErrUserHasNodes) {
		t.Fatalf("DeleteUser with nodes: %v", err)
	}
	if err := s.DeleteUser(ctx, "karan"); err != nil {
		t.Fatal(err)
	}
}

func TestRoutes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.CreateUser(ctx, "karan")
	_, key, _ := s.CreatePreAuthKey(ctx, "karan", true, false, time.Hour)
	n, _, _ := s.RegisterNode(ctx, RegisterParams{AuthKey: key, MachineKey: "mk", Hostname: "router"})

	lan := netip.MustParsePrefix("192.168.1.0/24")
	exit := netip.MustParsePrefix("0.0.0.0/0")
	changed, err := s.SetAdvertisedRoutes(ctx, n.ID, []netip.Prefix{lan, exit})
	if err != nil || !changed {
		t.Fatalf("advertise: %v %v", changed, err)
	}
	if changed, _ := s.SetAdvertisedRoutes(ctx, n.ID, []netip.Prefix{exit, lan}); changed {
		t.Fatal("same set reported as changed")
	}
	nodes, _ := s.ListNodes(ctx, "")
	if len(nodes[0].AdvertisedRoutes) != 2 || len(nodes[0].Routes) != 0 {
		t.Fatalf("before approval: %+v", nodes[0])
	}
	before, _ := s.Fingerprint(ctx)
	if err := s.SetRouteApproved(ctx, n.ID, lan, true); err != nil {
		t.Fatal(err)
	}
	// A running server detects CLI approvals through the fingerprint.
	if after, _ := s.Fingerprint(ctx); after == before {
		t.Fatal("fingerprint unchanged after route approval")
	}
	if err := s.SetRouteApproved(ctx, n.ID, netip.MustParsePrefix("10.0.0.0/8"), true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approving an unadvertised route: %v", err)
	}
	nodes, _ = s.ListNodes(ctx, "")
	if len(nodes[0].Routes) != 1 || nodes[0].Routes[0] != lan {
		t.Fatalf("after approval: %+v", nodes[0].Routes)
	}
	// Withdrawn routes stop being active but keep their approval.
	s.SetAdvertisedRoutes(ctx, n.ID, nil)
	nodes, _ = s.ListNodes(ctx, "")
	if len(nodes[0].Routes) != 0 {
		t.Fatal("withdrawn route still active")
	}
	s.SetAdvertisedRoutes(ctx, n.ID, []netip.Prefix{lan})
	nodes, _ = s.ListNodes(ctx, "")
	if len(nodes[0].Routes) != 1 {
		t.Fatal("re-advertised route lost its approval")
	}
}

func TestRelayOffer(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.CreateUser(ctx, "karan")
	_, key, _ := s.CreatePreAuthKey(ctx, "karan", true, false, time.Hour)
	n, _, _ := s.RegisterNode(ctx, RegisterParams{AuthKey: key, MachineKey: "mk", Hostname: "vps"})
	if changed, err := s.SetRelayOffered(ctx, n.ID, true); err != nil || !changed {
		t.Fatalf("offer: %v %v", changed, err)
	}
	if changed, _ := s.SetRelayOffered(ctx, n.ID, true); changed {
		t.Fatal("same offer reported as changed")
	}
	before, _ := s.Fingerprint(ctx)
	if err := s.SetRelayApproved(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.Fingerprint(ctx); after == before {
		t.Fatal("fingerprint unchanged after relay approval")
	}
	nodes, _ := s.ListNodes(ctx, "")
	if !nodes[0].RelayOffered || !nodes[0].RelayApproved {
		t.Fatalf("relay flags not stored: %+v", nodes[0])
	}
	if err := s.SetRelayApproved(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
}

func TestRecordings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	dir := filepath.Join(t.TempDir(), "rec")
	start := time.Now().Add(-time.Minute)
	r, err := s.SaveRecording(ctx, dir, Recording{NodeName: "nas", LocalUser: "root", SrcNode: "laptop", SrcUser: "karan",
		StartedAt: start, EndedAt: time.Now()}, []byte(`{"version":2}`+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListRecordings(ctx, 10)
	if len(list) != 1 || list[0].SrcUser != "karan" || list[0].Size != r.Size {
		t.Fatalf("list = %+v", list)
	}
	got, data, err := s.RecordingByID(ctx, dir, r.ID)
	if err != nil || got.LocalUser != "root" || !strings.HasPrefix(string(data), `{"version":2}`) {
		t.Fatalf("RecordingByID = %+v %q %v", got, data, err)
	}
	if _, _, err := s.RecordingByID(ctx, dir, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown recording: %v", err)
	}
}
