package clientstate

import (
	"path/filepath"
	"testing"
)

func TestProfiles(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state.json")
	if name, path := Current(base); name != DefaultProfile || path != base {
		t.Fatalf("fresh Current = %s %s", name, path)
	}
	Save(base, &State{ServerURL: "https://home", NodeName: "pc"})
	work := ProfilePath(base, "work")
	Save(work, &State{ServerURL: "https://work", NodeName: "pc-work"})

	if err := SetCurrent(base, "work"); err != nil {
		t.Fatal(err)
	}
	if name, path := Current(base); name != "work" || path != work {
		t.Fatalf("Current = %s %s", name, path)
	}
	list, err := Profiles(base)
	if err != nil || len(list) != 2 || list[0].Name != "default" || list[1].Name != "work" || list[1].State.ServerURL != "https://work" {
		t.Fatalf("Profiles = %+v, %v", list, err)
	}
	if err := SetCurrent(base, "../evil"); err == nil {
		t.Fatal("path-like profile name accepted")
	}
	if err := RemoveProfile(base, "work"); err != nil {
		t.Fatal(err)
	}
	if name, _ := Current(base); name != DefaultProfile {
		t.Fatalf("after removing the active profile, Current = %s", name)
	}
	if err := RemoveProfile(base, DefaultProfile); err == nil {
		t.Fatal("removed the default profile")
	}
}
