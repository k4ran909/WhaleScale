package clientstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Profiles let one machine belong to several networks (work, home, a
// customer's) and switch between them. Each profile is a complete state
// file with its own identity and keys:
//
//	<dir>/state.json            the "default" profile (and the base path)
//	<dir>/profiles/<name>.json  every other profile
//	<dir>/current-profile       the active profile's name (absent: default)
//
// One network is active at a time: networks all use 100.64.0.0/10, so two
// at once would fight over routes and DNS.

// DefaultProfile is the profile stored in the base state file.
const DefaultProfile = "default"

var profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidProfileName reports whether name works as a profile name.
func ValidProfileName(name string) bool { return profileNameRe.MatchString(name) }

// ProfilePath is where profile name's state lives, given the base path.
func ProfilePath(base, name string) string {
	if name == DefaultProfile || name == "" {
		return base
	}
	return filepath.Join(filepath.Dir(base), "profiles", name+".json")
}

func currentFile(base string) string { return filepath.Join(filepath.Dir(base), "current-profile") }

// Current returns the active profile's name and state path.
func Current(base string) (name, path string) {
	b, err := os.ReadFile(currentFile(base))
	name = strings.TrimSpace(string(b))
	if err != nil || !ValidProfileName(name) {
		name = DefaultProfile
	}
	return name, ProfilePath(base, name)
}

// SetCurrent makes name the active profile. It needn't exist yet ('ws
// login --profile' creates it).
func SetCurrent(base, name string) error {
	if !ValidProfileName(name) {
		return fmt.Errorf("profile name %q: use up to 32 lowercase letters, digits, '-' and '_'", name)
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return err
	}
	if name == DefaultProfile {
		err := os.Remove(currentFile(base))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.WriteFile(currentFile(base), []byte(name+"\n"), 0o600)
}

// ProfileInfo describes one stored profile.
type ProfileInfo struct {
	Name, Path string
	State      *State
}

// Profiles lists the stored profiles, default first, then by name.
func Profiles(base string) ([]ProfileInfo, error) {
	var out []ProfileInfo
	if st, err := Load(base); err != nil {
		return nil, err
	} else if st != nil {
		out = append(out, ProfileInfo{Name: DefaultProfile, Path: base, State: st})
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(base), "profiles", "*.json"))
	sort.Strings(files)
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		if !ValidProfileName(name) {
			continue
		}
		st, err := Load(f)
		if err != nil {
			return nil, err
		}
		if st != nil {
			out = append(out, ProfileInfo{Name: name, Path: f, State: st})
		}
	}
	return out, nil
}

// RemoveProfile deletes a profile's state (not the default's: that is
// logged out in place). The active profile falls back to default.
func RemoveProfile(base, name string) error {
	if name == DefaultProfile {
		return errors.New("the default profile can't be removed; log it out instead")
	}
	if err := os.Remove(ProfilePath(base, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cur, _ := Current(base); cur == name {
		return SetCurrent(base, DefaultProfile)
	}
	return nil
}
