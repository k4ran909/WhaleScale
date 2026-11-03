package clientstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// PublicStatus is what wsd tells every local user (the tray icon): whether
// the tunnel is up and who else is on the network. No keys or tokens.
type PublicStatus struct {
	Updated time.Time `json:"updated"`
	// State is "connected", "connecting", "down" ('ws down') or
	// "logged-out".
	State   string       `json:"state"`
	Server  string       `json:"server,omitempty"`
	Name    string       `json:"name,omitempty"`
	Address string       `json:"address,omitempty"`
	User    string       `json:"user,omitempty"`
	Peers   []PublicPeer `json:"peers,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type PublicPeer struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	OS      string `json:"os,omitempty"`
	Online  bool   `json:"online"`
	// Path is "direct", "relay", "peer-relay", "idle" or "none".
	Path string `json:"path,omitempty"`
}

// PublicStatusPath is where the wsd service writes its PublicStatus.
func PublicStatusPath() string { return filepath.Join(SystemDir(), "public", "status.json") }

// WritePublicStatus saves st for local users to read.
func WritePublicStatus(path string, st PublicStatus) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := protectPublic(dir); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadPublicStatus reads what WritePublicStatus saved.
func ReadPublicStatus(path string) (PublicStatus, error) {
	var st PublicStatus
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}
