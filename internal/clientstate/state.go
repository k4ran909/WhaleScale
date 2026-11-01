// Package clientstate stores a node's identity on disk: its machine key,
// the credentials it received from the control server, and its preferences.
package clientstate

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type State struct {
	ServerURL  string `json:"server_url"`
	MachineKey string `json:"machine_key"` // X25519 private key, base64
	// NodeKey is the WireGuard private key, base64. Created by wsd on first run.
	NodeKey   string `json:"node_key,omitempty"`
	NodeToken string `json:"node_token,omitempty"`
	NodeID    uint64 `json:"node_id,omitempty"`
	NodeName  string `json:"node_name,omitempty"`
	// SSHHostKey is the mesh SSH server's private host key (OpenSSH PEM).
	SSHHostKey string `json:"ssh_host_key,omitempty"`
	// LockHead is the newest network lock state this node has verified
	// (an encoded LockState, base64). Later states must follow from it.
	LockHead string `json:"lock_head,omitempty"`
	// LockTrust pins the lock keys ("wslock:...") this node accepts the
	// first lock state from, instead of trusting whatever comes first.
	LockTrust []string `json:"lock_trust,omitempty"`
	Prefs     Prefs    `json:"prefs"`
}

// Prefs are the settings 'ws up' and 'ws down' change.
type Prefs struct {
	// Down keeps wsd running but the tunnel stopped.
	Down bool `json:"down,omitempty"`
	// AdvertiseRoutes are subnets (or 0.0.0.0/0 and ::/0 for an exit
	// node) this node offers to route. An admin must approve them.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
	// AcceptRoutes installs subnet routes that other nodes offer.
	AcceptRoutes bool `json:"accept_routes,omitempty"`
	// ExitNode sends all internet traffic through this peer.
	ExitNode string `json:"exit_node,omitempty"`
	// Exposures publishes local services (name -> localhost port) at
	// https://<name>.<gateway domain>.
	Exposures map[string]uint16 `json:"exposures,omitempty"`
	// Relay offers this node as a peer relay.
	Relay bool `json:"relay,omitempty"`
	// SSH runs the mesh SSH server; the access policy's "ssh" rules decide
	// who may log in.
	SSH bool `json:"ssh,omitempty"`
}

// SystemDir is where a wsd service keeps its state. When it exists, ws and
// wsd use it instead of the per-user config directory.
func SystemDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Whalescale")
	case "darwin":
		return "/Library/Application Support/Whalescale"
	default:
		return "/var/lib/whalescale"
	}
}

// DefaultPath is $WHALESCALE_STATE; else the system state file if a wsd
// service was installed; else <user config dir>/whalescale/state.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("WHALESCALE_STATE"); p != "" {
		return p, nil
	}
	if fi, err := os.Stat(SystemDir()); err == nil && fi.IsDir() {
		return filepath.Join(SystemDir(), "state.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "whalescale", "state.json"), nil
}

// Load reads state from path. A missing file returns (nil, nil).
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if errors.Is(err, os.ErrPermission) {
		return nil, fmt.Errorf("%s: permission denied (the wsd service owns it; run this as root/Administrator)", path)
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}

// Save writes state atomically with owner-only permissions.
func Save(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// The node token and keys are in here: only the service may read them.
	if err := Protect(filepath.Dir(path)); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NewMachineKey generates a fresh X25519 private key.
func NewMachineKey() (string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), nil
}

// PublicKey derives the base64 public key from the stored private key.
func (s *State) PublicKey() (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s.MachineKey)
	if err != nil {
		return "", fmt.Errorf("decode machine key: %w", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
