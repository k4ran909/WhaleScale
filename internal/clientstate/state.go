// Package clientstate stores a node's identity on disk: its machine key and
// the credentials it received from the control server.
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
)

type State struct {
	ServerURL  string `json:"server_url"`
	MachineKey string `json:"machine_key"` // X25519 private key, base64
	// NodeKey is the WireGuard private key, base64. Created by wsd on first run.
	NodeKey   string `json:"node_key,omitempty"`
	NodeToken string `json:"node_token,omitempty"`
	NodeID    uint64 `json:"node_id,omitempty"`
	NodeName  string `json:"node_name,omitempty"`
}

// DefaultPath is $WHALESCALE_STATE, else <user config dir>/whalescale/state.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("WHALESCALE_STATE"); p != "" {
		return p, nil
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
