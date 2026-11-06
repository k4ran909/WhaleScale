package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		cur, latest string
		want        bool
	}{
		{"v0.1.3", "v0.1.4", true},
		{"v0.1.3", "v0.2.0", true},
		{"v0.9.9", "v1.0.0", true},
		{"v0.1.10", "v0.1.9", false},
		{"v0.1.4", "v0.1.4", false},
		{"v0.1.4-rc1", "v0.1.4", false},
		{"dev", "v9.9.9", false},
		{"v0.1.3", "garbage", false},
	} {
		if got := newer(tc.cur, tc.latest); got != tc.want {
			t.Errorf("newer(%q, %q) = %v", tc.cur, tc.latest, got)
		}
	}
}

func TestUpdateDownload(t *testing.T) {
	installer := []byte("pretend installer")
	sum := sha256.Sum256(installer)
	name := installerName()
	tampered := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "GitHub wants a User-Agent", 403)
			return
		}
		w.Write([]byte(`{"tag_name":"v0.1.4","name":"v0.1.4"}`))
	})
	mux.HandleFunc("/dl/v0.1.4/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0000  other.zip\n" + hex.EncodeToString(sum[:]) + "  " + name + "\n"))
	})
	mux.HandleFunc("/dl/v0.1.4/"+name, func(w http.ResponseWriter, r *http.Request) {
		if tampered {
			w.Write([]byte("something else"))
			return
		}
		w.Write(installer)
	})
	hs := httptest.NewServer(mux)
	defer hs.Close()
	ctx := context.Background()

	tag, err := latestRelease(ctx, hs.Client(), hs.URL+"/api")
	if err != nil || tag != "v0.1.4" {
		t.Fatalf("latestRelease = %q, %v", tag, err)
	}
	dir := t.TempDir()
	path, err := downloadInstaller(ctx, hs.Client(), hs.URL+"/dl", tag, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(installer) || !strings.HasSuffix(path, "-v0.1.4.exe") {
		t.Fatalf("downloaded %q to %s", b, path)
	}

	// A file that doesn't match the checksum is refused and removed.
	tampered = true
	if _, err := downloadInstaller(ctx, hs.Client(), hs.URL+"/dl", tag, t.TempDir()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered installer: %v", err)
	}
	if _, err := downloadInstaller(ctx, hs.Client(), hs.URL+"/dl", "v9.9.9", t.TempDir()); err == nil {
		t.Fatal("missing release accepted")
	}
}
