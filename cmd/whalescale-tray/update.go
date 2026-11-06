package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Where releases come from. The installer is checked against the
// release's checksums.txt before it runs.
const (
	releasesAPI = "https://api.github.com/repos/k4ran909/WhaleScale/releases/latest"
	downloadURL = "https://github.com/k4ran909/WhaleScale/releases/download"
)

// installerName is the release's installer for this PC.
func installerName() string { return "whalescale-setup-windows-" + runtime.GOARCH + ".exe" }

// latestRelease returns the newest release's tag (e.g. "v0.1.4").
func latestRelease(ctx context.Context, hc *http.Client, api string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "whalescale-tray")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("release check: %s", resp.Status)
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", err
	}
	if _, ok := parseVersion(r.Tag); !ok {
		return "", fmt.Errorf("release check: unexpected tag %q", r.Tag)
	}
	return r.Tag, nil
}

// parseVersion reads "v1.2.3" or "1.2.3" (a "-suffix" is ignored).
func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	s, _, _ = strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// newer reports whether latest is a later release than current. A
// development build ("dev") is never offered updates.
func newer(current, latest string) bool {
	c, ok1 := parseVersion(current)
	l, ok2 := parseVersion(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// downloadInstaller fetches tag's installer into dir and checks it against
// the release's checksums.txt, returning its path.
func downloadInstaller(ctx context.Context, hc *http.Client, base, tag, dir string) (string, error) {
	name := installerName()
	want, err := checksumFor(ctx, hc, base+"/"+tag+"/checksums.txt", name)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/"+tag+"/"+name, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download %s: %s", name, resp.Status)
	}
	path := filepath.Join(dir, strings.TrimSuffix(name, ".exe")+"-"+tag+".exe")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = errors.New("the downloaded installer doesn't match the release's checksum")
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// checksumFor returns name's SHA-256 from a checksums.txt ("<hex>  name").
func checksumFor(ctx context.Context, hc *http.Client, url, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download checksums: %s", resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s isn't in the release's checksums", name)
}
