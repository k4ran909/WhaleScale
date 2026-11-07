package release

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseKey(k.Encode())
	if err != nil || k2.PublicKey() != k.PublicKey() {
		t.Fatalf("ParseKey round trip: %v", err)
	}
	// What pasting into a secrets form adds is forgiven.
	enc := k.Encode()
	for _, pasted := range []string{"\"" + enc + "\"", " " + enc + "\r\n", enc[:30] + "\n" + enc[30:]} {
		if k3, err := ParseKey(pasted); err != nil || k3.PublicKey() != k.PublicKey() {
			t.Errorf("ParseKey(pasted form): %v", err)
		}
	}
	// Wrong values are explained without being repeated.
	for in, want := range map[string]string{
		"":                 "empty",
		k.PublicKey():      "that's the public key",
		k.PublicKeyFile():  ".pub file",
		"hello":            "5 characters",
		keyPrefix + "AAAA": "there are 4",
	} {
		_, err := ParseKey(in)
		if err == nil || !strings.Contains(err.Error(), want) || (len(in) > 8 && strings.Contains(err.Error(), in)) {
			t.Errorf("ParseKey(%.20q) = %v, want it to mention %q", in, err, want)
		}
	}
	msg := []byte("abc123  whalescale-setup-windows-amd64.exe\n")
	sig := k.Sign(msg, "checksums.txt", time.Unix(1700000000, 0))
	if err := Verify(k.PublicKey(), msg, sig); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	if !strings.Contains(sig, "trusted comment: timestamp:1700000000\tfile:checksums.txt\thashed\n") {
		t.Fatalf("trusted comment: %q", sig)
	}
	// Anything changed fails: the message, the trusted comment, the key.
	if Verify(k.PublicKey(), append(msg, 'x'), sig) == nil {
		t.Error("changed message verified")
	}
	if Verify(k.PublicKey(), msg, strings.Replace(sig, "checksums.txt", "other.txt", 1)) == nil {
		t.Error("changed trusted comment verified")
	}
	other, _ := NewKey()
	if Verify(other.PublicKey(), msg, sig) == nil {
		t.Error("another key verified")
	}
	if Verify(k.PublicKey(), msg, "garbage") == nil {
		t.Error("garbage verified")
	}
	if !strings.HasPrefix(k.PublicKeyFile(), "untrusted comment: minisign public key ") {
		t.Errorf("public key file: %q", k.PublicKeyFile())
	}
}

// The real minisign tool accepts our signatures, when it's installed.
func TestMinisignInterop(t *testing.T) {
	bin, err := exec.LookPath("minisign")
	if err != nil {
		t.Skip("minisign not installed")
	}
	k, _ := NewKey()
	dir := t.TempDir()
	msg := []byte("hello\n")
	os.WriteFile(filepath.Join(dir, "f"), msg, 0o644)
	os.WriteFile(filepath.Join(dir, "f.minisig"), []byte(k.Sign(msg, "f", time.Now())), 0o644)
	out, err := exec.Command(bin, "-Vm", filepath.Join(dir, "f"), "-P", k.PublicKey()).CombinedOutput()
	if err != nil {
		t.Fatalf("minisign: %v\n%s", err, out)
	}
}

// The release key in the source matches packaging/release-key.pub and the
// install script.
func TestPublicKeyFile(t *testing.T) {
	b, err := os.ReadFile("../../packaging/release-key.pub")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || strings.TrimSpace(lines[1]) != PublicKey {
		t.Fatalf("packaging/release-key.pub doesn't hold PublicKey")
	}
	sh, err := os.ReadFile("../../deploy/install.sh")
	if err != nil || !strings.Contains(string(sh), `RELEASE_KEY="`+PublicKey+`"`) {
		t.Fatalf("deploy/install.sh doesn't hold PublicKey (%v)", err)
	}
}

func TestSBOM(t *testing.T) {
	exe, err := os.Executable() // this test binary: a Go program with build info
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	a, err := SBOM("v1.2.3", when, []string{exe})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SBOM("v1.2.3", when, []string{exe})
	if string(a) != string(b) {
		t.Fatal("the same inputs gave different SBOMs")
	}
	var doc struct {
		BOMFormat, SpecVersion, SerialNumber string
		Components                           []struct{ Name, Version, PURL string }
	}
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Fatalf("header: %+v", doc)
	}
	found := map[string]bool{}
	for _, c := range doc.Components {
		found[c.Name] = true
	}
	if !found["stdlib"] || !found["golang.org/x/crypto"] {
		t.Fatalf("components: %+v", doc.Components)
	}
}
