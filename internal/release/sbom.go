package release

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SBOM returns a CycloneDX 1.5 software bill of materials for the release:
// every Go module compiled into the given programs (read from their build
// information, so it lists what was really linked, per platform), plus the
// Go standard library.
func SBOM(version string, when time.Time, binaries []string) ([]byte, error) {
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type component struct {
		Type       string `json:"type"`
		BOMRef     string `json:"bom-ref"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		PURL       string `json:"purl"`
		Properties []prop `json:"properties,omitempty"`
	}
	type entry struct {
		component
		in map[string]bool // which programs (os_arch/name)
	}
	mods := map[string]*entry{}
	add := func(path, version, sum, program string) {
		ref := "pkg:golang/" + path + "@" + version
		e := mods[ref]
		if e == nil {
			e = &entry{component: component{Type: "library", BOMRef: ref, Name: path, Version: version, PURL: ref}, in: map[string]bool{}}
			if sum != "" {
				e.Properties = append(e.Properties, prop{"go:module:sum", sum})
			}
			mods[ref] = e
		}
		e.in[program] = true
	}
	main := ""
	for _, b := range binaries {
		bi, err := buildinfo.ReadFile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b, err)
		}
		program := filepath.Base(filepath.Dir(b)) + "/" + filepath.Base(b)
		main = bi.Main.Path
		add("stdlib", bi.GoVersion, "", program)
		for _, d := range bi.Deps {
			if d.Replace != nil {
				d = d.Replace
			}
			add(d.Path, d.Version, d.Sum, program)
		}
	}
	if main == "" {
		return nil, fmt.Errorf("no programs given")
	}
	var comps []component
	for _, e := range mods {
		var in []string
		for p := range e.in {
			in = append(in, p)
		}
		sort.Strings(in)
		if len(in) < len(binaries) {
			e.Properties = append(e.Properties, prop{"whalescale:in", strings.Join(in, " ")})
		}
		comps = append(comps, e.component)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })

	v := strings.TrimPrefix(version, "v")
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": when.UTC().Format(time.RFC3339),
			"tools": map[string]any{"components": []map[string]string{
				{"type": "application", "name": "whalescale internal/release", "version": v},
			}},
			"component": component{Type: "application", BOMRef: "pkg:golang/" + main + "@v" + v,
				Name: "whalescale", Version: v, PURL: "pkg:golang/" + main + "@v" + v},
		},
		"components": comps,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	// The same inputs give the same document, serial number included.
	doc["serialNumber"] = uuidFrom(sha256.Sum256(body))
	return json.MarshalIndent(doc, "", "  ")
}

// uuidFrom makes a name-based UUID (RFC 4122 layout) from a hash.
func uuidFrom(sum [32]byte) string {
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
