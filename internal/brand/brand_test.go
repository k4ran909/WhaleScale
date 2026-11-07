package brand

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
)

// The shapes here are the ones in the SVG files.
func TestMatchesSVGFiles(t *testing.T) {
	for _, f := range []string{"app-icon.svg", "logo.svg", "logo-blue.svg", "logo-monochrome.svg", "logo-on-blue.svg"} {
		b, err := os.ReadFile("../../assets/brand/" + f)
		if err != nil {
			t.Fatal(err)
		}
		svg := string(b)
		for _, want := range []string{spoutPath, bodyPath} {
			if !strings.Contains(svg, `d="`+want+`"`) {
				t.Errorf("%s: path %.30s... differs", f, want)
			}
		}
		for _, r := range accentRects {
			rect := fmt.Sprintf(`<rect x="%v" y="%v" width="%v" height="%v"/>`, r[0], r[1], r[2], r[3])
			if !strings.Contains(svg, rect) {
				t.Errorf("%s: missing %s", f, rect)
			}
		}
	}
	b, _ := os.ReadFile("../../assets/brand/app-icon.svg")
	if !strings.Contains(string(b), `viewBox="24 -46 354 354"`) {
		t.Error("app-icon.svg viewBox changed; update AppIcon")
	}
	b, _ = os.ReadFile("../../assets/brand/logo.svg")
	if !strings.Contains(string(b), `viewBox="48 46 306 168"`) {
		t.Error("logo.svg viewBox changed; update Whale")
	}
}

func TestRender(t *testing.T) {
	const size = 354 // one pixel per unit of AppIcon
	img := Render(size, size, AppIcon, Style{Background: Navy, Radius: 0.22, Body: White, Accent: Sky})
	at := func(x, y float64) color.NRGBA { return img.NRGBAAt(int(x-AppIcon.X), int(y-AppIcon.Y)) }
	for _, c := range []struct {
		what string
		x, y float64
		want color.NRGBA
	}{
		{"background", 200, 0, Navy},
		{"body", 300, 115, White},
		{"spout", 147, 60, White},
		{"accent pixel", 64, 89, Sky},
		{"the eye, a hole in the body", 263.4, 132.9, Navy},
		{"rounded corner", 25, -45, color.NRGBA{}},
	} {
		if got := at(c.x, c.y); got != c.want {
			t.Errorf("%s at (%v,%v): %v, want %v", c.what, c.x, c.y, got, c.want)
		}
	}
}

func TestICO(t *testing.T) {
	sizes := []int{16, 32, 256}
	ico := ICO(AppIcon, Style{Background: Navy, Body: White, Accent: Sky}, sizes...)
	var hdr [3]uint16
	binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr)
	if hdr != [3]uint16{0, 1, 3} {
		t.Fatalf("header %v", hdr)
	}
	for i, size := range sizes {
		e := ico[6+16*i:]
		dim := int(e[0])
		if dim == 0 {
			dim = 256
		}
		n, off := binary.LittleEndian.Uint32(e[8:12]), binary.LittleEndian.Uint32(e[12:16])
		img, err := png.Decode(bytes.NewReader(ico[off : off+n]))
		if err != nil || dim != size || img.Bounds().Dx() != size {
			t.Fatalf("entry %d: %d px, %v", i, dim, err)
		}
	}
}
