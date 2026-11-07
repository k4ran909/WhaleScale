// Package brand draws the Whalescale logo, the pixel whale in
// assets/brand, as images: the tray icon, the Windows .ico and the PNG
// icons are rendered from the same shapes as the SVG files.
package brand

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"sort"
	"strings"
)

// The logo's colours.
var (
	Navy  = color.NRGBA{0x1f, 0x2e, 0xa5, 0xff}
	Sky   = color.NRGBA{0x69, 0x89, 0xfa, 0xff}
	White = color.NRGBA{0xff, 0xff, 0xff, 0xff}
)

// Box is a region of the logo's coordinate space, like an SVG viewBox.
type Box struct{ X, Y, W, H float64 }

var (
	// Whale is the bare whale (logo.svg's viewBox).
	Whale = Box{48, 46, 306, 168}
	// AppIcon is the square around it (app-icon.svg's viewBox).
	AppIcon = Box{24, -46, 354, 354}
	// Icon is a square closer around the whale, for small icons: in a
	// 16-pixel tray icon the whale is only a dozen pixels wide.
	Icon = Box{43, -28, 316, 316}
)

// IconStyle is the app icon's look: the white whale on a rounded navy
// square.
var IconStyle = Style{Background: Navy, Radius: 0.22, Body: White, Accent: Sky}

// The shapes, exactly as in the SVG files (brand_test.go checks that).
var accentRects = [][4]float64{
	{57.38, 82.81, 13.925, 13.925},
	{127.005, 68.885, 13.925, 13.925},
	{99.155, 96.735, 13.925, 13.925},
	{154.855, 110.66, 13.925, 13.925},
	{127.005, 152.435, 13.925, 13.925},
}

const (
	spoutPath = "M71.305 54.96H85.23V68.885H99.155V82.81H140.93V96.735H127.005V110.66H140.93V124.585H154.855V138.51H168.78V152.435H140.93V138.51H113.08V96.735H85.23V82.81H71.305Z M140.93 54.96H154.855V82.81H140.93Z"
	bodyPath  = "M182.705 110.74H335.15C340.28 110.74 344.61 114.72 344.61 118.87C344.61 119.72 344.21 120.12 343.5 120.12H319.3554C284.983 120.12 280.9549 152.56 255.7449 152.56L242.1953 173.9402C282.1051 174.5145 308.177 161.4922 324.809 141.0517C329.8665 134.8362 333.766 129.8752 339.85 126.08C341.37 125.0612 342.43 126.3195 341.2 128.5C325.04 157.1473 303.4696 171.1076 275.3369 177.2099L265.2315 192.755C260.6654 199.779 252.2595 204.96 241.2912 204.96H232.2039C230.87 204.96 230.39 204.14 231.19 202.88L245.1103 180.3095H238.0621L230.6877 191.4469C225.12 199.86 215.3474 204.96 204.3887 204.96H190.0482C188.62 204.96 188.22 203.92 189.11 202.53L204.1536 178.5432C197.5264 177.1602 186.6417 175.7384 179.7371 173.0635C178.7282 172.5145 178.4936 170.9994 180.2108 170.3652C189.2247 171.0809 200.1766 172.8022 208.0294 172.9444L211.3998 166.4219H168.78V152.435H182.705V138.51H168.78V124.585H182.705Z M257.9115 132.9374a5.5336 5.5336 0 1 0 11.0672 0a5.5336 5.5336 0 1 0 -11.0672 0Z"
)

// Style says how to colour the logo.
type Style struct {
	// Background fills the box; a zero alpha leaves it transparent.
	Background color.NRGBA
	// Radius rounds the background's corners, as a share of its shorter
	// side (0.22 looks like an app icon).
	Radius float64
	// Body is the whale and its spout, Accent the five loose pixels.
	Body, Accent color.NRGBA
}

// Render draws box of the logo into a w×h image, scaled to fit and
// centred, antialiased.
func Render(w, h int, box Box, s Style) *image.NRGBA {
	scale := math.Min(float64(w)/box.W, float64(h)/box.H)
	ox := (float64(w) - box.W*scale) / 2
	oy := (float64(h) - box.H*scale) / 2
	toPx := func(polys [][]pt) [][]pt {
		out := make([][]pt, len(polys))
		for i, p := range polys {
			q := make([]pt, len(p))
			for j, v := range p {
				q[j] = pt{(v.x-box.X)*scale + ox, (v.y-box.Y)*scale + oy}
			}
			out[i] = q
		}
		return out
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	if s.Background.A != 0 {
		r := s.Radius * math.Min(box.W, box.H)
		paint(img, coverage(toPx([][]pt{roundedRect(box, r)}), w, h), s.Background)
	}
	var rects [][]pt
	for _, r := range accentRects {
		rects = append(rects, []pt{{r[0], r[1]}, {r[0] + r[2], r[1]}, {r[0] + r[2], r[1] + r[3]}, {r[0], r[1] + r[3]}})
	}
	paint(img, coverage(toPx(rects), w, h), s.Accent)
	paint(img, coverage(toPx(append(parsePath(spoutPath), parsePath(bodyPath)...)), w, h), s.Body)
	return img
}

// SVG returns box of the logo as an SVG document.
func SVG(box Box, s Style) string {
	fill := func(c color.NRGBA) string {
		f := fmt.Sprintf(`fill="#%02X%02X%02X"`, c.R, c.G, c.B)
		if c.A != 0xff {
			f += fmt.Sprintf(` fill-opacity="%.3g"`, float64(c.A)/255)
		}
		return f
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="%v %v %v %v">`, box.X, box.Y, box.W, box.H)
	if s.Background.A != 0 {
		r := s.Radius * math.Min(box.W, box.H)
		fmt.Fprintf(&b, `<rect x="%v" y="%v" width="%v" height="%v" rx="%.4g" %s/>`, box.X, box.Y, box.W, box.H, r, fill(s.Background))
	}
	fmt.Fprintf(&b, `<g %s>`, fill(s.Accent))
	for _, r := range accentRects {
		fmt.Fprintf(&b, `<rect x="%v" y="%v" width="%v" height="%v"/>`, r[0], r[1], r[2], r[3])
	}
	fmt.Fprintf(&b, `</g><g %s><path d="%s"/><path fill-rule="evenodd" d="%s"/></g></svg>`, fill(s.Body), spoutPath, bodyPath)
	b.WriteString("\n")
	return b.String()
}

// PNG encodes Render's image.
func PNG(w, h int, box Box, s Style) []byte {
	var b bytes.Buffer
	png.Encode(&b, Render(w, h, box, s))
	return b.Bytes()
}

// ICO returns a Windows icon holding the square box at each size, as PNG
// images (Windows Vista and later read those).
func ICO(box Box, s Style, sizes ...int) []byte {
	var pngs [][]byte
	for _, n := range sizes {
		pngs = append(pngs, PNG(n, n, box, s))
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))}) // reserved, type icon, count
	offset := 6 + 16*len(sizes)
	for i, n := range sizes {
		dim := byte(n) // 0 means 256
		if n >= 256 {
			dim = 0
		}
		out.Write([]byte{dim, dim, 0, 0}) // width, height, palette, reserved
		binary.Write(&out, binary.LittleEndian, [2]uint16{1, 32})
		binary.Write(&out, binary.LittleEndian, [2]uint32{uint32(len(pngs[i])), uint32(offset)})
		offset += len(pngs[i])
	}
	for _, p := range pngs {
		out.Write(p)
	}
	return out.Bytes()
}

// paint composites c over img wherever cov (0..1 per pixel) says.
func paint(img *image.NRGBA, cov []float64, c color.NRGBA) {
	for i, a := range cov {
		a = math.Min(1, a) * float64(c.A) / 255
		if a <= 0 {
			continue
		}
		d := img.Pix[i*4 : i*4+4]
		da := float64(d[3]) / 255
		oa := a + da*(1-a)
		mix := func(src uint8, dst uint8) uint8 {
			return uint8((float64(src)*a+float64(dst)*da*(1-a))/oa + 0.5)
		}
		d[0], d[1], d[2] = mix(c.R, d[0]), mix(c.G, d[1]), mix(c.B, d[2])
		d[3] = uint8(oa*255 + 0.5)
	}
}

// coverage returns how much of each pixel the polygons cover, filled
// even-odd (the eye is a hole in the body): several sample rows per
// pixel, each with exact horizontal coverage.
func coverage(polys [][]pt, w, h int) []float64 {
	const rows = 5
	cov := make([]float64, w*h)
	var xs []float64
	for py := 0; py < h; py++ {
		line := cov[py*w : (py+1)*w]
		for sy := 0; sy < rows; sy++ {
			y := float64(py) + (float64(sy)+0.5)/rows
			xs = xs[:0]
			for _, p := range polys {
				for i := range p {
					a, b := p[i], p[(i+1)%len(p)]
					if (a.y <= y) == (b.y <= y) {
						continue
					}
					xs = append(xs, a.x+(y-a.y)/(b.y-a.y)*(b.x-a.x))
				}
			}
			sort.Float64s(xs)
			for i := 0; i+1 < len(xs); i += 2 {
				span(line, xs[i], xs[i+1], 1.0/rows)
			}
		}
	}
	return cov
}

func span(line []float64, x0, x1, weight float64) {
	x0, x1 = math.Max(0, x0), math.Min(float64(len(line)), x1)
	for px := int(x0); px < len(line) && float64(px) < x1; px++ {
		if o := math.Min(x1, float64(px+1)) - math.Max(x0, float64(px)); o > 0 {
			line[px] += o * weight
		}
	}
}

func roundedRect(b Box, r float64) []pt {
	if r <= 0 {
		return []pt{{b.X, b.Y}, {b.X + b.W, b.Y}, {b.X + b.W, b.Y + b.H}, {b.X, b.Y + b.H}}
	}
	var out []pt
	corners := [4]pt{{b.X + b.W - r, b.Y + r}, {b.X + b.W - r, b.Y + b.H - r}, {b.X + r, b.Y + b.H - r}, {b.X + r, b.Y + r}}
	for i, c := range corners {
		start := -math.Pi/2 + float64(i)*math.Pi/2
		for j := 0; j <= 16; j++ {
			t := start + float64(j)/16*math.Pi/2
			out = append(out, pt{c.x + r*math.Cos(t), c.y + r*math.Sin(t)})
		}
	}
	return out
}
