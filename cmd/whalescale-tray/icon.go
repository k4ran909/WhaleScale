package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

var colors = map[string]color.RGBA{
	"green": {0x12, 0x80, 0x5c, 0xff},
	"amber": {0xc7, 0x7c, 0x00, 0xff},
	"grey":  {0x6b, 0x77, 0x82, 0xff},
}

// wave is the logo's stroke (web/src/App.tsx's Logo), sampled from its
// cubic curves in the 32-unit box.
var wave = func() [][2]float64 {
	type pt = [2]float64
	segs := [][4]pt{
		{{6, 19}, {9, 19}, {10, 16}, {13, 16}},
		{{13, 16}, {16, 16}, {17, 19}, {20, 19}},
		{{20, 19}, {23, 19}, {24, 16}, {26, 16}},
	}
	var out []pt
	for _, s := range segs {
		for i := 0; i <= 40; i++ {
			t := float64(i) / 40
			u := 1 - t
			x := u*u*u*s[0][0] + 3*u*u*t*s[1][0] + 3*u*t*t*s[2][0] + t*t*t*s[3][0]
			y := u*u*u*s[0][1] + 3*u*u*t*s[1][1] + 3*u*t*t*s[2][1] + t*t*t*s[3][1]
			out = append(out, pt{x, y})
		}
	}
	return out
}()

// draw renders the logo at size×size: a rounded square in c with the white
// wave, antialiased by sampling each pixel 4×4 times.
func draw(size int, c color.RGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	scale := 32 / float64(size)
	const n = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var inBox, onWave float64
			for sy := 0; sy < n; sy++ {
				for sx := 0; sx < n; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/n) * scale
					y := (float64(py) + (float64(sy)+0.5)/n) * scale
					if !inRoundedSquare(x, y, 32, 8) {
						continue
					}
					inBox++
					if nearWave(x, y, 1.6) {
						onWave++
					}
				}
			}
			if inBox == 0 {
				continue
			}
			f := onWave / inBox // share of the covered part that's white
			mix := func(a uint8) uint8 { return uint8(float64(a)*(1-f) + 255*f + 0.5) }
			img.SetNRGBA(px, py, color.NRGBA{mix(c.R), mix(c.G), mix(c.B), uint8(255*inBox/(n*n) + 0.5)})
		}
	}
	return img
}

func inRoundedSquare(x, y, side, r float64) bool {
	cx := math.Max(r, math.Min(side-r, x))
	cy := math.Max(r, math.Min(side-r, y))
	return x >= 0 && y >= 0 && x <= side && y <= side && math.Hypot(x-cx, y-cy) <= r
}

// nearWave: within half the stroke width (2.5 in the logo) of the curve,
// which gives round caps too.
func nearWave(x, y, half float64) bool {
	for i := 1; i < len(wave); i++ {
		if segDist(x, y, wave[i-1], wave[i]) <= half {
			return true
		}
	}
	return false
}

func segDist(x, y float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := 0.0
	if l := dx*dx + dy*dy; l > 0 {
		t = math.Max(0, math.Min(1, ((x-a[0])*dx+(y-a[1])*dy)/l))
	}
	return math.Hypot(x-(a[0]+t*dx), y-(a[1]+t*dy))
}

// icon returns a Windows .ico with the logo in color at 16, 32 and 48
// pixels. ICO files may hold PNG images (Windows Vista and later).
func icon(name string) []byte {
	sizes := []int{16, 32, 48}
	var pngs [][]byte
	for _, s := range sizes {
		var b bytes.Buffer
		png.Encode(&b, draw(s, colors[name]))
		pngs = append(pngs, b.Bytes())
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))}) // reserved, type icon, count
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		out.Write([]byte{byte(s), byte(s), 0, 0}) // width, height, palette, reserved
		binary.Write(&out, binary.LittleEndian, [2]uint16{1, 32})
		binary.Write(&out, binary.LittleEndian, [2]uint32{uint32(len(pngs[i])), uint32(offset)})
		offset += len(pngs[i])
	}
	for _, p := range pngs {
		out.Write(p)
	}
	return out.Bytes()
}
