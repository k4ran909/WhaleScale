package brand

import (
	"fmt"
	"math"
	"strconv"
)

type pt struct{ x, y float64 }

// parsePath flattens SVG path data into closed polygons, one per subpath.
// It knows the commands the logo uses and their relatives: M L H V C A Z.
func parsePath(d string) [][]pt {
	p := pathScanner{s: d}
	var polys [][]pt
	var cur []pt
	var pos, start pt
	cmd := byte(0)
	flush := func() {
		if len(cur) > 2 {
			polys = append(polys, cur)
		}
		cur = nil
	}
	for {
		if c, ok := p.command(); ok {
			cmd = c
		} else if p.done() {
			break
		} else if cmd == 0 {
			panic(fmt.Sprintf("brand: path data starts without a command at %d", p.i))
		}
		rel := cmd >= 'a'
		at := func(x, y float64) pt {
			if rel {
				return pt{pos.x + x, pos.y + y}
			}
			return pt{x, y}
		}
		switch cmd | 0x20 {
		case 'm':
			flush()
			pos = at(p.num(), p.num())
			start = pos
			cur = []pt{pos}
			cmd = 'L' + (cmd - 'M') // further pairs are lines
		case 'l':
			pos = at(p.num(), p.num())
			cur = append(cur, pos)
		case 'h':
			x := p.num()
			if rel {
				x += pos.x
			}
			pos = pt{x, pos.y}
			cur = append(cur, pos)
		case 'v':
			y := p.num()
			if rel {
				y += pos.y
			}
			pos = pt{pos.x, y}
			cur = append(cur, pos)
		case 'c':
			c1 := at(p.num(), p.num())
			c2 := at(p.num(), p.num())
			end := at(p.num(), p.num())
			for i := 1; i <= 24; i++ {
				t := float64(i) / 24
				u := 1 - t
				cur = append(cur, pt{
					u*u*u*pos.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*end.x,
					u*u*u*pos.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*end.y,
				})
			}
			pos = end
		case 'a':
			rx, ry, rot := p.num(), p.num(), p.num()
			large, sweep := p.flag(), p.flag()
			end := at(p.num(), p.num())
			cur = append(cur, arc(pos, end, rx, ry, rot, large, sweep)...)
			pos = end
		case 'z':
			pos = start
			flush()
			cmd = 0
		default:
			panic(fmt.Sprintf("brand: unsupported path command %q", cmd))
		}
	}
	flush()
	return polys
}

// arc flattens an SVG elliptical arc (SVG 1.1, appendix F.6.5), ending
// at to.
func arc(from, to pt, rx, ry, rotDeg float64, large, sweep bool) []pt {
	if rx == 0 || ry == 0 {
		return []pt{to}
	}
	rx, ry = math.Abs(rx), math.Abs(ry)
	phi := rotDeg * math.Pi / 180
	cos, sin := math.Cos(phi), math.Sin(phi)
	dx, dy := (from.x-to.x)/2, (from.y-to.y)/2
	x1 := cos*dx + sin*dy
	y1 := -sin*dx + cos*dy
	if l := x1*x1/(rx*rx) + y1*y1/(ry*ry); l > 1 {
		rx, ry = rx*math.Sqrt(l), ry*math.Sqrt(l)
	}
	num := rx*rx*ry*ry - rx*rx*y1*y1 - ry*ry*x1*x1
	den := rx*rx*y1*y1 + ry*ry*x1*x1
	k := math.Sqrt(math.Max(0, num/den))
	if large == sweep {
		k = -k
	}
	cx1, cy1 := k*rx*y1/ry, -k*ry*x1/rx
	cx := cos*cx1 - sin*cy1 + (from.x+to.x)/2
	cy := sin*cx1 + cos*cy1 + (from.y+to.y)/2
	angle := func(ux, uy, vx, vy float64) float64 {
		return math.Atan2(ux*vy-uy*vx, ux*vx+uy*vy)
	}
	t1 := angle(1, 0, (x1-cx1)/rx, (y1-cy1)/ry)
	dt := angle((x1-cx1)/rx, (y1-cy1)/ry, (-x1-cx1)/rx, (-y1-cy1)/ry)
	if !sweep && dt > 0 {
		dt -= 2 * math.Pi
	} else if sweep && dt < 0 {
		dt += 2 * math.Pi
	}
	const steps = 32
	out := make([]pt, 0, steps)
	for i := 1; i <= steps; i++ {
		t := t1 + dt*float64(i)/steps
		ex, ey := rx*math.Cos(t), ry*math.Sin(t)
		out = append(out, pt{cos*ex - sin*ey + cx, sin*ex + cos*ey + cy})
	}
	out[len(out)-1] = to
	return out
}

type pathScanner struct {
	s string
	i int
}

func (p *pathScanner) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == ',' || p.s[p.i] == '\n' || p.s[p.i] == '\t' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *pathScanner) done() bool { p.skip(); return p.i >= len(p.s) }

func (p *pathScanner) command() (byte, bool) {
	p.skip()
	if p.i < len(p.s) {
		if c := p.s[p.i]; (c|0x20) >= 'a' && (c|0x20) <= 'z' && c != 'e' && c != 'E' {
			p.i++
			return c, true
		}
	}
	return 0, false
}

// flag reads an arc flag, which may be written without a separator.
func (p *pathScanner) flag() bool {
	p.skip()
	if p.i >= len(p.s) || (p.s[p.i] != '0' && p.s[p.i] != '1') {
		panic(fmt.Sprintf("brand: bad arc flag at %d", p.i))
	}
	p.i++
	return p.s[p.i-1] == '1'
}

func (p *pathScanner) num() float64 {
	p.skip()
	j := p.i
	if j < len(p.s) && (p.s[j] == '-' || p.s[j] == '+') {
		j++
	}
	dot := false
	for j < len(p.s) {
		c := p.s[j]
		switch {
		case c >= '0' && c <= '9':
		case c == '.' && !dot:
			dot = true
		case (c == 'e' || c == 'E') && j+1 < len(p.s):
			j++
			if p.s[j] == '-' || p.s[j] == '+' {
				j++
			}
			continue
		default:
			goto end
		}
		j++
	}
end:
	v, err := strconv.ParseFloat(p.s[p.i:j], 64)
	if err != nil {
		panic(fmt.Sprintf("brand: bad number %q at %d", p.s[p.i:j], p.i))
	}
	p.i = j
	return v
}
