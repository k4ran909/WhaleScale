package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

func TestViewOf(t *testing.T) {
	now := time.Now()
	fresh := func(ps clientstate.PublicStatus) clientstate.PublicStatus {
		ps.Updated = now.Add(-time.Second)
		return ps
	}
	connected := fresh(clientstate.PublicStatus{State: "connected", Server: "https://ws.example.com",
		Name: "karan", Address: "100.64.0.1", Peers: []clientstate.PublicPeer{
			{Name: "nas", Address: "100.64.0.3", Online: false},
			{Name: "phone", Address: "100.64.0.4", Online: true, Path: "relay"},
			{Name: "laptop", Address: "100.64.0.2", Online: true, Path: "direct"},
		}})

	for name, tc := range map[string]struct {
		ps                                clientstate.PublicStatus
		err                               error
		color, title                      string
		start, connect, disconnect, peers bool
	}{
		"no status file": {err: errors.New("missing"), color: "grey", title: "isn't running", start: true},
		"stale":          {ps: clientstate.PublicStatus{State: "connected", Updated: now.Add(-time.Minute)}, color: "grey", title: "isn't running", start: true},
		"stopped":        {ps: fresh(clientstate.PublicStatus{State: "stopped"}), color: "grey", title: "isn't running", start: true},
		"not logged in":  {ps: fresh(clientstate.PublicStatus{State: "logged-out"}), color: "grey", title: "Not on a network"},
		"ws down":        {ps: fresh(clientstate.PublicStatus{State: "down", Server: "https://ws.example.com"}), color: "grey", title: "Disconnected", connect: true},
		"connecting":     {ps: fresh(clientstate.PublicStatus{State: "connecting"}), color: "amber", title: "Connecting", disconnect: true},
		"connected":      {ps: connected, color: "blue", title: "Connected", disconnect: true, peers: true},
	} {
		v := viewOf(tc.ps, tc.err, now)
		if v.Color != tc.color || !strings.Contains(v.Title, tc.title) || v.CanStart != tc.start ||
			v.CanConnect != tc.connect || v.CanDisconnect != tc.disconnect || (len(v.Peers) > 0) != tc.peers {
			t.Errorf("%s: %+v", name, v)
		}
		if len(v.Tooltip) > 127 || v.Tooltip == "" {
			t.Errorf("%s: tooltip %q", name, v.Tooltip)
		}
	}

	v := viewOf(connected, nil, now)
	if v.Self != "karan · 100.64.0.1" || v.Address != "100.64.0.1" || v.Devices != "Devices (2 of 3 online)" || v.Dashboard != "https://ws.example.com" {
		t.Fatalf("connected view %+v", v)
	}
	// Online devices first, by name; each copies its own address.
	var got []string
	for _, p := range v.Peers {
		got = append(got, p.Label+" = "+p.Address)
	}
	want := []string{
		"●  laptop  ·  100.64.0.2  (direct) = 100.64.0.2",
		"●  phone  ·  100.64.0.4  (relay) = 100.64.0.4",
		"○  nas  ·  offline = 100.64.0.3",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("peers:\n%s", strings.Join(got, "\n"))
	}
	if !strings.Contains(v.Tooltip, "2 of 3 devices online") {
		t.Fatalf("tooltip %q", v.Tooltip)
	}
	long := viewOf(fresh(clientstate.PublicStatus{State: "connecting", Error: strings.Repeat("x", 300)}), nil, now)
	if len(long.Tooltip) > 127 {
		t.Fatalf("tooltip is %d bytes", len(long.Tooltip))
	}
}

// The icon is a valid .ico: three PNG images of the whale on its colour.
func TestIcon(t *testing.T) {
	for name, want := range colors {
		ico := icon(name)
		var hdr [3]uint16
		binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr)
		if hdr != [3]uint16{0, 1, 3} {
			t.Fatalf("%s: header %v", name, hdr)
		}
		for i, size := range []int{16, 32, 48} {
			e := ico[6+16*i:]
			n := binary.LittleEndian.Uint32(e[8:12])
			off := binary.LittleEndian.Uint32(e[12:16])
			if int(e[0]) != size || int(off+n) > len(ico) {
				t.Fatalf("%s: entry %d: size %d, %d bytes at %d of %d", name, i, e[0], n, off, len(ico))
			}
			img, err := png.Decode(bytes.NewReader(ico[off : off+n]))
			if err != nil || img.Bounds().Dx() != size {
				t.Fatalf("%s: entry %d: %v", name, i, err)
			}
			// A point on the square, above the whale, has the colour; a
			// corner is transparent.
			r, g, b, a := img.At(size/2, size/5).RGBA()
			if uint8(r>>8) != want.R || uint8(g>>8) != want.G || uint8(b>>8) != want.B || a>>8 != 0xff {
				t.Fatalf("%s %dpx: body colour %d,%d,%d,%d", name, size, r>>8, g>>8, b>>8, a>>8)
			}
			if _, _, _, a := img.At(0, 0).RGBA(); a>>8 > 0x40 {
				t.Fatalf("%s %dpx: corner not transparent (alpha %d)", name, size, a>>8)
			}
		}
	}
}
