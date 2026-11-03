// Command whalescale-tray is Whalescale's icon in the Windows notification
// area: green when this PC is connected, grey when not, with the network's
// devices in its menu and Connect, Disconnect and Open dashboard.
//
// It runs as the signed-in user, who may not use wsd's local API, so it
// reads the status wsd publishes (clientstate.PublicStatusPath) and runs
// 'ws up' and 'ws down' through a UAC prompt.
package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

// staleAfter: wsd rewrites its status every 2 s, so an older one means it
// isn't running.
const staleAfter = 10 * time.Second

// view is what the tray shows.
type view struct {
	Color   string // "green", "amber" or "grey"
	Title   string // the menu's first line
	Tooltip string
	// Self is this PC's line ("karan · 100.64.0.1"); Address is copied.
	Self, Address string
	// Which actions make sense now.
	CanStart, CanConnect, CanDisconnect bool
	Dashboard                           string
	Devices                             string // "Devices (2 of 3 online)"
	Peers                               []peerLine
}

type peerLine struct {
	Label, Address string
}

func viewOf(ps clientstate.PublicStatus, err error, now time.Time) view {
	v := view{Color: "grey", Dashboard: ps.Server}
	switch {
	case err != nil || now.Sub(ps.Updated) > staleAfter || ps.State == "stopped":
		v.Title, v.Tooltip, v.CanStart = "Whalescale isn't running", "Whalescale: the service isn't running", true
		v.Dashboard = ""
		return v
	case ps.State == "logged-out":
		v.Title = "Not on a network yet"
		v.Tooltip = "Whalescale: not on a network yet. Run 'ws login <join code>' as Administrator."
		return v
	case ps.State == "down":
		v.Title, v.Tooltip, v.CanConnect = "Disconnected", "Whalescale: disconnected", true
		return v
	case ps.State == "connecting":
		v.Color, v.Title, v.Tooltip, v.CanDisconnect = "amber", "Connecting…", "Whalescale: connecting…", true
		if ps.Error != "" {
			v.Tooltip = trim("Whalescale: can't connect: "+ps.Error, 127)
		}
		return v
	}
	v.Color, v.Title, v.CanDisconnect = "green", "Connected", true
	v.Self, v.Address = ps.Name, ps.Address
	if ps.Address != "" {
		v.Self = ps.Name + " · " + ps.Address
	}
	peers := append([]clientstate.PublicPeer(nil), ps.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online
		}
		return peers[i].Name < peers[j].Name
	})
	online := 0
	for _, p := range peers {
		label := "○  " + p.Name + "  ·  offline"
		if p.Online {
			online++
			label = "●  " + p.Name + "  ·  " + p.Address
			if p.Path != "" && p.Path != "none" {
				label += "  (" + p.Path + ")"
			}
		}
		v.Peers = append(v.Peers, peerLine{Label: label, Address: p.Address})
	}
	v.Devices = fmt.Sprintf("Devices (%d of %d online)", online, len(peers))
	v.Tooltip = trim(fmt.Sprintf("Whalescale: connected as %s, %d of %d devices online", v.Self, online, len(peers)), 127)
	return v
}

// trim cuts s to at most n bytes, ellipsis included and never mid-character
// (Windows caps tooltips at 127 characters).
func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	cut := 0
	for i := range s { // i is each character's starting byte
		if i+len(ellipsis) > n {
			break
		}
		cut = i
	}
	return s[:cut] + ellipsis
}
