package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

// maxPeers is how many devices the menu lists.
const maxPeers = 30

func main() {
	// One icon per session: the installer starts it, and so does sign-in.
	if _, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Local\WhalescaleTray`)); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return
	}
	systray.Run(onReady, func() {})
}

type tray struct {
	mu   sync.Mutex
	view view

	icons                                          map[string][]byte
	title, self, devices                           *systray.MenuItem
	start, connect, disconnect, dashboard, details *systray.MenuItem
	peers                                          []*systray.MenuItem
	lastColor                                      string
}

func onReady() {
	t := &tray{icons: map[string][]byte{}}
	for name := range colors {
		t.icons[name] = icon(name)
	}
	systray.SetIcon(t.icons["grey"])
	systray.SetTooltip("Whalescale")

	t.title = systray.AddMenuItem("Whalescale", "")
	t.title.Disable()
	t.self = systray.AddMenuItem("", "Copy this PC's address")
	t.devices = systray.AddMenuItem("Devices", "The other devices on your network: click one to copy its address")
	for i := 0; i < maxPeers; i++ {
		p := t.devices.AddSubMenuItem("", "Copy this device's address")
		p.Hide()
		t.peers = append(t.peers, p)
	}
	systray.AddSeparator()
	t.start = systray.AddMenuItem("Start Whalescale", "Start the Whalescale service (asks for administrator rights)")
	t.connect = systray.AddMenuItem("Connect", "Connect this PC to your network (asks for administrator rights)")
	t.disconnect = systray.AddMenuItem("Disconnect", "Disconnect this PC from your network (asks for administrator rights)")
	t.dashboard = systray.AddMenuItem("Open dashboard", "Open your Whalescale dashboard in the browser")
	t.details = systray.AddMenuItem("Status details…", "Show 'ws status' in a terminal (asks for administrator rights)")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Hide this icon", "Close the tray icon; Whalescale keeps running")

	t.refresh()
	go func() {
		for range time.Tick(2 * time.Second) {
			t.refresh()
		}
	}()
	go t.clicks(t.self, func(v view) { copyText(v.Address) })
	go t.clicks(t.start, func(view) { runElevated("sc.exe", "start Whalescale", windows.SW_HIDE) })
	go t.clicks(t.connect, func(view) { runElevated(wsPath(), "up", windows.SW_HIDE) })
	go t.clicks(t.disconnect, func(view) { runElevated(wsPath(), "down", windows.SW_HIDE) })
	go t.clicks(t.dashboard, func(v view) { open(v.Dashboard) })
	go t.clicks(t.details, func(view) { runElevated("cmd.exe", `/k "`+wsPath()+`" status`, windows.SW_SHOWNORMAL) })
	for i, p := range t.peers {
		go t.clicks(p, func(v view) {
			if i < len(v.Peers) {
				copyText(v.Peers[i].Address)
			}
		})
	}
	go func() {
		<-quit.ClickedCh
		systray.Quit()
	}()
}

// clicks runs do with the current view each time item is clicked.
func (t *tray) clicks(item *systray.MenuItem, do func(view)) {
	for range item.ClickedCh {
		t.mu.Lock()
		v := t.view
		t.mu.Unlock()
		do(v)
	}
}

// statusPath is where wsd publishes its status (WHALESCALE_STATUS_FILE
// overrides it, for testing).
func statusPath() string {
	if p := os.Getenv("WHALESCALE_STATUS_FILE"); p != "" {
		return p
	}
	return clientstate.PublicStatusPath()
}

func (t *tray) refresh() {
	ps, err := clientstate.ReadPublicStatus(statusPath())
	v := viewOf(ps, err, time.Now())
	t.mu.Lock()
	t.view = v
	t.mu.Unlock()

	if v.Color != t.lastColor {
		systray.SetIcon(t.icons[v.Color])
		t.lastColor = v.Color
	}
	systray.SetTooltip(v.Tooltip)
	t.title.SetTitle(v.Title)
	showIf(t.self, v.Self != "")
	t.self.SetTitle("This PC: " + v.Self)
	showIf(t.devices, v.Devices != "")
	t.devices.SetTitle(v.Devices)
	for i, p := range t.peers {
		if i < len(v.Peers) {
			p.SetTitle(v.Peers[i].Label)
			p.Show()
		} else {
			p.Hide()
		}
	}
	showIf(t.start, v.CanStart)
	showIf(t.connect, v.CanConnect)
	showIf(t.disconnect, v.CanDisconnect)
	showIf(t.dashboard, v.Dashboard != "")
	showIf(t.details, !v.CanStart)
}

func showIf(item *systray.MenuItem, show bool) {
	if show {
		item.Show()
	} else {
		item.Hide()
	}
}

// wsPath is ws.exe next to this program.
func wsPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "ws.exe"
	}
	return filepath.Join(filepath.Dir(exe), "ws.exe")
}

// runElevated runs a program as Administrator: Windows asks the user first.
// Saying no is fine: nothing happens.
func runElevated(file, args string, show int32) {
	verb, _ := windows.UTF16PtrFromString("runas")
	f, _ := windows.UTF16PtrFromString(file)
	a, _ := windows.UTF16PtrFromString(args)
	windows.ShellExecute(0, verb, f, a, nil, show)
}

func open(url string) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return
	}
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

// copyText puts s on the clipboard, through clip.exe (part of Windows).
func copyText(s string) {
	if s == "" {
		return
	}
	cmd := exec.Command("clip.exe")
	cmd.Stdin = strings.NewReader(s)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Run()
}
