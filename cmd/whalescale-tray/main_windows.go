package main

import (
	"context"
	"errors"
	"net/http"
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
	"github.com/k4ran909/whalescale/internal/version"
)

// maxPeers is how many devices the menu lists.
const maxPeers = 30

// updateEvery is how often the tray looks for a new release.
const updateEvery = 12 * time.Hour

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

	icons                                           map[string][]byte
	title, self, devices                            *systray.MenuItem
	start, connect, disconnect, dashboard, terminal *systray.MenuItem
	peers                                           []*systray.MenuItem
	lastColor                                       string

	// Updates: the version line, and the newest release once one is found.
	versionItem, checkItem, updateItem *systray.MenuItem
	latest                             string // a newer release's tag, or ""
	updating                           bool
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
	t.terminal = systray.AddMenuItem("Open terminal", "A terminal for 'ws' commands, showing 'ws status' (asks for administrator rights)")
	systray.AddSeparator()
	t.versionItem = systray.AddMenuItem("Whalescale "+version.Version, "The installed version")
	t.versionItem.Disable()
	t.updateItem = systray.AddMenuItem("Update Whalescale", "Download and install the new version (asks for administrator rights)")
	t.updateItem.Hide()
	t.checkItem = systray.AddMenuItem("Check for updates", "Look for a newer Whalescale release")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Exit", "Close this icon. Whalescale keeps this PC connected in the background (use Disconnect to stop it)")

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
	go t.clicks(t.terminal, func(view) {
		runElevated("cmd.exe", `/k cd /d "`+filepath.Dir(wsPath())+`" && ws status`, windows.SW_SHOWNORMAL)
	})
	go t.clicks(t.checkItem, func(view) { t.checkUpdate(true) })
	go t.clicks(t.updateItem, func(view) { t.update() })
	go func() {
		time.Sleep(30 * time.Second) // let sign-in finish first
		for {
			t.checkUpdate(false)
			time.Sleep(updateEvery)
		}
	}()
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
	showIf(t.terminal, !v.CanStart)
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// setVersionLine shows the installed version and, after it, what the
// update check says.
func (t *tray) setVersionLine(note string) {
	title := "Whalescale " + version.Version
	if note != "" {
		title += "  ·  " + note
	}
	t.versionItem.SetTitle(title)
}

// checkUpdate looks for a newer release. asked: the user clicked "Check for
// updates", so say what happened even when there's nothing new.
func (t *tray) checkUpdate(asked bool) {
	if _, ok := parseVersion(version.Version); !ok {
		if asked {
			t.setVersionLine("development build: no updates")
		}
		return
	}
	if asked {
		t.setVersionLine("checking…")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tag, err := latestRelease(ctx, httpClient, releasesAPI)
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case err != nil:
		if asked {
			t.setVersionLine("couldn't check for updates")
		}
	case newer(version.Version, tag):
		t.latest = tag
		t.updateItem.SetTitle("Update to " + tag)
		t.updateItem.Show()
		t.setVersionLine(tag + " is available")
	default:
		t.latest = ""
		t.updateItem.Hide()
		if asked {
			t.setVersionLine("up to date")
		} else {
			t.setVersionLine("")
		}
	}
}

// update downloads the newest installer, checks it against the release's
// checksums and runs it. The installer replaces the running version, keeps
// this PC on its network and starts the new tray icon.
func (t *tray) update() {
	t.mu.Lock()
	tag, busy := t.latest, t.updating
	if tag == "" || busy {
		t.mu.Unlock()
		return
	}
	t.updating = true
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.updating = false
		t.mu.Unlock()
	}()

	t.setVersionLine("downloading " + tag + "…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	path, err := downloadInstaller(ctx, httpClient, downloadURL, tag, os.TempDir())
	if err != nil {
		t.setVersionLine("update failed: " + trim(err.Error(), 60))
		return
	}
	t.setVersionLine("installing " + tag + "…")
	if err := runElevated(path, "/S /UPDATE", windows.SW_SHOWNORMAL); err != nil {
		os.Remove(path)
		t.setVersionLine(tag + " is available") // the administrator prompt was declined
	}
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
// Saying no is fine: nothing happens, and it returns an error.
func runElevated(file, args string, show int32) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	f, _ := windows.UTF16PtrFromString(file)
	a, _ := windows.UTF16PtrFromString(args)
	return windows.ShellExecute(0, verb, f, a, nil, show)
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
