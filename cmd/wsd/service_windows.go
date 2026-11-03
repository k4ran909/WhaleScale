package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/k4ran909/whalescale/internal/clientstate"
	"github.com/k4ran909/whalescale/internal/osnet"
)

const serviceName = "Whalescale"

func runningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct{ args []string }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	f, _ := parseFlags(h.args)
	logPath := filepath.Join(clientstate.SystemDir(), "wsd.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 10<<20 {
		os.Rename(logPath, logPath+".1")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return true, 1
	}
	defer logFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f, logFile) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				fmt.Fprintln(logFile, "wsd exited:", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func runService(args []string) error { return svc.Run(serviceName, handler{args: args}) }

// lockDownDir restricts the state directory to SYSTEM and Administrators:
// it holds the node's private keys and token, and ProgramData is readable
// by every user by default.
func lockDownDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("run this from an Administrator terminal")
	}
	return m, err
}

func installService(f *flags) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil && f.tunMode == "os" {
		return errors.New("wintun.dll must sit next to wsd.exe for OS TUN mode (download it from https://www.wintun.net/), or use --tun=userspace")
	}
	if err := lockDownDir(clientstate.SystemDir()); err != nil {
		return fmt.Errorf("secure %s: %w", clientstate.SystemDir(), err)
	}
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return errors.New("the service is already installed; run 'wsd uninstall-service' first")
	}
	s, err = m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "Whalescale mesh VPN agent",
		Description: "Connects this machine to your Whalescale network.",
		StartType:   mgr.StartAutomatic,
	}, f.serviceArgs()...)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 24*3600)
	if err := s.Start(); err != nil {
		return fmt.Errorf("installed, but starting failed: %w", err)
	}
	// 'ws' from any new terminal.
	dir := filepath.Dir(exe)
	if err := updateSystemPath(func(p string) (string, bool) { return pathWith(p, dir) }); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not add", dir, "to PATH:", err)
	}
	fmt.Println("Whalescale service installed and started. Next (as Administrator): ws login <join code from the dashboard>")
	return nil
}

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// updateSystemPath rewrites the machine-wide PATH and tells running programs
// (Explorer, so new terminals) that it changed.
func updateSystemPath(update func(string) (string, bool)) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, typ, err := k.GetStringValue("Path") // unexpanded: %SystemRoot% stays as it is
	if err != nil {
		return err
	}
	next, changed := update(cur)
	if !changed {
		return nil
	}
	if typ == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", next)
	} else {
		err = k.SetStringValue("Path", next)
	}
	if err != nil {
		return err
	}
	env, _ := windows.UTF16PtrFromString("Environment")
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x1a, 0x2
	var result uintptr
	sendMessageTimeout.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000,
		uintptr(unsafe.Pointer(&result)))
	return nil
}

var sendMessageTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

func uninstallService() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.New("the service is not installed")
	}
	defer s.Close()
	if st, err := s.Control(svc.Stop); err == nil {
		for i := 0; i < 40 && st.State != svc.Stopped; i++ {
			time.Sleep(250 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		updateSystemPath(func(p string) (string, bool) { return pathWithout(p, dir) })
	}
	osnet.RemoveFirewallRule()
	fmt.Printf("Whalescale service removed. State is kept in %s.\n", clientstate.SystemDir())
	return nil
}
