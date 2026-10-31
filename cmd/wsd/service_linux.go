package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

const unitPath = "/etc/systemd/system/wsd.service"

const unitTemplate = `[Unit]
Description=Whalescale mesh VPN agent
Documentation=https://github.com/k4ran909/WhaleScale
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=%s
Restart=on-failure
RestartSec=2
StateDirectory=whalescale
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

func runningAsService() bool         { return false }
func runService(args []string) error { return errors.New("not a service") }

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo wsd install-service)")
	}
	return nil
}

func installService(f *flags) error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd not found; run wsd under your init system manually")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clientstate.SystemDir(), 0o700); err != nil {
		return err
	}
	cmd := append([]string{exe}, f.serviceArgs()...)
	unit := fmt.Sprintf(unitTemplate, strings.Join(cmd, " "))
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "wsd"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	fmt.Println("wsd service installed and started. Next: sudo ws login --server URL, then sudo ws up")
	return nil
}

func uninstallService() error {
	if err := needRoot(); err != nil {
		return err
	}
	exec.Command("systemctl", "disable", "--now", "wsd").Run()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Printf("wsd service removed. State is kept in %s; delete it to forget this node.\n", clientstate.SystemDir())
	return nil
}
