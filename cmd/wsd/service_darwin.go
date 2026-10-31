package main

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"

	"github.com/k4ran909/whalescale/internal/clientstate"
)

const plistPath = "/Library/LaunchDaemons/com.whalescale.wsd.plist"

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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clientstate.SystemDir(), 0o700); err != nil {
		return err
	}
	var args strings.Builder
	for _, a := range append([]string{exe}, f.serviceArgs()...) {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", html.EscapeString(a))
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.whalescale.wsd</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>/var/log/wsd.log</string>
</dict>
</plist>
`
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("launchctl", "load", "-w", plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %v: %s", err, out)
	}
	fmt.Println("wsd service installed and started. Next: sudo ws login --server URL, then sudo ws up")
	return nil
}

func uninstallService() error {
	if err := needRoot(); err != nil {
		return err
	}
	exec.Command("launchctl", "unload", "-w", plistPath).Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Printf("wsd service removed. State is kept in %s.\n", clientstate.SystemDir())
	return nil
}
