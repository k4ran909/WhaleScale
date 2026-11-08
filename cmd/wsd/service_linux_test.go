package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/k4ran909/whalescale/internal/engine"
)

// The .deb and .rpm packages ship packaging/linux/wsd.service: it must be
// the unit 'wsd install-service' writes, for the packaged /usr/bin/wsd.
func TestPackagedUnitMatchesInstallService(t *testing.T) {
	want, err := os.ReadFile("../../packaging/linux/wsd.service")
	if err != nil {
		t.Fatal(err)
	}
	f := &flags{tunMode: "os", port: engine.DefaultPort, portmap: true}
	cmd := append([]string{"/usr/bin/wsd"}, f.serviceArgs()...)
	got := fmt.Sprintf(unitTemplate, strings.Join(cmd, " "))
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("packaging/linux/wsd.service differs from unitTemplate; it should be:\n%s", got)
	}
}
