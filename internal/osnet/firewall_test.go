package osnet

import (
	"strings"
	"testing"
)

func TestFirewallScript(t *testing.T) {
	s := firewallScript("Whalescale")
	for _, want := range []string{
		"Get-NetFirewallRule -Name WhalescaleIn",
		"Set-NetFirewallRule -Name WhalescaleIn -InterfaceAlias 'Whalescale' -Direction Inbound -Action Allow -Profile Any -Enabled True",
		"New-NetFirewallRule -Name WhalescaleIn",
		"-InterfaceAlias 'Whalescale' -Direction Inbound -Action Allow -Profile Any",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	// The adapter name is a PowerShell string literal, quotes doubled.
	if s := firewallScript("it's"); !strings.Contains(s, "-InterfaceAlias 'it''s'") {
		t.Errorf("quote not escaped:\n%s", s)
	}
}
