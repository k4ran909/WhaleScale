package osnet

import (
	"fmt"
	"strings"
)

// FirewallRule names the Windows Firewall rule that lets mesh traffic in on
// Whalescale's adapter.
const FirewallRule = "WhalescaleIn"

// firewallScript is the PowerShell that creates the rule, or points an
// existing one at iface. Windows Firewall puts a new adapter in the Public
// profile and drops what arrives on it (ping included); Whalescale's packet
// filter already enforces the access policy on that adapter, so the rule
// lets everything in there and nowhere else.
func firewallScript(iface string) string {
	alias := "'" + strings.ReplaceAll(iface, "'", "''") + "'" // a PowerShell string literal
	return fmt.Sprintf(`if (Get-NetFirewallRule -Name %[1]s -ErrorAction SilentlyContinue) { `+
		`Set-NetFirewallRule -Name %[1]s -InterfaceAlias %[2]s -Direction Inbound -Action Allow -Profile Any -Enabled True } `+
		`else { New-NetFirewallRule -Name %[1]s -DisplayName 'Whalescale' `+
		`-Description 'Traffic from your Whalescale network; Whalescale enforces its access policy' `+
		`-InterfaceAlias %[2]s -Direction Inbound -Action Allow -Profile Any | Out-Null }`, FirewallRule, alias)
}
