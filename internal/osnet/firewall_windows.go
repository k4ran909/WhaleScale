package osnet

// RemoveFirewallRule deletes the rule apply creates (on uninstall).
func RemoveFirewallRule() {
	run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Remove-NetFirewallRule -Name "+FirewallRule+" -ErrorAction SilentlyContinue")
}
