//go:build !windows

package osnet

// RemoveFirewallRule does nothing: only Windows gets a firewall rule.
func RemoveFirewallRule() {}
