package policy

import "testing"

func TestDeviceLimit(t *testing.T) {
	p, err := Parse([]byte(`{
		"groups": {"group:eng": ["ann", "ben"], "group:ops": ["ben"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"device_limits": {"*": 3, "group:eng": 5, "group:ops": 8, "ann": 1}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	for user, want := range map[string]int{
		"ann": 1, // her own entry wins, even below her group's
		"ben": 8, // the most generous of his groups
		"cat": 3, // everyone else
	} {
		if got, ok := p.DeviceLimit(user); !ok || got != want {
			t.Errorf("DeviceLimit(%s) = %d, %v; want %d", user, got, ok, want)
		}
	}
	if _, ok := AllowAll().DeviceLimit("ann"); ok {
		t.Error("no device_limits should mean no limit")
	}
	for name, src := range map[string]string{
		"negative":      `{"acls":[],"device_limits":{"*":-1}}`,
		"unknown group": `{"acls":[],"device_limits":{"group:nope":2}}`,
		"node selector": `{"acls":[],"device_limits":{"node:pc":2}}`,
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
