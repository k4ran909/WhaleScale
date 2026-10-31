package osnet

import "testing"

func TestDefaultGateway(t *testing.T) {
	gw, local, err := DefaultGateway()
	if err != nil {
		t.Skipf("no usable default gateway here: %v", err)
	}
	if !gw.Is4() || !local.Is4() || gw == local {
		t.Fatalf("gateway %v via local %v", gw, local)
	}
	t.Logf("default gateway %v, reached from %v", gw, local)
}
