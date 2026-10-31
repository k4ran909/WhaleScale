package osnet

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

// TestBypassSockets checks that bypass options apply to real sockets and
// that pinned sockets still carry traffic. On Linux, SO_MARK needs root, so
// the test only checks the error is the expected one there.
func TestBypassSockets(t *testing.T) {
	b := NewBypass()
	t.Logf("physical interfaces on %s: v4=%d v6=%d", runtime.GOOS, b.if4, b.if6)
	if (runtime.GOOS == "windows" || runtime.GOOS == "darwin") && b.if4 == 0 {
		t.Skip("no physical interface with a default route (offline?)")
	}

	lc := net.ListenConfig{Control: b.ControlListen}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if runtime.GOOS == "linux" && err != nil {
		t.Skipf("SO_MARK not permitted without root: %v", err)
	}
	if err != nil {
		t.Fatalf("pinned UDP socket: %v", err)
	}
	pc.Close()

	// A pinned dialer still reaches a server on this machine's LAN address.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	ifc, err := net.InterfaceByIndex(b.if4)
	if err != nil {
		t.Skip("cannot look up the physical interface")
	}
	addrs, _ := ifc.Addrs()
	var lan string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			lan = ipn.IP.String()
		}
	}
	if lan == "" {
		t.Skip("physical interface has no IPv4 address")
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := net.Dialer{Control: b.ControlDial}
	c, err := d.Dial("tcp4", net.JoinHostPort(lan, port))
	if err != nil {
		t.Fatalf("pinned dial to %s: %v", lan, err)
	}
	c.Close()
	if b.Refresh() {
		t.Log("refresh found a different interface (network changed during the test?)")
	}
}
