package gateway

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	s := NewServer("Apps.Example.com.", nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for host, want := range map[string]string{
		"ha.apps.example.com":       "ha",
		"HA.apps.example.com:443":   "ha",
		"ha.apps.example.com.":      "ha",
		"a.b.apps.example.com":      "",
		"apps.example.com":          "",
		"ha.apps.example.com.evil":  "",
		"ha.otherapps.example.com":  "",
		"bad_name.apps.example.com": "",
	} {
		got, ok := s.Match(host)
		if got != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q, %v; want %q", host, got, ok, want)
		}
	}
}

// TestClientOnlyServesItsOwnExposures: a stream naming anything the node
// didn't expose is closed without touching the network.
func TestClientOnlyServesItsOwnExposures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			io.WriteString(c, "backend")
			c.Close()
		}
	}()
	port, _ := strconv.Atoi(ln.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):])

	c := NewClient("", "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.SetExposures(map[string]uint16{"ha": uint16(port)})

	try := func(header string) string {
		server, client := net.Pipe()
		go c.handle(client)
		server.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(server, header)
		b, _ := io.ReadAll(server)
		server.Close()
		return string(b)
	}
	if got := try("WSGW1 other\n"); got != "" {
		t.Fatalf("unexposed name got a response: %q", got)
	}
	if got := try("GET / HTTP/1.1\r\n\r\n"); got != "" {
		t.Fatalf("stream without a header got a response: %q", got)
	}
	select {
	case <-accepted:
		t.Fatal("the backend was dialed for a refused stream")
	default:
	}
	if got := try("WSGW1 ha\n"); got != "backend" {
		t.Fatalf("exposed name: got %q", got)
	}
}
