package portmap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// fakeRouter speaks whichever of PCP, NAT-PMP and UPnP is enabled.
type fakeRouter struct {
	pcp, pmp, upnp bool
	external       netip.Addr
	badLocation    atomic.Bool // UPnP: advertise a description URL on another host

	pmpConn  *net.UDPConn
	ssdpConn *net.UDPConn
	http     *httptest.Server

	mu      sync.Mutex
	mapped  map[uint16]uint32 // external port -> lifetime
	deleted []string
}

func newFakeRouter(t *testing.T, pcp, pmp, upnp bool, external string) *fakeRouter {
	t.Helper()
	r := &fakeRouter{pcp: pcp, pmp: pmp, upnp: upnp, external: netip.MustParseAddr(external), mapped: map[uint16]uint32{}}
	var err error
	if r.pmpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	if r.ssdpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	r.http = httptest.NewServer(http.HandlerFunc(r.serveHTTP))
	t.Cleanup(func() { r.pmpConn.Close(); r.ssdpConn.Close(); r.http.Close() })
	go r.servePMP()
	go r.serveSSDP()
	return r
}

func (r *fakeRouter) config(port uint16) Config {
	return Config{Gateway: loopback, Local: loopback, Port: port,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PMPPort:    uint16(r.pmpConn.LocalAddr().(*net.UDPAddr).Port),
		SSDPTarget: r.ssdpConn.LocalAddr().(*net.UDPAddr).AddrPort()}
}

func (r *fakeRouter) servePMP() {
	buf := make([]byte, 1100)
	for {
		n, from, err := r.pmpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		switch {
		case req[0] == pcpVersion && !r.pcp:
			if r.pmp { // NAT-PMP routers reject PCP with version 0
				r.pmpConn.WriteToUDPAddrPort([]byte{0, 0x80 | req[1], 0, 1}, from)
			}
		case req[0] == pcpVersion && req[1] == 0: // ANNOUNCE
			resp := make([]byte, pcpHeaderLen)
			resp[0], resp[1] = pcpVersion, 0x80
			r.pmpConn.WriteToUDPAddrPort(resp, from)
		case req[0] == pcpVersion && req[1] == pcpOpMap && n >= pcpHeaderLen+pcpMapLen:
			life := binary.BigEndian.Uint32(req[4:8])
			m := req[pcpHeaderLen:]
			port := binary.BigEndian.Uint16(m[18:20])
			r.record("pcp", port, life)
			resp := make([]byte, pcpHeaderLen+pcpMapLen)
			resp[0], resp[1] = pcpVersion, 0x80|pcpOpMap
			binary.BigEndian.PutUint32(resp[4:8], life)
			copy(resp[pcpHeaderLen:], m[:18])
			binary.BigEndian.PutUint16(resp[pcpHeaderLen+18:], port)
			ext := r.external.As16()
			copy(resp[pcpHeaderLen+20:], ext[:])
			r.pmpConn.WriteToUDPAddrPort(resp, from)
		case req[0] == 0 && r.pmp && n == 2 && req[1] == 0:
			resp := make([]byte, 12)
			resp[1] = 128
			a := r.external.As4()
			copy(resp[8:], a[:])
			r.pmpConn.WriteToUDPAddrPort(resp, from)
		case req[0] == 0 && r.pmp && n == 12 && req[1] == 1:
			life := binary.BigEndian.Uint32(req[8:12])
			r.record("nat-pmp", binary.BigEndian.Uint16(req[6:8]), life)
			resp := make([]byte, 16)
			resp[1] = 129
			copy(resp[8:12], req[4:8])
			binary.BigEndian.PutUint32(resp[12:16], life)
			r.pmpConn.WriteToUDPAddrPort(resp, from)
		}
	}
}

func (r *fakeRouter) record(proto string, port uint16, life uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if life == 0 {
		delete(r.mapped, port)
		r.deleted = append(r.deleted, proto)
		return
	}
	r.mapped[port] = life
}

func (r *fakeRouter) serveSSDP() {
	buf := make([]byte, 2048)
	for {
		_, from, err := r.ssdpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if !r.upnp {
			continue
		}
		loc := r.http.URL + "/desc.xml"
		if r.badLocation.Load() {
			loc = "http://198.51.100.7/desc.xml"
		}
		r.ssdpConn.WriteToUDPAddrPort([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"+
			"LOCATION: "+loc+"\r\n\r\n"), from)
	}
}

func (r *fakeRouter) serveHTTP(w http.ResponseWriter, req *http.Request) {
	const svc = "urn:schemas-upnp-org:service:WANIPConnection:1"
	if req.URL.Path == "/desc.xml" {
		fmt.Fprintf(w, `<?xml version="1.0"?><root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceList><device><serviceList><service><serviceType>%s</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`, svc)
		return
	}
	action := req.Header.Get("SOAPAction")
	body, _ := io.ReadAll(req.Body)
	switch {
	case strings.HasSuffix(action, `#GetExternalIPAddress"`):
		fmt.Fprintf(w, `<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, r.external)
	case strings.HasSuffix(action, `#AddPortMapping"`):
		var port uint16
		fmt.Sscanf(string(body[strings.Index(string(body), "<NewExternalPort>")+len("<NewExternalPort>"):]), "%d", &port)
		r.record("upnp", port, 3600)
		fmt.Fprint(w, `<s:Envelope><s:Body/></s:Envelope>`)
	case strings.HasSuffix(action, `#DeletePortMapping"`):
		r.record("upnp", 0, 0)
		fmt.Fprint(w, `<s:Envelope><s:Body/></s:Envelope>`)
	default:
		http.Error(w, "unknown action", 500)
	}
}

func runOnce(t *testing.T, r *fakeRouter, port uint16) (*Client, *Mapping) {
	t.Helper()
	c := New(r.config(port), nil)
	m, err := c.mapOnce(context.Background())
	if err != nil {
		t.Fatalf("mapOnce: %v", err)
	}
	c.set(m, nil)
	return c, m
}

func TestProtocols(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pcp, pmp, upnp bool
		want           string
	}{
		{"pcp", true, true, true, "pcp"},
		{"nat-pmp only", false, true, false, "nat-pmp"},
		{"upnp only", false, false, true, "upnp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeRouter(t, tc.pcp, tc.pmp, tc.upnp, "203.0.113.9")
			c, m := runOnce(t, r, 41641)
			if m.Protocol != tc.want || m.External != netip.MustParseAddrPort("203.0.113.9:41641") {
				t.Fatalf("mapping = %+v", m)
			}
			r.mu.Lock()
			_, ok := r.mapped[41641]
			r.mu.Unlock()
			if !ok {
				t.Fatal("router has no mapping")
			}
			c.release()
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.deleted) != 1 || r.deleted[0] != tc.want {
				t.Fatalf("mapping not removed on shutdown: %v", r.deleted)
			}
		})
	}
}

func TestNoRouterSupport(t *testing.T) {
	r := newFakeRouter(t, false, false, false, "203.0.113.9")
	c := New(r.config(41641), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := c.mapOnce(ctx); err == nil {
		t.Fatal("expected failure with no protocol available")
	}
}

func TestUPnPIgnoresForeignDescriptionURL(t *testing.T) {
	r := newFakeRouter(t, false, false, true, "203.0.113.9")
	r.badLocation.Store(true)
	_, err := discoverIGD(context.Background(), loopback, r.config(1).SSDPTarget)
	if err == nil {
		t.Fatal("followed a description URL pointing away from the gateway")
	}
}

func TestProbe(t *testing.T) {
	r := newFakeRouter(t, false, true, true, "100.72.1.2") // CGNAT behind the router
	rep := Probe(context.Background(), r.config(41641))
	if rep.PCP || !rep.NATPMP || !rep.UPnP || rep.ExternalIP != netip.MustParseAddr("100.72.1.2") || !rep.DoubleNAT {
		t.Fatalf("probe = %+v", rep)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.mapped) != 0 {
		t.Fatal("probe created a mapping")
	}
}
