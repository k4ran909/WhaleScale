package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/k4ran909/whalescale/internal/dnsserver"
	"github.com/k4ran909/whalescale/internal/filter"
)

// udp4 builds an IPv4 UDP packet (checksum left zero, as allowed).
func udp4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	pkt := make([]byte, 28+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	b, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var self4 = netip.MustParseAddr("100.64.0.1")

func TestParseDNSQuery(t *testing.T) {
	q := []byte("query")
	src, sport, msg, ok := parseDNSQuery(udp4(self4, MagicDNSAddr, 53001, 53, q))
	if !ok || src != self4 || sport != 53001 || !bytes.Equal(msg, q) {
		t.Fatalf("parse = %v %v %q %v", src, sport, msg, ok)
	}
	frag := udp4(self4, MagicDNSAddr, 53001, 53, q)
	binary.BigEndian.PutUint16(frag[6:8], 0x2000)
	tcp := udp4(self4, MagicDNSAddr, 53001, 53, q)
	tcp[9] = 6
	for name, pkt := range map[string][]byte{
		"other address": udp4(self4, netip.MustParseAddr("100.64.0.9"), 53001, 53, q),
		"other port":    udp4(self4, MagicDNSAddr, 53001, 5353, q),
		"tcp":           tcp,
		"fragment":      frag,
		"short":         {0x45, 0, 0},
		"ipv6":          append([]byte{0x60}, make([]byte, 60)...),
	} {
		if _, _, _, ok := parseDNSQuery(pkt); ok {
			t.Errorf("%s: taken as a MagicDNS query", name)
		}
	}
}

// checkIPv4 verifies a reply packet's header checksum and returns its
// fragment offset (bytes), more-fragments flag and payload.
func checkIPv4(t *testing.T, ip []byte) (int, bool, []byte) {
	t.Helper()
	if ip[0] != 0x45 || ip[9] != 17 || int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
		t.Fatalf("bad header % x", ip[:20])
	}
	if checksumFold(checksumAdd(0, ip[:20])) != 0xffff {
		t.Fatal("bad IPv4 header checksum")
	}
	if netip.AddrFrom4([4]byte(ip[12:16])) != MagicDNSAddr || netip.AddrFrom4([4]byte(ip[16:20])) != self4 {
		t.Fatal("wrong addresses")
	}
	ff := binary.BigEndian.Uint16(ip[4+2 : 8])
	return int(ff&0x1fff) * 8, ff&0x2000 != 0, ip[20:]
}

func TestDNSReply(t *testing.T) {
	for _, size := range []int{50, 1252, 1253, 4000} {
		msg := bytes.Repeat([]byte{0xab}, size)
		pkts := dnsReply(self4, 53001, msg, 1280, 99, tunHeadroom)
		var udp []byte
		for i, b := range pkts {
			ip := b[tunHeadroom:]
			if len(ip) > 1280 {
				t.Fatalf("size %d: packet %d is %d bytes, over the MTU", size, i, len(ip))
			}
			off, more, data := checkIPv4(t, ip)
			if off != len(udp) || more != (i < len(pkts)-1) {
				t.Fatalf("size %d: fragment %d at %d (more %v)", size, i, off, more)
			}
			udp = append(udp, data...)
		}
		// The reassembled datagram: ports, length, checksum, message.
		src4, dst4 := MagicDNSAddr.As4(), self4.As4()
		sum := checksumAdd(checksumAdd(0, src4[:]), dst4[:]) + 17 + uint32(len(udp))
		if checksumFold(checksumAdd(sum, udp)) != 0xffff {
			t.Fatalf("size %d: bad UDP checksum", size)
		}
		if binary.BigEndian.Uint16(udp[0:2]) != 53 || binary.BigEndian.Uint16(udp[2:4]) != 53001 ||
			int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) || !bytes.Equal(udp[8:], msg) {
			t.Fatalf("size %d: reassembled datagram wrong", size)
		}
		if want := (size + 8 + 1255) / 1256; len(pkts) != want {
			t.Fatalf("size %d: %d packets, want %d", size, len(pkts), want)
		}
	}
}

// fakeTUN hands out queued packets and records what's written to it.
type fakeTUN struct {
	in      [][]byte
	written chan []byte
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return MTU, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written <- bytes.Clone(b[offset:])
	}
	return len(bufs), nil
}
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := min(len(bufs), len(f.in))
	for i := 0; i < n; i++ {
		sizes[i] = copy(bufs[i][offset:], f.in[i])
	}
	f.in = f.in[n:]
	return n, nil
}

// A lookup the OS sends to MagicDNSAddr never reaches WireGuard; the
// answer comes back into the TUN.
func TestInterceptDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dns := dnsserver.New(log)
	dns.SetRecords("whale.internal", map[string][]netip.Addr{"laptop": {netip.MustParseAddr("100.64.0.7")}})
	dev := &fakeTUN{written: make(chan []byte, 4)}
	e := &Engine{ctx: ctx, log: log, dns: dns, tunDev: dev, dnsSem: make(chan struct{}, 4)}

	other := udp4(self4, netip.MustParseAddr("100.64.0.7"), 40000, 7000, []byte("app data"))
	dev.in = [][]byte{udp4(self4, MagicDNSAddr, 53001, 53, dnsQuery(t, "laptop.whale.internal.")), other}
	ft := &filteredTUN{Device: dev, f: filter.New(), intercept: e.interceptDNS}
	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	n, err := ft.Read(bufs, sizes, tunHeadroom)
	if err != nil || n != 2 || sizes[0] != 0 || sizes[1] != len(other) {
		t.Fatalf("Read = %d %v, sizes %v", n, err, sizes)
	}

	select {
	case reply := <-dev.written:
		_, more, data := checkIPv4(t, reply)
		if more || binary.BigEndian.Uint16(data[2:4]) != 53001 {
			t.Fatalf("reply to the wrong port or fragmented: % x", data[:8])
		}
		var m dnsmessage.Message
		if err := m.Unpack(data[8:]); err != nil || m.ID != 7 || len(m.Answers) != 1 ||
			m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{100, 64, 0, 7} {
			t.Fatalf("answer %+v, %v", m, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply written to the TUN")
	}
}
