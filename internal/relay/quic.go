package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/k4ran909/whalescale/internal/key"
)

// QUIC transport. A client opens one connection, sends "Bearer <token>\n"
// on a first stream and waits for "OK\n". Frames then travel as QUIC
// datagrams; one too large for a datagram (path MTU) goes on that stream
// instead, as a 4-byte length and the frame. The server's certificate is
// self-signed and pinned: its SHA-256 travels in the network map, so this
// needs no public CA and works when HTTPS is terminated by a proxy.

const quicALPN = "whalescale-relay"

func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 20 * time.Second, MaxIdleTimeout: 60 * time.Second}
}

// NewQUICCert makes a self-signed certificate for the QUIC relay, as PEM
// (certificate then key).
func NewQUICCert() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "whalescale relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0), // pinned, so expiry adds nothing
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"whalescale-relay"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	return out.Bytes(), nil
}

// ParseQUICCert loads a NewQUICCert PEM and returns it with its pin.
func ParseQUICCert(pemData []byte) (tls.Certificate, []byte, error) {
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return cert, sum[:], nil
}

// ServeQUIC accepts QUIC relay connections on pc until ctx is done.
func (s *Server) ServeQUIC(ctx context.Context, pc net.PacketConn, cert tls.Certificate) error {
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicALPN},
		MinVersion: tls.VersionTLS13}, quicConfig())
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close(); tr.Close() }()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleQUIC(conn)
	}
}

func (s *Server) handleQUIC(conn *quic.Conn) {
	actx, cancel := context.WithTimeout(conn.Context(), 10*time.Second)
	st, err := conn.AcceptStream(actx)
	cancel()
	if err != nil {
		conn.CloseWithError(1, "no auth stream")
		return
	}
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(st, 4096)
	line, err := br.ReadString('\n')
	tok, ok := bearer(strings.TrimSpace(line))
	var k key.Public
	if err == nil && ok {
		k, err = s.auth(conn.Context(), tok)
	}
	if err != nil || !ok || k.IsZero() {
		conn.CloseWithError(2, "unauthorized")
		return
	}
	st.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(st, "OK\n"); err != nil {
		conn.CloseWithError(1, "")
		return
	}
	w := &quicWriter{conn: conn, stream: st}
	c := &client{key: k, out: make(chan []byte, sendQueue), kick: func() { conn.CloseWithError(0, "replaced by newer connection") }}
	s.register(c)
	defer func() {
		s.unregister(c)
		conn.CloseWithError(0, "")
	}()
	ctx := conn.Context()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-c.out:
				if err := w.send(m); err != nil {
					conn.CloseWithError(1, "write failed")
					return
				}
			}
		}
	}()
	go readStreamFrames(br, func(f []byte) { s.route(k, f) })
	for {
		d, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		s.route(k, d)
	}
}

// quicWriter sends a frame as a datagram, or on the stream if too large.
type quicWriter struct {
	conn   *quic.Conn
	mu     sync.Mutex
	stream io.Writer
}

func (w *quicWriter) send(frame []byte) error {
	err := w.conn.SendDatagram(frame)
	var tooLarge *quic.DatagramTooLargeError
	if err == nil || !errors.As(err, &tooLarge) {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	hdr := binary.BigEndian.AppendUint32(nil, uint32(len(frame)))
	if _, err := w.stream.Write(hdr); err != nil {
		return err
	}
	_, err = w.stream.Write(frame)
	return err
}

// readStreamFrames reads length-prefixed frames until the stream ends.
func readStreamFrames(r io.Reader, handle func([]byte)) {
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		if n > MaxPacket+32 {
			return
		}
		f := make([]byte, n)
		if _, err := io.ReadFull(r, f); err != nil {
			return
		}
		handle(f)
	}
}

func pinnedTLS(pin []byte) *tls.Config {
	return &tls.Config{
		NextProtos: []string{quicALPN}, MinVersion: tls.VersionTLS13, ServerName: "whalescale-relay",
		// The chain is checked by pin instead of by a CA.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !bytes.Equal(sum[:], pin) {
				return errors.New("relay certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
}

func (c *Client) sessionQUIC(ctx context.Context) error {
	listen := c.listenUDP
	if listen == nil {
		listen = func() (net.PacketConn, error) { return net.ListenPacket("udp4", ":0") }
	}
	pc, err := listen()
	if err != nil {
		return err
	}
	defer pc.Close()
	addr, err := net.ResolveUDPAddr("udp4", c.quicAddr)
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := tr.Dial(dctx, addr, pinnedTLS(c.quicPin), quicConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(dctx)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(st, "Bearer "+c.token+"\n"); err != nil {
		return err
	}
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(st, 4096)
	if line, err := br.ReadString('\n'); err != nil || line != "OK\n" {
		return fmt.Errorf("relay refused the connection: %v", err)
	}
	st.SetReadDeadline(time.Time{})
	c.setConnected(true, "quic")
	c.log.Info("relay connected", "addr", c.quicAddr, "transport", "quic")

	sctx := conn.Context()
	w := &quicWriter{conn: conn, stream: st}
	go func() {
		for {
			select {
			case <-ctx.Done():
				conn.CloseWithError(0, "")
				return
			case <-sctx.Done():
				return
			case b := <-c.send:
				if err := w.send(b); err != nil {
					conn.CloseWithError(1, "write failed")
					return
				}
			}
		}
	}()
	deliver := func(f []byte) {
		if len(f) < 32 {
			return
		}
		select {
		case c.recv <- Packet{Src: key.Public(f[:32]), Data: f[32:]}:
		default:
		}
	}
	go readStreamFrames(br, deliver)
	for {
		d, err := conn.ReceiveDatagram(sctx)
		if err != nil {
			return err
		}
		deliver(d)
	}
}

// ProbeQUIC completes a QUIC handshake with a relay and checks its pinned
// certificate, without authenticating (for 'whalescale doctor').
func ProbeQUIC(ctx context.Context, addr string, pin []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, pinnedTLS(pin), quicConfig())
	if err != nil {
		return err
	}
	return conn.CloseWithError(0, "")
}
