// Package nodeauth proves a request comes from the machine that owns a
// machine key, without sending a reusable secret.
//
// The server has an X25519 key; clients learn its public half when they
// log in (over TLS). Each request carries, instead of the node token, a
// proof: an HMAC keyed by the X25519 secret between the machine's key and
// the server's, over the method, the server it is meant for, the path, a
// timestamp and a random nonce. Anything that sees the header (a proxy's
// log, a debugging dump, a TLS-intercepting middlebox) learns nothing it
// can use: the proof is for that one request, expires, and the server
// refuses to see a nonce twice.
//
//	Authorization: WS-Machine v1 <machine key>,<authority>,<unix time>,<nonce>,<mac>
package nodeauth

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scheme starts every proof header.
const Scheme = "WS-Machine v1 "

// MaxSkew is how far a proof's time may be from the server's clock.
const MaxSkew = 5 * time.Minute

var b64 = base64.RawURLEncoding

// macKey derives the HMAC key from the X25519 secret.
func macKey(shared []byte) []byte {
	h := sha256.Sum256(append([]byte("whalescale node auth v1\x00"), shared...))
	return h[:]
}

func mac(key []byte, method, authority, path string, ts int64, nonce, machine []byte) []byte {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s\n%s\n%s\n%d\n%x\n%x", method, authority, path, ts, nonce, machine)
	return m.Sum(nil)
}

// Signer makes proofs for one machine and one server.
type Signer struct {
	machine []byte // public key
	key     []byte // HMAC key
}

// NewSigner takes the machine's X25519 private key and the server's public
// key, both base64 (standard encoding, as stored in client state).
func NewSigner(machinePriv, serverPub string) (*Signer, error) {
	pb, err := base64.StdEncoding.DecodeString(machinePriv)
	if err != nil {
		return nil, fmt.Errorf("machine key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(pb)
	if err != nil {
		return nil, fmt.Errorf("machine key: %w", err)
	}
	sb, err := base64.StdEncoding.DecodeString(serverPub)
	if err != nil {
		return nil, fmt.Errorf("server key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(sb)
	if err != nil {
		return nil, fmt.Errorf("server key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return &Signer{machine: priv.PublicKey().Bytes(), key: macKey(shared)}, nil
}

// Header returns an Authorization value proving this machine sent a
// request with this method to path on authority (the server's host[:port]
// as the client addresses it).
func (s *Signer) Header(method, authority, path string) string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	ts := time.Now().Unix()
	m := mac(s.key, method, authority, path, ts, nonce, s.machine)
	return Scheme + strings.Join([]string{b64.EncodeToString(s.machine), authority,
		strconv.FormatInt(ts, 10), hex.EncodeToString(nonce), b64.EncodeToString(m)}, ",")
}

// IsProof reports whether an Authorization value is a proof (rather than
// a bearer token).
func IsProof(h string) bool { return strings.HasPrefix(h, Scheme) }

// Verifier checks proofs with the server's private key and remembers
// nonces so a proof works once.
type Verifier struct {
	priv        *ecdh.PrivateKey
	authorities []string

	mu   sync.Mutex
	seen map[string]time.Time
	next time.Time // next sweep of seen
}

// NewVerifier takes the server's X25519 private key and the authorities
// (host[:port]) proofs may name: this server's, as clients address it.
func NewVerifier(priv *ecdh.PrivateKey, authorities []string) *Verifier {
	var as []string
	for _, a := range authorities {
		as = append(as, Authority(a))
	}
	return &Verifier{priv: priv, authorities: as, seen: map[string]time.Time{}}
}

// Errors from Verify.
var (
	ErrMalformed = errors.New("malformed machine proof")
	ErrBadProof  = errors.New("machine proof doesn't verify")
	ErrStale     = errors.New("machine proof expired (is this machine's clock right?)")
	ErrReplayed  = errors.New("machine proof already used")
	ErrElsewhere = errors.New("machine proof is for another server")
)

// Verify checks a proof for a request with this method and path, and
// returns the machine's public key (standard base64, as stored for nodes).
func (v *Verifier) Verify(header, method, path string, now time.Time) (string, error) {
	rest, ok := strings.CutPrefix(header, Scheme)
	if !ok {
		return "", ErrMalformed
	}
	// Commas can't occur in a host, a number, hex or URL-safe base64.
	parts := strings.Split(rest, ",")
	if len(parts) != 5 {
		return "", ErrMalformed
	}
	machine, err1 := b64.DecodeString(parts[0])
	authority := parts[1]
	ts, err2 := strconv.ParseInt(parts[2], 10, 64)
	nonce, err3 := hex.DecodeString(parts[3])
	got, err4 := b64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(nonce) != 16 {
		return "", ErrMalformed
	}
	if !slices.Contains(v.authorities, authority) {
		return "", ErrElsewhere
	}
	if d := now.Sub(time.Unix(ts, 0)); d > MaxSkew || d < -MaxSkew {
		return "", ErrStale
	}
	pub, err := ecdh.X25519().NewPublicKey(machine)
	if err != nil {
		return "", ErrMalformed
	}
	shared, err := v.priv.ECDH(pub)
	if err != nil {
		return "", ErrBadProof
	}
	if !hmac.Equal(got, mac(macKey(shared), method, authority, path, ts, nonce, machine)) {
		return "", ErrBadProof
	}
	// Only proofs that verify reach the nonce cache, so it can't be filled
	// by anyone without a machine key.
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.After(v.next) {
		for n, at := range v.seen {
			if now.Sub(at) > 2*MaxSkew {
				delete(v.seen, n)
			}
		}
		v.next = now.Add(time.Minute)
	}
	id := parts[3] + parts[0]
	if _, dup := v.seen[id]; dup {
		return "", ErrReplayed
	}
	v.seen[id] = now
	return base64.StdEncoding.EncodeToString(machine), nil
}

// GenerateKey makes a server key.
func GenerateKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
