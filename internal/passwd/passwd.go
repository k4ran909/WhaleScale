// Package passwd hashes console passwords with argon2id, stored in the PHC
// string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// The parameters are OWASP's minimum for argon2id: 19 MiB, two passes, one
// lane. They're part of each hash, so raising them later still verifies
// old passwords.
package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memoryKiB = 19 * 1024
	passes    = 2
	lanes     = 1
	saltLen   = 16
	keyLen    = 32
)

// MinLength and MaxLength bound new passwords.
const (
	MinLength = 10
	MaxLength = 256
)

var b64 = base64.RawStdEncoding

// Check returns an error saying what's wrong with a new password, or nil.
func Check(pw string) error {
	switch {
	case len(pw) < MinLength:
		return fmt.Errorf("use at least %d characters", MinLength)
	case len(pw) > MaxLength:
		return fmt.Errorf("use at most %d characters", MaxLength)
	}
	return nil
}

// Hash returns a PHC string for pw.
func Hash(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, passes, memoryKiB, lanes, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, passes, lanes, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// ErrMismatch: the password doesn't match the hash.
var ErrMismatch = errors.New("wrong password")

// Verify checks pw against a PHC string from Hash.
func Verify(pw, phc string) error {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported password hash")
	}
	var version int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported password hash")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<22 || t > 64 {
		return errors.New("unsupported password hash")
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return errors.New("unsupported password hash")
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// dummy is a hash of nothing anyone types, verified when an account doesn't
// exist so that a wrong name takes as long as a wrong password.
var dummy, _ = Hash("\x00no such account\x00")

// VerifyNone spends the time a real Verify would and returns ErrMismatch.
func VerifyNone(pw string) error {
	Verify(pw, dummy)
	return ErrMismatch
}
