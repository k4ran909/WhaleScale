// Package joincode packs a server address and a pre-auth key into one
// string, so adding a device takes a single paste:
//
//	wsjoin-<base64url("https://ws.example.com\nwskey-…")>
//
// The code is as secret as the key inside it.
package joincode

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Prefix starts every join code.
const Prefix = "wsjoin-"

var enc = base64.RawURLEncoding

// Encode makes a join code for a server URL and a pre-auth key.
func Encode(server, key string) string {
	return Prefix + enc.EncodeToString([]byte(strings.TrimRight(server, "/")+"\n"+key))
}

// Is reports whether s looks like a join code (rather than a bare key).
func Is(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), Prefix) }

// Decode returns the server URL and pre-auth key in a join code.
func Decode(code string) (server, key string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(code), Prefix)
	if !ok {
		return "", "", errors.New("not a join code: it should start with " + Prefix)
	}
	raw, err := enc.DecodeString(rest)
	if err != nil {
		return "", "", errors.New("join code is damaged: copy it again from the dashboard")
	}
	server, key, ok = strings.Cut(string(raw), "\n")
	u, perr := url.Parse(server)
	if !ok || perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || !strings.HasPrefix(key, "wskey-") {
		return "", "", errors.New("join code is damaged: copy it again from the dashboard")
	}
	return server, key, nil
}
