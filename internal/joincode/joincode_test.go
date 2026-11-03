package joincode

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	code := Encode("https://ws.example.com/", "wskey-ab12cd34-0123456789abcdef")
	if !strings.HasPrefix(code, Prefix) || !Is("  "+code+"\n") || Is("wskey-ab12cd34-x") {
		t.Fatalf("code %q", code)
	}
	// Only URL-safe characters: it goes on command lines and in installers.
	if strings.ContainsAny(code, "+/= \n") {
		t.Fatalf("code %q has characters that need quoting", code)
	}
	server, key, err := Decode(" " + code + "\r\n")
	if err != nil || server != "https://ws.example.com" || key != "wskey-ab12cd34-0123456789abcdef" {
		t.Fatalf("Decode = %q, %q, %v", server, key, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, code := range map[string]string{
		"bare key":       "wskey-ab12cd34-0123",
		"not base64":     Prefix + "!!!",
		"no separator":   Prefix + enc.EncodeToString([]byte("https://ws.example.com")),
		"not a key":      Encode("https://ws.example.com", "hello"),
		"not a URL":      Encode("ws.example.com", "wskey-a-b"),
		"other scheme":   Encode("ftp://ws.example.com", "wskey-a-b"),
		"truncated code": Encode("https://ws.example.com", "wskey-a-b")[:12],
	} {
		if _, _, err := Decode(code); err == nil {
			t.Errorf("%s: accepted %q", name, code)
		}
	}
}
