package nodeauth

import (
	"testing"
	"time"
)

// Authorization headers come from anyone who can reach the server.
func FuzzVerify(f *testing.F) {
	mPriv, _, srv := keys(f)
	signer, _ := NewSigner(mPriv, b64std(srv.PublicKey().Bytes()))
	f.Add(signer.Header("POST", "ws.example.com", "/p"), "POST", "/p")
	f.Add(Scheme+"a,b,c,d,e", "GET", "/relay")
	f.Add("Bearer wsnode-x", "POST", "/p")
	v := NewVerifier(srv, []string{"ws.example.com"})
	f.Fuzz(func(t *testing.T, header, method, path string) {
		mk, err := v.Verify(header, method, path, time.Now())
		if err == nil && mk == "" {
			t.Fatal("verified without a machine key")
		}
	})
}
