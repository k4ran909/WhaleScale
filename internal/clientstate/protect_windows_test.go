package clientstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectRemovesUserAccess(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "state.json")
	os.WriteFile(f, []byte("{}"), 0o600)
	if err := protect(dir); err != nil {
		t.Fatal(err)
	}
	// As the owner the test may still rewrite the ACL; give access back so
	// the temp directory can be removed.
	t.Cleanup(func() {
		sd, _ := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
		dacl, _, _ := sd.DACL()
		windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	})
	for _, p := range []string{dir, f} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		sddl := sd.String()
		// Only SYSTEM (SY) and Administrators (BA): no users (BU), everyone
		// (WD), authenticated users (AU) or the creating user's own SID.
		dacl := sddl[strings.Index(sddl, "D:"):]
		for _, ace := range strings.Split(strings.Trim(dacl[strings.Index(dacl, "("):], "()"), ")(") {
			trustee := ace[strings.LastIndex(ace, ";")+1:]
			if trustee != "SY" && trustee != "BA" {
				t.Errorf("%s: unexpected access for %s (%s)", filepath.Base(p), trustee, sddl)
			}
		}
	}
}
