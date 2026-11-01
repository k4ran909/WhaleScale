package clientstate

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// systemOnlySDDL grants full control to SYSTEM and Administrators only, and
// stops inheriting the parent's (on ProgramData: everyone may read).
const systemOnlySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Protect locks down a state directory the wsd service uses. Unix file
// modes do nothing on Windows: without this, files in ProgramData inherit
// read access for every local user, node token and keys included. Per-user
// directories (in the profile) are private already and left alone.
func Protect(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	sys := filepath.Clean(SystemDir())
	if !strings.EqualFold(abs, sys) && !strings.HasPrefix(strings.ToLower(abs), strings.ToLower(sys)+`\`) {
		return nil
	}
	return protect(abs)
}

func protect(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(systemOnlySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// Existing files in the directory pick up the new inherited ACL too.
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
