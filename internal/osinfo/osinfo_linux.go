package osinfo

import (
	"bufio"
	"os"
	"strings"
)

func version() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VERSION_ID="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}
