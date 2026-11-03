package main

import "strings"

// pathWith returns a Windows PATH value with dir appended, and whether that
// changed anything. Entries compare case-insensitively, ignoring a trailing
// backslash, as Windows does.
func pathWith(path, dir string) (string, bool) {
	for _, e := range strings.Split(path, ";") {
		if samePathEntry(e, dir) {
			return path, false
		}
	}
	if path != "" && !strings.HasSuffix(path, ";") {
		path += ";"
	}
	return path + dir, true
}

// pathWithout returns PATH with every entry for dir removed.
func pathWithout(path, dir string) (string, bool) {
	var keep []string
	changed := false
	for _, e := range strings.Split(path, ";") {
		if samePathEntry(e, dir) {
			changed = true
			continue
		}
		keep = append(keep, e)
	}
	return strings.Join(keep, ";"), changed
}

func samePathEntry(a, b string) bool {
	norm := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), `\`) }
	return a != "" && strings.EqualFold(norm(a), norm(b))
}
