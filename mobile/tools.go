//go:build tools

package mobile

// gomobile bind needs golang.org/x/mobile/bind in this module; the import
// keeps it in go.mod (the "tools" tag means it is never compiled).
import _ "golang.org/x/mobile/bind"
