// Package winconsole helps console programs that someone double-clicked in
// Windows Explorer: Windows opens a console window just for them and closes
// it the moment they exit, so their output vanishes before anyone reads it.
package winconsole

import (
	"bufio"
	"fmt"
	"os"
)

// Hold prints msg and, if this program has a console window of its own
// (it was double-clicked), waits for Enter so the window stays open.
func Hold(msg string) {
	fmt.Fprint(os.Stderr, msg)
	if !OwnWindow() {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
