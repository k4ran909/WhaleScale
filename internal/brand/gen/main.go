// Command gen writes the icon files made from the logo. Run it, from the
// repository root, through scripts/brand.sh, which also puts the icon into
// the Windows programs:
//
//	packaging/windows/whalescale.ico  installer, programs and Apps list
//	web/public/favicon.svg            the console's browser tab and sidebar
//	web/public/whale.svg              the console's sign-in page
//	web/public/apple-touch-icon.png   the console on a phone's home screen
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/k4ran909/whalescale/internal/brand"
)

func main() {
	write("packaging/windows/whalescale.ico", brand.ICO(brand.Icon, brand.IconStyle, 16, 20, 24, 32, 40, 48, 64, 128, 256))
	write("web/public/favicon.svg", []byte(brand.SVG(brand.Icon, brand.IconStyle)))
	write("web/public/whale.svg", []byte(brand.SVG(brand.Whale, brand.Style{Body: brand.Navy, Accent: brand.Sky})))
	// iOS rounds the corners itself.
	touch := brand.IconStyle
	touch.Radius = 0
	write("web/public/apple-touch-icon.png", brand.PNG(180, 180, brand.AppIcon, touch))
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%-34s %6d bytes\n", path, len(data))
}
