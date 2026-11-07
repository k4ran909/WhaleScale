package main

import (
	"image/color"

	"github.com/k4ran909/whalescale/internal/brand"
)

// colors are the icon's backgrounds: the logo's navy when connected.
var colors = map[string]color.NRGBA{
	"blue":  brand.Navy,
	"amber": {0xc7, 0x7c, 0x00, 0xff},
	"grey":  {0x6b, 0x77, 0x82, 0xff},
}

// icon returns a Windows .ico with the white whale on a rounded square in
// the named colour, at 16, 32 and 48 pixels.
func icon(name string) []byte {
	accent := brand.Sky
	if name != "blue" {
		accent = color.NRGBA{0xff, 0xff, 0xff, 0x8c} // sky blue clashes with amber and grey
	}
	s := brand.IconStyle
	s.Background, s.Accent = colors[name], accent
	return brand.ICO(brand.Icon, s, 16, 32, 48)
}
