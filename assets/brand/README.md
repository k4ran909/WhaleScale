# The Whalescale logo

The pixel whale, in five versions:

| File | Use it on |
|---|---|
| `logo.svg` | dark backgrounds (white whale) |
| `logo-blue.svg` | light backgrounds (navy whale) |
| `logo-monochrome.svg` | anything one-coloured: it takes the surrounding text colour (`currentColor`) |
| `logo-on-blue.svg` | the whale on a navy panel, for banners |
| `app-icon.svg` | the square app icon |

Colours: navy `#1F2EA5`, sky `#6989FA`, white.

The icons made from it (the Windows `.ico`, the console's favicon and
sign-in logo, the phone home-screen icon) are drawn from the same shapes by
`internal/brand`, which also draws the Windows tray icon. After changing the
logo, update the shapes in `internal/brand/brand.go` (its test checks they
match these files), run `scripts/brand.sh` and rebuild the console.
