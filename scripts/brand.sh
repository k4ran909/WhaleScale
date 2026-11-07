#!/bin/sh
# Regenerates every icon made from the logo (assets/brand): run it from the
# repository root after changing the logo, and commit what it writes:
#
#   packaging/windows/whalescale.ico   installer, Start menu, Apps list
#   web/public/favicon.svg             the console's browser tab and sidebar
#   web/public/whale.svg               the console's sign-in page
#   web/public/apple-touch-icon.png    the console on a phone's home screen
#
# Then rebuild the console (cd web && npm run build) for the favicon.
set -eu
go run ./internal/brand/gen
