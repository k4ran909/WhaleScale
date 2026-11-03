#!/bin/sh
# Builds a Windows installer: windows-installer.sh SRCDIR ARCH VERSION OUTFILE
# SRCDIR holds ws.exe, wsd.exe, wintun.dll and wintun-LICENSE.txt; VERSION
# is like 1.2.3 (anything after the numbers, as in 1.2.3-rc1, is kept in
# the name shown but left out of the Windows file version).
set -eu
src=$1 arch=$2 version=$3 out=$4
numeric=$(printf '%s' "$version" | sed 's/[^0-9.].*$//')
case "$numeric" in
*.*.*) ;;
*) numeric=0.0.0 ;;
esac
abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
makensis -V2 -DVERSION="$version" -DNUMVERSION="$numeric" -DARCH="$arch" -DSRCDIR="$(abs "$src")" \
  -DOUTFILE="$(abs "$out")" "$(dirname "$0")/../../packaging/windows/whalescale.nsi"
ls -l "$out"
