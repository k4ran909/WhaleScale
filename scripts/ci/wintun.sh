#!/bin/sh
# Downloads the signed Wintun driver DLLs (https://www.wintun.net, from the
# WireGuard project) into $1 and checks them against the published SHA-256.
# They ship unmodified, with their license, in the Windows downloads.
set -eu
version=0.14.1
sum=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
dir=$1
mkdir -p "$dir"
zip="$dir/wintun-$version.zip"
if [ ! -f "$zip" ] || ! echo "$sum  $zip" | sha256sum -c - >/dev/null 2>&1; then
	sh "$(dirname "$0")/retry.sh" curl -fsSL -o "$zip" "https://www.wintun.net/builds/wintun-$version.zip"
fi
echo "$sum  $zip" | sha256sum -c -
(cd "$dir" && rm -rf wintun && unzip -q "wintun-$version.zip")
ls "$dir/wintun/bin/amd64/wintun.dll" "$dir/wintun/bin/arm64/wintun.dll" "$dir/wintun/LICENSE.txt" >/dev/null
