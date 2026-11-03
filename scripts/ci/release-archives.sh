#!/bin/sh
# Builds the release downloads for tag $1 (e.g. v1.2.3) into dist/: an
# archive per OS/arch, Windows installers, and checksums. Needs zip, unzip,
# curl and makensis (NSIS).
set -eu
version=$1
v=${version#v}
commit=$(printf '%s' "${CI_COMMIT_SHA:-$(git rev-parse HEAD)}" | cut -c1-7)
rm -rf build dist
mkdir -p dist
sh scripts/ci/wintun.sh build/wintun
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64; do
  os=${target%/*} arch=${target#*/} ext=""
  [ "$os" = windows ] && ext=".exe"
  out="build/${os}_${arch}"
  mkdir -p "$out"
  for cmd in whalescale ws wsd; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
      -ldflags "-s -w -X github.com/k4ran909/whalescale/internal/version.Version=$version -X github.com/k4ran909/whalescale/internal/version.Commit=$commit" \
      -o "$out/$cmd$ext" "./cmd/$cmd"
  done
  cp README.md "$out/"
  name="whalescale_${v}_${os}_${arch}"
  if [ "$os" = windows ]; then
    # The network driver goes next to wsd.exe.
    cp "build/wintun/wintun/bin/$arch/wintun.dll" "$out/"
    cp build/wintun/wintun/LICENSE.txt "$out/wintun-LICENSE.txt"
    (cd "$out" && zip -q "../../dist/$name.zip" ./*)
    # The installer most people want: stable names, so the dashboard can
    # link to .../releases/latest/download/whalescale-setup-windows-amd64.exe.
    sh scripts/ci/windows-installer.sh "$out" "$arch" "$v" "dist/whalescale-setup-windows-$arch.exe"
  else
    tar -czf "dist/$name.tar.gz" -C "$out" .
  fi
done
(cd dist && sha256sum ./* | sed 's# \./# #' > checksums.txt)
ls -l dist
