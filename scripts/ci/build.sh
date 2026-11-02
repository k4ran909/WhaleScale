#!/bin/sh
# Cross-compiles the three binaries for each GOOS/GOARCH given (default:
# the platforms CI checks), into dist/.
set -eu
commit=$(printf '%s' "${CI_COMMIT_SHA:-$(git rev-parse HEAD)}" | cut -c1-7)
targets=${*:-linux/amd64 linux/arm64 windows/amd64 darwin/arm64}
for target in $targets; do
  os=${target%/*} arch=${target#*/}
  for cmd in whalescale ws wsd; do
    echo "== $cmd $os/$arch"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
      -ldflags "-s -w -X github.com/k4ran909/whalescale/internal/version.Commit=$commit" \
      -o "dist/$cmd-$os-$arch" "./cmd/$cmd"
  done
done
