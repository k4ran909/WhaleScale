#!/bin/sh
# Builds the Go core (../mobile) into app/libs/whalescale.aar with gomobile.
# Needs Go, the Android SDK and NDK (ANDROID_HOME, ANDROID_NDK_HOME) and a
# JDK. VERSION (e.g. v0.1.9) is stamped into the core; it defaults to
# 'git describe'.
set -eu
cd "$(dirname "$0")/.."
version=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
commit=$(git rev-parse --short=7 HEAD 2>/dev/null || echo none)

# gomobile and gobind at the version go.mod pins.
go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
PATH="$(go env GOPATH)/bin:$PATH"

mkdir -p android/app/libs
# arm64 and arm for phones, amd64 for the emulator. API 26 is the app's
# minSdk.
gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 -trimpath \
  -ldflags "-s -w -X github.com/k4ran909/whalescale/internal/version.Version=$version -X github.com/k4ran909/whalescale/internal/version.Commit=$commit" \
  -o android/app/libs/whalescale.aar ./mobile
echo "built android/app/libs/whalescale.aar ($version)"
