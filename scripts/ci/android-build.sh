#!/bin/sh
# Builds the Android app: the Go core (.aar) with gomobile, then the APK
# with Gradle, into dist/whalescale-android-<type>.apk. $1 is "debug"
# (default) or "release"; a release APK is signed only when
# WS_ANDROID_KEYSTORE is set (see docs/guides/android.md). Uses the tools
# android-sdk.sh installed.
set -eu
type=${1:-debug}
T=${ANDROID_TOOLS:-/opt/android-tools}
export JAVA_HOME="$T/jdk17"
export ANDROID_HOME="$T/sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
export PATH="$JAVA_HOME/bin:$PATH"
version=${VERSION:-${CI_COMMIT_TAG:-$(git describe --tags --always 2>/dev/null || echo dev)}}

sh scripts/ci/retry.sh go mod download
VERSION=$version sh android/build-go.sh
task=assembleDebug
[ "$type" = release ] && task=assembleRelease
(cd android && ./gradlew --no-daemon -q "-PwsVersion=${version#v}" "$task")
mkdir -p dist
apk=$(find "android/app/build/outputs/apk/$type" -name '*.apk' | head -n 1)
cp "$apk" "dist/whalescale-android-$type.apk"
ls -l dist/whalescale-android-*.apk
