#!/bin/sh
# Installs JDK 17 and the Android SDK and NDK the app needs into
# $ANDROID_TOOLS (default /opt/android-tools, a cached volume in CI), if
# they aren't there yet. Installing accepts the Android SDK license.
# Needs curl and unzip. Prints the environment to use, for android-build.sh.
set -eu
T=${ANDROID_TOOLS:-/opt/android-tools}
# Keep in step with android/app/build.gradle.kts and docs/guides/android.md.
NDK=27.2.12479018
PACKAGES="platform-tools platforms;android-35 build-tools;35.0.0 ndk;$NDK"
CMDLINE_TOOLS=13114758
mkdir -p "$T"
retry() { sh "$(dirname "$0")/retry.sh" "$@"; }

if [ ! -x "$T/jdk17/bin/java" ]; then
  retry curl -fsSL -o "$T/jdk17.tar.gz" "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
  rm -rf "$T/jdk17" && mkdir -p "$T/jdk17"
  tar -xzf "$T/jdk17.tar.gz" -C "$T/jdk17" --strip-components=1 && rm "$T/jdk17.tar.gz"
fi
export JAVA_HOME="$T/jdk17"

SDK=$T/sdk
SM=$SDK/cmdline-tools/latest/bin/sdkmanager
if [ ! -x "$SM" ]; then
  retry curl -fsSL -o "$T/clt.zip" "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip"
  rm -rf "$T/clt" && unzip -q "$T/clt.zip" -d "$T/clt" && rm "$T/clt.zip"
  mkdir -p "$SDK/cmdline-tools" && rm -rf "$SDK/cmdline-tools/latest"
  mv "$T/clt/cmdline-tools" "$SDK/cmdline-tools/latest" && rm -rf "$T/clt"
fi
if [ ! -d "$SDK/ndk/$NDK" ] || [ ! -d "$SDK/platforms/android-35" ] || [ ! -d "$SDK/build-tools/35.0.0" ]; then
  yes | "$SM" --sdk_root="$SDK" --licenses > /dev/null || true
  # shellcheck disable=SC2086 # one package per word
  retry "$SM" --sdk_root="$SDK" $PACKAGES > /dev/null
fi
echo "JAVA_HOME=$JAVA_HOME ANDROID_HOME=$SDK ANDROID_NDK_HOME=$SDK/ndk/$NDK"
