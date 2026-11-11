#!/bin/sh
# Builds the signed release APK for tag $1 (e.g. v1.2.3) into $2 (default
# build-android/whalescale-android.apk), outside dist/, which
# release-archives.sh starts afresh and then copies the APK into.
#
# The signing key comes from CI secrets (see docs/development/ci.md):
#   ANDROID_KEYSTORE               the keystore (.jks), base64-encoded
#   WS_ANDROID_KEYSTORE_PASSWORD   its password
#   WS_ANDROID_KEY_ALIAS           optional, default "whalescale"
#   WS_ANDROID_KEY_PASSWORD        optional, default: the keystore's
# Without them it fails: an unsigned APK can't be installed, and one signed
# with another key can't update the app on phones that have it.
set -eu
version=$1
out=${2:-build-android/whalescale-android.apk}
if [ -z "${ANDROID_KEYSTORE:-}" ] || [ -z "${WS_ANDROID_KEYSTORE_PASSWORD:-}" ]; then
  echo "android-release: the android_keystore and android_keystore_password secrets are not set" >&2
  exit 1
fi
key=$(mktemp)
trap 'rm -f "$key"' EXIT
printf '%s' "$ANDROID_KEYSTORE" | base64 -d > "$key"
export WS_ANDROID_KEYSTORE="$key"
# A password pasted into the secret form often carries a line break.
WS_ANDROID_KEYSTORE_PASSWORD=$(printf '%s' "$WS_ANDROID_KEYSTORE_PASSWORD" | tr -d '\r\n')
export WS_ANDROID_KEYSTORE_PASSWORD

sh scripts/ci/retry.sh apt-get update -qq
sh scripts/ci/retry.sh apt-get install -y -qq unzip
sh scripts/ci/android-sdk.sh
T=${ANDROID_TOOLS:-/opt/android-tools}
sh scripts/ci/android-keystore-check.sh "$key" "$T/jdk17/bin/keytool"
VERSION=$version sh scripts/ci/android-build.sh release

apk=dist/whalescale-android-release.apk
# Refuse anything that isn't properly signed, and show whose key it is.
"$T/jdk17/bin/java" -jar "$T/sdk/build-tools/35.0.0/lib/apksigner.jar" verify --print-certs "$apk"
mkdir -p "$(dirname "$out")"
mv "$apk" "$out"
ls -l "$out"
