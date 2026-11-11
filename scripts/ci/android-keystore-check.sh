#!/bin/sh
# Checks, in seconds, that the release keystore $1 opens with
# $WS_ANDROID_KEYSTORE_PASSWORD and holds the key ${WS_ANDROID_KEY_ALIAS:-whalescale},
# so a wrong secret fails before the long build rather than at signing.
# $2 is the keytool to use (default: keytool on PATH).
#
# It prints the keystore file's size and SHA-256 (of the encrypted file,
# not the key), to compare with the .jks the secret was made from:
#   sha256sum whalescale.jks
set -eu
key=$1
keytool=${2:-keytool}
alias=${WS_ANDROID_KEY_ALIAS:-whalescale}
echo "android keystore: $(wc -c < "$key") bytes, sha256 $(sha256sum "$key" | cut -d' ' -f1)"
if ! out=$("$keytool" -list -keystore "$key" -storepass:env WS_ANDROID_KEYSTORE_PASSWORD -alias "$alias" 2>&1); then
  echo "android keystore: can't open it with the android_keystore_password secret, or it has no key \"$alias\":" >&2
  echo "$out" | grep -iv 'picked up' >&2
  echo "If the size and SHA-256 above match your .jks, the password secret is wrong; if not, the android_keystore secret holds another file." >&2
  exit 1
fi
echo "android keystore: password and key \"$alias\" OK"
