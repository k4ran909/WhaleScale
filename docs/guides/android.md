# Android app

The Android app puts a phone on your network like any other device: join
with a code from the dashboard, then switch the VPN on. It is new and not on
Google Play yet. Download `whalescale-android.apk` from the
[latest release](https://github.com/k4ran909/WhaleScale/releases/latest/download/whalescale-android.apk)
on the phone and open it (Android asks once to allow installing apps from
your browser or file manager), or build it yourself (below). Android 8 or
newer; arm64, 32-bit arm and x86_64.

## Using it

1. In the dashboard, open **Machines → Add device**, get a join code and pick
   the **Android** tab. It shows the code as a QR code.
2. In the app, tap **Scan QR code** and point the camera at it, or paste the
   join code (`wsjoin-…`). Check the device name and tap **Join**.
3. Android asks whether Whalescale may set up a VPN connection: allow it.

The main screen then shows:

- **The switch:** connect and disconnect.
- **This device:** its name and mesh IP address (tap the address to copy it).
- **Devices:** everyone else on the network, with a green dot when online
  and how traffic reaches them: **Direct** (peer to peer), **Relay** (through
  the server's relay), **Peer relay**, or **Idle** (no traffic lately).
- **Sign out:** removes this phone from the network and the dashboard. To come
  back, join with a new code.
- The app's version, and the Go core's.

What it does on the phone:

- Traffic to `100.64.0.0/10` (the mesh) and to [subnet routes](networking.md)
  an admin approved goes through the tunnel. Everything else, including the
  internet, goes the usual way. When a route is approved or removed the app
  rebuilds the VPN interface on its own.
- DNS goes to MagicDNS at `100.100.100.100`, so names like
  `laptop.whale.internal` (or just `laptop`) work. Other names are looked up
  with the phone's own DNS servers.
- The app's own connections (to the server, the relay, peers' real
  addresses) stay outside the tunnel.
- The device's keys and identity are in the app's private storage
  (`files/state.json`), so reconnecting doesn't register it again. They are
  left out of backups and phone-to-phone transfers on purpose: a new phone
  joins as a new device.

Tips and limits:

- **Stay connected across restarts:** Android Settings → Network & internet →
  VPN → Whalescale (gear) → **Always-on VPN**. The app also reconnects on its
  own when you open it, if it was connected before.
- **Private DNS:** with a fixed Private DNS provider (Settings → Network &
  internet → Private DNS → hostname), Android sends lookups there instead of
  to MagicDNS, so mesh names don't resolve; mesh IP addresses still work.
  "Automatic" is fine.
- Not on Android yet: using an exit node, offering this phone as a subnet
  router, relay or exit node, SSH into the phone, and several networks
  (profiles). The roadmap ([plan.md](../../plan.md), Phase 5) lists what's
  next.

## Building it

The app is two parts: the Go core, `mobile/` (it wraps the same engine as
`wsd`), built into `android/app/libs/whalescale.aar` with
[gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile), and the Kotlin
app in `android/` (Jetpack Compose), built with Gradle.

You need, on Linux, macOS or WSL:

| Tool | Version |
|---|---|
| Go | the one in `go.mod` (1.27.3) |
| JDK | 17 |
| Android SDK | platform 35, build-tools 35.0.0 |
| Android NDK | r27c (`27.2.12479018`) |

[`scripts/ci/android-sdk.sh`](../../scripts/ci/android-sdk.sh) installs the
JDK, SDK and NDK into one folder without root (about 3 GB; it accepts the
Android SDK license for you):

```bash
ANDROID_TOOLS=$HOME/android-tools sh scripts/ci/android-sdk.sh
```

Then, from the repository root:

```bash
export JAVA_HOME=$HOME/android-tools/jdk17 ANDROID_HOME=$HOME/android-tools/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018 PATH=$HOME/android-tools/jdk17/bin:$PATH
sh android/build-go.sh
cd android && ./gradlew assembleDebug
```

The APK is `android/app/build/outputs/apk/debug/app-debug.apk`. Install it
with `adb install`, or copy it to the phone and open it (allow installing
from that app when Android asks). `ANDROID_TOOLS=$HOME/android-tools sh
scripts/ci/android-build.sh` does both steps and copies the APK to `dist/`.

To work on the Kotlin side in Android Studio, run `sh android/build-go.sh`
once (and again after changing Go code), then open the `android/` folder.

`build-go.sh` builds for arm64 and 32-bit arm phones and the x86_64
emulator. Set `VERSION=v0.1.9` to stamp a version into the core, and pass
`-PwsVersion=0.1.9` to Gradle for the app's own version (its `versionCode`
is derived from it: 0.1.9 becomes 109).

Debug builds print the Go core's debug messages to logcat (tag `GoLog`):
`adb logcat -s GoLog`.

### Testing on an emulator

An emulator (`sdkmanager "emulator" "system-images;android-35;google_apis;x86_64"`,
then `avdmanager create avd -n ws -k "system-images;android-35;google_apis;x86_64"`)
works as a phone. On Linux and WSL it needs `/dev/kvm`, so your user must be
in the `kvm` group. Start the server on an address the emulator can reach,
such as the machine's LAN or WSL address rather than `localhost` (inside the
emulator, `localhost` is the emulator itself). Long join codes typed with
`adb shell input text` can lose characters, so type them in pieces.

The app has been tried this way on Android 15: joining, connecting, a direct
path and pings to a Linux peer both ways, MagicDNS and internet names,
approving and removing a subnet route (the VPN interface is rebuilt without
dropping traffic), reconnecting on launch, disconnecting and signing out.
Scanning a QR code with a real camera hasn't been tried yet.

### Release builds

`./gradlew assembleRelease` signs the APK when these are set, and leaves it
unsigned (not installable) otherwise:

| Variable | |
|---|---|
| `WS_ANDROID_KEYSTORE` | path to the keystore (`.jks`) |
| `WS_ANDROID_KEYSTORE_PASSWORD` | its password |
| `WS_ANDROID_KEY_ALIAS` | the key's alias (default `whalescale`) |
| `WS_ANDROID_KEY_PASSWORD` | the key's password (default: the keystore's) |

Make a key once with
`keytool -genkeypair -keystore whalescale.jks -alias whalescale -keyalg EC -validity 10000`
and keep it safe: Android only installs an update signed with the same key.
Released APKs are signed with the key in the CI secrets (below); an APK you
build with another key can't update one from a release, or the other way
round, without uninstalling first.

### CI

[`.woodpecker/android.yaml`](../../.woodpecker/android.yaml) builds a debug APK.
It only runs when started by hand (**Run pipeline** in Woodpecker), because
on the arm64 agent it takes well over an hour (below). The first run downloads the JDK, SDK and NDK
into the `woodpecker-android` volume; later runs reuse it. Google ships the
NDK and Gradle's `aapt2` only for x86_64 Linux, so on an arm64 agent the step
runs an amd64 image under QEMU emulation. The agent's Docker host must have
it registered, or the step fails at once with `exec format error` (BuildKit's
own emulation, which builds the amd64 release image, doesn't cover normal
steps). Use a recent QEMU: `docker run --privileged --rm tonistiigi/binfmt
--install amd64` at every boot. Ubuntu 24.04's `qemu-user-static` is too old:
`apt-get update` fails in the build image with "No good signature" (details
in [CI](../development/ci.md)). The build is several times slower than on
x86_64.

Releases: the `android apk` step of
[`.woodpecker/release.yaml`](../../.woodpecker/release.yaml) builds the signed
APK ([`scripts/ci/android-release.sh`](../../scripts/ci/android-release.sh))
before the other downloads, so `checksums.txt` and its signature cover it,
and it's published as `whalescale-android.apk`, a fixed name for the
`releases/latest/download/` link. It needs the `android_keystore` and
`android_keystore_password` secrets ([CI](../development/ci.md)) and the same
amd64 emulation. Without either, the step fails, the release goes out without
the APK, and its notes leave out the Android row.
