# Adding devices

Put computers, servers and phones on your network: the Windows installer and tray icon, one command on macOS and Linux, and join codes.

The dashboard's **Machines → Add device** walks you through it and shows each device appear as it joins. It makes a *join code*: the server's address and a key in one string (`wsjoin-…`), as secret as a password. A code works for one device for a day, or for several devices for a week if you choose that.

- **Windows:** run `whalescale-setup-windows-amd64.exe` (`-arm64` for ARM laptops) from the [latest release](https://github.com/k4ran909/WhaleScale/releases/latest) and paste the join code. It installs the network driver and the service, puts `ws` on the PATH, joins, and adds a **tray icon** next to the clock: the whale on blue while connected, on grey when not (amber while connecting). Its menu shows this PC's address and your devices (click one to copy its address), and has Connect, Disconnect, Open dashboard, Open terminal and the installed version. It checks for new releases twice a day and offers **Update to vX.Y.Z**: that downloads the installer, checks that the release's checksums are signed with the Whalescale release key and that the installer matches them, and installs it over the old version, keeping this PC on its network. Connect, Disconnect, Open terminal and Update ask for administrator rights. **Exit** closes only the icon: Whalescale keeps the PC connected in the background, and the icon comes back at the next sign-in (or from the Start menu). To upgrade by hand, just run the new installer over the old one; there's no need to uninstall first. Windows may tuck the icon under the **^** arrow. Whalescale also adds a Windows Firewall rule (`WhalescaleIn`) that lets traffic in on its own adapter only, where its packet filter already enforces your access policy; without it Windows treats the adapter as a public network and drops everything, ping included. Windows may warn that the publisher is unknown, because the installer isn't code-signed yet: choose **More info → Run anyway**. For scripted installs: `whalescale-setup-windows-amd64.exe /S /JOIN=wsjoin-…`.
- **macOS and Linux:**

  ```bash
  curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --join wsjoin-...
  ```

- **Linux, with a package:** see [Linux packages](#linux-packages) below. The system's package manager then installs upgrades.
- **Android:** install [`whalescale-android.apk`](https://github.com/k4ran909/WhaleScale/releases/latest/download/whalescale-android.apk) on the phone (see the [Android app](android.md) guide), then tap **Scan QR code** and scan the code the dashboard's Android tab shows, or paste the join code.
- **Already installed:** `sudo ws login wsjoin-…` (on Windows, `ws login wsjoin-…` in a terminal opened as Administrator). It joins and connects.

Then:

```bash
ws status                     # peers, direct/relay path, latency
ping laptop.whale.internal
```

Without the dashboard: `whalescale preauthkeys create --user NAME` on the server prints a key and its join code, and `ws login --server URL` with no key opens a browser sign-in if OIDC is set up.

For short-lived machines (CI runners, containers), use an ephemeral key: `whalescale preauthkeys create --user ci --reusable --ephemeral`. Machines it adds are removed once they've been offline for `ephemeral-timeout` (10 minutes by default). `ws logout` removes a machine from the server right away.

Machines prove each request with their machine key rather than sending a reusable token. The server has an X25519 key; a machine learns its public half at login (over TLS) and then signs every control, relay and gateway request. Each signature covers the method, the server, the path and the time, and the server accepts it once. Once a machine has signed a request, its login token is refused. So a header copied from a proxy log, a debugging dump or a TLS-inspecting middlebox is useless, and so is the token itself. Older clients keep using the token until they're upgraded. If machines reach the server under names other than `--public-url`'s (an internal address, say), list them with `--node-auth-hosts`.

Manual install on Windows, without the installer: unzip `whalescale_<version>_windows_amd64.zip` (it includes the `wintun.dll` network driver next to `wsd.exe`), and in an Administrator terminal run `wsd install-service`, then `ws login wsjoin-…`.

## Linux packages

Every release has `.deb` and `.rpm` packages for amd64 and arm64, under fixed names, so these links always get the latest:

| System | Install |
|---|---|
| Debian, Ubuntu, Mint, Pop!_OS, Raspberry Pi OS | `curl -fLO https://github.com/k4ran909/WhaleScale/releases/latest/download/whalescale-amd64.deb && sudo apt install ./whalescale-amd64.deb` |
| Fedora, RHEL, Rocky, Alma, CentOS Stream | `sudo dnf install https://github.com/k4ran909/WhaleScale/releases/latest/download/whalescale-x86_64.rpm` |
| openSUSE | `sudo zypper install https://github.com/k4ran909/WhaleScale/releases/latest/download/whalescale-x86_64.rpm` |

On ARM (Raspberry Pi 4/5 with a 64-bit system, ARM servers), use `whalescale-arm64.deb` or `whalescale-aarch64.rpm`. Then join:

```bash
sudo ws login wsjoin-...
```

| Package | Contains |
|---|---|
| `whalescale` | `ws` and `wsd` in `/usr/bin`, and the `wsd` systemd service, started and enabled on install |
| `whalescale-server` | the server in `/usr/bin`, its hardened systemd unit and the example config in `/usr/share/doc/whalescale-server/` |

- **Upgrading:** install the newer package the same way. It restarts `wsd` and keeps the machine on its network.
- **Removing:** `sudo apt remove whalescale` or `sudo dnf remove whalescale`. This stops the service and keeps the machine's identity in `/var/lib/whalescale`, so reinstalling rejoins as the same machine. Delete that folder to forget it.
- **Moving from install.sh:** installing the package replaces the service that `install.sh` set up. Afterwards `/usr/local/bin/ws` and `/usr/local/bin/wsd` can be deleted.
- **Other distributions** (Arch, Alpine, NixOS…): use the install command above, or the `whalescale_<version>_linux_<arch>.tar.gz` archive and `sudo wsd install-service`.

The packages aren't signed themselves. They're listed in the signed `checksums.txt`, so they can be checked as below.

## Verifying downloads

Every release from v0.1.8 on signs its `checksums.txt` with the Whalescale release key ([packaging/release-key.pub](../../packaging/release-key.pub)), in [minisign](https://jedisct1.github.io/minisign/)'s format, and lists what went into the programs in `sbom.cdx.json` (CycloneDX). To check a download by hand:

```bash
minisign -Vm checksums.txt -P RWQTDZ8OU3crgX88ZlDbLDwo0k+eu+ZQJMQ/DF3FsOwAoYXbEWqs6Jz5
sha256sum -c --ignore-missing checksums.txt
```

The tray icon's Update does both before it installs anything, and the install script checks the signature when `minisign` is installed.

## Several networks on one machine

A machine can belong to more than one network (work, home, a customer's) and switch between them:

```bash
sudo ws login --profile work --server https://ws.work.example   # adds a profile and switches to it
sudo ws profiles                                                # * marks the active one
sudo ws switch default                                          # back to the first network
```

- **Separate identities:** each profile has its own machine identity, keys and settings.
- **One at a time:** networks all use 100.64.0.0/10, so having two up at once would mix their routes and DNS. Switching takes a second or two.
- **Logging out:** `ws logout` on an added profile removes it and returns to the default profile.
