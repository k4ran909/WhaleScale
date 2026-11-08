### Which file do I need?

Adding a device is easiest from your dashboard: **Machines → Add device** gives you a join code and the right download for that device.

| Device | Download |
|---|---|
| **Windows PC** (almost all) | `whalescale-setup-windows-amd64.exe`: run it and paste your join code |
| Windows on ARM (Snapdragon laptops, Surface Pro X) | `whalescale-setup-windows-arm64.exe` |
| **Mac** or **Linux** | nothing to pick: run `curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh \| sh -s -- --join <your join code>` |
| Debian, Ubuntu, Mint, Raspberry Pi OS | or the package: `whalescale-amd64.deb` (`whalescale-arm64.deb` on ARM), with `sudo apt install ./whalescale-amd64.deb` |
| Fedora, RHEL, Rocky, Alma, openSUSE | or the package: `whalescale-x86_64.rpm` (`whalescale-aarch64.rpm` on ARM), with `sudo dnf install ./whalescale-x86_64.rpm` |
| **Android phone** (Android 8 or newer) | `whalescale-android.apk`: open it on the phone, allow installing from your browser or file manager, then scan the QR code from **Add device → Android** |
| The server | one command: `install.sh --server --domain NAME` (see the README); or the Docker image `ghcr.io/k4ran909/whalescale`; or the `whalescale-server` package (`.deb` / `.rpm`) |

The packages install the programs in `/usr/bin`, start the `wsd` service and keep themselves upgradable with your system's package manager. Then join with `sudo ws login <your join code>`.

The `.tar.gz` and `.zip` archives hold the plain programs, for manual installs and servers. Each system appears twice because there are two kinds of processor:

- **amd64**: Intel and AMD processors, which most PCs and servers have.
- **arm64**: ARM processors, such as Apple Silicon Macs (M1 and later), Raspberry Pi 4/5 with a 64-bit system, ARM cloud servers and Snapdragon laptops.

`checksums.txt` lets you verify a download (`sha256sum -c --ignore-missing checksums.txt`), and `checksums.txt.minisig` proves the checksums come from the Whalescale release key: `minisign -Vm checksums.txt -P RWQTDZ8OU3crgX88ZlDbLDwo0k+eu+ZQJMQ/DF3FsOwAoYXbEWqs6Jz5`. The tray icon's Update checks both by itself. `sbom.cdx.json` lists every Go module built into the programs (CycloneDX). GitHub adds the two "Source code" entries to every release by itself; you don't need them.

Windows may warn that the installer is from an unknown publisher because it isn't code-signed yet: choose **More info → Run anyway**.
