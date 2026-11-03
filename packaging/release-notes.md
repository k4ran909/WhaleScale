### Which file do I need?

Adding a device is easiest from your dashboard: **Machines → Add device** gives you a join code and the right download for that device.

| Device | Download |
|---|---|
| **Windows PC** (almost all) | `whalescale-setup-windows-amd64.exe`: run it and paste your join code |
| Windows on ARM (Snapdragon laptops, Surface Pro X) | `whalescale-setup-windows-arm64.exe` |
| **Mac** or **Linux** | nothing to pick: run `curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh \| sh -s -- --join <your join code>` |
| The server | the Docker image `ghcr.io/k4ran909/whalescale` (see the README), or the archive for your server's system |

The `.tar.gz` and `.zip` archives hold the plain programs, for manual installs and servers. Each system appears twice because there are two kinds of processor:

- **amd64**: Intel and AMD processors, which most PCs and servers have.
- **arm64**: ARM processors, such as Apple Silicon Macs (M1 and later), Raspberry Pi 4/5 with a 64-bit system, ARM cloud servers and Snapdragon laptops.

`checksums.txt` lets you verify a download (`sha256sum -c checksums.txt`). GitHub adds the two "Source code" entries to every release by itself; you don't need them.

Windows may warn that the installer is from an unknown publisher because it isn't code-signed yet: choose **More info → Run anyway**.
