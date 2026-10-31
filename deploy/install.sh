#!/bin/sh
# Whalescale installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh
#   ... | sh -s -- --server      also set up the server (Linux, systemd)
#   ... | sh -s -- --version v0.2.0
#
# Downloads the release for this OS/arch, verifies its SHA-256 checksum,
# installs ws, wsd (and whalescale) to /usr/local/bin and sets up services.
set -eu

REPO="k4ran909/WhaleScale"
VERSION="latest"
SERVER=0
while [ $# -gt 0 ]; do
	case "$1" in
	--server) SERVER=1 ;;
	--version) VERSION="$2"; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
	command -v sudo >/dev/null || die "run as root or install sudo"
	SUDO="sudo"
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux|darwin) ;; *) die "unsupported OS: $os (Windows: download the zip from GitHub releases)" ;; esac
arch=$(uname -m)
case "$arch" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) die "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
	VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
	[ -n "$VERSION" ] || die "could not find the latest release"
fi
asset="whalescale_${VERSION#v}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
say "downloading $asset ($VERSION)"
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

say "verifying checksum"
expected=$(grep " $asset\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$expected" ] || die "$asset is not listed in checksums.txt"
if command -v sha256sum >/dev/null; then
	actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
	actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset"

tar -xzf "$tmp/$asset" -C "$tmp"
say "installing to /usr/local/bin"
for bin in ws wsd whalescale; do
	[ -f "$tmp/$bin" ] && $SUDO install -m 0755 "$tmp/$bin" /usr/local/bin/$bin
done

if [ "$SERVER" -eq 1 ]; then
	[ "$os" = "linux" ] || die "--server is supported on Linux only"
	say "setting up the server"
	id whalescale >/dev/null 2>&1 || $SUDO useradd --system --home /var/lib/whalescale --shell /usr/sbin/nologin whalescale
	$SUDO mkdir -p /etc/whalescale/conf.d
	if [ ! -f /etc/whalescale/config.yaml ]; then
		curl -fsSL "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/config.example.yaml" | $SUDO tee /etc/whalescale/config.yaml >/dev/null
		echo "    edit /etc/whalescale/config.yaml (public-url, TLS), then: sudo whalescale configtest"
	fi
	curl -fsSL "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/whalescale.service" | $SUDO tee /etc/systemd/system/whalescale.service >/dev/null
	$SUDO systemctl daemon-reload
	echo "    start it with: sudo systemctl enable --now whalescale && sudo whalescale doctor"
else
	say "installing the wsd service"
	$SUDO /usr/local/bin/wsd install-service
fi
say "done"
