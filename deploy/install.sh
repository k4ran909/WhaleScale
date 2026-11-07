#!/bin/sh
# Whalescale installer for Linux and macOS.
#
#   A device:
#     curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --join wsjoin-...
#
#   The server, ready to use (Linux with systemd; DNS for the domain must
#   point at this machine):
#     curl -fsSL https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh | sh -s -- --server --domain ws.example.com
#
# Options:
#   --join CODE             join your network (code from the dashboard: Machines -> Add device)
#   --server                set up the server: config, HTTPS, firewall, service; prints the setup code
#   --domain NAME           the server's name (needed with --server; asked for if missing)
#   --email ADDRESS         Let's Encrypt contact for certificate expiry warnings
#   --gateway-domain NAME   publish machines' services at <name>.NAME (needs a wildcard DNS record)
#   --db URL                a PostgreSQL URL instead of SQLite, to run several servers for failover
#   --version vX.Y.Z        a specific release (default: the latest)
#
# Re-running it upgrades in place and keeps the configuration. It downloads
# the release for this OS/arch, checks its signature (with minisign
# installed) and SHA-256 checksum, and installs ws, wsd and whalescale to
# /usr/local/bin.
set -eu

REPO="k4ran909/WhaleScale"
# The release key's public half (internal/release.PublicKey).
RELEASE_KEY="RWQTDZ8OU3crgX88ZlDbLDwo0k+eu+ZQJMQ/DF3FsOwAoYXbEWqs6Jz5"
VERSION="latest"
SERVER=0
JOIN=""
DOMAIN=""
EMAIL=""
GATEWAY_DOMAIN=""
DB=""
need() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
	case "$1" in
	--server) SERVER=1 ;;
	--join) need "$@"; JOIN="$2"; shift ;;
	--domain) need "$@"; DOMAIN="$2"; shift ;;
	--email) need "$@"; EMAIL="$2"; shift ;;
	--gateway-domain) need "$@"; GATEWAY_DOMAIN="$2"; shift ;;
	--db) need "$@"; DB="$2"; shift ;;
	--version) need "$@"; VERSION="$2"; shift ;;
	-h|--help) sed -n '2,25p' "$0" 2>/dev/null || true; exit 0 ;;
	*) echo "unknown option: $1 (see the comments at the top of install.sh)" >&2; exit 2 ;;
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

# server_setup turns this machine into a Whalescale server: a config with
# automatic HTTPS, the firewall ports, the systemd service, and the setup
# code that creates the first admin account in the browser.
server_setup() {
	[ "$os" = "linux" ] || die "--server is supported on Linux only"
	command -v systemctl >/dev/null || die "--server needs systemd (or use Docker: see docs/install/docker.md)"
	conf=/etc/whalescale/config.yaml
	if [ ! -f "$conf" ]; then
		if [ -z "$DOMAIN" ] && [ -r /dev/tty ]; then
			printf 'Domain name for this server (its DNS must point here), e.g. ws.example.com: ' >/dev/tty
			read -r DOMAIN </dev/tty || true
		fi
		[ -n "$DOMAIN" ] || die "--server needs --domain ws.example.com"
		case "$DOMAIN" in *://*|*/*|*:*|*.) die "--domain takes a bare name like ws.example.com" ;; esac
		case "$DOMAIN" in *.*) ;; *) die "--domain takes a full name like ws.example.com" ;; esac
		if command -v getent >/dev/null; then
			addr=$(getent hosts "$DOMAIN" | awk '{print $1; exit}')
			if [ -n "$addr" ]; then
				say "$DOMAIN points at $addr (it must be this machine for HTTPS to work)"
			else
				say "warning: $DOMAIN doesn't resolve yet; HTTPS starts working once its DNS points here"
			fi
		fi
	fi

	say "setting up the server"
	id whalescale >/dev/null 2>&1 || $SUDO useradd --system --home /var/lib/whalescale --shell /usr/sbin/nologin whalescale
	$SUDO mkdir -p /etc/whalescale/conf.d
	if [ -f "$conf" ]; then
		say "keeping $conf (an upgrade)"
	else
		tmpconf=$(mktemp)
		{
			echo "# Written by install.sh. Every setting: deploy/config.example.yaml in the"
			echo "# repository. Local changes can also go in conf.d/*.yaml. Check: whalescale configtest"
			echo ""
			echo "public-url: https://$DOMAIN"
			echo "listen: \":443\""
			echo "# Certificates from Let's Encrypt, renewed by the server itself."
			echo "tls-acme: true"
			[ -n "$EMAIL" ] && echo "acme-email: $EMAIL"
			if [ -n "$DB" ]; then
				echo "# Several servers share this database and take over from each other."
				echo "db: $DB"
			else
				echo "db: /var/lib/whalescale/whalescale.db"
			fi
			echo "# STUN on two ports lets devices detect hard NATs; QUIC relay on 3480."
			echo "stun-listen: \":3478,:3479\""
			echo "relay-quic-listen: \":3480\""
			echo "dns-suffix: whale.internal"
			echo "metrics-listen: \"127.0.0.1:9090\""
			[ -n "$GATEWAY_DOMAIN" ] && echo "gateway-domain: $GATEWAY_DOMAIN"
			echo "log-level: info"
		} >"$tmpconf"
		$SUDO install -m 0640 -g whalescale "$tmpconf" "$conf"
		rm -f "$tmpconf"
		say "wrote $conf"
	fi
	$SUDO /usr/local/bin/whalescale configtest --config "$conf" >/dev/null || die "the configuration has a problem: run 'sudo whalescale configtest' to see it"

	curl -fsSL "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/whalescale.service" | $SUDO tee /etc/systemd/system/whalescale.service >/dev/null
	$SUDO systemctl daemon-reload

	# Open the ports where a host firewall is on. (Cloud firewalls and
	# security groups still need TCP 443 and UDP 3478-3480 by hand.)
	if command -v ufw >/dev/null && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
		say "opening TCP 443 and UDP 3478-3480 in ufw"
		$SUDO ufw allow 443/tcp >/dev/null
		$SUDO ufw allow 3478:3480/udp >/dev/null
	elif command -v firewall-cmd >/dev/null && $SUDO firewall-cmd --state >/dev/null 2>&1; then
		say "opening TCP 443 and UDP 3478-3480 in firewalld"
		$SUDO firewall-cmd --permanent --add-port=443/tcp >/dev/null
		$SUDO firewall-cmd --permanent --add-port=3478-3480/udp >/dev/null
		$SUDO firewall-cmd --reload >/dev/null
	fi

	say "starting the service"
	started=$(date '+%Y-%m-%d %H:%M:%S')
	$SUDO systemctl enable whalescale >/dev/null 2>&1
	$SUDO systemctl restart whalescale
	ok=0
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if $SUDO systemctl is-active --quiet whalescale; then ok=1; break; fi
		sleep 1
	done
	[ "$ok" -eq 1 ] || die "the service didn't start: sudo journalctl -u whalescale -n 50"

	# The server logs the setup code while no admin account exists.
	code=""
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		code=$($SUDO journalctl -u whalescale --since "$started" -o cat 2>/dev/null | sed -n 's/.*setup_code=\([A-Z0-9-]*\).*/\1/p' | tail -n 1)
		[ -n "$code" ] && break
		sleep 1
	done
	url=$($SUDO sed -n 's/^public-url: *//p' "$conf" | tr -d '"' | head -n 1)

	printf '\n\033[1mWhalescale server is running.\033[0m\n\n'
	echo "  Open        $url"
	if [ -n "$code" ]; then
		echo "  Setup code  $code   (creates your admin account; works once)"
	else
		echo "  Setup code  none: an admin account exists already (sign in, or: sudo whalescale admins reset-password NAME)"
	fi
	echo ""
	echo "  Then        Machines -> Add device, for each computer and phone"
	echo "  Check       sudo whalescale doctor"
	echo "  Logs        sudo journalctl -u whalescale -f"
	echo "  Config      $conf"
	echo ""
	echo "  The first visit may take a few seconds while the HTTPS certificate is issued."
	echo "  Cloud firewall? Allow TCP 443 and UDP 3478-3480 to this machine."
	echo ""
}

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

# The checksums are signed with the release key (packaging/release-key.pub),
# from v0.1.8 on. With minisign installed, a bad signature stops here.
if command -v minisign >/dev/null; then
	if curl -fsSL -o "$tmp/checksums.txt.minisig" "$base/checksums.txt.minisig"; then
		say "verifying signature"
		minisign -Vqm "$tmp/checksums.txt" -P "$RELEASE_KEY" || die "checksums.txt isn't signed with the Whalescale release key"
	else
		say "note: $VERSION has no signature (releases before v0.1.8 weren't signed)"
	fi
fi

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
	server_setup
else
	say "installing the wsd service"
	$SUDO /usr/local/bin/wsd install-service
	if [ -n "$JOIN" ]; then
		say "joining your network"
		$SUDO /usr/local/bin/ws login "$JOIN"
	else
		echo "    next: sudo ws login <join code from the dashboard: Machines -> Add device>"
	fi
fi
say "done"
