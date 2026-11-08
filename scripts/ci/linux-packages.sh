#!/bin/sh
# Builds the Linux packages for one architecture from release binaries:
#
#   whalescale         the client: ws, wsd and the wsd service (started on install)
#   whalescale-server  the server and its service, with the example config
#
# as .deb (Debian, Ubuntu, Mint, Raspberry Pi OS...) and .rpm (Fedora, RHEL,
# Rocky, Alma, openSUSE...), with stable names so that
# .../releases/latest/download/whalescale-amd64.deb always works.
#
#   sh scripts/ci/linux-packages.sh v1.2.3 amd64 build/linux_amd64 dist
#
# Needs dpkg-deb and rpmbuild (on Debian: apt install rpm).
set -eu
version=$1 arch=$2 bin=$3 out=$4
case "$arch" in
  amd64) rpmarch=x86_64 ;;
  arm64) rpmarch=aarch64 ;;
  *) echo "linux-packages.sh: unsupported architecture $arch" >&2; exit 2 ;;
esac
# 1.2.3-rc.1 -> 1.2.3~rc.1: both dpkg and rpm sort ~ before the release.
pv=$(printf '%s' "${version#v}" | tr '-' '~')
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The same timestamps in every build of a commit.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
export SOURCE_DATE_EPOCH

maintainer="k4ran909 <k4ran909@users.noreply.github.com>"
homepage="https://github.com/k4ran909/WhaleScale"

# --- what goes in each package -------------------------------------------

r=$work/whalescale
install -Dm0755 "$bin/ws" "$r/usr/bin/ws"
install -Dm0755 "$bin/wsd" "$r/usr/bin/wsd"
install -Dm0644 packaging/linux/wsd.service "$r/usr/lib/systemd/system/wsd.service"
install -Dm0644 README.md "$r/usr/share/doc/whalescale/README.md"

r=$work/whalescale-server
install -Dm0755 "$bin/whalescale" "$r/usr/bin/whalescale"
mkdir -p "$r/usr/lib/systemd/system"
sed 's#/usr/local/bin/#/usr/bin/#' deploy/whalescale.service >"$r/usr/lib/systemd/system/whalescale.service"
chmod 0644 "$r/usr/lib/systemd/system/whalescale.service"
install -Dm0644 deploy/config.example.yaml "$r/usr/share/doc/whalescale-server/config.example.yaml"
install -Dm0644 README.md "$r/usr/share/doc/whalescale-server/README.md"

summary_whalescale="Whalescale mesh VPN client"
long_whalescale="Connects this machine to your self-hosted Whalescale network: the wsd
agent (a system service) and the ws command. Join with: sudo ws login CODE"
summary_whalescale_server="Whalescale mesh VPN server"
long_whalescale_server="The self-hosted Whalescale server: coordination, relay, STUN, MagicDNS
and the web console, in one program. Configure /etc/whalescale/config.yaml."

# --- .deb ------------------------------------------------------------------

# build_deb NAME: builds $out/NAME-ARCH.deb from $work/NAME.
build_deb() {
  name=$1 root=$work/$1 key=$(printf '%s' "$1" | tr - _)
  eval "summary=\$summary_$key long=\$long_$key"
  size=$(du -sk "$root" | cut -f1)
  mkdir -p "$root/DEBIAN"
  {
    echo "Package: $name"
    echo "Version: $pv"
    echo "Architecture: $arch"
    echo "Maintainer: $maintainer"
    echo "Installed-Size: $size"
    echo "Section: net"
    echo "Priority: optional"
    echo "Homepage: $homepage"
    echo "Description: $summary"
    printf '%s\n' "$long" | sed 's/^/ /'
  } >"$root/DEBIAN/control"
  dir=packaging/linux/${name#whalescale-}
  [ "$name" = whalescale ] && dir=packaging/linux/client
  {
    printf '#!/bin/sh\nset -e\n[ "$1" = configure ] || exit 0\n'
    printf 'if [ -n "${2:-}" ]; then set -- upgrade; else set -- install; fi\n'
    cat "$dir/after-install"
  } >"$root/DEBIAN/postinst"
  {
    printf '#!/bin/sh\nset -e\n[ "$1" = remove ] || exit 0\n'
    cat "$dir/before-remove"
  } >"$root/DEBIAN/prerm"
  chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm"
  dpkg-deb --root-owner-group -Zxz --build "$root" "$out/$name-$arch.deb" >/dev/null
  rm -rf "$root/DEBIAN"
}

# --- .rpm ------------------------------------------------------------------

# build_rpm NAME: builds $out/NAME-RPMARCH.rpm from $work/NAME.
build_rpm() {
  name=$1 root=$work/$1 key=$(printf '%s' "$1" | tr - _)
  eval "summary=\$summary_$key long=\$long_$key"
  dir=packaging/linux/${name#whalescale-}
  [ "$name" = whalescale ] && dir=packaging/linux/client
  spec=$work/$name.spec
  {
    echo "Name: $name"
    echo "Version: $pv"
    echo "Release: 1"
    echo "Summary: $summary"
    # No license has been chosen yet (plan.md, open question 1).
    echo "License: Proprietary"
    echo "URL: $homepage"
    echo "Packager: $maintainer"
    # Static Go programs: nothing to depend on, nothing to strip.
    echo "AutoReqProv: no"
    echo "%global debug_package %{nil}"
    echo "%global __os_install_post %{nil}"
    echo "%global _build_id_links none"
    # xz, not zstd: older rpm (RHEL/CentOS 7) reads it too.
    echo "%global _binary_payload w6.xzdio"
    echo ""
    echo "%description"
    printf '%s\n' "$long"
    echo ""
    echo "%install"
    echo "cp -a $root/. %{buildroot}/"
    echo ""
    echo "%post"
    echo 'if [ "$1" -ge 2 ]; then set -- upgrade; else set -- install; fi'
    cat "$dir/after-install"
    echo ""
    echo "%preun"
    echo '[ "$1" -eq 0 ] || exit 0'
    cat "$dir/before-remove"
    echo ""
    echo "%files"
    (cd "$root" && find . -type f | sed 's#^\.##' | sort)
  } >"$spec"
  rpmbuild -bb --quiet --target "$rpmarch" \
    --define "_topdir $work/rpmbuild" \
    --define "_rpmdir $out" \
    --define "_build_name_fmt $name-$rpmarch.rpm" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "_buildhost whalescale-release" \
    "$spec" >/dev/null
}

for name in whalescale whalescale-server; do
  build_deb "$name"
  build_rpm "$name"
done
ls -l "$out"/*-"$arch".deb "$out"/*-"$rpmarch".rpm
