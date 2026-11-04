#!/usr/bin/env bash
# Builds the bundled bash, wg, wg-quick and wireguard-go for this Mac's architecture,
# plus the smoke-test peer, from pinned sources. No cross-compilation: each architecture
# is built natively so that it is also executed natively.
set -euo pipefail
source "$(dirname "$0")/deps.sh"

[[ $(uname -s) == Darwin ]] || die "build-tools.sh must run on macOS"
arch=$(uname -m)
case $arch in
  arm64) goarch=arm64 ;;
  x86_64) goarch=amd64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

# Homebrew libraries on the runner must not leak into the bundled binaries.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
unset CPATH C_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH LDFLAGS CPPFLAGS
export MACOSX_DEPLOYMENT_TARGET=$MIN_MACOS

src="$WORK/src"
out="$WORK/tools"
licenses="$WORK/licenses"
jobs=$(sysctl -n hw.ncpu)
rm -rf "$src" "$out" "$licenses"
mkdir -p "$src" "$out" "$licenses/go-modules"

fetch_gpl_and_wireguard_sources
go_tarball="$DOWNLOADS/go$GO_VERSION.darwin-$goarch.tar.gz"
go_sha_var="GO_SHA256_$goarch"
fetch "$go_tarball" "${!go_sha_var}" "https://go.dev/dl/go$GO_VERSION.darwin-$goarch.tar.gz"

echo "==> bash $BASH_PIN_VERSION patchlevel $BASH_PIN_PATCHLEVEL"
tar -xf "$DOWNLOADS/bash-$BASH_PIN_VERSION.tar.gz" -C "$src"
bash_src="$src/bash-$BASH_PIN_VERSION"
for entry in $BASH_PATCHES; do
  (cd "$bash_src" && patch -p0 -s <"$DOWNLOADS/bash53-${entry%%:*}")
done
# strchrnul exists only on newer SDKs; detecting it would break macOS 13 at load time.
(
  cd "$bash_src"
  bash_cv_func_strchrnul_works=no ./configure --disable-nls --disable-readline \
    --without-bash-malloc --without-libintl-prefix --without-libiconv-prefix >/dev/null
  make -j"$jobs" bash >/dev/null
)
cp "$bash_src/bash" "$out/bash"
cp "$bash_src/COPYING" "$licenses/bash-COPYING"

echo "==> wireguard-tools $WG_TOOLS_VERSION"
tar -xf "$DOWNLOADS/wireguard-tools-$WG_TOOLS_VERSION.tar.xz" -C "$src"
wg_src="$src/wireguard-tools-$WG_TOOLS_VERSION"
make -C "$wg_src/src" -j"$jobs" wg >/dev/null
cp "$wg_src/src/wg" "$out/wg"
# Byte-for-byte upstream: the shebang is unused because callers name the bundled bash.
cp "$wg_src/src/wg-quick/darwin.bash" "$out/wg-quick"
chmod 755 "$out/wg-quick"
cp "$wg_src/COPYING" "$licenses/wireguard-tools-COPYING"

echo "==> go $GO_VERSION and wireguard-go $WG_GO_VERSION"
tar -xf "$go_tarball" -C "$src"
export GOROOT="$src/go" GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache"
export GOTOOLCHAIN=local GOFLAGS="-mod=readonly -modcacherw -trimpath -buildvcs=false" CGO_ENABLED=0
go="$GOROOT/bin/go"
tar -xf "$DOWNLOADS/wireguard-go-$WG_GO_VERSION.tar.xz" -C "$src"
wggo_src="$src/wireguard-go-$WG_GO_VERSION"
(cd "$wggo_src" && "$go" build -o "$out/wireguard-go" .)
cp "$GOROOT/LICENSE" "$licenses/go-LICENSE"
(cd "$wggo_src" && "$go" list -deps -f '{{with .Module}}{{.Path}}|{{.Dir}}{{end}}' .) | sort -u |
  while IFS='|' read -r module dir; do
    [[ -n $module ]] || continue
    name=${module//\//_}
    [[ -f $dir/LICENSE ]] || die "module $module has no LICENSE file to bundle"
    cp "$dir/LICENSE" "$licenses/go-modules/$name.LICENSE"
    if [[ -f $dir/PATENTS ]]; then cp "$dir/PATENTS" "$licenses/go-modules/$name.PATENTS"; fi
  done

echo "==> smoke-test peer (never bundled in the app)"
mkdir "$wggo_src/smokepeer"
cp "$REPO_ROOT/scripts/smoke-peer/"*.go "$wggo_src/smokepeer/"
(cd "$wggo_src" && "$go" build -o "$WORK/smoke-peer" ./smokepeer)
(cd "$wggo_src" && "$go" test -count=1 -timeout 120s -v ./smokepeer)

ls -l "$out" "$WORK/smoke-peer"
