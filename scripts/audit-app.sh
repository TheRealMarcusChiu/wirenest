#!/usr/bin/env bash
# Fails unless the app has the frozen layout, the expected single architecture, no
# non-system runtime dependencies, a macOS 13 load target, a valid signature, and
# bundled tools that actually run.
#
# Usage: scripts/audit-app.sh path/to/WireNest.app ARCH
set -euo pipefail
source "$(dirname "$0")/deps.sh"

app=${1:?usage: audit-app.sh WireNest.app ARCH}
arch=${2:?usage: audit-app.sh WireNest.app ARCH}
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
contents="$app/Contents"
tools="$contents/Resources/Tools"

plist_value() { plutil -extract "$1" raw -o - "$contents/Info.plist"; }
expect_plist() {
  [[ $(plist_value "$1") == "$2" ]] || die "Info.plist $1 is not $2"
}
expect_plist CFBundleExecutable WireNestApp
expect_plist CFBundleIdentifier "$BUNDLE_ID"
expect_plist CFBundleName WireNest
expect_plist LSMinimumSystemVersion "$MIN_MACOS"
expect_plist LSUIElement true
plist_value NSLocationUsageDescription >/dev/null

machos=("$contents/MacOS/WireNestApp" "$contents/Library/LaunchServices/WireNestHelper" "$tools/bash" "$tools/wg" "$tools/wireguard-go")
[[ -x $tools/wg-quick ]] || die "missing $tools/wg-quick"
for binary in "${machos[@]}"; do
  [[ -x $binary ]] || die "missing executable: $binary"
  [[ $(lipo -archs "$binary") == "$arch" ]] || die "$binary is $(lipo -archs "$binary"), expected only $arch"
  deps=$(otool -L "$binary" | tail -n +2 | awk '{print $1}')
  for dep in $deps; do
    case $dep in
      /usr/lib/* | /System/Library/*) ;;
      *) die "$binary links a non-system library: $dep" ;;
    esac
  done
  minos=$(vtool -show-build "$binary" | awk '$1 == "minos" {print $2}')
  [[ -n $minos ]] || die "$binary declares no minimum macOS version"
  [[ $(printf '%s\n' "$minos" "$MIN_MACOS" | sort -V | tail -n 1) == "$MIN_MACOS" ]] ||
    die "$binary requires macOS $minos, above the $MIN_MACOS minimum"
  echo "ok: $(basename "$binary"): $arch, minos $minos, system libraries only"
done

codesign --verify --strict --deep --verbose=2 "$app"

patchlevel=$("$tools/bash" -c 'declare -A probe=([k]=v); [[ ${probe[k]} == v ]] && echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]}"')
[[ $patchlevel == "$BASH_PIN_VERSION.$BASH_PIN_PATCHLEVEL" ]] || die "bundled bash is $patchlevel, expected $BASH_PIN_VERSION.$BASH_PIN_PATCHLEVEL"
"$tools/wg" --version
"$tools/wireguard-go" --version
key=$("$tools/wg" genkey)
[[ $(printf '%s' "$key" | "$tools/wg" pubkey | wc -c | tr -d ' ') -eq 45 ]] || die "wg pubkey produced an unexpected result"
usage=$(env -i "$tools/bash" "$tools/wg-quick" --help 2>&1) || die "wg-quick failed under the bundled bash"
[[ $usage == *"Usage: wg-quick"* ]] || die "wg-quick printed unexpected help output"
echo "ok: bundled bash $patchlevel runs wg-quick; wg and wireguard-go execute"
