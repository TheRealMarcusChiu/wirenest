#!/usr/bin/env bash
# Verifies the real DMG rather than the build tree: checks it, mounts it read-only,
# copies the app out, audits that copy, then launches its binaries for a bounded time.
# This shows that they load and do not crash at launch. It is not a UI or VPN test.
#
# Usage: scripts/verify-dmg.sh path/to/WireNest.dmg ARCH
set -euo pipefail
source "$(dirname "$0")/deps.sh"

dmg=${1:?usage: verify-dmg.sh WireNest.dmg ARCH}
arch=${2:?usage: verify-dmg.sh WireNest.dmg ARCH}
[[ $(uname -m) == "$arch" ]] || die "cannot execute $arch binaries natively on $(uname -m)"

hdiutil verify "$dmg"

mount_point="$WORK/dmg-mount"
copy="$WORK/from-dmg"
rm -rf "$copy"
mkdir -p "$mount_point" "$copy"
detach() { hdiutil detach "$mount_point" -force >/dev/null 2>&1 || true; }
trap detach EXIT
hdiutil attach "$dmg" -readonly -nobrowse -noverify -mountpoint "$mount_point"
[[ -L $mount_point/Applications ]] || die "DMG has no Applications link"
ditto "$mount_point/WireNest.app" "$copy/WireNest.app"
detach
trap - EXIT

app="$copy/WireNest.app"
bash "$REPO_ROOT/scripts/audit-app.sh" "$app" "$arch"

# The helper's command line belongs to the app; only a crash at load counts against it.
helper="$app/Contents/Library/LaunchServices/WireNestHelper"
"$helper" --help >/dev/null 2>&1 &
pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  echo "ok: helper loaded and was still running after 10s (terminated)"
else
  status=0
  wait "$pid" || status=$?
  [[ $status -lt 128 ]] || die "helper crashed at load: exit status $status"
  echo "ok: helper loaded, exit status $status"
fi

"$app/Contents/MacOS/WireNestApp" >/dev/null 2>&1 &
pid=$!
sleep 8
kill -0 "$pid" 2>/dev/null || die "WireNestApp exited within 8s of launch"
kill "$pid"
wait "$pid" 2>/dev/null || true
echo "ok: WireNestApp stayed running for 8s (launch only; no UI was exercised)"
