#!/usr/bin/env bash
# Packages the assembled app into dist/WireNest-VERSION-ARCH.dmg with a checksum file.
#
# Usage: scripts/make-dmg.sh VERSION
set -euo pipefail
source "$(dirname "$0")/deps.sh"

version=${1:?usage: make-dmg.sh VERSION}
arch=$(uname -m)
app="$WORK/app/WireNest.app"
[[ -d $app ]] || die "$app not found: run scripts/build-app.sh first"

dist="$REPO_ROOT/dist"
name="WireNest-$version-$arch.dmg"
staging="$WORK/dmg-staging"
rm -rf "$staging"
mkdir -p "$staging" "$dist"
ditto "$app" "$staging/WireNest.app"
ln -s /Applications "$staging/Applications"

# hdiutil on hosted runners intermittently reports "Resource busy", so retry it.
for attempt in 1 2 3 4 5; do
  if hdiutil create -volname WireNest -srcfolder "$staging" -fs HFS+ -format UDZO -ov "$dist/$name"; then
    break
  fi
  [[ $attempt -lt 5 ]] || die "hdiutil create failed after $attempt attempts"
  sleep $((attempt * 5))
done
hdiutil verify "$dist/$name"
(cd "$dist" && shasum -a 256 "$name" >"$name.sha256")
echo "Built $dist/$name"
