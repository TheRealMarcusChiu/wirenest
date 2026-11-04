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
final="$dist/$name"
staging="$WORK/dmg-staging"
candidate_dir="$WORK/dmg-candidate"
candidate="$candidate_dir/$name"
rm -rf "$staging"
# An earlier build's image or checksum must not survive a failure here.
rm -f "$final" "$final.sha256"
mkdir -p "$staging" "$dist"
ditto "$app" "$staging/WireNest.app"
ln -s /Applications "$staging/Applications"

# Hosted runners have returned "Resource busy" from create, and also a created image that
# failed verify immediately, so every attempt is a fresh image that must pass verify.
for attempt in 1 2 3 4 5; do
  rm -rf "$candidate_dir"
  mkdir -p "$candidate_dir"
  if hdiutil create -volname WireNest -srcfolder "$staging" -fs HFS+ -format UDZO -ov "$candidate" &&
    hdiutil verify "$candidate"; then
    break
  fi
  echo "warning: DMG attempt $attempt failed create or verify; discarding it" >&2
  ls -l "$candidate_dir" >&2
  rm -rf "$candidate_dir"
  [[ $attempt -lt 5 ]] || die "no DMG passed create and verify after $attempt attempts"
  sleep $((attempt * 5))
done

# Same filesystem under the repo, so publishing is a rename of exactly the verified bytes.
(cd "$candidate_dir" && shasum -a 256 "$name" >"$name.sha256")
mv "$candidate" "$final"
mv "$candidate.sha256" "$final.sha256"
rm -rf "$candidate_dir"
echo "Built $final"
