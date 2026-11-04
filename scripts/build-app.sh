#!/usr/bin/env bash
# Builds the SwiftPM products and assembles a signed WireNest.app for this Mac's
# architecture. Run build-tools.sh first.
#
# Usage: scripts/build-app.sh VERSION [BUILD_NUMBER]
# SIGN_IDENTITY selects a Developer ID certificate; the default "-" is ad-hoc signing.
set -euo pipefail
source "$(dirname "$0")/deps.sh"

[[ $(uname -s) == Darwin ]] || die "build-app.sh must run on macOS"
version=${1:?usage: build-app.sh VERSION [BUILD_NUMBER]}
build_number=${2:-1}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must look like 1.2.3, got: $version"
[[ $build_number =~ ^[0-9]+$ ]] || die "BUILD_NUMBER must be numeric, got: $build_number"
[[ -f $REPO_ROOT/Package.swift ]] || die "Package.swift not found: the app sources are not in this checkout"
[[ -f $REPO_ROOT/LICENSE ]] || die "LICENSE not found"
[[ -x $WORK/tools/bash && -x $WORK/tools/wg && -x $WORK/tools/wg-quick && -x $WORK/tools/wireguard-go ]] ||
  die "bundled tools are missing: run scripts/build-tools.sh first"

arch=$(uname -m)
sign_identity=${SIGN_IDENTITY:--}

cd "$REPO_ROOT"
swift build -c release --product WireNestApp
swift build -c release --product WireNestHelper
bin=$(swift build -c release --show-bin-path)

app="$WORK/app/WireNest.app"
rm -rf "$WORK/app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchServices" "$app/Contents/Resources/Tools" "$app/Contents/Resources/Licenses"

cp "$bin/WireNestApp" "$app/Contents/MacOS/WireNestApp"
cp "$bin/WireNestHelper" "$app/Contents/Library/LaunchServices/WireNestHelper"
cp "$WORK/tools/bash" "$WORK/tools/wg" "$WORK/tools/wg-quick" "$WORK/tools/wireguard-go" "$app/Contents/Resources/Tools/"
cp -R "$WORK/licenses/" "$app/Contents/Resources/Licenses/"
cp LICENSE "$app/Contents/Resources/Licenses/WireNest-LICENSE"
cp THIRD_PARTY_NOTICES.md "$app/Contents/Resources/Licenses/"
find "$bin" -maxdepth 1 -name '*.bundle' -exec cp -R {} "$app/Contents/Resources/" \;

cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>WireNest</string>
  <key>CFBundleExecutable</key><string>WireNestApp</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>WireNest</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$build_number</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_MACOS</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocationUsageDescription</key><string>WireNest reads the current Wi-Fi network name to apply your network rules. macOS treats Wi-Fi names as location data. Your location is not stored or sent anywhere.</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>WireNest reads the current Wi-Fi network name to apply your network rules. macOS treats Wi-Fi names as location data. Your location is not stored or sent anywhere.</string>
</dict>
</plist>
EOF
plutil -lint "$app/Contents/Info.plist"

# Inside-out, not --deep: each nested binary gets an explicit identifier and flags.
sign() { codesign --force --sign "$sign_identity" "$@"; }
if [[ $sign_identity == "-" ]]; then
  for tool in bash wg wireguard-go; do
    sign --identifier "$BUNDLE_ID.tools.$tool" "$app/Contents/Resources/Tools/$tool"
  done
  sign --identifier "$BUNDLE_ID.helper" "$app/Contents/Library/LaunchServices/WireNestHelper"
  sign --identifier "$BUNDLE_ID" "$app"
else
  for tool in bash wg wireguard-go; do
    sign --options runtime --identifier "$BUNDLE_ID.tools.$tool" "$app/Contents/Resources/Tools/$tool"
  done
  sign --options runtime --identifier "$BUNDLE_ID.helper" "$app/Contents/Library/LaunchServices/WireNestHelper"
  # Hardened runtime blocks Location, needed for SSID rules, unless entitled.
  sign --options runtime --entitlements "$REPO_ROOT/scripts/WireNest.entitlements" --identifier "$BUNDLE_ID" "$app"
fi

bash "$REPO_ROOT/scripts/audit-app.sh" "$app" "$arch"
echo "Built $app"
