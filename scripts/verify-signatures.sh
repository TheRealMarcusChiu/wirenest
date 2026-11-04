#!/usr/bin/env bash
# Checks the pinned sources against their maintainers' OpenPGP signatures, then writes and
# validates the corresponding-source archive published next to the DMGs.
# wireguard-go has no signature upstream, so it relies on its SHA-256 pin alone. Go
# tarballs are pinned to the hashes published by go.dev.
#
# Usage: scripts/verify-signatures.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/deps.sh"

CHET_RAMEY_FPR=7C0135FB088AAF6C66C650B9BB5869F064EA74AB
JASON_DONENFELD_FPR=AB9942E6D4A4CFC3412620A749FC7012A5DE03AE
SOURCE_PREFIX=WireNest-third-party-sources

gpg_batch() { gpg --homedir "$gnupghome" --batch --no-tty "$@"; }

download() {
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 -o "$1" "$2"
}

# The key must be the pinned maintainer's: any valid key in the GNU keyring would otherwise pass.
# GOODSIG is required too: gpg can exit 0 with VALIDSIG for an expired or revoked key.
# expect_signer FPR SIGNATURE FILE
expect_signer() {
  local fpr=$1 sig=$2 file=$3 status primary
  status=$(gpg_batch --status-fd 1 --verify "$sig" "$file" 2>/dev/null) || die "gpg rejected the signature on $file"
  [[ $status == *"[GNUPG:] GOODSIG "* ]] || die "no good signature on $file (bad, expired or revoked key)"
  primary=$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print $NF}' <<<"$status")
  [[ $primary == "$fpr" ]] || die "wrong signer on $file: '$primary'"
  echo "ok: $(basename "$file") signed by $fpr"
}

# Everything README-SOURCES.md needs to rebuild a release, relative to the archive root.
required_source_files() {
  local entry
  printf '%s\n' README-SOURCES.md SOURCE-REVISION.txt LICENSE Package.swift THIRD_PARTY_NOTICES.md \
    scripts/deps.sh scripts/build-tools.sh scripts/build-app.sh scripts/audit-app.sh \
    scripts/make-dmg.sh scripts/verify-dmg.sh scripts/smoke-two-tunnels.sh \
    scripts/smoke-peer/main.go scripts/WireNest.entitlements \
    "upstream/bash-$BASH_PIN_VERSION.tar.gz" \
    "upstream/wireguard-tools-$WG_TOOLS_VERSION.tar.xz" \
    "upstream/wireguard-go-$WG_GO_VERSION.tar.xz"
  for entry in $BASH_PATCHES; do
    echo "upstream/bash53-${entry%%:*}"
  done
}

# check_source_listing FILE: FILE holds the output of tar -tf for the archive.
check_source_listing() {
  local listing=$1 entry missing=0
  for entry in $(required_source_files); do
    if ! grep -Fxq "$SOURCE_PREFIX/$entry" "$listing"; then
      echo "error: source archive is missing $entry" >&2
      missing=1
    fi
  done
  [[ $missing -eq 0 ]]
}

write_source_archive() {
  local root="$staging/$SOURCE_PREFIX" extracted="$staging/extracted"
  local archive="$REPO_ROOT/dist/$SOURCE_PREFIX.tar" entry
  git -C "$REPO_ROOT" diff --quiet HEAD || die "uncommitted changes: the source archive must match a commit"

  mkdir -p "$root/upstream" "$extracted" "$REPO_ROOT/dist"
  git -C "$REPO_ROOT" archive --format=tar HEAD | tar -xf - -C "$root"
  cp "$REPO_ROOT/scripts/SOURCES-README.md" "$root/README-SOURCES.md"
  git -C "$REPO_ROOT" rev-parse HEAD >"$root/SOURCE-REVISION.txt"
  cp "$DOWNLOADS/bash-$BASH_PIN_VERSION.tar.gz" "$DOWNLOADS/wireguard-tools-$WG_TOOLS_VERSION.tar.xz" \
    "$DOWNLOADS/wireguard-go-$WG_GO_VERSION.tar.xz" "$root/upstream/"
  for entry in $BASH_PATCHES; do
    cp "$DOWNLOADS/bash53-${entry%%:*}" "$root/upstream/"
  done
  tar -cf "$archive" -C "$staging" "$SOURCE_PREFIX"

  tar -tf "$archive" >"$staging/listing"
  check_source_listing "$staging/listing" || die "source archive is incomplete"

  # Follow the README's preparation step from the archive alone: the pins in its own
  # deps.sh must accept its own upstream files, with no network to fall back on.
  tar -xf "$archive" -C "$extracted"
  (
    cd "$extracted/$SOURCE_PREFIX"
    mkdir -p .build/packaging
    cp -R upstream .build/packaging/downloads
    source scripts/deps.sh
    curl() { die "source archive is not self-contained: tried to download ${*: -1}"; }
    fetch_gpl_and_wireguard_sources
  )
  echo "ok: source archive is complete and its upstream files match its pins"
  echo "Wrote $archive"
}

main() {
  fetch_gpl_and_wireguard_sources

  gnupghome=$(mktemp -d)
  staging=$(mktemp -d)
  trap 'rm -rf "$gnupghome" "$staging"' EXIT

  download "$gnupghome/gnu-keyring.gpg" https://ftp.gnu.org/gnu/gnu-keyring.gpg
  download "$gnupghome/zx2c4.asc" "https://keys.openpgp.org/vks/v1/by-fingerprint/$JASON_DONENFELD_FPR"
  # The GNU keyring holds legacy keys gpg refuses, so judge the import by the keys we need.
  gpg_batch --quiet --import "$gnupghome/gnu-keyring.gpg" "$gnupghome/zx2c4.asc" 2>/dev/null ||
    echo "note: gpg reported errors importing the keyrings; checking the pinned keys next"
  gpg_batch --list-keys "$CHET_RAMEY_FPR" >/dev/null 2>&1 || die "pinned key $CHET_RAMEY_FPR was not imported"
  gpg_batch --list-keys "$JASON_DONENFELD_FPR" >/dev/null 2>&1 || die "pinned key $JASON_DONENFELD_FPR was not imported"

  local base="bash/bash-$BASH_PIN_VERSION" entry n
  download "$gnupghome/bash.sig" "https://ftp.gnu.org/gnu/$base.tar.gz.sig"
  expect_signer "$CHET_RAMEY_FPR" "$gnupghome/bash.sig" "$DOWNLOADS/bash-$BASH_PIN_VERSION.tar.gz"
  for entry in $BASH_PATCHES; do
    n=${entry%%:*}
    download "$gnupghome/patch.sig" "https://ftp.gnu.org/gnu/$base-patches/bash53-$n.sig"
    expect_signer "$CHET_RAMEY_FPR" "$gnupghome/patch.sig" "$DOWNLOADS/bash53-$n"
  done

  # zx2c4 signs the uncompressed tar.
  local tools_name="wireguard-tools-$WG_TOOLS_VERSION"
  download "$gnupghome/tools.asc" "https://git.zx2c4.com/wireguard-tools/snapshot/$tools_name.tar.asc"
  xz -dc "$DOWNLOADS/$tools_name.tar.xz" >"$gnupghome/$tools_name.tar"
  expect_signer "$JASON_DONENFELD_FPR" "$gnupghome/tools.asc" "$gnupghome/$tools_name.tar"

  write_source_archive
}

# test-packaging.sh sources this file to test the checks above with fake gpg results.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
