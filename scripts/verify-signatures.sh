#!/usr/bin/env bash
# Checks the pinned sources against their maintainers' OpenPGP signatures, then writes the
# corresponding-source archive published next to the DMGs for the GPL components.
# wireguard-go has no signature upstream, so it relies on its SHA-256 pin alone. Go
# tarballs are pinned to the hashes published by go.dev.
#
# Usage: scripts/verify-signatures.sh
set -euo pipefail
source "$(dirname "$0")/deps.sh"

CHET_RAMEY_FPR=7C0135FB088AAF6C66C650B9BB5869F064EA74AB
JASON_DONENFELD_FPR=AB9942E6D4A4CFC3412620A749FC7012A5DE03AE

fetch_gpl_and_wireguard_sources

gnupghome=$(mktemp -d)
trap 'rm -rf "$gnupghome"' EXIT
gpg_batch() { gpg --homedir "$gnupghome" --batch --no-tty "$@"; }

download() {
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 -o "$1" "$2"
}
download "$gnupghome/gnu-keyring.gpg" https://ftp.gnu.org/gnu/gnu-keyring.gpg
download "$gnupghome/zx2c4.asc" "https://keys.openpgp.org/vks/v1/by-fingerprint/$JASON_DONENFELD_FPR"
gpg_batch --quiet --import "$gnupghome/gnu-keyring.gpg" "$gnupghome/zx2c4.asc" 2>/dev/null || true

# The key must be the pinned maintainer's: any valid key in the GNU keyring would otherwise pass.
# expect_signer FPR SIGNATURE FILE
expect_signer() {
  local fpr=$1 sig=$2 file=$3 primary
  primary=$(gpg_batch --status-fd 1 --verify "$sig" "$file" 2>/dev/null | awk '$2 == "VALIDSIG" {print $NF}' || true)
  [[ $primary == "$fpr" ]] || die "bad or wrong signer on $file: '$primary'"
  echo "ok: $(basename "$file") signed by $fpr"
}

base="bash/bash-$BASH_PIN_VERSION"
download "$gnupghome/bash.sig" "https://ftp.gnu.org/gnu/$base.tar.gz.sig"
expect_signer "$CHET_RAMEY_FPR" "$gnupghome/bash.sig" "$DOWNLOADS/bash-$BASH_PIN_VERSION.tar.gz"
for entry in $BASH_PATCHES; do
  n=${entry%%:*}
  download "$gnupghome/patch.sig" "https://ftp.gnu.org/gnu/$base-patches/bash53-$n.sig"
  expect_signer "$CHET_RAMEY_FPR" "$gnupghome/patch.sig" "$DOWNLOADS/bash53-$n"
done

# zx2c4 signs the uncompressed tar.
tools_name="wireguard-tools-$WG_TOOLS_VERSION"
download "$gnupghome/tools.asc" "https://git.zx2c4.com/wireguard-tools/snapshot/$tools_name.tar.asc"
xz -dc "$DOWNLOADS/$tools_name.tar.xz" >"$gnupghome/$tools_name.tar"
expect_signer "$JASON_DONENFELD_FPR" "$gnupghome/tools.asc" "$gnupghome/$tools_name.tar"

mkdir -p "$REPO_ROOT/dist"
archive="$REPO_ROOT/dist/WireNest-third-party-sources.tar"
patches=()
for entry in $BASH_PATCHES; do patches+=("bash53-${entry%%:*}"); done
tar -cf "$archive" -C "$DOWNLOADS" "bash-$BASH_PIN_VERSION.tar.gz" "${patches[@]}" \
  "$tools_name.tar.xz" "wireguard-go-$WG_GO_VERSION.tar.xz"
echo "Wrote $archive"
