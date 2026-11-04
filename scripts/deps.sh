# shellcheck shell=bash
# Pinned third-party inputs and integrity helpers. Sourced, never executed.
# Compatible with macOS's bash 3.2 because this runs before the bundled bash exists.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK="$REPO_ROOT/.build/packaging"
DOWNLOADS="$WORK/downloads"

MIN_MACOS=13.0
BUNDLE_ID=com.marcuschiu.WireNest

GO_VERSION=1.27.3
GO_SHA256_arm64=dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2
GO_SHA256_amd64=b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750

BASH_PIN_VERSION=5.3
BASH_PIN_PATCHLEVEL=20
BASH_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba
BASH_PATCHES="
001:1f608434364af86b9b45c8b0ea3fb3b165fb830d27697e6cdfc7ac17dee3287f
002:e385548a00130765ec7938a56fbdca52447ab41fabc95a25f19ade527e282001
003:f245d9c7dc3f5a20d84b53d249334747940936f09dc97e1dcb89fc3ab37d60ed
004:9591d245045529f32f0812f94180b9d9ce9023f5a765c039b852e5dfc99747d0
005:cca1ef52dbbf433bc98e33269b64b2c814028efe2538be1e2c9a377da90bc99d
006:29119addefed8eff91ae37fd51822c31780ee30d4a28376e96002706c995ff10
007:c0976bbfffa1453c7cfdd62058f206a318568ff2d690f5d4fa048793fa3eb299
008:097cd723cbfb8907674ac32214063a3fd85282657ec5b4e544d2c0f719653fb4
009:eee30fe78a4b0cb2fe20e010e00308899cfc613e0774ebb3c8557a1552f24f8c
010:cf76f1cce2ea300c18bff9f002d21f280cc931acd17c28518110b93fe6e72569
011:0298df8f5ea2a31d3be43ed7d269c5b3c7c342dd5b570bea7f64d66dcbbe7531
012:d71379b39bebaedaf123414414e77fb458a0a43b9ad3116594c6df7ca6754573
013:042f9cda967e24bf4211944697441e93d06ff42b4b998629a98a1b249279f200
014:bd4360b401d38507e358783dcad8536a99c6789f0d3a5bd0cfb8c4a34144696c
015:55b79ceee2fc27f6767eed697e939a7eb2fe2a28c01556bd75f18d581014f46e
016:9ea29b266b7d24cb34d0ff3f1c4631e4d527bfe2d1ef15d17cdb924bf31ef767
017:443b927b45c1558ca72052410f8b8f6e5152b617ed707061a2781d4375b0d1c3
018:ae715d76c50341d7d7095e9a8d2eeed1ca9546152c2ac7289206f90cf30ac697
019:a25c581e4d0057dea3833918438a930e2e86ee4c6dc17fe15267b7f04cbc4e3d
020:df217ed3a9122aa2286d9b67bbe348661b6a9db262b580c29150dae55d532896
"

WG_TOOLS_VERSION=1.0.20260223
WG_TOOLS_SHA256=af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf

WG_GO_VERSION=0.0.20250522
WG_GO_SHA256=c7eeffb13e5eb43b93e54a21d78dd71414771af9e07112da5275690493695c9c

GNU_HOSTS="https://ftp.gnu.org/gnu https://ftpmirror.gnu.org"

die() {
  echo "error: $*" >&2
  exit 1
}

# Deletes the file on mismatch so a bad download can never be reused.
check_sha256() {
  local file=$1 expected=$2 actual
  if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  fi
  if [[ $actual != "$expected" ]]; then
    rm -f "$file"
    echo "error: SHA-256 mismatch for $file: expected $expected, got $actual" >&2
    return 1
  fi
}

# fetch DEST SHA256 URL...: mirrors are safe to try in turn because the pin decides.
fetch() {
  local dest=$1 sha=$2 url
  shift 2
  mkdir -p "$(dirname "$dest")"
  if [[ -f $dest ]] && check_sha256 "$dest" "$sha" 2>/dev/null; then
    return 0
  fi
  for url in "$@"; do
    if curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 -o "$dest.tmp" "$url"; then
      mv "$dest.tmp" "$dest"
      check_sha256 "$dest" "$sha" || return 1
      return 0
    fi
    echo "warning: download failed: $url" >&2
  done
  rm -f "$dest.tmp"
  echo "error: could not download $dest" >&2
  return 1
}

gnu_urls() {
  local host
  for host in $GNU_HOSTS; do
    echo "$host/$1"
  done
}

fetch_gpl_and_wireguard_sources() {
  local entry n
  # shellcheck disable=SC2046 # gnu_urls emits URLs without whitespace, one per word.
  fetch "$DOWNLOADS/bash-$BASH_PIN_VERSION.tar.gz" "$BASH_SHA256" $(gnu_urls "bash/bash-$BASH_PIN_VERSION.tar.gz")
  for entry in $BASH_PATCHES; do
    n=${entry%%:*}
    # shellcheck disable=SC2046
    fetch "$DOWNLOADS/bash53-$n" "${entry#*:}" $(gnu_urls "bash/bash-$BASH_PIN_VERSION-patches/bash53-$n")
  done
  fetch "$DOWNLOADS/wireguard-tools-$WG_TOOLS_VERSION.tar.xz" "$WG_TOOLS_SHA256" \
    "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-$WG_TOOLS_VERSION.tar.xz"
  fetch "$DOWNLOADS/wireguard-go-$WG_GO_VERSION.tar.xz" "$WG_GO_SHA256" \
    "https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-$WG_GO_VERSION.tar.xz"
}

# Tools run from a scrubbed environment so user PATH and BASH_ENV cannot reach root.
wg_quick_scrubbed() {
  local tools=$1
  shift
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin WG_QUICK_USERSPACE_IMPLEMENTATION="$tools/wireguard-go" \
    "$tools/bash" "$tools/wg-quick" "$@"
}
