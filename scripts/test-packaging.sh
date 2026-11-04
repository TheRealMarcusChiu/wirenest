#!/usr/bin/env bash
# Portable self-checks for the packaging scripts. Runs on Linux and macOS, and never
# touches routing. Uses shellcheck when installed.
set -euo pipefail
source "$(dirname "$0")/deps.sh"
cd "$REPO_ROOT"

fails=0
pass() { echo "ok: $*"; }
fail() {
  echo "FAIL: $*" >&2
  fails=$((fails + 1))
}

scripts=(scripts/*.sh)
for script in "${scripts[@]}"; do
  bash -n "$script" && pass "syntax $script" || fail "syntax $script"
done
if command -v shellcheck >/dev/null; then
  shellcheck -S error "${scripts[@]}" && pass shellcheck || fail shellcheck
else
  echo "skip: shellcheck not installed"
fi

sha_pattern='^[0-9a-f]{64}$'
for sha in "$GO_SHA256_arm64" "$GO_SHA256_amd64" "$BASH_SHA256" "$WG_TOOLS_SHA256" "$WG_GO_SHA256"; do
  [[ $sha =~ $sha_pattern ]] && pass "pin format ${sha:0:12}" || fail "pin format $sha"
done
expected=0
for entry in $BASH_PATCHES; do
  expected=$((expected + 1))
  [[ ${entry%%:*} == "$(printf %03d "$expected")" && ${entry#*:} =~ $sha_pattern ]] || fail "bash patch entry $entry"
done
[[ $expected -eq $BASH_PIN_PATCHLEVEL ]] && pass "patch list matches patchlevel" || fail "patch count $expected != $BASH_PIN_PATCHLEVEL"

mkdir -p "$WORK"
scratch=$(mktemp -d "$WORK/test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
printf 'abc' >"$scratch/good"
check_sha256 "$scratch/good" ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad &&
  pass "check_sha256 accepts a match" || fail "check_sha256 rejected a match"
printf 'tampered' >"$scratch/bad"
if check_sha256 "$scratch/bad" ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad 2>/dev/null; then
  fail "check_sha256 accepted a mismatch"
elif [[ -e $scratch/bad ]]; then
  fail "check_sha256 kept a mismatched file"
else
  pass "check_sha256 rejects and deletes a mismatch"
fi

if [[ $(uname -s) != Darwin ]]; then
  if bash scripts/smoke-two-tunnels.sh /nonexistent /nonexistent >"$scratch/smoke.out" 2>&1; then
    fail "smoke test ran off macOS"
  elif grep -q 'refusing to touch routing' "$scratch/smoke.out"; then
    pass "smoke test refuses to run off macOS"
  else
    fail "smoke test failed for an unexpected reason: $(cat "$scratch/smoke.out")"
  fi
fi

# Signature policy, with gpg faked so no real keys or downloads are involved.
source scripts/verify-signatures.sh
gpg_batch() {
  printf '%s\n' "$fake_status"
  return "$fake_rc"
}
validsig() { echo "[GNUPG:] VALIDSIG AAAA 2025-01-01 0 0 4 0 1 10 00 $1"; }
signer_case() {
  local name=$1 want=$2 got=rejected
  fake_rc=$3
  fake_status=$4
  if (expect_signer "$JASON_DONENFELD_FPR" sig file) >/dev/null 2>&1; then got=accepted; fi
  [[ $got == "$want" ]] && pass "expect_signer $want: $name" || fail "expect_signer $got: $name"
}
pinned=$(validsig "$JASON_DONENFELD_FPR")
other=$(validsig "$CHET_RAMEY_FPR")
signer_case "good signature from the pinned key" accepted 0 "[GNUPG:] GOODSIG K N"$'\n'"$pinned"
signer_case "pinned VALIDSIG but gpg failed" rejected 1 "[GNUPG:] GOODSIG K N"$'\n'"$pinned"
signer_case "wrong fingerprint" rejected 0 "[GNUPG:] GOODSIG K N"$'\n'"$other"
signer_case "no VALIDSIG" rejected 0 "[GNUPG:] GOODSIG K N"
signer_case "malformed output naming the pinned key" rejected 0 "GOODSIG VALIDSIG $JASON_DONENFELD_FPR"
signer_case "empty output" rejected 0 ""
signer_case "expired key, gpg exit 0" rejected 0 "[GNUPG:] EXPKEYSIG K N"$'\n'"$pinned"
signer_case "revoked key, gpg exit 0" rejected 0 "[GNUPG:] REVKEYSIG K N"$'\n'"$pinned"
signer_case "two signers, one pinned" rejected 0 "[GNUPG:] GOODSIG K N"$'\n'"$pinned"$'\n'"$other"

# Source archive completeness, tested against listings so no archive is built here.
required_source_files | awk -v p="$SOURCE_PREFIX/" '{print p $0}' >"$scratch/listing"
if check_source_listing "$scratch/listing" 2>/dev/null; then
  pass "complete source listing accepted"
else
  fail "complete source listing rejected"
fi
for missing in README-SOURCES.md SOURCE-REVISION.txt scripts/build-tools.sh scripts/build-app.sh scripts/deps.sh \
  scripts/make-dmg.sh upstream/bash53-020 "upstream/wireguard-tools-$WG_TOOLS_VERSION.tar.xz"; do
  grep -Fxv "$SOURCE_PREFIX/$missing" "$scratch/listing" >"$scratch/listing.short" || true
  if check_source_listing "$scratch/listing.short" 2>/dev/null; then
    fail "source listing accepted without $missing"
  else
    pass "source listing rejected without $missing"
  fi
done
sed "s#^$SOURCE_PREFIX/#$SOURCE_PREFIX/elsewhere/#" "$scratch/listing" >"$scratch/listing.moved"
if check_source_listing "$scratch/listing.moved" 2>/dev/null; then
  fail "source listing accepted files at the wrong paths"
else
  pass "source listing rejected files at the wrong paths"
fi
# Every scripts/ file the instructions run must be required, so CI catches its loss.
for script in $(grep -Eo 'scripts/[A-Za-z0-9_.-]+\.sh' scripts/SOURCES-README.md | sort -u); do
  grep -Fxq "$SOURCE_PREFIX/$script" "$scratch/listing" && pass "required: $script" || fail "$script is in the instructions but not required"
done

# Smoke isolation: a default route or DNS line in its template would be disruptive.
if grep -Eq '^(DNS|PreUp|PostUp|PreDown|PostDown|SaveConfig|Table) *=|0\.0\.0\.0/|::/0|networksetup -set' scripts/smoke-two-tunnels.sh; then
  fail "smoke test contains a directive that could touch default routing, DNS or hooks"
else
  pass "smoke test has no default-route, DNS or hook directives"
fi

# Third-party actions run with the repository's token, so tags are not acceptable pins.
unpinned=$(grep -hE '^\s*(- )?uses:' .github/workflows/*.yml | grep -vE 'uses: *(\./|[^@]+@[0-9a-f]{40}( |$))' || true)
[[ -z $unpinned ]] && pass "workflow actions pinned to commits" || fail "unpinned actions: $unpinned"

[[ $fails -eq 0 ]] || die "$fails check(s) failed"
echo "All packaging self-checks passed."
