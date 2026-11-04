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
  scripts/make-dmg.sh scripts/smoke-helper.sh upstream/bash53-020 "upstream/wireguard-tools-$WG_TOOLS_VERSION.tar.xz"; do
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

# The helper proof is an acceptance gate: exact unprivileged command, bounded, after the
# direct smoke test, with nothing able to hide its failure or widen the job's access.
helper_run='run: bash scripts/smoke-helper.sh .build/packaging/from-dmg/WireNest.app .build/packaging/smoke-peer'
helper_step_is_gated() {
  local workflow=$1 direct helper
  direct=$(grep -nF 'run: sudo bash scripts/smoke-two-tunnels.sh' "$workflow" | cut -d: -f1 || true)
  helper=$(grep -nFx "        $helper_run" "$workflow" | cut -d: -f1 || true)
  [[ -n $direct && -n $helper && $helper -gt $direct ]] &&
    [[ $(sed -n "$((helper - 1))p" "$workflow") == '        timeout-minutes: 10' ]] &&
    ! grep -Eq 'continue-on-error|\|\| *true|contents: write|secrets\.' "$workflow"
}
workflow=.github/workflows/macos.yml
helper_step_is_gated "$workflow" && pass "helper proof is gated in CI" || fail "helper proof step is missing or weakened"
sed 's#run: bash scripts/smoke-helper#run: sudo bash scripts/smoke-helper#' "$workflow" >"$scratch/sudo.yml"
{ cat "$workflow"; echo '        continue-on-error: true'; } >"$scratch/soft.yml"
sed 's#^\( *\)timeout-minutes: 10$#\1timeout-minutes: 30#' "$workflow" >"$scratch/slow.yml"
{ echo '        timeout-minutes: 10'; echo "        $helper_run"; grep -Fv "$helper_run" "$workflow"; } >"$scratch/early.yml"
for variant in sudo soft slow early; do
  helper_step_is_gated "$scratch/$variant.yml" && fail "helper gate accepted the $variant variant" || pass "helper gate rejected the $variant variant"
done

# Blocked until lane C's script is integrated: CI would otherwise fail much later on a Mac.
[[ -f scripts/smoke-helper.sh ]] && pass "scripts/smoke-helper.sh present" || fail "scripts/smoke-helper.sh is missing from this checkout"

# The full-route experiment captures the default route, so only an explicit manual dispatch
# may start it, after the mandatory helper proof. Static checks: nothing here runs it.
full_route_run='run: bash scripts/smoke-full-route.sh .build/packaging/from-dmg/WireNest.app .build/packaging/smoke-peer'
full_route_if="if: github.event_name == 'workflow_dispatch' && inputs.full_route_proof == true"
full_route_is_opt_in() {
  local workflow=$1 release=$2 dispatch call input options helper run
  dispatch=$(grep -nx '  workflow_dispatch:' "$workflow" | cut -d: -f1 || true)
  call=$(grep -nx '  workflow_call:' "$workflow" | cut -d: -f1 || true)
  input=$(grep -nE '^ *full_route_proof:' "$workflow" | cut -d: -f1 || true)
  helper=$(grep -nFx "        $helper_run" "$workflow" | cut -d: -f1 || true)
  run=$(grep -nFx "        $full_route_run" "$workflow" | cut -d: -f1 || true)
  [[ $dispatch =~ ^[0-9]+$ && $call =~ ^[0-9]+$ && $input =~ ^[0-9]+$ && $helper =~ ^[0-9]+$ && $run =~ ^[0-9]+$ ]] || return 1
  [[ $dispatch -lt $input && $input -lt $call && $helper -lt $run ]] || return 1
  options=$(awk -v start="$input" 'NR > start { if (!/^        /) exit; print }' "$workflow")
  [[ $'\n'$options$'\n' == *$'\n        type: boolean\n'* && $'\n'$options$'\n' == *$'\n        default: false\n'* ]] || return 1
  [[ $(sed -n "$((run - 1))p" "$workflow") == '        timeout-minutes: 10' ]] || return 1
  [[ $(sed -n "$((run - 2))p" "$workflow") == "        $full_route_if" ]] || return 1
  [[ $(sed -n "$((run - 3))p" "$workflow") == '      - name: '* ]] || return 1
  [[ $run -eq $(grep -c '' "$workflow") && $(grep -c 'smoke-full-route' "$workflow") -eq 1 ]] || return 1
  ! grep -q 'full_route_proof' "$release" && helper_step_is_gated "$workflow"
}
release=.github/workflows/release.yml
full_route_is_opt_in "$workflow" "$release" && pass "full-route proof is manual opt-in only" || fail "full-route step is missing or not opt-in"
full_route_line=$(grep -nFx "        $full_route_run" "$workflow" | cut -d: -f1 || true)
if [[ -n $full_route_line ]]; then
  sed 's/^        default: false$/        default: true/' "$workflow" >"$scratch/on-by-default.yml"
  sed 's/^        type: boolean$/        type: string/' "$workflow" >"$scratch/not-boolean.yml"
  grep -Fv 'inputs.full_route_proof == true' "$workflow" >"$scratch/unconditional.yml"
  sed "s/^        if: github.event_name == .*/        if: always()/" "$workflow" >"$scratch/always.yml"
  sed "s/^        if: github.event_name == .*/        if: inputs.full_route_proof == true/" "$workflow" >"$scratch/any-event.yml"
  sed 's#run: bash scripts/smoke-full-route#run: sudo bash scripts/smoke-full-route#' "$workflow" >"$scratch/root.yml"
  sed "$((full_route_line - 1))s/timeout-minutes: 10/timeout-minutes: 45/" "$workflow" >"$scratch/long.yml"
  sed "$((full_route_line - 1))d" "$workflow" >"$scratch/unbounded.yml"
  awk '{print} /^  workflow_call:$/ {print "      full_route_proof:"}' "$workflow" >"$scratch/callable.yml"
  { cat "$workflow"; echo '      - name: Later step'; } >"$scratch/not-last.yml"
  sed -n "$((full_route_line - 3)),${full_route_line}p" "$workflow" >"$scratch/step"
  sed "$((full_route_line - 3)),${full_route_line}d" "$workflow" |
    awk -v step="$scratch/step" '/- name: Real app-to-root-helper/ { while ((getline line <step) > 0) print line } {print}' >"$scratch/premature.yml"
  sed 's#run: bash scripts/smoke-helper#run: sudo bash scripts/smoke-helper#' "$workflow" >"$scratch/helper-weakened.yml"
  for variant in on-by-default not-boolean unconditional always any-event root long unbounded callable not-last premature helper-weakened; do
    full_route_is_opt_in "$scratch/$variant.yml" "$release" && fail "full-route gate accepted the $variant variant" || pass "full-route gate rejected the $variant variant"
  done
  { cat "$release"; echo '      full_route_proof: true'; } >"$scratch/release.yml"
  full_route_is_opt_in "$workflow" "$scratch/release.yml" && fail "full-route gate accepted a release call" || pass "full-route gate rejected a release call"
fi

# Deliberately not a failure: this step only runs on manual dispatch, so normal CI doesn't need the script.
if [[ -f scripts/smoke-full-route.sh ]]; then
  echo "note: scripts/smoke-full-route.sh present; not run by these checks"
else
  echo "note: scripts/smoke-full-route.sh not in this checkout; dispatching with full_route_proof=true would fail until it is integrated"
fi

[[ $fails -eq 0 ]] || die "$fails check(s) failed"
echo "All packaging self-checks passed."
