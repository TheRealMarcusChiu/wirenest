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
