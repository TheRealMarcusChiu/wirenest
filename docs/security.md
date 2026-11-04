# Security

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub security advisories](https://github.com/TheRealMarcusChiu/wirenest/security/advisories/new). Don't include real private keys or configurations in a report.

## Status

**There is no installer release yet.** Security and behavior fixes to the root helper are still pending, so don't rely on CI builds to protect real traffic.

WireNest has had no independent security audit. It isn't notarized, has no Developer ID signature, and has not been tested on real Mac hardware. The requirements below describe what the design has to guarantee, not what has been proven. CI tests only part of this, as listed under [What has been verified](#what-has-been-verified).

## What needs protecting

- WireGuard private keys and tunnel configurations.
- The privileged helper, which runs as root and must not become a way for other local programs to gain root.
- System network state: routes and DNS must end up restored, including after a failure.

WireNest doesn't defend against an attacker who already has root or has taken over your user account while you are logged in. It can't protect traffic before you log in, because tunnels only start after login.

## Requirements

**Stored configurations**

- Imports are copied by value into app-owned storage: `0700` directories and `0600` files, or the Keychain for keys.
- Later changes to the original file have no effect on the import.
- This repository contains no usable keys. The smoke test generates its own and deletes them.

**Configuration validation**

- Configurations are validated on import, on edit, and again inside the helper.
- `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`, and unknown settings are rejected, as are invalid keys, endpoints, addresses, and CIDR ranges. This matters because `wg-quick` runs hook values with `eval` as root.
- Per-tunnel `DNS` is removed from the runtime configuration, because WireNest manages DNS for the whole connection.
- Keys are never logged or passed as command-line arguments.

**Privileged helper**

- The helper and its tools run from fixed, root-owned locations that normal users can't write to.
- It authenticates local callers and offers only bounded VPN operations. There is no general way to run a command as root.
- Every request is validated. It doesn't trust paths, `PATH`, or other environment values supplied by the user.
- Installation requires administrator approval. The password isn't stored, and SIP and Gatekeeper stay on.

**Running the bundled tools**

The upstream `wg-quick` starts with `#!/usr/bin/env bash`, requires Bash 4 or later, and reads `PATH`, while macOS ships Bash 3.2. It must therefore be started as `Tools/bash Tools/wg-quick ...` with a cleared environment containing only a fixed system `PATH`. Otherwise `PATH` or `BASH_ENV` could run someone else's code as root. `wg_quick_scrubbed` in `scripts/deps.sh` shows the required form for the smoke test.

## Supply chain

- `scripts/deps.sh` pins every downloaded input by SHA-256, and a mismatch stops the build and deletes the file.
- `scripts/verify-signatures.sh` runs in CI and checks the bash tarball, all 20 bash patches, and wireguard-tools against their maintainers' pinned OpenPGP fingerprints. `gpg` must succeed and report a good signature from the pinned key, so a bad, expired, revoked, or wrong key stops the build.
- The same script builds the release's source archive. It fails if a required build script, instruction file, or third-party source is missing, or if the third-party sources don't match the archive's own pins.
- wireguard-go has no upstream signature, so it relies on its SHA-256 pin. Its Go modules are verified by the upstream `go.sum`, and Go tarballs are pinned to go.dev's published hashes.
- Builds set `GOTOOLCHAIN=local` and clear Homebrew paths from the environment. `scripts/audit-app.sh` fails if any bundled binary links a non-system library.
- GitHub Actions are pinned to full commit hashes. Workflows run with read-only access, except the job that creates a draft release.
- Builds aren't reproducible byte for byte, so you can't confirm a release by rebuilding and comparing hashes.

## Signing

Default builds are ad-hoc signed, which detects accidental damage but doesn't prove who built the app. Anyone can produce an ad-hoc signature, so the signature can't establish that a download came from this project. Only compare checksums from the official release page, and remember that those checksums come from the same place as the DMG.

The helper's caller checks can't rely on an Apple-issued Team ID in ad-hoc builds. Reviewers should keep that in mind when assessing how the helper authenticates callers.

## What has been verified

These results come from [CI run 41753758485](https://github.com/TheRealMarcusChiu/wirenest/actions/runs/41753758485) at commit `6ae7ce0`, which passed on GitHub's `macos-15` (Apple silicon) and `macos-15-intel` runners. "Implemented" means the code exists, not that it works end to end.

| Area | Implemented | Tested in CI on both architectures |
|---|---|---|
| Core logic in the Swift tests | Yes | **Yes:** 112 tests, 0 failures |
| Upstream source hashes and maintainer signatures | Yes | **Yes** |
| App layout, architecture, system-only linking, macOS 13 load target, ad-hoc signature | Yes | **Yes** |
| DMG integrity, mounting, and auditing the app inside | Yes | **Yes** |
| App and helper binaries load from the DMG | Yes | **Load only:** the app stayed running for 8 seconds, and the helper ran with `--help` |
| Two simultaneous tunnels with TCP traffic, using the bundled tools directly, with one stopped independently and default route and DNS unchanged | Yes | **Yes**, without the app or helper |
| App and helper running a tunnel together | Yes, fixes pending | **No:** proof configured, not yet run |
| Root helper installation and IPC | Yes, fixes pending | **No:** proof configured, not yet run |
| Helper caller authentication, including any code-identity check | Yes, fixes pending | **No:** the `--help` launch doesn't exercise it, and the proof hasn't run |
| WireNest's DNS changes and restoration | Yes, fixes pending | **No:** the smoke test only confirms that DNS stays untouched |
| Failure recovery and sleep/wake handling | Yes, fixes pending | **No** |
| Menu-bar UI | Yes | **No** |
| Wi-Fi and public IP rules on a live network | Yes, fixes pending | **No** |
| Start at login | Yes | **No** |

Also untested: real VPN servers, physical Mac hardware, macOS 13 and 14, and Gatekeeper's first-launch flow.

### Root helper proof

CI is configured to run `scripts/smoke-helper.sh` on both architectures after the two-tunnel test. It's meant to drive the signed app's real helper client over the authenticated connection to install the root helper, start two tunnels, restart one while the other keeps working, and tear everything down.

**It hasn't run or passed yet**, and an app without the pending root helper fixes is expected to fail it. It runs only on disposable CI machines and is not an install method.

Even once it passes, it won't cover the menu-bar UI, Wi-Fi rules, start at login, sleep/wake, or WireNest changing DNS. It can't show that the whole app is ready for production use.
