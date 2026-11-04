# Third-party notices

WireNest bundles the programs below in `WireNest.app/Contents/Resources/Tools` and runs them as separate processes. Their license texts are in `Contents/Resources/Licenses`. WireNest's own license is in `LICENSE`.

| Component | Version | License | Source |
|---|---|---|---|
| GNU Bash (`bash`) | 5.3, patch level 20 | GPL-3.0-or-later | <https://ftp.gnu.org/gnu/bash/> |
| wireguard-tools (`wg`, `wg-quick`) | 1.0.20260223 | GPL-2.0-only | <https://git.zx2c4.com/wireguard-tools/> |
| wireguard-go (`wireguard-go`) | 0.0.20250522 | MIT | <https://git.zx2c4.com/wireguard-go/> |

`wireguard-go` is built with Go 1.27.3 and links the Go standard library (BSD-3-Clause) and the `golang.org/x` modules it depends on (BSD-3-Clause). The build copies the license of every linked module into `Licenses/go-modules`.

## Changes from upstream

- **bash:** the official upstream patches `bash53-001` to `bash53-020` are applied. It is configured without NLS and readline.
- **`wg`:** unmodified source.
- **`wg-quick`:** an unmodified copy of `src/wg-quick/darwin.bash`.
- **`wireguard-go`:** unmodified source.

## Source code for the GPL components

Each release is published with `WireNest-third-party-sources.tar`, which contains:

- The exact bash tarball and patches, wireguard-tools tarball, and wireguard-go tarball used for that release, with their upstream license files.
- The WireNest source tree for that release, including the scripts that build these tools and package them into the app.
- `scripts/deps.sh`, which lists the SHA-256 hash of each input.
- `SOURCE-REVISION.txt`, which names the WireNest commit.
- `README-SOURCES.md`, which has the rebuild instructions.

CI fails if any of these required files is missing from the archive, or if the third-party files don't match their hashes.

A rebuild also downloads the Go toolchain and the Go modules that `wireguard-go` uses. These aren't in the archive and aren't GPL-licensed. Xcode and the macOS SDK come from Apple and aren't included either.

## Used only for testing

The smoke-test peer in `scripts/smoke-peer` is never included in the app. It also links gVisor (Apache-2.0) through wireguard-go's `tun/netstack` package.

WireGuard is a registered trademark of Jason A. Donenfeld. WireNest is not affiliated with or endorsed by the WireGuard project.
