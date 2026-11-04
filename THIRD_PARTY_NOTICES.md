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

Each release includes `WireNest-third-party-sources.tar`, which contains the exact bash tarball and patches, the wireguard-tools tarball, and the wireguard-go tarball used for that release. `scripts/build-tools.sh` in this repository holds the build instructions, and `scripts/deps.sh` lists the SHA-256 pin of every input.

## Used only for testing

The smoke-test peer in `scripts/smoke-peer` is never included in the app. It also links gVisor (Apache-2.0) through wireguard-go's `tun/netstack` package.

WireGuard is a registered trademark of Jason A. Donenfeld. WireNest is not affiliated with or endorsed by the WireGuard project.
