Download the DMG for your Mac: `arm64` for Apple silicon, `x86_64` for Intel. Each has a `.sha256` file beside it.

**This build is not notarized.** It is ad-hoc signed and has no Developer ID, so macOS blocks it on first launch. See the README for how to open it without turning off Gatekeeper.

**What CI ran on each architecture:** Swift tests, DMG and signature verification, a brief launch of the app and helper binaries, and a two-tunnel test of the bundled `wg-quick` and `wireguard-go`.

**What CI did not run:** the menu-bar UI, helper installation, WireNest's DNS management, sleep/wake recovery, network rules, or real VPN servers. These need testing on a real Mac.

Reconnecting a tunnel interrupts its traffic. Tunnels start after you log in, not before.

`WireNest-third-party-sources.tar` contains the source for the bundled GPL and WireGuard tools. See `THIRD_PARTY_NOTICES.md`.
