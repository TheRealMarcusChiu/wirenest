# WireNest

WireNest is a native macOS menu-bar app for WireGuard. It keeps named connections, each holding one or more tunnels you can switch on and off separately, and runs one connection at a time.

It requires macOS 13 or later.

> **There is no installer release yet.** The repaired privileged-helper path has passed native CI and a bounded source review. Conditional full-tunnel/local-tunnel routing is now implemented but still awaits its own validation. WireNest has not been tested on physical Mac hardware or with real VPN servers, so don't rely on it to protect real traffic. See [What has been tested](#what-has-been-tested).

## Features

These are implemented, but most have not been tested end to end.

- **Connections:** create several, each with its own tunnels, and turn the active one on, off, or switch to another. If you disconnect, it stays off, even after a restart.
- **Private imports:** importing a `.conf` file copies it into storage only your account can read. Later changes to the original have no effect.
- **Editing:** duplicate a tunnel or edit its configuration, including multiple `AllowedIPs` ranges. Hooks such as `PostUp`, `SaveConfig`, and unknown settings are rejected.
- **Route conflicts:** only one tunnel can own each address family's default route. One IPv4 full tunnel can coexist with disjoint narrower tunnels only when the helper proves existing, more-specific physical-LAN or loopback routes protect their endpoints. It checks the actual kernel routes before and after startup and while running; it does not add bypass routes. Unproven protection, competing `/1` routes, overlapping narrower routes, and unsupported IPv6 overlap remain errors. This conditional mode still needs actual-default-route verification.
- **DNS:** set a primary and optional secondary server per connection. The original settings are restored afterwards, and an empty primary leaves system DNS alone. macOS does not guarantee strict failover between the two.
- **Recovery:** only the failed tunnel is restarted, with increasing delays. A tunnel isn't treated as failed just because it has been idle.
- **Network rules:** choose a connection based on the Wi-Fi name (equals or does not equal), or optionally when your public IP changes. A manual disconnect takes priority over rules. An unknown Wi-Fi name never matches a "does not equal" rule.
- **Start at login:** optionally reopen WireNest and restore your connection when you log in.

## Install

These steps apply once a release is published. There isn't one yet.

Download the DMG for your Mac from [Releases](https://github.com/TheRealMarcusChiu/wirenest/releases): `arm64` for Apple silicon, `x86_64` for Intel. Open it and drag WireNest to Applications.

WireNest is **not notarized** and has no Developer ID signature, so macOS blocks it the first time:

1. Try to open WireNest, then dismiss the warning.
2. Go to **System Settings > Privacy & Security** and choose **Open Anyway**.

You never need to turn off Gatekeeper or System Integrity Protection.

Before trusting a download, compare it with its checksum:

```sh
shasum -a 256 -c WireNest-*.dmg.sha256
```

### Administrator approval

WireGuard tunnels need root to create network interfaces and change routes, so WireNest uses a privileged helper. Expect macOS to ask for an administrator password when the helper is installed. WireNest doesn't store that password. [docs/security.md](docs/security.md) covers what the helper may do.

## Limitations

- **Reconnecting interrupts traffic.** Traffic through a tunnel stops while it restarts, and open connections may drop.
- **Login isn't boot.** Tunnels start after you log in, so nothing is protected before that.
- **Wi-Fi rules need Location permission.** macOS treats Wi-Fi names as location data. Without permission the name stays unknown, WireNest shows that it is unavailable, and rules that depend on it don't match.
- **Public IP checks are optional.** They contact a third-party service when you turn them on, and are off by default.
- **Ad-hoc signing has side effects.** Each build counts as a new app, so macOS may ask for Location permission again after an update. Login items may also be less reliable than in a Developer ID build.
- **Separate downloads.** There is no universal app, so pick the DMG for your architecture.

## What has been tested

[CI run 41760761375](https://github.com/TheRealMarcusChiu/wirenest/actions/runs/41760761375), at commit `59094ec` (before the conditional-routing changes), passed on GitHub's Apple silicon and Intel macOS 15 runners:

- All 218 Swift tests on each architecture.
- Maintainer signature checks on the upstream sources.
- Building the app and bundled tools, and checking that they link only system libraries.
- Creating, mounting, and checking the DMG.
- Starting the app and helper binaries from the DMG to confirm that they load. This shows nothing about helper installation, IPC, or caller authentication.
- A real two-tunnel test with `scripts/smoke-two-tunnels.sh`.
- The authenticated app-to-root-helper test with `scripts/smoke-helper.sh`: real installation, simultaneous tunnel traffic, independent restarts, teardown and uninstallation, with network-state restoration checked.
- A real installer ACL regression: the signed source tools were deliberately given user-write grants, installation removed the grants, and ordinary-user write/append/create attempts against the installed tools were denied.

The direct two-tunnel test uses the bundled `bash`, `wg`, `wg-quick`, and `wireguard-go` directly, without the app or helper. It starts two tunnels with throwaway keys to peers on the same machine, sends TCP traffic through each, stops one while the other keeps working, and confirms that the default route and DNS didn't change.

The app-to-helper test uses generated keys, reserved test networks and userspace peers. It does not install a default route or change DNS. Its success must not be treated as proof of the new full-tunnel/local-tunnel combination, the menu-bar UI, Wi-Fi rules, start at login, sleep/wake, or actual DNS mutation. Separate read-only observations from both native runner architectures ground the new route parser, but do not prove behavior with default-capturing routes installed.

**Not tested yet:**

- Actual-default-route behavior of the new conditional full-tunnel/local-tunnel mode
- WireNest's DNS changes and restoration
- Failure recovery and sleep/wake handling
- Using the menu-bar UI
- Wi-Fi and public IP rules on a live network
- Start at login
- Real VPN servers and physical Mac hardware
- macOS 13 and 14

[docs/security.md](docs/security.md#what-has-been-verified) has the full breakdown.

## Build from source

You need a Mac with Xcode. Run these on each architecture you want to build for, since builds are native rather than cross-compiled:

```sh
swift test
bash scripts/build-tools.sh
bash scripts/build-app.sh 0.1.0
bash scripts/make-dmg.sh 0.1.0
bash scripts/verify-dmg.sh "dist/WireNest-0.1.0-$(uname -m).dmg" "$(uname -m)"
sudo bash scripts/smoke-two-tunnels.sh .build/packaging/from-dmg/WireNest.app .build/packaging/smoke-peer
```

`verify-dmg.sh` briefly launches WireNest. The smoke test needs root because it creates real `utun` interfaces, but it only adds routes in the reserved `198.18.0.0/15` test range and removes them when it exits.

To sign with your own Developer ID certificate, set `SIGN_IDENTITY` when running `build-app.sh`. Notarizing isn't part of these scripts.

Pushing a tag like `v0.1.0` builds both architectures and creates a draft release for review.

## License and security

See `LICENSE` for WireNest's license and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the bundled tools. To report a vulnerability, follow [docs/security.md](docs/security.md).
