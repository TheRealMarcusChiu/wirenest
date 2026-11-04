# WireNest implementation plan

WireNest is a native macOS 13+ menu-bar app that runs one active named connection, made of one or
more simultaneous WireGuard tunnels with independent toggles. This document records the
architecture, the contract with packaging, and what has and has not been verified.

## Verification status

No Swift toolchain exists on the host where this code was written. **Nothing here has been compiled
or run yet.** Tests were written first but RED could not be observed. Compiler, `swift test` and
real-Mac evidence are deferred to macOS CI and hands-on testing. Until then, treat every behavior
below as designed, not proven.

## Targets

| Target | Kind | Purpose |
| --- | --- | --- |
| `WireNestCore` | library | Parser, routes, state, rules, health, helper engine. No UI. |
| `WireNestApp` | executable | SwiftUI/AppKit menu-bar app. |
| `WireNestHelper` | executable | Root launchd daemon and installer. |
| `WireNestCoreTests` | tests | XCTest suite for core and engine. |

Privileged logic lives in `HelperEngine` (core) behind `CommandRunning`, so tests exercise production
logic with only the subprocess edge replaced. The helper target adds XPC, install and `Process`.

## Contract with packaging

### Bundle layout (frozen)

```
WireNest.app/Contents/MacOS/WireNestApp
WireNest.app/Contents/Library/LaunchServices/WireNestHelper
WireNest.app/Contents/Resources/Tools/{bash,wg,wg-quick,wireguard-go}
```

### Info.plist

- `CFBundleIdentifier` = `com.marcuschiu.WireNest`, `CFBundleExecutable` = `WireNestApp`,
  `CFBundleName` = `WireNest`, `LSUIElement` = true, `LSMinimumSystemVersion` = `13.0`.
- `NSLocationUsageDescription` and `NSLocationWhenInUseUsageDescription`: macOS gives the Wi-Fi name
  only with Location permission. Suggested text: "WireNest uses your Wi-Fi network name to choose a
  connection when you create Wi-Fi rules. Your location is not used or stored."

### Signing requirements the installer enforces

The installer refuses a bundle that fails these, so packaging must:

1. Sign inside-out: each binary in `Tools/` that is Mach-O, then `WireNestHelper`, then the app.
2. Use identifier `com.marcuschiu.WireNest` for the app bundle. Ad-hoc (`codesign -s -`) is accepted.
3. Leave the signed bundle untouched afterwards: `SecStaticCodeCheckValidity` checks all
   architectures, nested code and sealed resources, including `Tools/wg-quick`.

### Tools

`wg-quick` must be the upstream Darwin script. It is run as `Tools/bash Tools/wg-quick up <conf>`.
Upstream prepends its own directory to `PATH`, so `wg` and `wireguard-go` must sit next to it. `bash`
must be 4+ and must not depend on non-system dylibs: the tools run from the root-owned install dir.

### Privileged installation protocol

`AppController` runs the following through `NSAppleScript` (Apple TN2065), so macOS shows the
administrator prompt. WireNest never sees the password. This needs no Developer ID, unlike
`SMAppService.daemon` and `SMJobBless`.

```
do shell script (quoted form of "<app>/Contents/Library/LaunchServices/WireNestHelper") & " '--install' '--uid' '<uid>'" with administrator privileges
```

| Item | Value |
| --- | --- |
| launchd label and Mach service | `com.marcuschiu.WireNest.helper` |
| launchd plist | `/Library/LaunchDaemons/com.marcuschiu.WireNest.helper.plist` |
| Install dir (root:wheel, 0755) | `/Library/PrivilegedHelperTools/com.marcuschiu.WireNest/` |
| Installed files | `WireNestHelper`, `Tools/*`, `client.json` (0644) |
| Runtime dir (root, 0700) | `/var/run/com.marcuschiu.WireNest/` holds `wnN.conf`, `session.json` |
| Durable dir (root, 0700) | `/Library/Application Support/com.marcuschiu.WireNest/` holds `dns-snapshot.json` |

Helper commands: `--help`, `--version`, `--install --uid <uid>`, `--uninstall` and `--daemon`. The
first two need no root and are safe for CI. The app also answers `WireNestApp --version` without
starting its UI.

## Security model

- **Install.** As root, verify the bundle signature, then copy the helper and tools out of the
  user-writable bundle into a root-owned directory. Nothing user-writable executes as root.
- **Caller authentication.** The listener's `setConnectionCodeSigningRequirement` pins the CDHash of
  this app build (native architecture), and `effectiveUserIdentifier` pins the installing user. The
  pin file counts only if it is root-owned and not group- or world-writable.
- **Bounded API.** One XPC method takes JSON that decodes into five request cases: `status`, `up`,
  `down`, `downAll`, `setDNS`. No request can name an executable, path or argument.
- **Re-validation.** The helper re-parses every config and re-checks route conflicts and DNS. It writes
  only text generated from typed fields, never the text it received.
- **Subprocesses.** Fixed absolute paths, a fixed `PATH`, no shell, a hard timeout.
- **Keys.** The app stores them in a 0600 file inside a 0700 directory
  (`~/Library/Application Support/WireNest/state.json`), chosen over Keychain because ad-hoc builds
  have unstable Keychain ACLs. At runtime keys sit in a root-only 0600 file deleted on `down`. They
  never appear in argv: `wg-quick` feeds `wg` through a file descriptor, and status uses
  `latest-handshakes` and `transfer`, never `dump`. Tool output is scrubbed of key-shaped text.

## Behavior

### Connections and tunnels

A connection holds 1..N tunnels. Connecting requires at least one enabled tunnel and no conflicts.
Disconnecting persists `connectionOn = false` and `manualOff = true`. Imports read the file once, by
value, up to 64 KB. A duplicate gets new identifiers and starts disabled, because it overlaps its source.

### Parser

Accepted in `[Interface]`: `PrivateKey`, `Address`, `DNS`, `ListenPort`, `MTU`, `Table` (`auto` or `off`).
Accepted in `[Peer]`: `PublicKey`, `PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`.
Hooks and `SaveConfig` are refused as unsafe. Anything else, including `FwMark`, is refused as unknown.
Error messages never echo values.

### Route conflicts

Checked per pair in input order, and refused by default:

- overlapping `AllowedIPs` or `Address` across tunnels, where a `/0` overlaps every route and address
  of its family in another tunnel;
- two owners of the same family's `/0`;
- an IP-literal endpoint inside another tunnel's routes, including its `/0`;
- the same `ListenPort`.

Disabled tunnels are ignored. `Table = off` installs no routes, so its `AllowedIPs` are exempt, but its
addresses are still checked.

There is deliberately no exception for a full tunnel beside a split tunnel. wg-quick installs `/0` as
two `/1` routes, so longest-prefix match cannot decide against another `/1`, and each tunnel's wg-quick
manages its endpoint routes alone.

**Limits.** Hostname endpoints cannot be checked before resolution. Conflicts with routes outside
WireNest are not detected.

### SSID eligibility

A connection can be limited to run only on a named Wi-Fi network, or only on a known Wi-Fi network other
than a named one. This is a hard limit, separate from rules, which only choose a connection.

`AppState.desiredTunnels(ssid:)` is the single gate for login restore, retries and every reconcile, and
the app re-reads the SSID before each `up`. On a disallowed network a connection the user left on
*pauses*: its tunnels stop, the helper restores DNS after the last one, and `connectionOn` stays true
with `manualOff` false, so it resumes when allowed. An explicit disconnect still wins. A manual connect
on a disallowed network is refused with the reason, and rules skip disallowed targets.

An unknown SSID (no Location permission, Wi-Fi off, Ethernet only) satisfies neither mode.

**Limits.** Enforcement lives in the app, not the helper, which cannot see the SSID, so tunnels already
running stay up if the app is force quit. A Wi-Fi name that is briefly unavailable, for example on wake,
stops a limited connection until the name returns. The check runs on network events and every 5 seconds,
so a disallowed tunnel can outlive a network change by that long. This is not a kill switch.

### DNS

`DNS` lines are kept for reference but stripped from runtime configs, so `wg-quick` never touches DNS
and tunnels cannot race. The first tunnel imported into a connection with no DNS of its own fills in that
connection's DNS from the file's first two IP entries, and the UI says so. Any other DNS in a file is
reported as unused, and configured DNS is never overwritten. The helper snapshots each enabled network service to disk before its first
change, re-applies idempotently, and restores after the last tunnel stops or on the next helper start
if none survived. An empty primary leaves system DNS alone. Server order is not guaranteed failover.

**Limit.** A DNS change made by the user while connected is overwritten and not added to the snapshot.

### Health and recovery

Every 5 seconds the app reads real handshakes and counters from `wg`:

| Observation | State | Restart? |
| --- | --- | --- |
| Interface gone | disconnected | yes |
| Handshake under 180 s old | connected | no |
| Old handshake, no outbound growth | connected (idle) | no |
| No handshake yet, no outbound growth | connecting | no |
| Outbound growing, no reply for 45 s | degraded | no |
| Outbound growing, no reply for 180 s | degraded | yes |

Each tunnel has its own backoff (2 s doubling to 300 s, ±20% jitter, reset after 120 s healthy), and
only that tunnel restarts. Wake and path changes re-check immediately and grant 30 s of grace, so they
do not restart healthy tunnels. A restart is a real interruption: WireNest does not offer invisible
reconnection. A hostname endpoint re-resolves only on restart.

### Login

`SMAppService.mainApp` starts the app at login; desired state is persisted, so the connection returns
if it was on and stays off if it was disconnected. This is restoration after login, not a VPN before
login. Quitting brings tunnels down without changing the saved intent. If the app crashes or is force
quit, tunnels keep running and the next launch adopts them.

### Rules

Rules run in list order and the first match wins. Each selects a connection and connects it; a rule
never disconnects. A candidate must hold for 5 s, with at least 30 s between automatic switches.
`manualOff` blocks rules until the user connects. A manual connect pins the current network context until
a *known* value contradicts it or a real public IP change occurs, so an unavailable SSID or a failed
probe never releases a pin.

An unavailable SSID satisfies no rule, including "Wi-Fi is not" (fail closed). The UI shows the reason
and the Location permission state.

Public-IP rules are opt-in and off by default, so local-only tunnels need no internet. A probe is one
HTTPS GET to a user-visible third-party URL, sent with no identifying data and bound with
`requiredInterface` to Wi-Fi or Ethernet, so it cannot leave through a tunnel. That avoids VPN egress
feedback. Two matching probes are needed to accept a change, and two failures make the address
unknown, which matches no rule. Cadence is about 5 minutes, plus after network events.

The "Public IP changes" rule needs no CIDR and fires once when the stable address moves from one known
value to a different known value. The first address after launch is only a baseline, and the baseline
survives failed probes, so failure followed by the same address is no change. Because it is kept in
memory, a change while the app is not running is not detected. The event stays pending through debounce
and dwell. It is dropped by `manualOff`, a holding pin, a disallowed target, or a higher-priority rule.
After it fires, a pin holds the choice until the network changes again, so lower rules cannot flip it back.

## Test map

| File | Covers |
| --- | --- |
| `ConfigParserTests` | Directives, keys, addresses, endpoints, secret-free errors, round trip |
| `RouteConflictTests` | CIDR math, every conflict kind, deterministic order |
| `StateTests` | By-value import, duplicate, edit, toggles, manual off, persistence, permissions, corruption |
| `RuleEngineTests` | SSID rules and fail-closed, priority, debounce, dwell, override, pin, public IP range and change trigger |
| `NetworkPolicyTests` | SSID eligibility, pause and resume against the real engine, older state decoding, import DNS seeding |
| `SupervisorTests` | Backoff, health table, per-tunnel restarts, no storms, adoption |
| `HelperEngineTests` | Argv and file hygiene, boundary validation, DNS lifecycle, crash and boot recovery, install protocol |

The app target and `Installer`, `ProcessRunner` and `Daemon` have no unit tests: they are thin OS
adapters that need a real Mac.

## Needs real-Mac verification

These rest on documentation or reasoning, not on execution:

1. `setConnectionCodeSigningRequirement` with a `cdhash` requirement accepts an ad-hoc signed client.
2. The whole install path: AppleScript prompt, `--install`, launchd bootstrap, first XPC call.
3. wg-quick behavior under launchd. `detect_launchd` may make `up` block in `wait` inside a daemon, so
   `ProcessRunner` treats the "Backgrounding route monitor" output as ready and keeps the process.
4. `wg show` on the real `utunN` name, and tunnel survival across a helper restart via
   `AbandonProcessGroup`.
5. The Location prompt from an `LSUIElement` app, and `SMAppService.mainApp` with an ad-hoc signature.
6. `requiredInterface` actually bypassing `wg-quick`'s split default routes.
7. The UI's look, layout and behavior: none of it has been seen on screen.

## Known limitations

- Each app update changes the CDHash, so the helper must be reinstalled; until then the app shows the
  install prompt. Running the app under Rosetta on Apple silicon also fails the pin.
- Without Developer ID and notarization, Gatekeeper warns on first launch.
- Keys are protected by file permissions, not Keychain, so other software running as the same user can
  read them. A process running as the user could also swap the bundle before install is authorized;
  signature validation catches only tampering that breaks the seal.
- No built-in editor for a brand-new tunnel: tunnels come from import, then edit or duplicate.
- The editor is raw text, like the official WireGuard app, and shows the private key while open.
