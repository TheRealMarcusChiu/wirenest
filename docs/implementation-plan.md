# WireNest implementation plan

WireNest is a native macOS 13+ menu-bar app that runs one active named connection, made of one or
more simultaneous WireGuard tunnels with independent toggles. This document records the
architecture, the contract with packaging, and what has and has not been verified.

## Verification status

No Swift toolchain exists on the host where this code was written, so tests were written first but RED
could not be observed. The integration coordinator reports that candidates up to the first network-policy
repair passed macOS CI, including tests and a sidecar two-tunnel run, but those runs did not exercise the
root helper path. The helper-lifecycle repair and later policy fixes have not been compiled or run. Treat
those behaviors, and everything that depends on the helper, as designed and not proven until macOS CI, the
authenticated helper proof below and hands-on testing pass.

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

- **Install.** As root, copy the whole app into a private 0700 root-owned staging directory, strip
  write bits, and reject anything but regular files and folders. Then verify that snapshot's signature
  (all architectures, nested code, sealed resources), derive the client pin from it, and install only
  its bytes. Copying also carries extended ACLs, which survive `chown` and `chmod` and could keep granting
  the user write access, so every copied or created item has its ACLs removed, and root ownership, mode and
  an empty ACL are read back before anything is published; any failure stops the install. The shared
  `/Library/PrivilegedHelperTools` is checked, not changed: the install stops if anyone but root could
  write to it. The daemon refuses a client pin that has an ACL. Source files are never changed.
  Changing the original bundle after the copy cannot affect the result, and an existing
  install is untouched until verification passes and is put back if bootstrap fails. An ad-hoc signature
  proves self-consistency, not authorship: this installs whichever app the administrator chose.
- **Caller authentication.** The listener's `setConnectionCodeSigningRequirement` pins the CDHash of
  this app build (native architecture), and `effectiveUserIdentifier` pins the installing user. The
  pin file counts only if it is root-owned and not group- or world-writable.
- **Bounded API.** One XPC method takes JSON that decodes into five request cases: `status`, `up`,
  `down`, `downAll`, `setDNS`. No request can name an executable, path or argument.
- **Re-validation.** The helper re-parses every config and re-checks route conflicts and DNS. It writes
  only text generated from typed fields, never the text it received.
- **Subprocesses.** Fixed absolute paths, a fixed `PATH`, no shell, a hard timeout, and a new process
  group for each command.
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

- overlapping `AllowedIPs` or `Address` across tunnels, including an IPv6 `/0` against that family's routes
  and addresses, and an IPv4 `/0` against a `/1` or an address no narrower than `/1`;
- two owners of the same family's `/0`;
- an IP-literal endpoint inside another tunnel's routes, except its IPv4 `/0`, which is conditional below;
- the same `ListenPort`.

Disabled tunnels are ignored. `Table = off` installs no routes, so its `AllowedIPs` are exempt, but its
addresses are still checked.

A hostname endpoint or a peer with no endpoint beside another tunnel's `/0` is refused in either family,
because it could arrive inside that route. The default owner's own hostname is fine: wg-quick pins its own
endpoint. The root helper runs the same check.

**Limits.** Hostname endpoints are not checked against narrower routes, since they cannot be resolved
ahead of time. Conflicts with routes outside WireNest are not detected.

### One IPv4 full tunnel beside narrower tunnels

wg-quick installs an IPv4 `/0` as two `/1` routes, so a narrower route of another tunnel wins by
longest-prefix match. `assessRoutes` therefore separates definite conflicts from `exposures`, which are
allowed only if proved on the running system. The app saves and enables such a pair, and the root helper
decides whether it can really run. There is no blanket exemption, and no route is ever added to make it safe.

The danger is the narrower tunnel's encrypted traffic being captured by the full tunnel. So each of its
endpoints, in the default route's family, must have an existing route that is more specific than `/1` and
outside every helper-owned interface. `EndpointRouteProof` reads `route -n get`, `netstat -rn`, `ifconfig -a`
and `networksetup -listallhardwareports`, through fixed paths with timeouts, and requires all of this:

- the ordinary unscoped lookup is not a reject, blackhole or gateway route, and its interface is not ours;
- that interface is `UP` and `RUNNING` and either really `LOOPBACK`, or listed as a hardware port, not
  point-to-point, and not inactive. Not being ours is not evidence of being physical;
- the interface's own address and mask give a connected network (`/2` to `/31`) containing the endpoint, and
  the table has an unscoped cloning row for exactly that network on that interface;
- the lookup is that connected route itself, or a cached or local host entry under it. A host entry alone
  proves nothing, and neither does a `/32` row.

Anything unknown, malformed or ambiguous is a refusal.

**When it is checked.** Before a start and before any root action, then again after `wg-quick` returns and
before `running`, when the kernel must also show the `/1` rows on the new interface and each narrower route
in effect, polled for up to 5 seconds. On a failure only the new tunnel is retired, through the normal
cleanup. The check also runs on every status poll, on same-config `up` and on helper start, using the
actual endpoints from `wg show … endpoints`, so a roamed endpoint is what gets proved. An unknown endpoint is
a refusal. If the proof is lost, the full tunnel is retired while the narrower tunnel and DNS continue, the
reason is reported in `routeFailure`, and a cleanup that cannot finish stays journaled and is retried. The
app then retries the full tunnel with its usual backoff, and each attempt is refused until the proof holds.

**Limits.** This is not a kill switch: traffic is not blocked while the full tunnel is stopped, and between
checks an endpoint could briefly be captured. A network change that briefly removes the connected route stops
the full tunnel until the route returns, which interrupts it. An endpoint reached through a router, not a
connected network, is refused even if it would work. `::/0` has no such exception, and the check only covers
IPv4 endpoints.

### SSID eligibility

A connection can be limited to run only on a named Wi-Fi network, or only on a known Wi-Fi network other
than a named one. This is a hard limit, separate from rules, which only choose a connection.

`AppState.desiredTunnels(ssid:)` is the single gate for login restore, retries and every reconcile, and
the app re-reads the SSID before each `up`. On a disallowed network a connection the user left on
*pauses*: its tunnels stop, the helper restores DNS after the last one, and `connectionOn` stays true
with `manualOff` false, so it resumes when allowed. An explicit disconnect still wins. A manual connect
on a disallowed network is refused with the reason, and rules skip disallowed targets.

An unknown SSID (no Location permission, Wi-Fi off, Ethernet only) satisfies neither mode. Names are
stored and compared exactly as entered, limited to 1 to 32 bytes, because spaces are real SSID bytes.

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

A journal entry leaves only once its service is confirmed restored. A disabled service keeps its entry
until it can be restored, while other services are restored now; a service that no longer exists at all
is dropped. A pending original is never replaced by a managed value. An unreadable journal is reported
and kept, and blocks new DNS changes. With no tunnels left, the app retries a pending restore about once
a minute and on Retry Now, and shows why it is still pending. Removing the helper refuses to discard
pending originals.

**Limit.** A DNS change made by the user while connected is overwritten and not added to the snapshot.

### Tunnel lifecycle in the helper

A journal in the root-only runtime directory records each tunnel as `starting`, `running` or `retiring`.
It is written before any root action, and a failed write stops that action, so no tunnel is ever untracked.

**Start.** `wg-quick` printing its ready line proves nothing: that line comes before the route monitor is
forked. A start counts only once `wg-quick` has exited 0, or has forked the monitor while blocked in its
launchd `wait`, and then the socket exists, the device answers `wg show` with exactly this config's
peers, and the monitor is running. Anything else rolls back.

**Stop.** `wg-quick down` only removes the socket. wireguard-go and the utun then go, and only then does
the route monitor notice, delete its routes and exit. The monitor's exit is therefore the proof of
finished cleanup, together with the utun being gone by `ifconfig`'s own "no such interface" answer. The
slot and its config stay reserved until then, with a 20 second limit. Past half of that, the helper sends
SIGTERM to the monitor's process group, which holds its wireguard-go and runs its cleanup trap. The helper
never deletes a socket, as sockets are named by utun number and that number may have another owner by then.

**Barrier.** A monitor outliving its tunnel would watch any tunnel that reuses its utun number and then
delete that tunnel's routes, so no new tunnel starts while any teardown is unfinished. A failure stays
journaled, is reported, and is retried by the next `down`, `up` or helper start. Other running tunnels are
never touched, and DNS is restored only after the last tunnel is really gone.

**Ownership.** The route monitor is a fork of `wg-quick up`, so it keeps that exact argv, including the
config path in this root-only directory. Processes are matched on a root real UID and the whole argv, read
from the kernel, which works after a helper restart with no stored PID to go stale. Only that process's own
group is ever signalled, and each `wg-quick` has a group of its own. On start the helper re-adopts live
`running` tunnels and finishes `starting`, `retiring` and dead ones. A `wnN.conf` with no journal entry is
treated as an interrupted tunnel of ours. Nothing else in the directory is touched.

**Limits.** A utun that still exists is never treated as cleaned up, because its number alone does not prove
who holds it. If another app takes the number before cleanup is confirmed, or a wireguard-go hangs with no
monitor left, that teardown keeps failing visibly and new tunnels stay blocked until the utun is gone,
for example when that app quits or after a reboot. This wait is deliberate: a false success could reuse a
slot alongside a live tunnel. Endpoint host routes are deleted by the monitor's trap and are not
independently verified.

### Health and recovery

Every 5 seconds the app reads real handshakes and counters from `wg`, and judges each peer by its own:

| Observation | State | Restart? |
| --- | --- | --- |
| Interface gone | disconnected | yes |
| Handshake under 180 s old | connected | no |
| Old handshake, no outbound growth | connected (idle) | no |
| No handshake yet, no outbound growth | connecting | no |
| Outbound growing, no reply for 45 s | degraded | no |
| Outbound growing, no reply for 180 s | degraded | yes |

A tunnel takes its worst peer's result, so a fresh peer cannot hide a stalled one, and one peer's replies
do not clear another's stall. A peer that never handshook and sends nothing leaves the tunnel `connecting`
but never restarts it. New peers and counters that went backwards get a fresh baseline. The backoff resets
only when no peer is stalled or waiting for a first handshake and at least one is fresh.

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

A rule whose connection cannot start (no enabled tunnels, an invalid config, a route conflict) is skipped,
and the UI shows why. It leaves no pin and uses no dwell time, and lower rules still apply. A public IP
change whose only matching rule is blocked this way stays pending, so repairing that connection can still
act on it. Other changes to saved state from a rule are committed only with a successful connect.

## Test map

| File | Covers |
| --- | --- |
| `ConfigParserTests` | Directives, keys, addresses, endpoints, secret-free errors, round trip |
| `RouteConflictTests` | CIDR math, every conflict kind, deterministic order |
| `StateTests` | By-value import, duplicate, edit, toggles, manual off, persistence, permissions, corruption |
| `RuleEngineTests` | SSID rules and fail-closed, priority, debounce, dwell, override, pin, public IP range and change trigger |
| `NetworkPolicyTests` | SSID eligibility, pause and resume against the real engine, older state decoding, import DNS seeding |
| `SupervisorTests` | Backoff, per-peer health, per-tunnel restarts, no storms, adoption |
| `HelperEngineTests` | Argv and file hygiene, boundary validation, DNS lifecycle, crash and boot recovery, install protocol |
| `EndpointRouteProofTests` | Assessment of the full-plus-narrow pair, replay of observed Darwin output with labelled synthetic mutations, read-only real commands, root preflight, postflight, loss of proof and recovery |
| `HelperLifecycleTests` | Teardown barrier, start verification, journal crash points, DNS retry and pending services, install staging race, smoke manifest |

The app target and `Installer`, `ProcessRunner` and `Daemon` have no unit tests: they are OS adapters that
need a real Mac. The lifecycle tests replace only the commands; real `wg-quick` timing is proved by the
helper smoke below.

## Authenticated helper proof

`WIRENEST_HELPER_SMOKE=1 WireNestApp --helper-smoke /absolute/manifest.json` is an off-by-default CI
diagnostic. It uses the production `HelperClient` and so the real XPC pin and engine, and never touches
saved state. It loads a manifest of exactly two tunnels whose 0600 configs stay inside `198.18.0.0/15` with
127.0.0.1 endpoints and no DNS, hooks or default routes, and refuses to run if the helper already owns
tunnels or DNS.

It starts both tunnels and probes both at once over real TCP for an exact token, and checks peer handshakes
and counters. It then restarts only A `restartCount` times (1 to 5). After each `down`, B must keep its utun
and answer with moving counters, and A must not answer. After each `up`, both must answer. After `downAll`
the helper must own nothing. It prints `HELPER_SMOKE_PASSED` and exits 0 only after all of that; anything
else exits nonzero with a key-free message and takes down what it started. Overall time is bounded by the
harness. `scripts/smoke-helper.sh` owns the fixtures, peers, install and uninstall.

## Needs real-Mac verification

These rest on documentation or reasoning, not on execution:

1. `setConnectionCodeSigningRequirement` with a `cdhash` requirement accepts an ad-hoc signed client.
2. The whole install path: AppleScript prompt, `--install`, launchd bootstrap, first XPC call.
3. wg-quick behavior under launchd, where `detect_launchd` may make `up` block in `wait`, and the
   monitor keeping the exact argv that `ProcessRunner` matches after it forks.
4. Real teardown order and timing within the 20 second limit, `wg show` on the real `utunN` name,
   and tunnel survival across a helper restart.
5. The Location prompt from an `LSUIElement` app, and `SMAppService.mainApp` with an ad-hoc signature.
6. `requiredInterface` actually bypassing `wg-quick`'s split default routes.
7. The UI's look, layout and behavior: none of it has been seen on screen.

8. A real `0.0.0.0/0` tunnel beside a narrower one. Neither the unit tests nor the existing helper proof, which
   stays on reserved addresses with no default route, install a default route. So the `netstat` format of the
   `/1` rows, how the route monitor behaves with them, and the proof with them in place are all unobserved,
   and need a disposable network or a real Mac.

## Known limitations

- Each app update changes the CDHash, so the helper must be reinstalled; until then the app shows the
  install prompt. Running the app under Rosetta on Apple silicon also fails the pin.
- Without Developer ID and notarization, Gatekeeper warns on first launch.
- Keys are protected by file permissions, not Keychain, so other software running as the same user can
  read them. A process running as the user could also swap the bundle before install is authorized;
  signature validation catches only tampering that breaks the seal.
- No built-in editor for a brand-new tunnel: tunnels come from import, then edit or duplicate.
- The editor is raw text, like the official WireGuard app, and shows the private key while open.
