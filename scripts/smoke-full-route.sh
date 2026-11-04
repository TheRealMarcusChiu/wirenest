#!/usr/bin/env bash
# Real full-default plus split IPv4 proof, for a disposable GitHub-hosted macOS VM only. Packaged
# WireNestApp's --helper-full-route-smoke drives the installed root helper through both startup
# orders, against userspace peers on leased loopback aliases. A separate root launchd watchdog
# arms before each window and restores outbound networking if the window overruns.
#
# Passing needs both exact app markers, independently observed routes, an unfired watchdog, and a
# network state identical to the baseline after everything is removed. An app without this
# entrypoint fails the opt-in refusal check before anything changes: a dependency, not a pass.
#
# Not covered: a real VPN server, the GUI, Wi-Fi, login, sleep, or a user's physical network.
#
# Usage: bash scripts/smoke-full-route.sh path/to/WireNest.app path/to/smoke-peer
#        bash scripts/smoke-full-route.sh --self-test    # offline logic only; proves nothing about macOS
set -euo pipefail
source "$(dirname "$0")/deps.sh"

if [[ $# -eq 1 && $1 == --self-test ]]; then
  python=python3
else
  [[ $# -eq 2 ]] || die "usage: smoke-full-route.sh WireNest.app smoke-peer"
  [[ $(uname -s) == Darwin ]] || die "this proof only runs on macOS; refusing to touch routing here"
  [[ ${CI:-} == true && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] ||
    die "this proof only runs on a disposable GitHub-hosted runner; refusing to touch routing here"
  [[ ${GITHUB_REPOSITORY:-} == TheRealMarcusChiu/wirenest ]] || die "this proof only runs in the WireNest repository"
  [[ $EUID -ne 0 ]] || die "run as the ordinary owner, not root"
  [[ -d $1 ]] || die "missing app bundle: $1"
  [[ -x $2 && -f $2 ]] || die "missing smoke peer: $2"
  [[ -x /usr/bin/python3 && -x /usr/bin/perl ]] || die "missing /usr/bin/python3 or /usr/bin/perl"
  export PATH=/usr/bin:/bin:/usr/sbin:/sbin
  python=/usr/bin/python3
  set -- "$(cd "$1" && pwd -P)" "$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2")"
fi
umask 077

exec "$python" -I - "$@" <<'PY'
import hashlib, ipaddress, json, os, plistlib, re, secrets, shutil, signal, socket, stat
import subprocess, sys, tempfile, time, uuid

A = {"name": "a", "address": "198.18.71.1", "probe": "198.18.71.2", "alias": "127.77.0.2", "allowed": "0.0.0.0/0"}
B = {"name": "b", "address": "198.18.72.1", "probe": "198.18.72.2", "alias": "127.77.0.3", "allowed": "198.18.72.0/24"}
ORDERS = ("split-first", "full-first")
MARKER = "FULL_ROUTE_SMOKE_PASSED"
HALVES = ("0.0.0.0/1", "128.0.0.0/1")
FALLBACKS = ("0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2")
WINDOW = 45
APP_DEADLINE = 38  # Below WINDOW, so an overrunning app is stopped before the watchdog has to act.
REFUSAL_DEADLINE = 30
FULL_ROUTES_GONE_DEADLINE = 60  # Above WINDOW, so a wedged app is still waiting when the watchdog acts.
RECOVERY_DEADLINE = 180

PERL = "/usr/bin/perl"
ALARM = "alarm shift; exec { $ARGV[0] } @ARGV; exit 127"
NETSTAT, ROUTE, IFCONFIG, SCUTIL = "/usr/sbin/netstat", "/sbin/route", "/sbin/ifconfig", "/usr/sbin/scutil"
LAUNCHCTL, MKDIR, TEST, RM, CAT = "/bin/launchctl", "/bin/mkdir", "/bin/test", "/bin/rm", "/bin/cat"
INSTALL = "/usr/bin/install"
INSTALL_DIR = "/Library/PrivilegedHelperTools/com.marcuschiu.WireNest"
INSTALLED_HELPER = INSTALL_DIR + "/WireNestHelper"
HELPER_LABEL = "com.marcuschiu.WireNest.helper"
HELPER_STATE = (
    INSTALL_DIR,
    "/Library/LaunchDaemons/com.marcuschiu.WireNest.helper.plist",
    "/var/run/com.marcuschiu.WireNest",
    "/Library/Application Support/com.marcuschiu.WireNest",
)
TOOL_NAMES = ("bash", "wg", "wg-quick", "wireguard-go")


class ProofError(Exception):
    pass


# --- Parsers: all fail closed, because an empty capture must never look like a clean network.

def canon_dest(dest):
    # netstat drops trailing zero octets by address class: 0/1, 128.0/1, 192.0.0/2, 127, 169.254.
    text, slash, mask = re.sub(r"%[^/]*", "", dest).partition("/")
    if text == "default":
        return "0.0.0.0/0"
    octets = text.split(".")
    if not 1 <= len(octets) <= 4 or not all(o.isdigit() and int(o) <= 255 for o in octets):
        return None
    if slash and not (mask.isdigit() and int(mask) <= 32):
        return None
    prefix = int(mask) if slash else 8 * len(octets)
    return ".".join(octets + ["0"] * (4 - len(octets))) + f"/{prefix}"


def parse_routes(text):
    lines = text.splitlines()
    header = next((i for i, line in enumerate(lines) if line.split()[:2] == ["Destination", "Gateway"]), None)
    if header is None or not {"Flags", "Netif"} <= set(lines[header].split()):
        raise ProofError("netstat output has no route table header")
    columns = lines[header].split()
    flags, netif = columns.index("Flags"), columns.index("Netif")
    rows = []
    for line in lines[header + 1:]:
        fields = line.split()
        if not fields:
            continue
        cidr = canon_dest(fields[0])
        if cidr is None or len(fields) <= max(flags, netif):
            raise ProofError(f"unreadable netstat row: {line.strip()}")
        rows.append((cidr, fields[1], fields[flags], fields[netif]))
    if not rows:
        raise ProofError("netstat output has no routes")
    return rows


def parse_default(text):
    fields = dict(re.findall(r"^\s*(destination|gateway|interface|flags):\s*(\S+)", text, re.M))
    if not {"destination", "gateway", "interface", "flags"} <= set(fields):
        raise ProofError("route output has no default gateway and interface")
    return fields


def stable_dns(text):
    # Everything but `reach`, a live reachability result rather than configuration.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("DNS configuration") or not any(line.startswith("resolver #") for line in lines):
        raise ProofError("scutil --dns output has no resolver configuration")
    return [line for line in lines if not re.match(r"reach\s*:", line)]


def parse_interfaces(text):
    interfaces, current = {}, None
    for line in text.splitlines():
        stanza = re.match(r"(\S+): flags=", line)
        if stanza:
            current = stanza.group(1)
            interfaces[current] = []
        inet = re.match(r"\s+inet (\S+)(?: --> \S+)? netmask (\S+)", line)
        if inet and current:
            interfaces[current].append((inet.group(1), inet.group(2)))
    if "lo0" not in interfaces:
        raise ProofError("ifconfig -a output has no lo0")
    return interfaces


def network(cidr):
    return ipaddress.ip_network(cidr, strict=False)


def watched(cidr):
    net = network(cidr)
    return net.prefixlen <= 2 or net.overlaps(network("127.0.0.0/8")) or net.overlaps(network("198.18.0.0/15"))


def snapshot_text(raw):
    default = parse_default(raw["default"])
    lines = [f"default {k} {default[k]}" for k in ("destination", "gateway", "interface")]
    lines += ["dns " + line for line in stable_dns(raw["dns"])]
    # Expire is left out because it is a countdown; flags stay.
    lines += sorted("route " + " ".join(row) for row in parse_routes(raw["routes"]) if watched(row[0]))
    for name, addresses in sorted(parse_interfaces(raw["ifaces"]).items()):
        lines += sorted(f"address {name} {addr} {mask}" for addr, mask in addresses if watched(addr + "/32"))
    names = raw["iflist"].split()
    if not names:
        raise ProofError("ifconfig -l listed no interfaces")
    lines += sorted("utun " + name for name in names if name.startswith("utun"))
    return "\n".join(lines) + "\n"


def preflight(raw):
    """The physical gateway and interface, or a refusal before anything has changed."""
    default = parse_default(raw["default"])
    rows = parse_routes(raw["routes"])
    interfaces = parse_interfaces(raw["ifaces"])
    gateway, interface = default["gateway"], default["interface"]
    if default["destination"] != "default" or "GATEWAY" not in default["flags"] or not valid_gateway(gateway, interface):
        raise ProofError("no unambiguous physical IPv4 default gateway")
    defaults = [row for row in rows if row[0] == "0.0.0.0/0"]
    if not defaults or any(row[1] != gateway or row[3] != interface for row in defaults):
        raise ProofError("the default routes disagree about the physical gateway")
    for row in rows:
        net = network(row[0])
        if net.prefixlen in (1, 2):
            raise ProofError(f"{row[0]} is already routed: another VPN or fallback is present")
        for fixture in (A["probe"], B["probe"], A["alias"], B["alias"]):
            if net.prefixlen > 8 and net.overlaps(network(fixture + "/32")):
                raise ProofError(f"{fixture} is already covered by {row[0]}")
    for name, addresses in interfaces.items():
        for addr, _ in addresses:
            if addr in (A["alias"], B["alias"]) or ipaddress.ip_address(addr) in network("198.18.0.0/15"):
                raise ProofError(f"{addr} is already assigned to {name}")
    for cidr in ("127.0.0.0/8", "127.0.0.1/32"):
        if not any(row[0] == cidr and row[3] == "lo0" for row in rows):
            raise ProofError(f"expected loopback route {cidr} is missing")
    stable_dns(raw["dns"])
    return gateway, interface


def valid_gateway(gateway, interface):
    try:
        address = ipaddress.IPv4Address(gateway)
    except ValueError:
        return False
    return str(address) == gateway and not address.is_loopback and not address.is_unspecified and bool(re.fullmatch(r"en[0-9]+", interface))


def alias_problem(raw, alias):
    """Why a leased alias is not exactly the /32 address and local route the proof depends on."""
    if (alias, "0xffffffff") not in parse_interfaces(raw["ifaces"])["lo0"]:
        return f"{alias} is not a /32 address on lo0"
    if not any(row[0] == alias + "/32" and row[3] == "lo0" for row in parse_routes(raw["routes"])):
        return f"{alias} has no exact local host route"
    return None


class Evidence:
    """What route tables and WireGuard showed during a window, independent of the app's own claims."""

    def __init__(self, baseline_utuns):
        self.baseline_utuns = set(baseline_utuns)
        self.samples = 0
        self.full_interfaces = set()
        self.split_interfaces = set()
        self.both_distinct = False
        self.endpoints = set()
        self.problems = []

    def add_routes(self, rows):
        self.samples += 1
        by_cidr = {}
        for row in rows:
            by_cidr.setdefault(row[0], []).append(row)
        halves = [by_cidr.get(cidr, []) for cidr in HALVES]
        full = None
        if all(len(h) == 1 for h in halves) and halves[0][0][3] == halves[1][0][3]:
            full = halves[0][0][3]
            if not full.startswith("utun") or full in self.baseline_utuns:
                self.problem(f"full routes use {full}, not a new tunnel interface")
            self.full_interfaces.add(full)
        split = by_cidr.get(B["allowed"], [])
        if len(split) == 1:
            self.split_interfaces.add(split[0][3])
            if full and split[0][3] != full:
                self.both_distinct = True
            if full and split[0][3] == full:
                self.problem("full and split tunnels share one interface")
        for row in rows:
            net = network(row[0])
            # Kernel-cloned host routes on the tunnel itself (W) are what traffic through /1 leaves behind.
            if 2 <= net.prefixlen and ipaddress.ip_address(A["probe"]) in net:
                if "W" not in row[2] or (full and row[3] != full):
                    self.problem(f"{row[0]} via {row[3]} is narrower than the default halves for A's probe")

    def add_endpoints(self, text):
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                self.problem("unreadable wg endpoint line")
            elif fields[2] != "(none)":
                host = fields[2].rpartition(":")[0]
                self.endpoints.add(host)
                if host not in (A["alias"], B["alias"]):
                    self.problem(f"WireGuard endpoint drifted to {host}")

    def problem(self, text):
        if text not in self.problems:
            self.problems.append(text)

    def failures(self):
        found = list(self.problems)
        if not self.full_interfaces:
            found.append("never saw both /1 halves on one tunnel interface")
        if not self.split_interfaces:
            found.append("never saw the split /24 route")
        if not self.both_distinct:
            found.append("never saw the full and split tunnels on distinct interfaces together")
        if {A["alias"], B["alias"]} - self.endpoints:
            found.append("never saw WireGuard use both leased alias endpoints")
        return found


def app_verdict(status, stdout, order):
    expected = f"{MARKER} {order}".encode()
    lines = [line for line in stdout.splitlines() if line.strip()]
    if status is None:
        return f"the app did not finish within its {APP_DEADLINE}s deadline"
    if status != 0:
        return f"the app exited {status}"
    if lines[-1:] != [expected] or lines.count(expected) != 1:
        return f"the app exited 0 without the exact final line: {expected.decode()}"
    return None


def refusal_verdict(status, stdout):
    if status is None:
        return ("--helper-full-route-smoke without its opt-in was still running; "
                "the app lacks this entrypoint and started normally")
    if status <= 0:
        return f"--helper-full-route-smoke without its opt-in must exit nonzero, got {status}"
    if MARKER.encode() in stdout:
        return "the refused run printed the success marker"
    return None


# --- Generated files.

def fixtures(case_dir, order, wg, port_for=None):
    port_for = port_for or free_udp_port

    def tool(*args, stdin=None):
        return subprocess.run([wg] + list(args), input=stdin, stdout=subprocess.PIPE, check=True, timeout=15).stdout.decode().strip()

    entries, peers, keys = [], {}, []
    for tunnel in (A, B):
        client_key, peer_key = tool("genkey"), tool("genkey")
        keys += [client_key, peer_key]
        udp_port = port_for(tunnel["alias"])
        http_port = secrets.randbelow(20000) + 20000
        token = secrets.token_hex(16)
        conf = os.path.join(case_dir, tunnel["name"] + ".conf")
        write_private(conf, f"""[Interface]
PrivateKey = {client_key}
Address = {tunnel["address"]}/32
MTU = 1280

[Peer]
PublicKey = {tool("pubkey", stdin=(peer_key + chr(10)).encode())}
Endpoint = {tunnel["alias"]}:{udp_port}
AllowedIPs = {tunnel["allowed"]}
""")
        keys_path = os.path.join(case_dir, tunnel["name"] + ".keys")
        write_private(keys_path, f"{peer_key}\n{tool('pubkey', stdin=(client_key + chr(10)).encode())}\n")
        peers[tunnel["name"]] = {"udp_port": udp_port, "http_port": http_port, "token": token, "keys": keys_path}
        entries.append({
            "id": str(uuid.uuid4()).upper(), "configPath": conf,
            "probeHost": tunnel["probe"], "probePort": http_port, "expectedToken": token,
        })
    manifest = os.path.join(case_dir, "manifest.json")
    write_private(manifest, json.dumps({"tunnels": entries, "restartCount": 1, "startupOrder": order}))
    return manifest, peers, [key.encode() for key in keys]


def write_private(path, text):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(text)


def free_udp_port(address):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((address, 0))
        return probe.getsockname()[1]


def wait_udp_bound(address, port, deadline=15):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind((address, port))
            except OSError:
                return
        time.sleep(0.1)
    raise ProofError(f"smoke peer did not bind {address}:{port} within {deadline}s")


NATIVE_TOOLS = {"perl": PERL, "route": ROUTE, "netstat": NETSTAT, "helper": INSTALLED_HELPER}

WATCHDOG = r"""#!/bin/bash
# Generated for one full-route proof case. Root-owned, and reads no file it did not create here.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
set -u
set -o pipefail
dir=@DIR@
gateway=@GATEWAY@
interface=@INTERFACE@
newline=$'\n'

log() { printf '%s\n' "$1" >>"$dir/recovery.log"; }
bounded() { @PERL@ -e 'alarm shift; exec { $ARGV[0] } @ARGV; exit 127' "$@"; }
rows() {
  bounded 5 @NETSTAT@ -rnf inet | awk '
    $1 == "Destination" { for (i = 1; i <= NF; i++) { if ($i == "Gateway") g = i; if ($i == "Netif") n = i } seen = 1; next }
    !seen || $1 !~ /\// { next }
    { split($1, parts, "/"); count = split(parts[1], octets, "."); text = octets[1]
      for (i = 2; i <= 4; i++) text = text "." (i <= count ? octets[i] : 0)
      print text "/" parts[2], $g, $n }
    END { if (!seen) exit 3 }'
}
# 0 present, 1 absent, 2 could not tell.
fallback_row() {
  local table
  table=$(rows) || return 2
  case "$newline$table$newline" in
    *"$newline$1 $gateway $interface$newline"*) return 0 ;;
  esac
  return 1
}
full_routes() {
  local table
  table=$(rows) || return 2
  case "$newline$table" in
    *"${newline}0.0.0.0/1 "* | *"${newline}128.0.0.0/1 "*) return 0 ;;
  esac
  return 1
}

: >"$dir/armed.tmp" && /bin/mv "$dir/armed.tmp" "$dir/armed" || exit 1
# One relative timer that nothing outside this process can extend.
/bin/sleep @WINDOW@
# Atomic with disarming: whichever mkdir succeeds decides, so a late disarm can never overlap repair.
/bin/mkdir "$dir/claim" 2>/dev/null || exit 0
: >"$dir/fired" || exit 1
status=ok

added=""
for prefix in 0.0.0.0/2 64.0.0.0/2 128.0.0.0/2 192.0.0.0/2; do
  if bounded 5 @ROUTE@ -q -n add -inet "$prefix" -gateway "$gateway" >/dev/null 2>&1; then
    added="$added $prefix"
    log "fallback added $prefix"
  else
    status=failed
    log "fallback add failed $prefix"
  fi
done
verified=""
for prefix in $added; do
  if fallback_row "$prefix"; then
    verified="$verified $prefix"
    log "fallback verified $prefix"
  else
    status=failed
    log "fallback not verified $prefix"
  fi
done

if bounded @UNINSTALL_LIMIT@ @HELPER@ --uninstall >/dev/null 2>&1; then
  log "helper uninstall ok"
else
  status=failed
  log "helper uninstall failed"
fi

gone=no
ticks=@GONE_TICKS@
while [ "$ticks" -gt 0 ]; do
  full_routes
  if [ $? -eq 1 ]; then
    gone=yes
    break
  fi
  ticks=$((ticks - 1))
  /bin/sleep 1
done

if [ "$gone" = yes ]; then
  log "full routes gone"
  for prefix in $verified; do
    if bounded 5 @ROUTE@ -q -n delete -inet "$prefix" "$gateway" >/dev/null 2>&1; then :; else
      status=failed
      log "fallback delete failed $prefix"
    fi
    fallback_row "$prefix"
    if [ $? -eq 1 ]; then
      log "fallback removed $prefix"
    else
      status=failed
      log "fallback still present or unknown $prefix"
    fi
  done
else
  status=failed
  log "full routes still present or unknown; fallbacks retained"
fi
log "recovery finished $status"
: >"$dir/done"
"""


def render_watchdog(directory, gateway, interface, tools=None, window=WINDOW, uninstall_limit=60, gone_ticks=30):
    if not valid_gateway(gateway, interface):
        raise ProofError("refusing to write an unvalidated gateway or interface into a root script")
    tools = tools or NATIVE_TOOLS
    text = WATCHDOG
    for key, value in (
        ("@DIR@", directory), ("@GATEWAY@", gateway), ("@INTERFACE@", interface), ("@WINDOW@", str(window)),
        ("@PERL@", tools["perl"]), ("@ROUTE@", tools["route"]), ("@NETSTAT@", tools["netstat"]), ("@HELPER@", tools["helper"]),
        ("@UNINSTALL_LIMIT@", str(uninstall_limit)), ("@GONE_TICKS@", str(gone_ticks)),
    ):
        text = text.replace(key, value)
    return text


def render_plist(label, directory):
    return plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/bin/bash", "--noprofile", "--norc", directory + "/watchdog.sh"],
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        "RunAtLoad": True,
        "KeepAlive": False,  # A restart would restart the timer, and the deadline must not extend.
        "StandardOutPath": directory + "/watchdog.out",
        "StandardErrorPath": directory + "/watchdog.out",
    })


# --- Native operations.

def run_read(cmd, limit=5):
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=limit)
    except subprocess.TimeoutExpired:
        raise ProofError(f"{cmd[0]} did not finish within {limit}s")
    text = result.stdout.decode(errors="replace")
    if result.returncode != 0:
        raise ProofError(f"{cmd[0]} exited {result.returncode}: {text.strip()}")
    return text


def capture():
    return {
        "dns": run_read([SCUTIL, "--dns"]),
        "routes": run_read([NETSTAT, "-rnf", "inet"]),
        "default": run_read([ROUTE, "-n", "get", "-inet", "default"]),
        "iflist": run_read([IFCONFIG, "-l"]),
        "ifaces": run_read([IFCONFIG, "-a"]),
    }


def root(limit, *argv):
    """Every privileged command: root-side alarm for the command, this side's timeout for sudo."""
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", PERL, "-e", ALARM, str(limit)] + list(argv),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=limit + 10,
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    return result.returncode, result.stdout.decode(errors="replace")


def job_state(label, launchctl=None):
    runner = launchctl or (lambda: subprocess.run(
        [LAUNCHCTL, "print", "system/" + label], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10))
    try:
        result = runner()
    except subprocess.TimeoutExpired:
        return "unknown"
    text = result.stdout.decode(errors="replace")
    if result.returncode == 113 or "Could not find service" in text:
        return "absent"
    if result.returncode != 0:
        return "unknown"
    state = re.search(r"^\s*state = (\S+)", text, re.M)
    return state.group(1) if state else "unknown"


def stop_peer(process):
    """True once this process's own child is confirmed exited and reaped."""
    if process.poll() is not None:
        return True
    process.terminate()
    try:
        process.wait(timeout=5)
        return True
    except subprocess.TimeoutExpired:
        pass
    process.kill()
    try:
        process.wait(timeout=5)
        return True
    except subprocess.TimeoutExpired:
        return False


def run_app(cmd, env, out, err, deadline, tick=lambda: None, interval=0.2):
    with open(out, "wb") as stdout, open(err, "wb") as stderr:
        process = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
    end = time.monotonic() + deadline
    try:
        while time.monotonic() < end:
            if process.poll() is not None:
                return process.returncode
            tick()
            time.sleep(interval)
        return process.poll()
    finally:
        # Also reached on a signal: only this app's own session is touched.
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"error: app {process.pid} survived SIGKILL", file=sys.stderr)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def show_public(paths, keys):
    """Prints logs only after checking them for this run's private keys."""
    for path in paths:
        if os.path.exists(path):
            data = read(path)
            if any(key in data for key in keys):
                raise ProofError(f"private key material appeared in {os.path.basename(path)}; output withheld")
            sys.stdout.buffer.write(data)
    sys.stdout.flush()


def check_bind_source(peer_bin, alias, runner=subprocess.run):
    try:
        result = runner([peer_bin, "--bind-ip", alias, "--check-bind-source"], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    except subprocess.TimeoutExpired:
        raise ProofError(f"bind source check for {alias} did not finish")
    if result.returncode != 0 or result.stdout.decode(errors="replace").strip() != f"BIND_SOURCE_OK {alias}":
        raise ProofError(f"peer replies from {alias} did not prove their source: {result.stdout.decode(errors='replace').strip()}")


class Watchdog:
    def __init__(self, nonce):
        self.directory = "/var/root/wirenest-full-route-" + nonce
        self.label = "com.marcuschiu.WireNest.fullroute." + nonce
        if not re.fullmatch(r"[0-9a-f]{16}", nonce):
            raise ProofError("invalid watchdog nonce")
        self.created = False


def arm_watchdog(watchdog, case_dir, gateway, interface, root=root, state=job_state):
    script = render_watchdog(watchdog.directory, gateway, interface).encode()
    plist = render_plist(watchdog.label, watchdog.directory)
    rc, text = root(10, MKDIR, "-m", "700", watchdog.directory)
    if rc != 0:
        raise ProofError(f"could not create the watchdog directory: {text.strip()}")
    watchdog.created = True
    for name, data, mode in (("watchdog.sh", script, "700"), ("watchdog.plist", plist, "644")):
        source = os.path.join(case_dir, name)
        with os.fdopen(os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(data)
        rc, text = root(10, INSTALL, "-o", "root", "-g", "wheel", "-m", mode, source, f"{watchdog.directory}/{name}")
        if rc != 0:
            raise ProofError(f"could not install {name}: {text.strip()}")
        # The source sat in a user directory, so root must hold exactly what was rendered.
        rc, text = root(10, CAT, f"{watchdog.directory}/{name}")
        if rc != 0 or text.encode() != data:
            raise ProofError(f"installed {name} differs from what was generated")
    rc, text = root(30, LAUNCHCTL, "bootstrap", "system", f"{watchdog.directory}/watchdog.plist")
    if rc != 0:
        raise ProofError(f"launchctl bootstrap failed: {text.strip()}")
    end = time.monotonic() + 10
    while time.monotonic() < end:
        if root(5, TEST, "-f", f"{watchdog.directory}/armed")[0] == 0 and state(watchdog.label) == "running":
            return time.monotonic()
        time.sleep(0.1)
    raise ProofError("the watchdog never acknowledged armed with a running job")


def disarm_watchdog(watchdog, root=root, state=job_state, recovery_deadline=RECOVERY_DEADLINE, sleep=time.sleep):
    """Failures from the synchronized stop. Any firing is one, even with a complete recovery."""
    if not watchdog.created:
        return []
    failures = []
    directory = watchdog.directory
    if state(watchdog.label) != "running" and root(10, TEST, "-d", directory + "/claim")[0] != 0:
        # Only a job that has already fired may have stopped before this point.
        failures.append(f"the watchdog was not running at disarm: {state(watchdog.label)}")
    rc, _ = root(10, MKDIR, directory + "/claim")
    if rc != 0:
        if root(10, TEST, "-d", directory + "/claim")[0] == 0:
            failures.append("the watchdog fired before disarm")
            waited = 0
            while root(10, TEST, "-f", directory + "/done")[0] != 0:
                if waited >= recovery_deadline:
                    failures.append("watchdog recovery did not finish")
                    break
                sleep(1)
                waited += 1
        else:
            failures.append("could not claim the watchdog, and it has not fired; its state is unknown")
    rc, text = root(30, LAUNCHCTL, "bootout", "system/" + watchdog.label)
    final = state(watchdog.label)
    if final != "absent":
        failures.append(f"the watchdog job did not stop: {final} {text.strip()}")
    # Checked after the job is gone, so a racing firing wins.
    rc, _ = root(10, TEST, "-e", directory + "/fired")
    if rc == 0:
        if not any("fired" in failure for failure in failures):
            failures.append("the watchdog fired")
    elif rc != 1:
        failures.append("could not read the watchdog's fired marker")
    if rc == 0:
        rc_log, log = root(10, CAT, directory + "/recovery.log")
        if rc_log == 0 and all(re.fullmatch(r"[a-z /0-9.;]+", line) for line in log.splitlines()):
            print(log, end="")
    rc, _ = root(30, RM, "-rf", directory)
    if rc != 0 or root(10, TEST, "-e", directory)[0] != 1:
        failures.append("could not remove the watchdog directory")
    return failures


def wait_full_routes_gone(reader=None, deadline=FULL_ROUTES_GONE_DEADLINE, sleep=time.sleep):
    reader = reader or (lambda: run_read([NETSTAT, "-rnf", "inet"]))
    end = time.monotonic() + deadline
    while True:
        try:
            if not any(row[0] in HALVES for row in parse_routes(reader())):
                return True
        except ProofError:
            pass  # Unknown is not gone.
        if time.monotonic() >= end:
            return False
        sleep(0.2)


def wait_restored(baseline, deadline=20):
    end = time.monotonic() + deadline
    current = None
    while True:
        try:
            current = snapshot_text(capture())
            if current == baseline:
                return None
        except ProofError as error:
            current = f"capture failed: {error}\n"
        if time.monotonic() >= end:
            return current
        time.sleep(1)


def check_install(uid, cdhash, tools_source):
    pin = json.loads(read(INSTALL_DIR + "/client.json"))
    if pin.get("ownerUID") != uid or not cdhash or str(pin.get("appCDHash", "")).lower() != cdhash.lower():
        raise ProofError("the installed client pin does not name this user and this exact app build")
    tools = os.path.join(INSTALL_DIR, "Tools")
    entries = [(INSTALL_DIR, stat.S_ISDIR), (tools, stat.S_ISDIR), (INSTALLED_HELPER, stat.S_ISREG), (INSTALL_DIR + "/client.json", stat.S_ISREG)]
    entries += [(os.path.join(tools, name), stat.S_ISREG) for name in TOOL_NAMES]
    for path, is_kind in entries:
        info = os.lstat(path)
        if not is_kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ProofError(f"{path} is not root-owned and closed to other writers")
        listing = run_read(["/bin/ls", "-led", path]).splitlines()
        if len(listing) != 1 or listing[0].split()[0].endswith("+"):
            raise ProofError(f"{path} has an extended ACL")
    wg = os.path.join(tools, "wg")
    if hashlib.sha256(read(wg)).digest() != hashlib.sha256(read(os.path.join(tools_source, "wg"))).digest():
        raise ProofError("the installed wg differs from the signed app's wg")
    require_write_denied(wg, tools)


def require_write_denied(tool, tools_dir, opener=os.open):
    probe = os.path.join(tools_dir, ".route-proof-" + secrets.token_hex(8))
    for label, path, arguments in (
        ("open for write", tool, (os.O_WRONLY,)),
        ("create a file", probe, (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)),
    ):
        try:
            descriptor = opener(path, *arguments)
        except PermissionError:
            continue
        except OSError as error:
            raise ProofError(f"{label} on {path} failed with errno {error.errno}, not a permission denial")
        os.close(descriptor)
        if path == probe:
            os.unlink(probe)
        raise ProofError(f"the installing user could {label} on {path}")


def helper_removed(state=job_state):
    return state(HELPER_LABEL) == "absent" and not any(os.path.lexists(path) for path in HELPER_STATE)


# --- The proof.

def sample(evidence, wg):
    try:
        evidence.add_routes(parse_routes(run_read([NETSTAT, "-rnf", "inet"], limit=3)))
    except ProofError:
        pass  # A sample that cannot be read proves nothing; failures() needs real sightings.
    rc, text = root(3, wg, "show", "all", "endpoints")
    if rc == 0:
        evidence.add_endpoints(text)


def run_case(order, ctx, fail):
    case_dir = os.path.join(ctx["tmp"], order)
    os.mkdir(case_dir)
    leased, peers, keys, logs = [], [], [], []
    watchdog = None
    try:
        for tunnel in (A, B):
            leased.append(tunnel["alias"])
            rc, text = root(15, IFCONFIG, "lo0", "alias", tunnel["alias"], "netmask", "255.255.255.255")
            if rc != 0:
                raise ProofError(f"could not lease {tunnel['alias']}: {text.strip()}")
        raw = capture()
        for tunnel in (A, B):
            problem = alias_problem(raw, tunnel["alias"])
            if problem:
                raise ProofError(problem)
            check_bind_source(ctx["peer"], tunnel["alias"])
        print(f"ok: {order}: both aliases leased, and peer replies come from them")

        manifest, generated, keys = fixtures(case_dir, order, ctx["wg"])
        for tunnel in (A, B):
            spec = generated[tunnel["name"]]
            log = os.path.join(case_dir, f"peer-{tunnel['name']}.log")
            logs.append(log)
            with open(spec["keys"], "rb") as stdin, open(log, "wb") as output:
                peers.append(subprocess.Popen(
                    [ctx["peer"], "--addr", tunnel["probe"], "--client", tunnel["address"], "--udp-port", str(spec["udp_port"]),
                     "--http-port", str(spec["http_port"]), "--token", spec["token"], "--bind-ip", tunnel["alias"]],
                    stdin=stdin, stdout=output, stderr=output))
            wait_udp_bound(tunnel["alias"], spec["udp_port"])

        watchdog = Watchdog(secrets.token_hex(8))
        armed_at = arm_watchdog(watchdog, case_dir, ctx["gateway"], ctx["interface"])
        print(f"ok: {order}: watchdog armed with a fixed {WINDOW}s deadline")

        evidence = Evidence(ctx["baseline_utuns"])
        out, err = os.path.join(case_dir, "app.out"), os.path.join(case_dir, "app.err")
        env = dict(os.environ, WIRENEST_FULL_ROUTE_SMOKE="1")
        status = run_app([ctx["driver"], "--helper-full-route-smoke", manifest], env, out, err,
                         APP_DEADLINE - (time.monotonic() - armed_at), lambda: sample(evidence, ctx["installed_wg"]))
        show_public([out, err], keys)
        verdict = app_verdict(status, read(out), order)
        if verdict:
            raise ProofError(verdict)
        for problem in evidence.failures():
            fail(f"{order}: {problem}")
        print(f"ok: {order}: app marker, plus {evidence.samples} route samples showing /1 on {sorted(evidence.full_interfaces)} and /24 on {sorted(evidence.split_interfaces)}")
    except (ProofError, OSError, subprocess.SubprocessError) as error:
        fail(f"{order}: {error}")
    finally:
        # Every step runs whatever happened before it, and only ever adds failures.
        def step(action):
            try:
                action()
            except (ProofError, OSError, subprocess.SubprocessError, ValueError) as error:
                fail(f"{order}: cleanup: {error}")

        def stop_watchdog():
            if not wait_full_routes_gone():
                fail(f"{order}: full routes were still present after {FULL_ROUTES_GONE_DEADLINE}s")
            for problem in disarm_watchdog(watchdog):
                fail(f"{order}: {problem}")

        def stop_peers():
            for process in peers:
                early = process.poll()
                if early is not None:
                    fail(f"{order}: a smoke peer exited early with {early}")
                if not stop_peer(process):
                    fail(f"{order}: could not confirm smoke peer {process.pid} stopped")
                    ctx["keep_tmp"] = True

        def remove_aliases():
            for alias in leased:
                rc, text = root(15, IFCONFIG, "lo0", "-alias", alias)
                if rc != 0:
                    fail(f"{order}: could not remove {alias}: {text.strip()}")

        def compare_baseline():
            leftover = wait_restored(ctx["baseline"])
            if leftover is not None:
                fail(f"{order}: the network did not return to its baseline:\n{leftover}")
            else:
                print(f"ok: {order}: network state identical to the baseline")

        if watchdog:
            step(stop_watchdog)
        step(stop_peers)
        step(lambda: show_public(logs if ctx["failures"] else [], keys))
        step(remove_aliases)
        step(compare_baseline)


def main(app, peer):
    failures = []

    def fail(text):
        failures.append(text)
        print("error: " + text, file=sys.stderr)

    def on_signal(number, _frame):
        for name in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(name, signal.SIG_IGN)  # Cleanup is bounded and must finish.
        raise SystemExit(128 + number)

    for name in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(name, on_signal)

    tmp = os.path.realpath(tempfile.mkdtemp())
    tools_source = app + "/Contents/Resources/Tools"
    helper = app + "/Contents/Library/LaunchServices/WireNestHelper"
    driver = app + "/Contents/MacOS/WireNestApp"
    ctx = {"tmp": tmp, "peer": peer, "driver": driver, "wg": tools_source + "/wg", "installed_wg": INSTALL_DIR + "/Tools/wg",
           "failures": failures, "keep_tmp": False}
    install_attempted, baseline = False, None
    try:
        for path in (driver, helper, ctx["wg"]):
            if not os.access(path, os.X_OK):
                raise ProofError(f"missing executable: {path}")
        # A timer that does not fire would make every privileged deadline below meaningless.
        alarm = subprocess.run([PERL, "-e", ALARM, "1", "/bin/sleep", "10"], timeout=8)
        if alarm.returncode != -signal.SIGALRM:
            raise ProofError(f"the root command deadline does not work: {alarm.returncode}")
        run_read(["/usr/bin/sudo", "-n", "/usr/bin/true"])
        run_read(["/usr/bin/codesign", "--verify", "--strict", "--deep", app], limit=60)
        cdhash = re.search(r"^CDHash=(\S+)", run_read(["/usr/bin/codesign", "-dv", "--verbose=4", app], limit=60), re.M)
        if not cdhash:
            raise ProofError("could not read the app's code directory hash")
        if not helper_removed():
            raise ProofError("a WireNest helper is already installed; refusing to disturb it")

        raw = capture()
        ctx["gateway"], ctx["interface"] = preflight(raw)
        baseline = snapshot_text(raw)
        ctx["baseline"] = baseline
        ctx["baseline_utuns"] = [name for name in raw["iflist"].split() if name.startswith("utun")]
        print(f"ok: baseline captured; physical gateway on {ctx['interface']}; no fixture, /1 or /2 route present")

        # Before anything changes: an app without this entrypoint fails here, as a dependency.
        env = {k: v for k, v in os.environ.items() if k != "WIRENEST_FULL_ROUTE_SMOKE"}
        out, err = os.path.join(tmp, "refusal.out"), os.path.join(tmp, "refusal.err")
        manifest = os.path.join(tmp, "refusal.json")
        write_private(manifest, "{}")
        status = run_app([driver, "--helper-full-route-smoke", manifest], env, out, err, REFUSAL_DEADLINE)
        show_public([out, err], [])
        verdict = refusal_verdict(status, read(out))
        if verdict:
            raise ProofError(verdict)
        print("ok: --helper-full-route-smoke refuses to run without its opt-in")

        install_attempted = True
        rc, text = root(90, helper, "--install", "--uid", str(os.getuid()))
        if rc != 0:
            raise ProofError(f"helper install failed: {text.strip()}")
        check_install(os.getuid(), cdhash.group(1), tools_source)
        print("ok: helper installed, root-owned without ACLs, pinned to this user and build, and closed to this user's writes")

        for order in ORDERS:
            run_case(order, ctx, fail)
            if failures:
                break
    except (ProofError, OSError, subprocess.SubprocessError) as error:
        fail(str(error))
    except SystemExit as stop:
        fail(f"interrupted (exit {stop.code})")
    finally:
        for name in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(name, signal.SIG_IGN)
        try:
            if install_attempted:
                rc, text = root(90, helper, "--uninstall")
                if rc != 0:
                    fail(f"helper uninstall failed: {text.strip()}")
                if not helper_removed():
                    fail("helper files or its launchd job remain after uninstall")
            if baseline is not None:
                leftover = wait_restored(baseline)
                if leftover is not None:
                    fail(f"the network did not return to its baseline:\n{leftover}")
        except (ProofError, OSError, subprocess.SubprocessError) as error:
            fail(f"final cleanup: {error}")
        if ctx["keep_tmp"]:
            fail(f"keeping {tmp} because a smoke peer may still be using it")
        else:
            try:
                shutil.rmtree(tmp)
            except OSError as error:
                fail(f"could not remove the temp directory: {error}")

    if failures:
        print(f"FULL ROUTE SMOKE FAILED: {len(failures)} problem(s)", file=sys.stderr)
        return 1
    print("FULL ROUTE SMOKE PASSED: both startup orders, watchdog never fired, network state restored.")
    print("Not covered: a real VPN server, the GUI, Wi-Fi, login, sleep, or a physical user network.")
    return 0


# --- Offline checks. Nothing here touches routing, root, ACLs or a real helper.

FIXTURE_ROUTES = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.64.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#7             UCS                   en0      !
192.168.64         link#7             UCS                   en0      !
192.168.64.1       a6:77:f3:20:33:64  UHLWIir               en0   1136
224.0.0/4          link#7             UmCS                  en0      !
"""
FIXTURE_DEFAULT = """   route to: default
destination: default
       mask: default
    gateway: 192.168.64.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""
FIXTURE_DNS = """DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  if_index : 7 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
"""
FIXTURE_IFACES = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST> mtu 1500
\tinet 192.168.64.8 netmask 0xffffff00 broadcast 192.168.64.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
"""
FIXTURE_RAW = {"dns": FIXTURE_DNS, "routes": FIXTURE_ROUTES, "default": FIXTURE_DEFAULT, "iflist": "lo0 en0 utun0\n", "ifaces": FIXTURE_IFACES}


def raises(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except ProofError:
        return True
    return False


def self_test_parsers():
    for short, full in (("default", "0.0.0.0/0"), ("0/1", "0.0.0.0/1"), ("128.0/1", "128.0.0.0/1"), ("0/2", "0.0.0.0/2"), ("64/2", "64.0.0.0/2"),
                        ("128.0/2", "128.0.0.0/2"), ("192.0.0/2", "192.0.0.0/2"), ("127", "127.0.0.0/8"), ("169.254", "169.254.0.0/16"),
                        ("192.168.64", "192.168.64.0/24"), ("224.0.0/4", "224.0.0.0/4"), ("127.0.0.1", "127.0.0.1/32"),
                        ("192.168.64.1/32", "192.168.64.1/32"), ("198.18.72/24", "198.18.72.0/24"), ("198.18.71.2%utun5", "198.18.71.2/32")):
        assert canon_dest(short) == full, short
    for bad in ("fe80::", "link#7", "1.2.3.4.5", "999", "1.2/40", ""):
        assert canon_dest(bad) is None, bad

    def changed(key, old, new):
        assert old in FIXTURE_RAW[key], old
        return dict(FIXTURE_RAW, **{key: FIXTURE_RAW[key].replace(old, new)})

    assert preflight(FIXTURE_RAW) == ("192.168.64.1", "en0")
    base = snapshot_text(FIXTURE_RAW)
    assert "route 127.0.0.1/32 127.0.0.1 UH lo0" in base and "utun utun0" in base and "search domain[0] : corp.example" in base

    extra = lambda row: dict(FIXTURE_RAW, routes=FIXTURE_ROUTES + row + "\n")
    for label, raw in (
        ("no gateway flag", changed("default", "GATEWAY,", "")),
        ("loopback gateway", changed("default", "192.168.64.1", "127.0.0.1")),
        ("tunnel default", changed("default", "en0", "utun3")),
        ("hostname gateway", changed("default", "192.168.64.1", "router")),
        ("two defaults", extra("default 192.168.64.9 UGScIg en0")),
        ("foreign /1", extra("0/1 link#9 UCS utun3")),
        ("foreign /1 high", extra("128.0/1 link#9 UCS utun3")),
        ("fallback /2", extra("64/2 192.168.64.1 UGSc en0")),
        ("route over probe", extra("198.18.71/24 link#9 UCS utun3")),
        ("route over alias", extra("127.77.0.2 127.77.0.2 UH lo0")),
        ("alias address", changed("ifaces", "\tinet 127.0.0.1 netmask 0xff000000", "\tinet 127.0.0.1 netmask 0xff000000\n\tinet 127.77.0.3 netmask 0xffffffff")),
        ("reserved address", changed("ifaces", "mtu 1380", "mtu 1380\n\tinet 198.18.9.1 --> 198.18.9.1 netmask 0xffffffff")),
        ("missing loopback", changed("routes", "127.0.0.1          127.0.0.1          UH                    lo0\n", "")),
        ("empty dns", dict(FIXTURE_RAW, dns="")),
        ("no resolver", dict(FIXTURE_RAW, dns="DNS configuration\n")),
        ("empty routes", dict(FIXTURE_RAW, routes="")),
        ("header only", dict(FIXTURE_RAW, routes="Destination Gateway Flags Netif Expire\n")),
        ("garbage row", extra("nonsense")),
        ("empty default", dict(FIXTURE_RAW, default="")),
        ("empty ifaces", dict(FIXTURE_RAW, ifaces="")),
    ):
        assert raises(preflight, raw), label

    for label, raw in (
        ("search domain", changed("dns", "corp.example", "evil.example")),
        ("server order", dict(FIXTURE_RAW, dns=FIXTURE_DNS.replace("[0] : 192.0.2.53\n  nameserver[1] : 192.0.2.54", "[0] : 192.0.2.54\n  nameserver[1] : 192.0.2.53"))),
        ("dns interface", changed("dns", "7 (en0)", "9 (utun3)")),
        ("default gateway", changed("default", "192.168.64.1", "192.168.64.2")),
        ("default interface", changed("default", "en0", "en1")),
        ("loopback route", changed("routes", "127.0.0.1          UH", "127.0.0.2          UH")),
        ("leftover /1", extra("0/1 link#9 UCS utun3")),
        ("leftover fallback", extra("192.0.0/2 192.168.64.1 UGSc en0")),
        ("leftover reserved", extra("198.19.1/24 link#9 UCS utun3")),
        ("leftover alias", extra("127.77.0.2 127.77.0.2 UH lo0")),
        ("leftover utun", dict(FIXTURE_RAW, iflist="lo0 en0 utun0 utun1\n")),
        ("leftover alias address", changed("ifaces", "\tinet 127.0.0.1 netmask 0xff000000", "\tinet 127.0.0.1 netmask 0xff000000\n\tinet 127.77.0.2 netmask 0xffffffff")),
    ):
        assert snapshot_text(raw) != base, label
    for label, raw in (
        ("reach", changed("dns", "0x00000002 (Reachable)", "0x00000000 (Not Reachable)")),
        ("arp expiry", changed("routes", "1136", "17")),
        ("unrelated route", extra("10.1/16 192.168.64.1 UGSc en0")),
    ):
        assert snapshot_text(raw) == base, label
    for key in FIXTURE_RAW:
        assert raises(snapshot_text, dict(FIXTURE_RAW, **{key: ""})), key

    leased = dict(FIXTURE_RAW,
                  routes=FIXTURE_ROUTES + "127.77.0.2 127.77.0.2 UH lo0\n",
                  ifaces=FIXTURE_IFACES.replace("\tinet 127.0.0.1 netmask 0xff000000", "\tinet 127.0.0.1 netmask 0xff000000\n\tinet 127.77.0.2 netmask 0xffffffff"))
    assert alias_problem(leased, "127.77.0.2") is None
    assert alias_problem(FIXTURE_RAW, "127.77.0.2")
    assert alias_problem(dict(leased, routes=FIXTURE_ROUTES), "127.77.0.2")
    assert alias_problem(dict(leased, ifaces=leased["ifaces"].replace("0xffffffff", "0xff000000")), "127.77.0.2")


def self_test_evidence():
    def rows(*extra):
        return parse_routes(FIXTURE_ROUTES + "\n".join(extra) + "\n")

    full = ("0/1 link#9 USc utun5", "128.0/1 link#9 USc utun5")
    split = "198.18.72/24 link#10 USc utun6"
    endpoints = "utun5\tKEY=\t127.77.0.2:50000\nutun6\tKEY=\t127.77.0.3:50001\n"

    good = Evidence(["utun0"])
    good.add_routes(rows(split))
    good.add_routes(rows(split, *full))
    good.add_routes(rows(*full, "198.18.71.2 link#9 UHWIi utun5"))
    good.add_endpoints(endpoints)
    assert good.failures() == [] and good.full_interfaces == {"utun5"} and good.split_interfaces == {"utun6"}

    def failures_of(*samples, text=endpoints):
        evidence = Evidence(["utun0"])
        for sample_rows in samples:
            evidence.add_routes(sample_rows)
        evidence.add_endpoints(text)
        return evidence.failures()

    assert failures_of(rows(split))  # No full routes.
    assert failures_of(rows(*full))  # No split route.
    assert failures_of(rows(split), rows(*full))  # Never together.
    assert failures_of(rows(split, full[0]))  # One half only.
    assert failures_of(rows(split, full[0], "128.0/1 link#11 USc utun7"))  # Halves on two interfaces.
    assert failures_of(rows("0/1 link#9 USc utun0", "128.0/1 link#9 USc utun0", split))  # Baseline interface.
    assert failures_of(rows("0/1 link#9 USc en0", "128.0/1 link#9 USc en0", split))
    assert failures_of(rows(split.replace("utun6", "utun5"), *full))  # One shared interface.
    narrower = rows(split, *full, "198.18.71/24 link#9 USc utun5")
    assert failures_of(narrower)  # A's traffic would not need the default halves.
    assert failures_of(rows(split, *full, "198.18.71.2 link#1 UHWIi en0"))  # Cloned off the tunnel.
    good_rows = rows(split, *full)
    assert failures_of(good_rows) == []
    assert failures_of(good_rows, text="")  # Endpoints never seen.
    assert failures_of(good_rows, text="utun5\tKEY=\t127.77.0.2:50000\n")  # Only one.
    assert failures_of(good_rows, text=endpoints + "utun5\tKEY=\t127.0.0.1:50000\n")  # Drift to the OS loopback.
    assert failures_of(good_rows, text=endpoints + "broken line\n")
    assert failures_of(good_rows, text=endpoints + "utun6\tKEY=\t(none)\n") == []

    assert app_verdict(0, b"note\nFULL_ROUTE_SMOKE_PASSED split-first\n", "split-first") is None
    assert app_verdict(0, b"FULL_ROUTE_SMOKE_PASSED full-first\n\n", "full-first") is None
    for status, stdout, order in (
        (None, b"FULL_ROUTE_SMOKE_PASSED split-first\n", "split-first"),
        (1, b"FULL_ROUTE_SMOKE_PASSED split-first\n", "split-first"),
        (-9, b"FULL_ROUTE_SMOKE_PASSED split-first\n", "split-first"),
        (0, b"", "split-first"),
        (0, b"FULL_ROUTE_SMOKE_PASSED full-first\n", "split-first"),
        (0, b"FULL_ROUTE_SMOKE_PASSED split-first\nlater\n", "split-first"),
        (0, b"FULL_ROUTE_SMOKE_PASSED split-first\nFULL_ROUTE_SMOKE_PASSED split-first\n", "split-first"),
        (0, b"FULL_ROUTE_SMOKE_PASSED\n", "split-first"),
        (0, b"xFULL_ROUTE_SMOKE_PASSED split-first\n", "split-first"),
    ):
        assert app_verdict(status, stdout, order), (status, stdout)
    assert refusal_verdict(2, b"") is None
    assert refusal_verdict(None, b"")  # The old app: it starts its normal UI.
    assert refusal_verdict(0, b"") and refusal_verdict(-9, b"") and refusal_verdict(2, MARKER.encode())


FAKE_TOOL = r"""#!/bin/sh
# Stands in for route, netstat and the helper: state lives in plain files, nothing else is touched.
state=@STATE@
tool=$1
shift
echo "$tool $*" >>"$state/calls"
[ -e "$state/dir/fired" ] || echo "unfired $tool" >>"$state/calls"
short() {
  case "$1" in
    0.0.0.0/2) echo 0/2 ;;
    64.0.0.0/2) echo 64/2 ;;
    128.0.0.0/2) echo 128.0/2 ;;
    192.0.0.0/2) echo 192.0.0/2 ;;
    *) echo "$1" ;;
  esac
}
case "$tool" in
  route)
    prefix=$5
    [ "$3" = add ] && [ -e "$state/fail-add-$(short "$prefix" | tr / _)" ] && exit 1
    if [ "$3" = add ]; then
      [ -e "$state/add-without-row" ] || echo "$(short "$prefix") $7 UGSc en0" >>"$state/table"
    elif [ -e "$state/delete-fails" ]; then
      exit 1
    else
      grep -v "^$(short "$prefix") " "$state/table" >"$state/table.new"
      mv "$state/table.new" "$state/table"
    fi
    ;;
  netstat)
    [ -e "$state/netstat-fails" ] && exit 1
    echo "Destination Gateway Flags Netif Expire"
    cat "$state/table"
    ;;
  helper)
    [ -e "$state/helper-hangs" ] && exec /bin/sleep 30
    [ -e "$state/helper-fails" ] && exit 1
    if [ ! -e "$state/helper-wedged" ]; then
      grep -v '/1 ' "$state/table" >"$state/table.new"
      mv "$state/table.new" "$state/table"
    fi
    ;;
esac
"""


def self_test_watchdog():
    with tempfile.TemporaryDirectory() as root_dir:
        production = render_watchdog("/var/root/wirenest-full-route-0123456789abcdef", "192.168.64.1", "en0")
        for needle in ("dir=/var/root/wirenest-full-route-0123456789abcdef", "gateway=192.168.64.1", "interface=en0", f"/bin/sleep {WINDOW}",
                       ROUTE, NETSTAT, INSTALLED_HELPER, PERL):
            assert needle in production, needle
        for forbidden in ("eval ", "\nsource ", "\n. ", root_dir):
            assert forbidden not in production, forbidden
        assert not re.search(r"@[A-Z_]+@", production)
        for gateway, interface in (("192.168.64.1; rm -rf /", "en0"), ("$(id)", "en0"), ("192.168.64.1", "en0; id"), ("127.0.0.1", "en0"),
                                   ("0.0.0.0", "en0"), ("192.168.64.1", "utun3"), ("192.168.064.1", "en0"), ("", "en0")):
            assert raises(render_watchdog, "/d", gateway, interface), (gateway, interface)
        plist = plistlib.loads(render_plist("label", "/d"))
        assert plist["KeepAlive"] is False and plist["ProgramArguments"][-1] == "/d/watchdog.sh" and plist["RunAtLoad"] is True

        def fire(name, setup=(), claimed=False, uninstall_limit=5, gone_ticks=1):
            state = os.path.join(root_dir, name)
            directory = os.path.join(state, "dir")
            os.makedirs(directory)
            with open(os.path.join(state, "table"), "w") as f:
                f.write("0/1 link#9 USc utun5\n128.0/1 link#9 USc utun5\n")
            fake = os.path.join(state, "fake.sh")
            write_private(fake, FAKE_TOOL.replace("@STATE@", state))
            for flag in setup:
                open(os.path.join(state, flag), "w").close()
            if claimed:
                os.mkdir(os.path.join(directory, "claim"))
            tool = lambda word: f"/bin/sh {fake} {word}"
            script = os.path.join(state, "watchdog.sh")
            write_private(script, render_watchdog(
                directory, "192.168.64.1", "en0", {"perl": PERL, "route": tool("route"), "netstat": tool("netstat"), "helper": tool("helper")},
                window=0, uninstall_limit=uninstall_limit, gone_ticks=gone_ticks))
            subprocess.run(["/bin/bash", "--noprofile", "--norc", script], timeout=30, check=False, env={})

            def lines(path):
                full = os.path.join(state, path)
                return read(full).decode().splitlines() if os.path.exists(full) else []
            return {"calls": lines("calls"), "log": lines("dir/recovery.log"), "table": lines("table"),
                    "fired": os.path.exists(os.path.join(directory, "fired")), "done": os.path.exists(os.path.join(directory, "done")),
                    "armed": os.path.exists(os.path.join(directory, "armed"))}

        def adds(result):
            return [c.split()[5] for c in result["calls"] if c.startswith("route -q -n add")]

        def index(result, prefix):
            return next(i for i, call in enumerate(result["calls"]) if call.startswith(prefix))

        ok = fire("normal")
        assert ok["armed"] and ok["fired"] and ok["done"]
        assert not any(call.startswith("unfired") for call in ok["calls"]), "a tool ran before the fired marker"
        assert adds(ok) == list(FALLBACKS)
        assert ["route -q -n add -inet 0.0.0.0/2 -gateway 192.168.64.1"] == [c for c in ok["calls"] if "add -inet 0.0.0.0/2" in c]
        assert index(ok, "route -q -n add -inet 192.0.0.0/2") < index(ok, "helper --uninstall") < index(ok, "route -q -n delete")
        assert ok["log"][-1] == "recovery finished ok" and sum("fallback verified" in line for line in ok["log"]) == 4
        assert ok["table"] == [], ok["table"]
        assert all(f"fallback removed {prefix}" in ok["log"] for prefix in FALLBACKS)
        assert not any(re.search(r"[A-Za-z0-9+/]{43}=", line) for line in ok["log"])

        idle = fire("claimed-by-disarm", claimed=True)
        assert idle["armed"] and idle["calls"] == [] and not idle["fired"] and not idle["done"], "a disarmed watchdog mutated something"
        assert len(idle["table"]) == 2

        partial = fire("one-add-fails", ["fail-add-64_2"])
        assert adds(partial) == list(FALLBACKS), "a failed add skipped the rest"
        assert index(partial, "route -q -n add -inet 192.0.0.0/2") < index(partial, "helper --uninstall")
        assert "fallback add failed 64.0.0.0/2" in partial["log"] and partial["log"][-1] == "recovery finished failed"
        assert not any("delete -inet 64.0.0.0/2" in call for call in partial["calls"]), "deleted a row it never added"

        wedged = fire("helper-wedged", ["helper-wedged"], gone_ticks=2)
        assert not any(call.startswith("route -q -n delete") for call in wedged["calls"]), "dropped fallbacks with full routes up"
        assert sum("/2 " in row for row in wedged["table"]) == 4 and wedged["log"][-1] == "recovery finished failed"

        failed = fire("helper-fails", ["helper-fails", "helper-wedged"], gone_ticks=1)
        assert "helper uninstall failed" in failed["log"] and failed["log"][-1] == "recovery finished failed" and failed["done"]

        hung = fire("helper-hangs", ["helper-hangs", "helper-wedged"], uninstall_limit=1, gone_ticks=1)
        assert "helper uninstall failed" in hung["log"] and hung["done"], "a hung helper was not bounded"

        blind = fire("netstat-fails", ["netstat-fails"], gone_ticks=1)
        assert adds(blind) == list(FALLBACKS) and not any(call.startswith("route -q -n delete") for call in blind["calls"])
        assert blind["log"][-1] == "recovery finished failed", "an unreadable table counted as gone"
        assert sum("fallback not verified" in line for line in blind["log"]) == 4

        rowless = fire("add-without-row", ["add-without-row"])
        assert not any(call.startswith("route -q -n delete") for call in rowless["calls"]), "deleted a row it never verified"
        assert rowless["log"][-1] == "recovery finished failed"

        stuck = fire("delete-fails", ["delete-fails"])
        assert stuck["log"][-1] == "recovery finished failed" and sum("/2 " in row for row in stuck["table"]) == 4


class FakeRoot:
    """Answers the disarm protocol's commands from a scripted state."""

    def __init__(self, claim=0, claim_exists=False, fired=False, done=True, bootout=0, rm=0, gone_after_rm=True):
        self.claim, self.claim_exists, self.fired, self.done = claim, claim_exists, fired, done
        self.bootout, self.rm, self.gone_after_rm = bootout, rm, gone_after_rm
        self.calls = []

    def __call__(self, _limit, *argv):
        self.calls.append(argv)
        command, last = argv[0], argv[-1]
        if command == MKDIR:
            return self.claim, ""
        if command == LAUNCHCTL:
            return self.bootout, ""
        if command == CAT:
            return 0, "fallback added 0.0.0.0/2\nrecovery finished ok\n"
        if command == RM:
            return self.rm, ""
        if command == TEST:
            if last.endswith("/claim"):
                return (0 if self.claim_exists else 1), ""
            if last.endswith("/fired"):
                return (0 if self.fired else 1), ""
            if last.endswith("/done"):
                return (0 if self.done else 1), ""
            return (1 if self.gone_after_rm else 0), ""
        raise AssertionError(argv)


def self_test_disarm():
    def disarm(fake, states=("running", "absent")):
        remaining = list(states)
        watchdog = Watchdog("0123456789abcdef")
        watchdog.created = True
        with open(os.devnull, "w") as quiet:
            stdout, sys.stdout = sys.stdout, quiet
            try:
                return disarm_watchdog(watchdog, fake, lambda _label: remaining.pop(0) if len(remaining) > 1 else remaining[0],
                                       recovery_deadline=2, sleep=lambda _s: None)
            finally:
                sys.stdout = stdout

    clean = FakeRoot()
    assert disarm(clean) == []
    names = [call[0] for call in clean.calls]
    assert names.index(MKDIR) < names.index(LAUNCHCTL) < names.index(RM), "must claim, then stop, then remove"
    fired_check = next(i for i, call in enumerate(clean.calls) if call[-1].endswith("/fired"))
    assert names.index(LAUNCHCTL) < fired_check, "the fired marker must be read after the job has stopped"

    # Firing wins, even if the claim looked fine and the recovery fully worked.
    assert disarm(FakeRoot(claim=1, claim_exists=True, fired=True), ("running", "absent"))
    assert disarm(FakeRoot(fired=True))
    assert disarm(FakeRoot(claim=1, claim_exists=True, fired=True, done=False))  # Recovery never finished.
    assert disarm(FakeRoot(claim=1, claim_exists=False))  # Neither claimed nor fired: unknown.
    assert disarm(FakeRoot(bootout=5), ("running", "running"))  # The job never stopped.
    assert disarm(FakeRoot(), ("running", "unknown"))
    assert disarm(FakeRoot(), ("absent", "absent"))  # Died early: the window had no protection.
    assert disarm(FakeRoot(rm=1))
    assert disarm(FakeRoot(gone_after_rm=False))

    class FiredReadFails(FakeRoot):
        def __call__(self, limit, *argv):
            if argv[0] == TEST and argv[-1].endswith("/fired"):
                return 124, ""
            return super().__call__(limit, *argv)

    assert disarm(FiredReadFails())  # A timeout reading the marker is not "not fired".

    never = Watchdog("0123456789abcdef")
    assert disarm_watchdog(never, FakeRoot(), lambda _label: "absent") == []
    assert raises(Watchdog, "../../etc") and raises(Watchdog, "0123456789ABCDEF")

    def launchctl(code, text=""):
        return lambda: subprocess.CompletedProcess([], code, stdout=text.encode())

    assert job_state("x", launchctl(113)) == "absent"
    assert job_state("x", launchctl(1, 'Bad request.\nCould not find service "x" in domain for system\n')) == "absent"
    assert job_state("x", launchctl(5)) == "unknown"
    assert job_state("x", launchctl(0, "x = {\n\tstate = running\n}\n")) == "running"
    assert job_state("x", launchctl(0, "x = {\n\tstate = not running\n}\n")) == "not"
    assert job_state("x", launchctl(0, "nothing\n")) == "unknown"


def self_test_processes():
    def spawn(script):
        return subprocess.Popen(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL)

    # Real child processes, with real signals.
    done = spawn("exit 0")
    done.wait()
    assert stop_peer(done) and done.returncode == 0
    plain = spawn("exec sleep 30")
    assert stop_peer(plain) and plain.returncode == -signal.SIGTERM
    with tempfile.TemporaryDirectory() as tmp:
        ready = os.path.join(tmp, "ready")
        stubborn = spawn(f"trap '' TERM; : >{ready}; while :; do sleep 0.1; done")
        end = time.monotonic() + 10
        while not os.path.exists(ready):
            assert time.monotonic() < end, "child did not start"
            time.sleep(0.05)
        assert stop_peer(stubborn) and stubborn.returncode == -signal.SIGKILL

        class Unstoppable:
            def poll(self): return None
            def terminate(self): pass
            def kill(self): pass
            def wait(self, timeout): raise subprocess.TimeoutExpired("peer", timeout)

        assert stop_peer(Unstoppable()) is False  # Simulated: cannot be stopped.

        out, err = os.path.join(tmp, "out"), os.path.join(tmp, "err")
        env = dict(os.environ)
        assert run_app(["/bin/sh", "-c", "exit 7"], env, out, err, 5) == 7
        assert run_app(["/bin/sh", "-c", "echo hi; exit 0"], env, out, err, 5) == 0 and read(out) == b"hi\n"
        ticks = []
        assert run_app(["/bin/sh", "-c", "sleep 30 & wait"], env, out, err, 0.5, lambda: ticks.append(1), interval=0.05) is None
        assert ticks, "the sampler never ran"

        write_private(os.path.join(tmp, "leak"), "secret-key\n")
        assert raises(show_public, [os.path.join(tmp, "leak")], [b"secret-key"])

        # Canned peer output: the real socket check only runs natively.
        def bound(text, code=0):
            return lambda *_args, **_kwargs: subprocess.CompletedProcess([], code, stdout=text)

        assert not raises(check_bind_source, "p", "127.77.0.2", bound(b"BIND_SOURCE_OK 127.77.0.2\n"))
        assert raises(check_bind_source, "p", "127.77.0.2", bound(b"BIND_SOURCE_OK 127.77.0.3\n"))
        assert raises(check_bind_source, "p", "127.77.0.2", bound(b"BIND_SOURCE_OK 127.77.0.2\n", 1))
        assert raises(check_bind_source, "p", "127.77.0.2", bound(b""))

        def timed_out(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("peer", 1)

        assert raises(check_bind_source, "p", "127.77.0.2", timed_out)

        def denied(*_):
            raise PermissionError(13, "denied")

        def enoent(*_):
            raise FileNotFoundError(2, "missing")

        assert not raises(require_write_denied, "/t/wg", "/t", denied)
        assert raises(require_write_denied, "/t/wg", "/t", enoent)
        file_path = os.path.join(tmp, "payload")
        write_private(file_path, "payload")
        assert raises(require_write_denied, file_path, tmp) and read(file_path) == b"payload"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as held:
        held.bind(("127.0.0.1", 0))
        assert not raises(wait_udp_bound, "127.0.0.1", held.getsockname()[1], deadline=2)
    assert raises(wait_udp_bound, "127.0.0.1", free_udp_port("127.0.0.1"), deadline=0.3)

    full = FIXTURE_ROUTES + "0/1 link#9 USc utun5\n"
    assert wait_full_routes_gone(lambda: FIXTURE_ROUTES, deadline=1)
    assert not wait_full_routes_gone(lambda: full, deadline=0.2, sleep=lambda _s: None)
    assert not wait_full_routes_gone(lambda: "", deadline=0.2, sleep=lambda _s: None), "an unreadable table counted as gone"


def self_test_fixtures():
    with tempfile.TemporaryDirectory() as tmp:
        def fake_run(cmd, input=None, stdout=None, check=None, timeout=None):
            assert cmd[0] == "wg" and cmd[1:] in (["genkey"], ["pubkey"]), "no key in argv"
            assert (input is not None) == (cmd[1] == "pubkey"), "keys go through stdin"
            return subprocess.CompletedProcess(cmd, 0, stdout=(secrets.token_urlsafe(30)[:43] + "=\n").encode())

        ports = iter((50001, 50002))
        real_run, subprocess.run = subprocess.run, fake_run
        try:
            manifest, peers, keys = fixtures(tmp, "full-first", "wg", lambda _alias: next(ports))
        finally:
            subprocess.run = real_run
        document = json.loads(read(manifest))
        assert document["restartCount"] == 1 and document["startupOrder"] == "full-first" and len(document["tunnels"]) == 2
        first, second = document["tunnels"]
        assert first["id"] != second["id"] and first["expectedToken"] != second["expectedToken"]
        assert first["probeHost"] == "198.18.71.2" and second["probeHost"] == "198.18.72.2"
        assert first["probePort"] != 0 and 1024 < first["probePort"] < 65536
        assert not any(key.decode() in json.dumps(document) for key in keys) and len(set(keys)) == 4

        for entry, address, allowed, alias in ((first, "198.18.71.1/32", "0.0.0.0/0", "127.77.0.2"), (second, "198.18.72.1/32", "198.18.72.0/24", "127.77.0.3")):
            assert stat.S_IMODE(os.stat(entry["configPath"]).st_mode) == 0o600 and os.path.isabs(entry["configPath"])
            conf = read(entry["configPath"]).decode()
            assert f"Address = {address}\n" in conf and f"AllowedIPs = {allowed}\n" in conf
            assert re.search(rf"^Endpoint = {re.escape(alias)}:\d+$", conf, re.M) and "127.0.0.1" not in conf
            assert set(re.findall(r"^(\w+) =", conf, re.M)) == {"PrivateKey", "Address", "MTU", "PublicKey", "Endpoint", "AllowedIPs"}
        for spec in peers.values():
            assert stat.S_IMODE(os.stat(spec["keys"]).st_mode) == 0o600


def self_test():
    self_test_parsers()
    self_test_evidence()
    self_test_watchdog()
    self_test_disarm()
    self_test_processes()
    self_test_fixtures()
    print("ok: full-route parsers, evidence, watchdog script, disarm protocol, process stopping and fixtures (no root, routing, ACL or macOS involved)")


if sys.argv[1:] == ["--self-test"]:
    self_test()
elif len(sys.argv) == 3:
    sys.exit(main(sys.argv[1], sys.argv[2]))
else:
    sys.exit("usage: smoke-full-route.sh WireNest.app smoke-peer")
PY
