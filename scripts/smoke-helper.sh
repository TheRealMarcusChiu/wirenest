#!/usr/bin/env bash
# Real authenticated-helper proof on an ephemeral macOS CI runner: the packaged app's
# `--helper-smoke` driver talks through the production HelperClient and authenticated XPC
# to the installed root helper, and carries TCP traffic to userspace netstack peers. Exit 0
# from the driver alone is not a pass: this script also requires the exact final marker,
# then uninstalls the helper and checks that nothing was left behind.
#
# An app without the driver starts its normal UI when given `--helper-smoke`, so it fails
# the opt-in refusal check before anything is installed. That is the expected RED.
#
# Non-disruptive by construction: throwaway keys, loopback endpoints, routes only inside
# the RFC 2544 test range, no DNS settings, no hooks. The GUI and real hardware are not covered.
#
# Compatible with macOS's bash 3.2 and /usr/bin/python3 3.9.
#
# Usage: bash scripts/smoke-helper.sh path/to/WireNest.app path/to/smoke-peer
#        bash scripts/smoke-helper.sh --self-test    # verdict logic only; proves nothing about macOS
set -euo pipefail
source "$(dirname "$0")/deps.sh"

write_harness() {
  cat >"$1" <<'PY'
import contextlib, errno, ipaddress, json, os, re, secrets, signal, socket, stat
import subprocess, sys, tempfile, time, uuid

MARKER = b"HELPER_SMOKE_PASSED"
TUNNELS = (("a", 71, 18081), ("b", 72, 18082))
REFUSAL_DEADLINE = 30
DRIVER_DEADLINE = 300
PEER_BIND_DEADLINE = 15
INSTALL_DIR = "/Library/PrivilegedHelperTools/com.marcuschiu.WireNest"


def write_private(path, text):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(text)


def free_udp_port(taken):
    # The peer binds the wildcard on both families, so the port must be free on both.
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as v4, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as v6:
            v4.bind(("", 0))
            port = v4.getsockname()[1]
            v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                v6.bind(("::", port))
            except OSError:
                continue
            if port not in taken:
                return port
    sys.exit("error: could not find a free UDP port")


def wait_udp_bound(port, deadline=PEER_BIND_DEADLINE):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(("", port))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    return
                raise
        time.sleep(0.1)
    sys.exit(f"error: smoke peer did not bind UDP port {port} within {deadline}s")


def fixtures(tmp, wg):
    def tool(*args, stdin=None):
        return subprocess.run(wg + list(args), input=stdin, stdout=subprocess.PIPE, check=True, timeout=15).stdout.decode().strip()

    tunnels, private_keys, ports = [], [], []
    for name, octet, http_port in TUNNELS:
        client_key, peer_key = tool("genkey"), tool("genkey")
        private_keys += [client_key, peer_key]
        peer_public = tool("pubkey", stdin=(peer_key + "\n").encode())
        client_public = tool("pubkey", stdin=(client_key + "\n").encode())
        udp_port = free_udp_port(ports)
        ports.append(udp_port)
        token = secrets.token_hex(16)
        conf = os.path.join(tmp, name + ".conf")
        write_private(conf, f"""[Interface]
PrivateKey = {client_key}
Address = 198.18.{octet}.1/32
MTU = 1280

[Peer]
PublicKey = {peer_public}
Endpoint = 127.0.0.1:{udp_port}
AllowedIPs = 198.18.{octet}.0/24
""")
        write_private(os.path.join(tmp, name + ".keys"), f"{peer_key}\n{client_public}\n")
        write_private(os.path.join(tmp, name + ".args"), f"{udp_port} {token}\n")
        tunnels.append({
            "id": str(uuid.uuid4()).upper(), "configPath": conf,
            "probeHost": f"198.18.{octet}.2", "probePort": http_port, "expectedToken": token,
        })
    write_private(os.path.join(tmp, "manifest.json"), json.dumps({"tunnels": tunnels, "restartCount": 3}))
    write_private(os.path.join(tmp, "private-keys"), "\n".join(private_keys) + "\n")


def run(cmd, env, out, err, deadline):
    # Output goes to files: a pipe held open by a stray child could outlive the deadline.
    with open(out, "wb") as stdout, open(err, "wb") as stderr:
        process = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
    try:
        return process.wait(timeout=deadline)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return None


def read(path):
    with open(path, "rb") as f:
        return f.read()


def reject_key_material(tmp, paths):
    keys = read(os.path.join(tmp, "private-keys")).split()
    for path in paths:
        data = read(path)
        if any(key in data for key in keys):
            sys.exit(f"error: private key material appeared in {os.path.basename(path)}; output withheld")


def show(paths):
    sys.stdout.flush()
    for path in paths:
        sys.stdout.buffer.write(read(path))
    sys.stdout.flush()


def refused(tmp, app, deadline=REFUSAL_DEADLINE):
    env = {k: v for k, v in os.environ.items() if k != "WIRENEST_HELPER_SMOKE"}
    out, err = os.path.join(tmp, "refusal.out"), os.path.join(tmp, "refusal.err")
    status = run(app + ["--helper-smoke", os.path.join(tmp, "manifest.json")], env, out, err, deadline)
    reject_key_material(tmp, [out, err])
    show([out, err])
    if status is None:
        sys.exit(f"error: --helper-smoke without WIRENEST_HELPER_SMOKE=1 was still running after {deadline}s; "
                 "the diagnostic entrypoint is missing and the normal app started")
    if status <= 0:
        sys.exit(f"error: --helper-smoke without WIRENEST_HELPER_SMOKE=1 must refuse with a nonzero exit, got {status}")
    if MARKER in read(out):
        sys.exit("error: the refused run printed the success marker")


def drive(tmp, app, deadline=DRIVER_DEADLINE):
    env = dict(os.environ, WIRENEST_HELPER_SMOKE="1")
    out, err = os.path.join(tmp, "driver.out"), os.path.join(tmp, "driver.err")
    peer_logs = [os.path.join(tmp, f"peer-{name}.log") for name, _, _ in TUNNELS]
    peer_logs = [path for path in peer_logs if os.path.exists(path)]
    status = run(app + ["--helper-smoke", os.path.join(tmp, "manifest.json")], env, out, err, deadline)
    reject_key_material(tmp, [out, err] + peer_logs)
    show([out, err])
    lines = [line for line in read(out).splitlines() if line.strip()]
    if status == 0 and lines[-1:] == [MARKER] and lines.count(MARKER) == 1:
        return
    show(peer_logs)
    if status is None:
        sys.exit(f"error: the driver did not finish within {deadline}s")
    sys.exit(f"error: the driver needs exit 0 and the exact final marker; it exited {status}")


def check_install(uid, cdhash):
    pin_path = INSTALL_DIR + "/client.json"
    for path in (pin_path, INSTALL_DIR + "/WireNestHelper"):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            sys.exit(f"error: {path} is not a root-owned file closed to other writers")
    pin = json.loads(read(pin_path))
    if pin.get("ownerUID") != int(uid) or not cdhash or str(pin.get("appCDHash", "")).lower() != cdhash.lower():
        sys.exit("error: the installed client pin does not name this user and this exact app build")


def self_test():
    def outcome(function, *args, **kwargs):
        try:
            function(*args, **kwargs)
            return True
        except SystemExit:
            return False

    fake_wg = ["/bin/sh", "-c", 'case "$1" in pubkey) cat >/dev/null;; esac; head -c 32 /dev/urandom | base64', "wg"]
    with tempfile.TemporaryDirectory() as tmp:
        fixtures(tmp, fake_wg)
        keys = read(os.path.join(tmp, "private-keys")).decode().split()
        assert len(set(keys)) == 4 and all(len(key) == 44 for key in keys)
        manifest = json.loads(read(os.path.join(tmp, "manifest.json")))
        tunnels = manifest["tunnels"]
        assert manifest["restartCount"] == 3 and len(tunnels) == 2
        assert tunnels[0]["expectedToken"] != tunnels[1]["expectedToken"] and tunnels[0]["id"] != tunnels[1]["id"]
        assert not any(key in json.dumps(manifest) for key in keys)
        udp_ports = [int(read(os.path.join(tmp, name + ".args")).split()[0]) for name, _, _ in TUNNELS]
        assert udp_ports[0] != udp_ports[1]
        reserved = ipaddress.ip_network("198.18.0.0/15")
        for name in ("a.conf", "b.conf", "a.keys", "b.keys", "a.args", "b.args", "manifest.json", "private-keys"):
            assert stat.S_IMODE(os.stat(os.path.join(tmp, name)).st_mode) == 0o600, name
        for tunnel, udp_port in zip(tunnels, udp_ports):
            assert os.path.isabs(tunnel["configPath"]) and ipaddress.ip_address(tunnel["probeHost"]) in reserved
            conf = read(tunnel["configPath"]).decode()
            assert f"Endpoint = 127.0.0.1:{udp_port}\n" in conf
            assert set(re.findall(r"^(\w+) =", conf, re.M)) == {"PrivateKey", "Address", "MTU", "PublicKey", "Endpoint", "AllowedIPs"}
            for value in re.findall(r"^(?:Address|AllowedIPs) = (.+)$", conf, re.M):
                assert ipaddress.ip_network(value, strict=False).subnet_of(reserved), value

        def app(body):
            return ["/bin/sh", "-c", body, "app"]

        opted_in = '[ "$WIRENEST_HELPER_SMOKE" = 1 ] && [ "$1" = --helper-smoke ] && [ -f "$2" ] || exit 9; '
        leak = f"echo {keys[0]}; "
        for body, expected in (
            (opted_in + "echo HELPER_SMOKE_PASSED", True),
            (opted_in + "echo noise; echo HELPER_SMOKE_PASSED; echo", True),
            (opted_in + "exit 0", False),
            (opted_in + "echo HELPER_SMOKE_PASSED; exit 1", False),
            (opted_in + "echo HELPER_SMOKE_PASSED; echo later", False),
            (opted_in + "echo HELPER_SMOKE_PASSED; echo HELPER_SMOKE_PASSED", False),
            (opted_in + "echo HELPER_SMOKE_PASSED_NOT", False),
            (opted_in + "echo HELPER_SMOKE_PASSED >&2", False),
            (opted_in + leak + "echo HELPER_SMOKE_PASSED", False),
            ("sleep 60", False),
            ("exit 2", False),
        ):
            assert outcome(drive, tmp, app(body), deadline=1) is expected, body
        for body, expected in (
            ("exit 2", True),
            ('[ -z "${WIRENEST_HELPER_SMOKE+x}" ] || exit 0; exit 2', True),
            ("exit 0", False),
            ("sleep 60", False),
            ("kill -9 $$", False),
            ("echo HELPER_SMOKE_PASSED; exit 2", False),
            (leak + "exit 2", False),
        ):
            assert outcome(refused, tmp, app(body), deadline=1) is expected, body

        captured = os.path.join(tmp, "captured")
        with open(captured, "w") as stream, contextlib.redirect_stdout(stream):
            assert not outcome(drive, tmp, app(opted_in + leak + "echo HELPER_SMOKE_PASSED"), deadline=5)
        assert keys[0].encode() not in read(captured)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as held:
            held.bind(("", 0))
            assert outcome(wait_udp_bound, held.getsockname()[1], deadline=2)
        assert not outcome(wait_udp_bound, free_udp_port([]), deadline=0.3)


command, args = sys.argv[1], sys.argv[2:]
if command == "fixtures":
    fixtures(args[0], [args[1]])
elif command == "wait-udp":
    wait_udp_bound(int(args[0]))
elif command == "refused":
    refused(args[0], [args[1]])
elif command == "drive":
    drive(args[0], [args[1]])
elif command == "check-install":
    check_install(args[0], args[1])
elif command == "self-test":
    self_test()
else:
    sys.exit(f"error: unknown harness command {command}")
PY
}

if [[ $# -eq 1 && $1 == --self-test ]]; then
  umask 077
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  write_harness "$tmp/harness.py"
  python3 -I "$tmp/harness.py" self-test >/dev/null
  echo "ok: helper smoke fixtures and verdict logic (no helper, routing or macOS involved)"
  exit 0
fi

[[ $# -eq 2 ]] || die "usage: smoke-helper.sh WireNest.app smoke-peer"
[[ $(uname -s) == Darwin ]] || die "this smoke test only runs on macOS; refusing to touch routing here"
[[ ${CI:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] ||
  die "this smoke test only runs on an ephemeral GitHub-hosted runner; refusing to touch routing here"
[[ $EUID -ne 0 ]] || die "run as the ordinary owner, not root; only the helper install and uninstall use sudo"
[[ -d $1 ]] || die "missing app bundle: $1"
[[ -x $2 && -f $2 ]] || die "missing smoke peer: $2"

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
app=$(cd "$1" && pwd -P)
peer_bin=$2
driver="$app/Contents/MacOS/WireNestApp"
helper="$app/Contents/Library/LaunchServices/WireNestHelper"
wg_tool="$app/Contents/Resources/Tools/wg"
launchd_label=com.marcuschiu.WireNest.helper
# From HelperConstants and HelperPaths.production.
helper_state=(
  /Library/PrivilegedHelperTools/com.marcuschiu.WireNest
  /Library/LaunchDaemons/com.marcuschiu.WireNest.helper.plist
  /var/run/com.marcuschiu.WireNest
  "/Library/Application Support/com.marcuschiu.WireNest"
)

for file in "$driver" "$helper" "$wg_tool" /usr/bin/python3; do
  [[ -x $file ]] || die "missing executable: $file"
done
python3 -I -c 'pass' || die "/usr/bin/python3 does not run"
codesign --verify --strict --deep "$app" || die "$app failed signature verification"
cdhash=$(codesign -dv --verbose=4 "$app" 2>&1 | awk -F= '$1 == "CDHash" {print $2}')
[[ -n $cdhash ]] || die "could not read the app's code directory hash"
sudo -n true || die "passwordless sudo is required"

route_field() { { route -n get -inet "$1" 2>/dev/null || true; } | awk -v f="$2:" '$1 == f {print $2}'; }
network_snapshot() {
  { route -n get -inet default 2>/dev/null || true; } | awk '$1 == "destination:" || $1 == "gateway:" || $1 == "interface:"'
  scutil --dns | awk '/nameserver\[/ {print $3}' | sort -u
  netstat -rnf inet | awk '$1 ~ /^198\.1[89](\.|\/|$)/ {print $1}' | sort -u
  ifconfig -a | awk '$1 == "inet" && $2 ~ /^198\.1[89]\./ {print $2}' | sort -u
  ifconfig -l | tr ' ' '\n' | { grep '^utun' || true; } | sort
}
helper_removed() {
  local path
  if launchctl print "system/$launchd_label" >/dev/null 2>&1; then return 1; fi
  for path in "${helper_state[@]}"; do
    [[ ! -e $path ]] || return 1
  done
}

helper_removed || die "a WireNest helper is already installed; refusing to disturb it"
for octet in 71 72; do
  case $(route_field "198.18.$octet.2" destination) in
    '' | default) ;;
    *) die "198.18.$octet.0/24 is already routed on this machine; refusing to continue" ;;
  esac
done

tmp=$(mktemp -d)
tmp=$(cd "$tmp" && pwd -P)
peer_pids=""
install_attempted=0

# The one exit path, so PASS can only be printed after uninstall and verified cleanup.
cleanup() {
  local rc=$? pid waited=0
  trap - EXIT INT TERM
  if [[ $install_attempted -eq 1 ]]; then
    sudo -n "$helper" --uninstall || {
      echo "error: helper uninstall failed" >&2
      rc=1
    }
  fi
  for pid in $peer_pids; do
    kill "$pid" 2>/dev/null || true
  done
  if [[ -f $tmp/before ]]; then
    until helper_removed && network_snapshot >"$tmp/after" && cmp -s "$tmp/before" "$tmp/after"; do
      waited=$((waited + 1))
      if [[ $waited -ge 20 ]]; then
        echo "error: helper state, routes, interfaces or DNS were not restored after ${waited}s:" >&2
        helper_removed || echo "helper files or launchd job remain" >&2
        diff "$tmp/before" "$tmp/after" >&2 || true
        rc=1
        break
      fi
      sleep 1
    done
  fi
  rm -rf "$tmp" || rc=1
  if [[ $rc -eq 0 ]]; then
    echo "HELPER SMOKE PASSED: authenticated app-to-root path, helper uninstalled, network state restored."
    echo "Not covered: the GUI, DNS management with real DNS settings, real hardware."
  else
    echo "HELPER SMOKE FAILED (exit $rc)" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_harness "$tmp/harness.py"
py() { python3 -I "$tmp/harness.py" "$@"; }

network_snapshot >"$tmp/before"
py fixtures "$tmp" "$wg_tool"

# Nothing is installed yet, so an app without the entrypoint fails here without touching root.
py refused "$tmp" "$driver"
echo "ok: --helper-smoke refuses to run without its opt-in"

# start_peer NAME OCTET HTTP_PORT
start_peer() {
  local name=$1 octet=$2 http_port=$3 udp_port token
  read -r udp_port token <"$tmp/$name.args"
  "$peer_bin" --addr "198.18.$octet.2" --client "198.18.$octet.1" --udp-port "$udp_port" \
    --http-port "$http_port" --token "$token" <"$tmp/$name.keys" >"$tmp/peer-$name.log" 2>&1 &
  peer_pids="$peer_pids $!"
  py wait-udp "$udp_port"
}
start_peer a 71 18081
start_peer b 72 18082
echo "ok: both userspace peers are listening"

install_attempted=1
# shortcut: sudo cannot be killed by this unprivileged script, so a hung helper is bounded by the
# workflow step's timeout-minutes instead; add a root-side alarm if this ever runs outside that step.
sudo -n "$helper" --install --uid "$(id -u)"
py check-install "$(id -u)" "$cdhash"
echo "ok: helper installed, root-owned, and pinned to this user and app build"

py drive "$tmp" "$driver"
echo "ok: driver finished with exit 0 and the exact final marker"
