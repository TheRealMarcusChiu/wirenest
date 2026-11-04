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
import contextlib, errno, hashlib, ipaddress, json, os, re, secrets, signal, socket, stat
import subprocess, sys, tempfile, time, types, uuid

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


SOURCE_TOOL_GRANT = "write,append"
SOURCE_DIR_GRANT = "add_file,add_subdirectory,delete_child"
TOOL_NAMES = ("bash", "wg", "wg-quick", "wireguard-go")


def run_native(cmd):
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    text = result.stdout.decode(errors="replace")
    if result.returncode != 0:
        sys.exit(f"error: {cmd[0]} exited {result.returncode}: {text.strip()}")
    return text


def acl_list_command(path):
    return ["/bin/ls", "-led", path]


def acl_grant_commands(user, tool, tools_dir):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", user):
        sys.exit("error: the user name cannot be used in an ACL entry")
    return [
        ["/bin/chmod", "+a", f"{user} allow {SOURCE_TOOL_GRANT}", tool],
        ["/bin/chmod", "+a", f"{user} allow {SOURCE_DIR_GRANT}", tools_dir],
    ]


def parse_acl(listing):
    # Every line must be understood: an unread line could be the grant this check exists to find.
    lines = [line for line in listing.splitlines() if line.strip()]
    if not lines or lines[0][0] not in "-d":
        sys.exit("error: ls -led printed no file entry")
    entries = []
    for line in lines[1:]:
        entry = re.fullmatch(r"\s*\d+:\s+(\S.*?)\s+(?:inherited\s+)?(allow|deny)\s+(\S+)\s*", line)
        if not entry:
            sys.exit(f"error: ls -led printed an unreadable ACL line: {line.strip()}")
        entries.append((entry.group(1), entry.group(2), set(entry.group(3).split(","))))
    return lines[0].split()[0], entries


def require_grant(listing, user, permissions, path):
    _, entries = parse_acl(listing)
    wanted = set(permissions.split(","))
    if not any(who == "user:" + user and kind == "allow" and wanted <= granted for who, kind, granted in entries):
        sys.exit(f"error: {path} does not carry the ACL grant, so the installer check would prove nothing")


def require_no_acl(listing, path):
    # ls shows @ instead of + when a file has both, so the entries decide as well as the marker.
    marker, entries = parse_acl(listing)
    if marker.endswith("+") or entries:
        sys.exit(f"error: installed {path} still has an extended ACL: {entries}")


def grant_source_acl(tools_dir, user, native=run_native):
    tool = os.path.join(tools_dir, "wg")
    for path in (tool, tools_dir):
        if os.lstat(path).st_uid != os.getuid():
            sys.exit(f"error: {path} is not this user's copy; refusing to change its ACL")
    for command in acl_grant_commands(user, tool, tools_dir):
        native(command)
    require_grant(native(acl_list_command(tool)), user, SOURCE_TOOL_GRANT, tool)
    require_grant(native(acl_list_command(tools_dir)), user, SOURCE_DIR_GRANT, tools_dir)


def require_root_protected(path, is_kind, lstat=os.lstat):
    try:
        info = lstat(path)
    except OSError as error:
        sys.exit(f"error: cannot inspect {path}: {errno.errorcode.get(error.errno, error.errno)}")
    if not is_kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        sys.exit(f"error: {path} is not a root-owned entry closed to other writers")


def require_write_denied(tool, tools_dir, opener=os.open):
    # Opening writes nothing, so a failed check cannot damage the root-owned tool. Only a denial
    # counts: ENOENT or EROFS would also stop a write without showing that permissions did.
    probe = os.path.join(tools_dir, ".acl-probe-" + secrets.token_hex(8))
    attempts = (
        ("open for write", tool, (os.O_WRONLY,)),
        ("open for append", tool, (os.O_WRONLY | os.O_APPEND,)),
        ("create a file", probe, (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)),
    )
    for label, path, arguments in attempts:
        try:
            descriptor = opener(path, *arguments)
        except PermissionError:
            continue
        except OSError as error:
            sys.exit(f"error: {label} on {path} failed with {errno.errorcode.get(error.errno, error.errno)}, not a permission denial")
        os.close(descriptor)
        if path == probe:
            os.unlink(probe)
        sys.exit(f"error: the installing user could {label} on {path} inside the root payload")


def check_installed_acl(source_tools, install_dir=INSTALL_DIR, native=run_native, lstat=os.lstat, opener=os.open):
    tools_dir = os.path.join(install_dir, "Tools")
    tool = os.path.join(tools_dir, "wg")
    require_root_protected(tools_dir, stat.S_ISDIR, lstat)
    tool_paths = [os.path.join(tools_dir, name) for name in TOOL_NAMES]
    for path in tool_paths:
        require_root_protected(path, stat.S_ISREG, lstat)
    # Reading it also proves the path is reachable, so a later denial is about the tool itself.
    if hashlib.sha256(read(tool)).digest() != hashlib.sha256(read(os.path.join(source_tools, "wg"))).digest():
        sys.exit("error: the installed wg differs from the signed app's wg")
    payload = [install_dir, os.path.join(install_dir, "WireNestHelper"), os.path.join(install_dir, "client.json"), tools_dir] + tool_paths
    for path in payload:
        require_no_acl(native(acl_list_command(path)), path)
    require_write_denied(tool, tools_dir, opener)


def snapshot_dns(text):
    # Everything but `reach`, a live reachability result rather than configuration. Order and
    # resolver numbering stay, because they decide which server answers.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("DNS configuration") or not any(line.startswith("resolver #") for line in lines):
        sys.exit("error: scutil --dns output has no resolver configuration")
    return ["dns " + line for line in lines if not re.match(r"reach\s*:", line)]


def snapshot_routes(text):
    lines = text.splitlines()
    header = next((i for i, line in enumerate(lines) if line.split()[:2] == ["Destination", "Gateway"]), None)
    if header is None or "Flags" not in lines[header].split() or "Netif" not in lines[header].split():
        sys.exit("error: netstat output has no route table header")
    columns = lines[header].split()
    flags, netif = columns.index("Flags"), columns.index("Netif")
    rows = [line.split() for line in lines[header + 1:] if line.strip()]
    if not rows:
        sys.exit("error: netstat output has no routes")
    # Expire is dropped: it is a countdown. All flags stay; this range is normally empty.
    routes = []
    for row in rows:
        if re.match(r"198\.1[89](\.|/|%|$)", row[0]):
            if len(row) <= max(flags, netif):
                sys.exit(f"error: netstat route {row[0]} is missing columns")
            routes.append(f"route {row[0]} {row[1]} {row[flags]} {row[netif]}")
    return sorted(routes)


def snapshot_default(text):
    fields = re.findall(r"^\s*(destination|gateway|interface):\s*(\S+)", text, re.M)
    if {"destination", "interface"} - {name for name, _ in fields}:
        sys.exit("error: route output has no default destination and interface")
    return [f"default {name} {value}" for name, value in fields]


def snapshot_interfaces(names, stanzas):
    names = names.split()
    if not names:
        sys.exit("error: ifconfig -l listed no interfaces")
    found, current = [], None
    for line in stanzas.splitlines():
        stanza = re.match(r"(\S+): flags=", line)
        if stanza:
            current = stanza.group(1)
        inet = re.match(r"\s+inet (198\.1[89]\.\S+)", line)
        if inet:
            found.append(f"address {current} {inet.group(1)}")
    if current is None:
        sys.exit("error: ifconfig -a output has no interfaces")
    return sorted(found) + sorted("utun " + name for name in names if name.startswith("utun"))


def snapshot_text(dns, routes, default, iflist, ifaces):
    lines = snapshot_default(default) + snapshot_dns(dns) + snapshot_routes(routes) + snapshot_interfaces(iflist, ifaces)
    return "\n".join(lines) + "\n"


def snapshot(dest):
    parts = [read(f"{dest}.{part}").decode(errors="replace") for part in ("dns", "routes", "default", "iflist", "ifaces")]
    text = snapshot_text(*parts)  # Parse first, so a bad capture never leaves a baseline behind.
    with open(dest, "w") as f:
        f.write(text)


FIXTURE_DNS = """DNS configuration

resolver #1
  search domain[0] : corp.example
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  if_index : 6 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.53
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
"""
FIXTURE_ROUTES = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
198.18.5/24        192.0.2.9          UGSc                  en0
198.18.6.7         link#6             UHLWI                 en0      42
"""
FIXTURE_DEFAULT = """   route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
"""
FIXTURE_IFLIST = "lo0 en0 utun0 utun1\n"
FIXTURE_IFACES = """lo0: flags=8049<UP,LOOPBACK> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,RUNNING> mtu 1500
\tinet 192.0.2.10 netmask 0xffffff00
utun1: flags=8051<UP,POINTOPOINT> mtu 1280
\tinet 198.18.5.1 --> 198.18.5.1 netmask 0xffffffff
"""
FIXTURES = {"dns": FIXTURE_DNS, "routes": FIXTURE_ROUTES, "default": FIXTURE_DEFAULT, "iflist": FIXTURE_IFLIST, "ifaces": FIXTURE_IFACES}


def snapshot_fixtures(tmp):
    for part, text in FIXTURES.items():
        write_private(os.path.join(tmp, "fixture." + part), text)


def self_test_snapshot():
    def taken(**changes):
        return snapshot_text(**dict(FIXTURES, **changes))

    def rejected(**changes):
        try:
            taken(**changes)
        except SystemExit:
            return True
        return False

    def changed(text, old, new):
        assert old in text, old
        return text.replace(old, new)

    base = taken()
    assert "198.18.5/24 192.0.2.9 UGSc en0" in base and "utun utun1" in base and "address utun1 198.18.5.1" in base

    # The nameserver set is identical in the first three, so a set comparison would miss them.
    for label, changes in (
        ("search domain", {"dns": changed(FIXTURE_DNS, "corp.example", "evil.example")}),
        ("server order", {"dns": FIXTURE_DNS.replace("[0] : 192.0.2.53\n  nameserver[1] : 192.0.2.54", "[0] : 192.0.2.54\n  nameserver[1] : 192.0.2.53", 1)}),
        ("scope", {"dns": changed(FIXTURE_DNS, "Scoped, Request", "Request")}),
        ("interface association", {"dns": changed(FIXTURE_DNS, "6 (en0)", "9 (utun1)")}),
        ("new server", {"dns": changed(FIXTURE_DNS, "192.0.2.54", "192.0.2.55")}),
        ("route gateway", {"routes": changed(FIXTURE_ROUTES, "192.0.2.9 ", "192.0.2.8 ")}),
        ("route interface", {"routes": changed(FIXTURE_ROUTES, "UGSc                  en0", "UGSc                  utun1")}),
        ("route flags", {"routes": changed(FIXTURE_ROUTES, "UGSc ", "UGS  ")}),
        ("added route", {"routes": FIXTURE_ROUTES + "198.19.1/24 192.0.2.9 UGSc en0\n"}),
        ("default gateway", {"default": changed(FIXTURE_DEFAULT, "192.0.2.1", "192.0.2.2")}),
        ("default interface", {"default": changed(FIXTURE_DEFAULT, "en0", "utun1")}),
        ("added utun", {"iflist": FIXTURE_IFLIST + "utun2\n"}),
        ("reserved address moved", {"ifaces": changed(FIXTURE_IFACES, "utun1:", "utun2:")}),
    ):
        assert taken(**changes) != base, label

    # Only what the parser documents as volatile or irrelevant may compare equal.
    for label, changes in (
        ("reach", {"dns": FIXTURE_DNS.replace("0x00000002 (Reachable)", "0x00000000 (Not Reachable)")}),
        ("route expiry", {"routes": changed(FIXTURE_ROUTES, "      42", "      17")}),
        ("unrelated route", {"routes": FIXTURE_ROUTES + "10.1/16 192.0.2.1 UGSc en0\n"}),
        ("other interface address", {"ifaces": changed(FIXTURE_IFACES, "192.0.2.10", "192.0.2.11")}),
        ("column layout", {"routes": changed(FIXTURE_ROUTES, "Gateway            Flags", "Gateway  RT_IFA  Flags").replace("192.0.2.9          ", "192.0.2.9 192.0.2.10 ").replace("link#6             ", "link#6 192.0.2.10 ").replace("192.0.2.1          ", "192.0.2.1 192.0.2.10 ")}),
    ):
        assert taken(**changes) == base, label

    for label, changes in (
        ("empty dns", {"dns": ""}),
        ("no dns", {"dns": "No DNS configuration available\n"}),
        ("dns header only", {"dns": "DNS configuration\n"}),
        ("empty routes", {"routes": ""}),
        ("no route header", {"routes": "Internet:\ndefault 192.0.2.1 UGScg en0\n"}),
        ("header without rows", {"routes": "Destination Gateway Flags Netif Expire\n"}),
        ("short reserved route", {"routes": "Destination Gateway Flags Netif Expire\n198.18.5/24 192.0.2.9\n"}),
        ("empty default", {"default": ""}),
        ("default without interface", {"default": "destination: default\n"}),
        ("empty interface list", {"iflist": ""}),
        ("empty interface stanzas", {"ifaces": ""}),
    ):
        assert rejected(**changes), label


def self_test_acl():
    # Canned listings and injected openers only: no ACL is created or read here.
    def refused(function, *args, **kwargs):
        try:
            function(*args, **kwargs)
        except SystemExit:
            return True
        return False

    tool_grant = "-rwxr-xr-x+ 1 runner staff 9 Nov  3 19:41 wg\n 0: user:runner allow write,append\n"
    dir_grant = "drwxr-xr-x+ 6 runner staff 9 Nov  3 19:41 Tools\n 0: user:runner allow add_file,add_subdirectory,delete_child\n"
    clean_tool = "-rwxr-xr-x  1 root wheel 9 Nov  3 19:41 wg\n"
    clean_dir = "drwxr-xr-x  6 root wheel 9 Nov  3 19:41 Tools\n"

    assert acl_grant_commands("runner", "/t/wg", "/t") == [
        ["/bin/chmod", "+a", "runner allow write,append", "/t/wg"],
        ["/bin/chmod", "+a", "runner allow add_file,add_subdirectory,delete_child", "/t"],
    ]
    assert acl_list_command("/t/wg") == ["/bin/ls", "-led", "/t/wg"]
    for user in ("", "two words", "-v", "x;y", "a\nb"):
        assert refused(acl_grant_commands, user, "/t/wg", "/t"), user

    assert not refused(require_grant, tool_grant, "runner", SOURCE_TOOL_GRANT, "p")
    assert not refused(require_grant, dir_grant, "runner", SOURCE_DIR_GRANT, "p")
    for label, listing in (
        ("no ACL", clean_tool),
        ("another user", tool_grant.replace("user:runner", "user:other")),
        ("a group", tool_grant.replace("user:runner", "group:runner")),
        ("deny", tool_grant.replace("allow", "deny")),
        ("partial", tool_grant.replace("write,append", "write")),
        ("unreadable line", tool_grant + " something else\n"),
        ("empty", ""),
        ("symlink", "lrwxr-xr-x  1 runner staff 9 Nov  3 19:41 wg -> x\n"),
    ):
        assert refused(require_grant, listing, "runner", SOURCE_TOOL_GRANT, "p"), label

    assert not refused(require_no_acl, clean_tool, "p")
    assert not refused(require_no_acl, clean_dir, "p")
    assert not refused(require_no_acl, clean_tool.replace("x  1", "x@ 1"), "p")
    for label, listing in (
        ("copied grant", tool_grant),
        ("directory grant", dir_grant),
        ("marker alone", clean_tool.replace("x  1", "x+ 1")),
        ("entry behind @", tool_grant.replace("x+ 1", "x@ 1")),
        ("inherited entry", clean_tool + " 0: group:everyone inherited deny delete\n"),
        ("unreadable line", clean_tool + " something else\n"),
        ("empty", ""),
    ):
        assert refused(require_no_acl, listing, "p"), label

    def denied(*_):
        raise PermissionError(errno.EACCES, "denied")

    def failing(code):
        def opener(*_):
            raise OSError(code, "failed")
        return opener

    def opened_after(denials):
        # Denies the first attempts, then succeeds with a harmless real descriptor.
        count = [0]

        def opener(*_):
            count[0] += 1
            if count[0] <= denials:
                denied()
            return os.open(os.devnull, os.O_WRONLY)
        return opener

    assert not refused(require_write_denied, "/t/wg", "/t", denied)
    assert not refused(require_write_denied, "/t/wg", "/t", failing(errno.EPERM))
    for code in (errno.ENOENT, errno.EROFS, errno.EISDIR, errno.ETXTBSY):
        assert refused(require_write_denied, "/t/wg", "/t", failing(code)), code
    assert refused(require_write_denied, "/t/wg", "/t", opened_after(0))
    assert refused(require_write_denied, "/t/wg", "/t", opened_after(1))

    def attempts_seen(tool, tools_dir):
        seen = []

        def opener(path, *arguments):
            seen.append((path, arguments[0]))
            denied()
        require_write_denied(tool, tools_dir, opener)
        return seen

    seen = attempts_seen("/t/wg", "/t")
    assert seen[0] == ("/t/wg", os.O_WRONLY) and seen[1] == ("/t/wg", os.O_WRONLY | os.O_APPEND)
    assert os.path.dirname(seen[2][0]) == "/t" and seen[2][1] & os.O_CREAT and seen[2][1] & os.O_EXCL
    assert not any(flags & os.O_TRUNC for _, flags in seen)

    regular = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
    assert not refused(require_root_protected, "p", stat.S_ISREG, lambda _: regular)
    for label, info in (
        ("user owned", types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=501)),
        ("group writable", types.SimpleNamespace(st_mode=stat.S_IFREG | 0o775, st_uid=0)),
        ("world writable", types.SimpleNamespace(st_mode=stat.S_IFREG | 0o757, st_uid=0)),
        ("symlink", types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0)),
        ("wrong kind", types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)),
    ):
        assert refused(require_root_protected, "p", stat.S_ISREG, lambda _, value=info: value), label
    assert refused(require_root_protected, "/nonexistent/acl-probe", stat.S_ISREG)

    with tempfile.TemporaryDirectory() as tmp:
        # Real files this user owns: a real open succeeds, so it must fail without changing them.
        file_path = os.path.join(tmp, "wg")
        write_private(file_path, "payload")
        assert refused(require_write_denied, file_path, tmp)
        assert read(file_path) == b"payload" and os.listdir(tmp) == ["wg"]

        def only_create_allowed(path, *arguments):
            return os.open(path, *arguments) if path != file_path else denied()

        assert refused(require_write_denied, file_path, tmp, only_create_allowed)
        assert os.listdir(tmp) == ["wg"]

        # grant_source_acl and check_installed_acl with native commands replaced.
        source = os.path.join(tmp, "source")
        os.mkdir(source)
        write_private(os.path.join(source, "wg"), "payload")

        def source_native(listing_tool, listing_dir, seen):
            def native(cmd):
                seen.append(cmd)
                if cmd[0] == "/bin/chmod":
                    return ""
                return listing_dir if cmd[-1] == source else listing_tool
            return native

        seen = []
        grant_source_acl(source, "runner", source_native(tool_grant, dir_grant, seen))
        assert seen == acl_grant_commands("runner", os.path.join(source, "wg"), source) + [
            acl_list_command(os.path.join(source, "wg")), acl_list_command(source)]
        assert refused(grant_source_acl, source, "runner", source_native(clean_tool, dir_grant, []))
        assert refused(grant_source_acl, source, "runner", source_native(tool_grant, clean_dir, []))

        install = os.path.join(tmp, "install")
        os.makedirs(os.path.join(install, "Tools"))
        for name in TOOL_NAMES:
            write_private(os.path.join(install, "Tools", name), "payload")

        def root_lstat(path):
            kind = stat.S_IFDIR if os.path.isdir(path) else stat.S_IFREG
            return types.SimpleNamespace(st_mode=kind | 0o755, st_uid=0)

        def clean_native(cmd):
            return clean_dir if cmd[-1].endswith("Tools") or cmd[-1] == install else clean_tool

        check = {"install_dir": install, "lstat": root_lstat}
        check_installed_acl(source, native=clean_native, opener=denied, **check)
        # Without these failures the fixture would pass on an installer that kept the grant.
        assert refused(check_installed_acl, source, native=lambda cmd: tool_grant, opener=denied, **check)
        assert refused(check_installed_acl, source, native=lambda cmd: dir_grant if cmd[-1].endswith("Tools") else clean_tool, opener=denied, **check)
        assert refused(check_installed_acl, source, native=clean_native, opener=opened_after(0), **check)
        assert refused(check_installed_acl, source, native=clean_native, opener=failing(errno.ENOENT), **check)
        assert refused(check_installed_acl, source, native=clean_native, opener=denied, install_dir=install, lstat=lambda _: types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=501))
        os.unlink(os.path.join(install, "Tools", "wg"))
        write_private(os.path.join(install, "Tools", "wg"), "tampered")
        assert refused(check_installed_acl, source, native=clean_native, opener=denied, **check)


def self_test():
    def outcome(function, *args, **kwargs):
        try:
            function(*args, **kwargs)
            return True
        except SystemExit:
            return False

    self_test_snapshot()
    self_test_acl()
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
elif command == "grant-source-acl":
    grant_source_acl(args[0], args[1])
elif command == "check-installed-acl":
    check_installed_acl(args[0])
elif command == "snapshot":
    snapshot(args[0])
elif command == "snapshot-fixtures":
    snapshot_fixtures(args[0])
elif command == "self-test":
    self_test()
else:
    sys.exit(f"error: unknown harness command {command}")
PY
}

py() { python3 -I "$tmp/harness.py" "$@"; }

# Every capture must succeed and parse, or there is no snapshot at all: an empty baseline
# would compare equal to an empty result.
network_snapshot() {
  scutil --dns >"$1.dns" &&
    netstat -rnf inet >"$1.routes" &&
    route -n get -inet default >"$1.default" &&
    ifconfig -l >"$1.iflist" &&
    ifconfig -a >"$1.ifaces" &&
    py snapshot "$1"
}

peer_stop_ticks=50 # of 0.1s, per signal
stopped_by=none

# gone, exited (our unreaped zombie), alive (our running child), foreign (the PID now belongs
# to another process, so ours is long gone), or unknown (ps itself failed).
peer_state() {
  local fields status=0 ppid stat
  fields=$(ps -o ppid= -o stat= -p "$1" 2>/dev/null) || status=$?
  if [[ -z $fields ]]; then
    if [[ $status -eq 1 ]]; then echo gone; else echo unknown; fi
    return 0
  fi
  read -r ppid stat <<<"$fields"
  if [[ $ppid != "$$" ]]; then
    echo foreign
  elif [[ $stat == Z* ]]; then
    echo exited
  else
    echo alive
  fi
}

peer_exit_wait() {
  local ticks=$peer_stop_ticks
  while [[ $(peer_state "$1") == alive ]]; do
    [[ $ticks -gt 0 ]] || return 1
    ticks=$((ticks - 1))
    sleep 0.1
  done
}

# Succeeds only once the child is confirmed gone. Signals only a live child of this shell.
stop_peer() {
  local pid=$1 state
  stopped_by=none
  if [[ $(peer_state "$pid") == alive ]]; then
    kill -s TERM "$pid" 2>/dev/null || true
    stopped_by=TERM
    if ! peer_exit_wait "$pid"; then
      kill -s KILL "$pid" 2>/dev/null || true
      stopped_by=KILL
      peer_exit_wait "$pid" || return 1
    fi
  fi
  state=$(peer_state "$pid")
  # wait would block forever on a child that is still running.
  [[ $state != alive && $state != unknown ]] || return 1
  # A nonzero status is expected here: this is the signal we just sent.
  wait "$pid" 2>/dev/null || true
  state=$(peer_state "$pid")
  [[ $state == gone || $state == foreign ]]
}

stop_peers() {
  local pid status=0
  for pid in $peer_pids; do
    stop_peer "$pid" || {
      echo "error: could not confirm that smoke peer $pid stopped" >&2
      status=1
    }
  done
  return "$status"
}

self_test_shell() {
  local child orphan first name
  # start_child TRAP: a real child of this shell, once its signal handling is in place.
  start_child() {
    rm -f "$tmp/ready"
    bash -c "$1"'; : >"$0"; while :; do sleep 0.1; done' "$tmp/ready" </dev/null >/dev/null 2>&1 &
    child=$!
    local ticks=100
    until [[ -e $tmp/ready ]]; do
      [[ $ticks -gt 0 ]] || die "self-test: child did not start"
      ticks=$((ticks - 1))
      sleep 0.1
    done
  }
  end_child() {
    unset -f kill ps 2>/dev/null || true
    kill -s KILL "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  }
  peer_stop_ticks=30

  # Real owned processes.
  sleep 0 </dev/null >/dev/null 2>&1 &
  child=$!
  peer_exit_wait "$child" || die "self-test: child did not exit"
  stop_peer "$child" || die "self-test: normal exit was not confirmed"
  [[ $stopped_by == none ]] || die "self-test: signalled a child that had already exited"

  start_child 'trap "sleep 0.5; exit 0" TERM'
  stop_peer "$child" || die "self-test: delayed TERM was not confirmed"
  [[ $stopped_by == TERM ]] || die "self-test: delayed TERM escalated to $stopped_by"
  [[ $(peer_state "$child") == gone ]] || die "self-test: delayed TERM child remains"

  peer_stop_ticks=5
  start_child 'trap "" TERM'
  stop_peer "$child" || die "self-test: TERM-ignoring child was not stopped"
  [[ $stopped_by == KILL ]] || die "self-test: TERM-ignoring child ended by $stopped_by"
  [[ $(peer_state "$child") == gone ]] || die "self-test: TERM-ignoring child remains"

  # A real process that is not this shell's child must not be signalled.
  orphan=$(bash -c 'sleep 30 </dev/null >/dev/null 2>&1 & echo $!')
  stop_peer "$orphan" || die "self-test: an unrelated PID failed the stop"
  [[ $stopped_by == none ]] || die "self-test: signalled a process this shell does not own"
  [[ $(peer_state "$orphan") == foreign ]] || die "self-test: unrelated process did not survive"
  kill -s KILL "$orphan"

  # Simulated failures: real children, with the failing command replaced by a function.
  start_child 'trap "" TERM'
  kill() { return 0; }
  if stop_peer "$child"; then die "self-test: passed with a child that could not be signalled"; fi
  [[ $stopped_by == KILL ]] || die "self-test: did not escalate before giving up"
  end_child

  start_child 'trap "" TERM'
  ps() { return 2; }
  if stop_peer "$child"; then die "self-test: passed with no way to observe the child"; fi
  end_child

  start_child 'trap "exit 0" TERM'
  first=$child
  start_child 'trap "" TERM'
  kill() { if [[ $3 == "$child" ]]; then return 0; fi; command kill "$@"; }
  peer_pids="$first $child"
  if stop_peers 2>/dev/null; then die "self-test: stop_peers hid a failure"; fi
  [[ $(peer_state "$first") == gone ]] || die "self-test: one failure skipped the other peer"
  end_child
  peer_pids=""
  peer_stop_ticks=50

  # Fixture captures, with the system commands replaced by functions.
  py snapshot-fixtures "$tmp"
  capture_fail=none
  fixture_capture() {
    if [[ $capture_fail == "$1" ]]; then return 3; fi
    cat "$tmp/fixture.$2"
  }
  scutil() { fixture_capture scutil dns; }
  netstat() { fixture_capture netstat routes; }
  route() { fixture_capture route default; }
  ifconfig() {
    if [[ $1 == -l ]]; then fixture_capture ifconfig-l iflist; else fixture_capture ifconfig-a ifaces; fi
  }
  network_snapshot "$tmp/good" || die "self-test: a good capture was rejected"
  [[ -s $tmp/good ]] || die "self-test: a good capture wrote nothing"
  for name in scutil netstat route ifconfig-l ifconfig-a; do
    capture_fail=$name
    if network_snapshot "$tmp/failed" 2>/dev/null || [[ -e $tmp/failed ]]; then
      die "self-test: a failed $name capture produced a snapshot"
    fi
  done
  capture_fail=none
  : >"$tmp/fixture.dns"
  if network_snapshot "$tmp/failed" 2>/dev/null || [[ -e $tmp/failed ]]; then
    die "self-test: an empty scutil capture produced a snapshot"
  fi
  unset -f scutil netstat route ifconfig fixture_capture start_child end_child
}

if [[ $# -eq 1 && $1 == --self-test ]]; then
  umask 077
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  write_harness "$tmp/harness.py"
  py self-test >/dev/null
  self_test_shell
  echo "ok: helper smoke fixtures, verdict logic, snapshot parsing, ACL check logic and peer stopping (no helper, real ACL, routing or macOS involved)"
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
tools_dir="$app/Contents/Resources/Tools"
wg_tool="$tools_dir/wg"
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
app_cdhash() { codesign -dv --verbose=4 "$app" 2>&1 | awk -F= '$1 == "CDHash" {print $2}'; }
cdhash=$(app_cdhash)
[[ -n $cdhash ]] || die "could not read the app's code directory hash"
sudo -n true || die "passwordless sudo is required"

helper_removed() {
  local path
  if launchctl print "system/$launchd_label" >/dev/null 2>&1; then return 1; fi
  for path in "${helper_state[@]}"; do
    [[ ! -e $path ]] || return 1
  done
}

helper_removed || die "a WireNest helper is already installed; refusing to disturb it"
for octet in 71 72; do
  if route_output=$(route -n get -inet "198.18.$octet.2" 2>&1); then
    # Only the default route may cover it; no destination at all means the check proved nothing.
    case $(printf '%s\n' "$route_output" | awk '$1 == "destination:" {print $2}') in
      default) ;;
      *) die "198.18.$octet.0/24 is already routed on this machine; refusing to continue" ;;
    esac
  elif [[ $route_output != *"not in table"* ]]; then
    die "could not check the route to 198.18.$octet.2: $route_output"
  fi
done

tmp=$(mktemp -d)
tmp=$(cd "$tmp" && pwd -P)
peer_pids=""
install_attempted=0

# The one exit path, so PASS can only be printed after uninstall and verified cleanup.
cleanup() {
  local rc=$? waited=0 peers_stopped=1
  trap - EXIT INT TERM
  if [[ $install_attempted -eq 1 ]]; then
    sudo -n "$helper" --uninstall || {
      echo "error: helper uninstall failed" >&2
      rc=1
    }
  fi
  stop_peers || {
    rc=1
    peers_stopped=0
  }
  if [[ -f $tmp/before ]]; then
    until helper_removed && network_snapshot "$tmp/after" && cmp -s "$tmp/before" "$tmp/after"; do
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
  if [[ $peers_stopped -eq 1 ]]; then
    rm -rf "$tmp" || rc=1
  else
    echo "error: keeping $tmp because a smoke peer may still be using it" >&2
  fi
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

network_snapshot "$tmp/before" || die "could not capture the network baseline"
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

# Metadata on this runner's extracted copy, never the mounted DMG: the installer must not carry
# a user's ACL grant into the root payload. Signatures do not seal ACLs, and no bytes change.
py grant-source-acl "$tools_dir" "$(id -un)"
codesign --verify --strict --deep "$app" || die "the ACL fixture broke the app signature"
[[ $(app_cdhash) == "$cdhash" ]] || die "the ACL fixture changed the app's code directory hash"
echo "ok: source Tools and wg grant this user write access through an ACL; signature unchanged"

install_attempted=1
# shortcut: sudo cannot be killed by this unprivileged script, so a hung helper is bounded by the
# workflow step's timeout-minutes instead; add a root-side alarm if this ever runs outside that step.
sudo -n "$helper" --install --uid "$(id -u)"
py check-install "$(id -u)" "$cdhash"
echo "ok: helper installed, root-owned, and pinned to this user and app build"
# Runs as the ordinary user on purpose: sudo would pass every permission check.
py check-installed-acl "$tools_dir"
echo "ok: installed payload has no ACL, and this user was denied writing to wg or adding to Tools"

py drive "$tmp" "$driver"
echo "ok: driver finished with exit 0 and the exact final marker"
