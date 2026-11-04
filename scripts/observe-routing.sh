#!/usr/bin/env bash
# Records raw, read-only routing observations and native documentation from a GitHub-hosted
# macOS runner. Sends no packets, changes no routes or DNS, and installs nothing. This is
# evidence about the runner only: not the reported user's Mac, and not application proof.
#
# Usage: bash scripts/observe-routing.sh OUTPUT_DIR
#        bash scripts/observe-routing.sh --self-test
set -euo pipefail
source "$(dirname "$0")/deps.sh"

CAPTURE_TIMEOUT=30
failures=0

# record_capture REQUIRED NAME ARGV...: stdout, stderr and exit status each stay separate
# and raw. A required command that fails or prints nothing counts as an observation failure.
record_capture() {
  local required=$1 name=$2 rc=0
  shift 2
  # macOS has no timeout(1); the alarm survives exec and kills a hung command.
  perl -e 'alarm shift @ARGV; exec { $ARGV[0] } @ARGV or exit 127' "$CAPTURE_TIMEOUT" "$@" \
    </dev/null >"$out/$name.stdout" 2>"$out/$name.stderr" || rc=$?
  printf '%s\t%s\t%s\t%s\t%s\t' "$name" "$required" "$rc" \
    "$(wc -c <"$out/$name.stdout" | tr -d ' ')" "$(wc -c <"$out/$name.stderr" | tr -d ' ')" >>"$out/commands.tsv"
  printf '%q ' "$@" >>"$out/commands.tsv"
  echo >>"$out/commands.tsv"
  if [[ $required == required && ($rc -ne 0 || ! -s $out/$name.stdout) ]]; then
    record_failure "$name: exit $rc, $(wc -c <"$out/$name.stdout" | tr -d ' ') stdout bytes"
  fi
}
capture() { record_capture required "$@"; }
capture_optional() { record_capture optional "$@"; }

record_failure() {
  failures=$((failures + 1))
  echo "$1" >>"$out/failures.txt"
}

# select_targets HARDWARE_PORTS IFCONFIG ROUTE_DEFAULT NETSTAT: one row per observed IPv4
# subnet, chosen only from these outputs. Rows are tab-separated with "-" for unknown.
select_targets() {
  python3 -I - "$@" <<'PY'
import ipaddress
import re
import sys

hardware, ifconfig, default_route, netstat = (open(p, errors="replace").read() for p in sys.argv[1:5])

ports = {m[2]: m[1] for m in re.finditer(r"^Hardware Port: (.+)\nDevice: ([a-zA-Z0-9]+)$", hardware, re.M)}
addresses = {device: [] for device in ports}
device = None
for line in ifconfig.splitlines():
    header = re.match(r"([a-zA-Z0-9]+): flags=", line)
    if header:
        device = header[1]
        continue
    inet = re.match(r"\s+inet (\S+)(?: --> \S+)? netmask (0x[0-9a-fA-F]+)", line)
    if inet and device:
        addresses.setdefault(device, []).append((inet[1], inet[2]))

local = {ip for rows in addresses.values() for ip, _ in rows}
gateway = re.search(r"^\s*gateway: (\S+)$", default_route, re.M)
gateway = gateway[1] if gateway else None
# A destination already in the table has its own host entry, which would hide the connected parent.
in_table = {line.split()[0].split("/")[0] for line in netstat.splitlines() if line.split()}

print("role\tdevice\thardware_port\tself_ip\tnetmask\tnetwork\ttarget\tnote")
for device, rows in addresses.items():
    if device.startswith("lo"):
        continue
    port = ports.get(device, "-")
    if not rows:
        print(f"unknown\t{device}\t{port}\t-\t-\t-\t-\tno_ipv4_address")
    for ip, mask in rows:
        try:
            dotted = ipaddress.IPv4Address(int(mask, 16))
            interface = ipaddress.ip_interface(f"{ip}/{dotted}")
        except ValueError:
            print(f"unknown\t{device}\t{port}\t{ip}\t{mask}\t-\t-\tinvalid_address_or_netmask")
            continue
        fields = f"{device}\t{port}\t{ip}\t{dotted}\t{interface.network}"
        if gateway and gateway != ip and gateway not in local:
            try:
                if ipaddress.ip_address(gateway) in interface.network:
                    print(f"gateway\t{fields}\t{gateway}\tdefault_gateway_may_have_host_entry")
            except ValueError:
                pass
        excluded = local | in_table | {gateway}
        neighbor = next((h for h in interface.network.hosts() if str(h) not in excluded), None)
        if neighbor:
            print(f"neighbor\t{fields}\t{neighbor}\tnot_self_not_gateway_not_in_route_table")
        else:
            print(f"unknown\t{fields}\t-\tno_unused_on_link_host")
PY
}

self_test() {
  local actual
  mkdir -p "$WORK"
  scratch=$(mktemp -d "$WORK/observe-test.XXXXXX")
  trap 'rm -rf "$scratch"' EXIT
  out=$scratch

  # SYNTHETIC fixtures that test the parser. They are not native observations.
  cat >"$scratch/ports" <<'EOF'

Hardware Port: Ethernet
Device: en0
Ethernet Address: 00:00:5e:00:53:01

Hardware Port: Wi-Fi Link
Device: en1
Ethernet Address: 00:00:5e:00:53:02

Hardware Port: Peer Link
Device: en2
Ethernet Address: 00:00:5e:00:53:03
EOF
  cat >"$scratch/ifconfig" <<'EOF'
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 10.1.2.5 netmask 0xffffff00 broadcast 10.1.2.255
en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
en2: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.0.2.0 netmask 0xfffffffe
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 198.51.100.1 netmask 0xffffff00 broadcast 198.51.100.255
utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
	inet 203.0.113.1 --> 203.0.113.1 netmask 0xffffffff
EOF
  cat >"$scratch/default" <<'EOF'
   route to: default
destination: default
    gateway: 10.1.2.1
  interface: en0
EOF
  cat >"$scratch/netstat" <<'EOF'
Destination        Gateway            Flags               Netif Expire
default            10.1.2.1           UGScg                 en0
10.1.2             link#4             UCS                   en0      !
10.1.2.1/32        link#4             UCS                   en0      !
10.1.2.2           aa:bb:cc:dd:ee:ff  UHLWIi                en0   1199
EOF
  cat >"$scratch/expected" <<'EOF'
role	device	hardware_port	self_ip	netmask	network	target	note
gateway	en0	Ethernet	10.1.2.5	255.255.255.0	10.1.2.0/24	10.1.2.1	default_gateway_may_have_host_entry
neighbor	en0	Ethernet	10.1.2.5	255.255.255.0	10.1.2.0/24	10.1.2.3	not_self_not_gateway_not_in_route_table
unknown	en1	Wi-Fi Link	-	-	-	-	no_ipv4_address
neighbor	en2	Peer Link	192.0.2.0	255.255.255.254	192.0.2.0/31	192.0.2.1	not_self_not_gateway_not_in_route_table
neighbor	bridge100	-	198.51.100.1	255.255.255.0	198.51.100.0/24	198.51.100.2	not_self_not_gateway_not_in_route_table
unknown	utun7	-	203.0.113.1	255.255.255.255	203.0.113.1/32	-	no_unused_on_link_host
EOF
  select_targets "$scratch/ports" "$scratch/ifconfig" "$scratch/default" "$scratch/netstat" >"$scratch/actual"
  diff "$scratch/expected" "$scratch/actual" || die "self-test: target selection differs from its fixture"
  echo "ok: target selection on synthetic fixtures"

  printf 'not an ifconfig dump\n' >"$scratch/junk"
  actual=$(select_targets "$scratch/junk" "$scratch/junk" "$scratch/junk" "$scratch/junk")
  [[ $actual == "role"$'\t'"device"* && $actual != *$'\n'* ]] || die "self-test: unparsable input produced targets"
  echo "ok: unparsable input produces no targets"

  expect_failures() {
    [[ $failures -eq $1 ]] || die "self-test: $2: expected $1 failures, got $failures"
    echo "ok: $2"
  }
  capture ok /bin/echo hello
  expect_failures 0 "successful capture is not a failure"
  [[ $(cat "$scratch/ok.stdout") == hello ]] || die "self-test: stdout not captured"
  capture_optional absent /bin/sh -c 'echo no page >&2; exit 16'
  expect_failures 0 "missing optional capture is recorded, not a failure"
  grep -q "^absent"$'\t'"optional"$'\t'"16"$'\t'"0"$'\t' "$scratch/commands.tsv" || die "self-test: optional exit status not recorded"
  capture fails /bin/sh -c 'echo partial; exit 3'
  expect_failures 1 "non-zero exit counts as a failure despite output"
  capture empty /bin/sh -c 'exit 0'
  expect_failures 2 "exit 0 with no output counts as a failure"
  CAPTURE_TIMEOUT=1
  capture hung /bin/sleep 5
  CAPTURE_TIMEOUT=30
  expect_failures 3 "hung command is killed and counts as a failure"
  grep -q "^hung"$'\t'"required"$'\t'"142"$'\t' "$scratch/commands.tsv" || die "self-test: timeout exit status not recorded"

  # Clearing the CI marker keeps this refusal test from capturing, even on a hosted runner.
  if env -u GITHUB_ACTIONS bash "$0" "$scratch/refused" >"$scratch/refusal" 2>&1; then
    die "self-test: ran outside GitHub-hosted CI"
  fi
  [[ ! -e $scratch/refused ]] || die "self-test: refusal still created output"
  echo "ok: refuses to run outside GitHub-hosted CI"
  echo "Self-test passed. These were synthetic fixtures, not native observations."
}

if [[ ${1:-} == --self-test ]]; then
  self_test
  exit 0
fi

[[ $# -eq 1 ]] || die "usage: observe-routing.sh OUTPUT_DIR | --self-test"
[[ $(uname -s) == Darwin ]] || die "native observations can only come from macOS"
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || die "only runs on a GitHub-hosted runner"
[[ $(id -u) -ne 0 ]] || die "must run as an ordinary user"
out=$1
[[ ! -e $out ]] || die "$out already exists"
mkdir -p "$out"

{
  echo "scope=ephemeral GitHub-hosted runner; NOT the reported user's Mac or endpoint route"
  echo "purpose=read-only observations and documentation; NOT application proof or acceptance"
  echo "comparison_only=route-get-ifscope-* files are NOT a substitute for the unscoped lookup"
  echo "image_os=${ImageOS:-unknown}"
  echo "image_version=${ImageVersion:-unknown}"
  echo "runner_arch=${RUNNER_ARCH:-unknown}"
  echo "commit=${GITHUB_SHA:-unknown}"
  echo "run_id=${GITHUB_RUN_ID:-unknown}"
  echo "uid=$(id -u)"
} >"$out/metadata.txt"
printf 'name\trequired\texit\tstdout_bytes\tstderr_bytes\targv\n' >"$out/commands.tsv"
: >"$out/failures.txt"

capture sw_vers /usr/bin/sw_vers
capture uname /usr/bin/uname -a
capture sdk-version /usr/bin/xcrun --sdk macosx --show-sdk-version
capture sdk-path /usr/bin/xcrun --sdk macosx --show-sdk-path
capture route-get-default /sbin/route -n get -inet default
capture route-get-loopback-127.0.0.1 /sbin/route -n get -inet 127.0.0.1
capture route-get-loopback-neighbor-127.0.0.2 /sbin/route -n get -inet 127.0.0.2
capture netstat-before-lookups /usr/sbin/netstat -rn -f inet
capture ifconfig /sbin/ifconfig -a
capture hardware-ports /usr/sbin/networksetup -listallhardwareports

if ! select_targets "$out/hardware-ports.stdout" "$out/ifconfig.stdout" "$out/route-get-default.stdout" \
  "$out/netstat-before-lookups.stdout" >"$out/selected-targets.tsv" 2>"$out/selected-targets.stderr"; then
  record_failure "selected-targets: parser failed"
fi

neighbors=0
while IFS=$'\t' read -r role device _ _ _ _ target _; do
  [[ $role == neighbor || $role == gateway ]] || continue
  [[ $role == gateway ]] || neighbors=$((neighbors + 1))
  capture "route-get-unscoped-$role-$device-$target" /sbin/route -n get -inet "$target"
  capture_optional "route-get-ifscope-COMPARISON-ONLY-$role-$device-$target" /sbin/route -n get -inet -ifscope "$device" "$target"
done <"$out/selected-targets.tsv"
[[ $neighbors -gt 0 ]] || record_failure "selected-targets: no connected on-link neighbor was observed"

# Shows whether the lookups above changed the table, such as by cloning a host entry.
capture netstat-after-lookups /usr/sbin/netstat -rn -f inet

for page in 8:route 1:netstat 8:ifconfig 3:acl_get_entry 3:acl_get_link_np 3:acl_set_file; do
  section=${page%%:*}
  topic=${page#*:}
  capture_optional "man-$topic.$section-path" /usr/bin/man -w "$section" "$topic"
  capture_optional "man-$topic.$section" /usr/bin/env MANPAGER=/bin/cat PAGER=/bin/cat MANWIDTH=100 /usr/bin/man "$section" "$topic"
  if [[ -s $out/man-$topic.$section.stdout ]]; then
    col -bx <"$out/man-$topic.$section.stdout" >"$out/man-$topic.$section.txt" || rm -f "$out/man-$topic.$section.txt"
  fi
done

sdk=$(cat "$out/sdk-path.stdout")
if [[ -n $sdk ]]; then
  capture sdk-header-sys-acl.h /bin/cat "$sdk/usr/include/sys/acl.h"
  capture sdk-header-net-route.h /bin/cat "$sdk/usr/include/net/route.h"
else
  record_failure "sdk headers: no SDK path was observed"
fi

echo "observation_failures=$failures" >>"$out/metadata.txt"
echo "Captured to $out, observation failures: $failures"
if [[ $failures -ne 0 ]]; then
  cat "$out/failures.txt" >&2
  exit 1
fi
