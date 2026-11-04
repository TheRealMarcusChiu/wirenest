#!/usr/bin/env bash
# Real two-tunnel proof on macOS, using the tools bundled in a built WireNest.app:
# two simultaneous wg-quick tunnels, each a TCP round trip through utun, WireGuard and
# a local userspace peer, then one tunnel brought down while the other keeps working.
#
# Non-disruptive by construction: throwaway keys, loopback endpoints, routes only inside
# the RFC 2544 test range, no DNS settings, and a final check that the default route and
# DNS are unchanged.
#
# Scope: this proves the bundled tools and multi-tunnel routing. It does NOT exercise
# WireNestApp, WireNestHelper, or WireNest's DNS management.
#
# Usage: sudo bash scripts/smoke-two-tunnels.sh path/to/WireNest.app path/to/smoke-peer
set -euo pipefail
source "$(dirname "$0")/deps.sh"

[[ $# -eq 2 ]] || die "usage: smoke-two-tunnels.sh WireNest.app smoke-peer"
[[ $(uname -s) == Darwin ]] || die "this smoke test only runs on macOS; refusing to touch routing here"
[[ $EUID -eq 0 ]] || die "must run as root because wg-quick creates utun interfaces"

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
tools="$1/Contents/Resources/Tools"
peer_bin=$2
for tool in bash wg wg-quick wireguard-go; do
  [[ -x $tools/$tool ]] || die "missing bundled tool: $tools/$tool"
done
[[ -x $peer_bin ]] || die "missing smoke peer: $peer_bin"

HTTP_PORT=18080
tmp=$(mktemp -d)
chmod 700 "$tmp"
peer_pids=""
started=""

iface_of() { cat "/var/run/wireguard/$1.name"; }
route_field() { { route -n get -inet "$1" 2>/dev/null || true; } | awk -v f="$2:" '$1 == f {print $2}'; }
network_snapshot() {
  { route -n get -inet default 2>/dev/null || true; } | awk '$1 == "destination:" || $1 == "gateway:" || $1 == "interface:"'
  scutil --dns | awk '/nameserver\[/ {print $3}' | sort -u
}

cleanup() {
  local rc=$? name
  trap - EXIT INT TERM
  for name in $started; do
    if [[ -e /var/run/wireguard/$name.name ]]; then
      wg_quick_scrubbed "$tools" down "$tmp/$name.conf" >/dev/null 2>&1 || echo "warning: could not bring down $name" >&2
    fi
  done
  for pid in $peer_pids; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$tmp"
  if [[ $rc -eq 0 ]]; then
    echo "SMOKE PASSED: two simultaneous tunnels, independent teardown, network state restored."
    echo "Not covered: WireNestApp, WireNestHelper, WireNest DNS management."
  else
    echo "SMOKE FAILED (exit $rc)" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# start_tunnel NAME OCTET UDP_PORT
start_tunnel() {
  local name=$1 octet=$2 port=$3 client_key peer_key
  client_key=$("$tools/wg" genkey)
  peer_key=$("$tools/wg" genkey)
  printf '%s\n%s\n' "$peer_key" "$(printf '%s' "$client_key" | "$tools/wg" pubkey)" >"$tmp/$name.keys"
  cat >"$tmp/$name.conf" <<EOF
[Interface]
PrivateKey = $client_key
Address = 198.18.$octet.1/32
MTU = 1280

[Peer]
PublicKey = $(printf '%s' "$peer_key" | "$tools/wg" pubkey)
Endpoint = 127.0.0.1:$port
AllowedIPs = 198.18.$octet.0/24
EOF
  openssl rand -hex 16 >"$tmp/$name.token"
  "$peer_bin" -addr "198.18.$octet.2" -client "198.18.$octet.1" -udp-port "$port" \
    -http-port "$HTTP_PORT" -token "$(cat "$tmp/$name.token")" <"$tmp/$name.keys" &
  peer_pids="$peer_pids $!"
  sleep 1
  kill -0 "$!" 2>/dev/null || die "peer for $name exited at startup (port $port in use?)"
  started="$started $name"
  wg_quick_scrubbed "$tools" up "$tmp/$name.conf"
}

# The random token is known only to that peer, so a match cannot come from anywhere else.
probe() {
  local name=$1 octet=$2 body
  body=$(curl --noproxy '*' -fsS --max-time 5 --retry 8 --retry-all-errors --retry-delay 1 "http://198.18.$octet.2:$HTTP_PORT/")
  [[ $body == "$(cat "$tmp/$name.token")" ]] || die "$name returned the wrong body"
  echo "ok: TCP round trip through $name ($(iface_of "$name"))"
}

assert_live_counters() {
  local iface handshake rx tx
  iface=$(iface_of "$1")
  read -r _ handshake < <("$tools/wg" show "$iface" latest-handshakes)
  read -r _ rx tx < <("$tools/wg" show "$iface" transfer)
  [[ $handshake -gt 0 && $rx -gt 0 && $tx -gt 0 ]] || die "$1 has no real activity: handshake=$handshake rx=$rx tx=$tx"
  echo "ok: $1 handshake=$handshake rx=$rx tx=$tx"
}

wait_iface_gone() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ifconfig "$1" >/dev/null 2>&1 || return 0
    sleep 1
  done
  die "interface $1 still exists after wg-quick down"
}

for octet in 101 102; do
  case $(route_field "198.18.$octet.2" destination) in
    '' | default) ;;
    *) die "198.18.$octet.0/24 is already routed on this machine; refusing to continue" ;;
  esac
done
[[ ! -e /var/run/wireguard/wnsmka.name && ! -e /var/run/wireguard/wnsmkb.name ]] || die "stale smoke tunnel state in /var/run/wireguard"
network_snapshot >"$tmp/before"

start_tunnel wnsmka 101 51901
start_tunnel wnsmkb 102 51902
if_a=$(iface_of wnsmka)
if_b=$(iface_of wnsmkb)
[[ $if_a != "$if_b" ]] || die "both tunnels resolved to the same interface"
[[ $(route_field 198.18.101.2 interface) == "$if_a" ]] || die "wnsmka route is not on $if_a"
[[ $(route_field 198.18.102.2 interface) == "$if_b" ]] || die "wnsmkb route is not on $if_b"

probe wnsmka 101 &
probe_a=$!
probe wnsmkb 102 &
probe_b=$!
wait "$probe_a"
wait "$probe_b"
assert_live_counters wnsmka
assert_live_counters wnsmkb

# Independence: taking one tunnel down must leave the other carrying new traffic.
read -r _ rx_before _ < <("$tools/wg" show "$if_b" transfer)
wg_quick_scrubbed "$tools" down "$tmp/wnsmka.conf"
wait_iface_gone "$if_a"
[[ $(route_field 198.18.101.2 interface) != "$if_a" ]] || die "wnsmka route survived teardown"
probe wnsmkb 102
read -r _ rx_after _ < <("$tools/wg" show "$if_b" transfer)
[[ $rx_after -gt $rx_before ]] || die "wnsmkb carried no new traffic after wnsmka went down"
echo "ok: wnsmkb kept working after wnsmka went down (rx $rx_before -> $rx_after)"

wg_quick_scrubbed "$tools" down "$tmp/wnsmkb.conf"
wait_iface_gone "$if_b"

network_snapshot >"$tmp/after"
diff "$tmp/before" "$tmp/after" || die "default route or DNS changed during the smoke test"
echo "ok: default route and DNS unchanged"
