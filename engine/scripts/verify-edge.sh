#!/usr/bin/env bash
set -u

CONFIG="${1:-/etc/mist/server.json}"
FAIL=0
WARN=0

pass(){ printf '\033[32m[PASS]\033[0m %s\n' "$*"; }
fail(){ printf '\033[31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
warn(){ printf '\033[33m[WARN]\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
check(){ if "$@"; then pass "$*"; else fail "$*"; fi; }

if [[ ! -r "$CONFIG" ]]; then fail "config readable: $CONFIG"; exit 2; fi
command -v python3 >/dev/null || { fail "python3 installed"; exit 2; }

read_cfg(){ python3 - "$CONFIG" "$1" <<'PY'
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: d=json.load(f)
v=d.get(sys.argv[2],"")
print(v if not isinstance(v,(dict,list)) else json.dumps(v))
PY
}
read_list(){ python3 - "$CONFIG" "$1" <<'PY'
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: d=json.load(f)
for v in d.get(sys.argv[2],[]) or []: print(v)
PY
}

TUN="$(read_cfg tun_name)"; [[ -n "$TUN" ]] || TUN=mist0
MTU="$(read_cfg mtu)"; [[ -n "$MTU" && "$MTU" != 0 ]] || MTU=1280
LISTEN="$(read_cfg listen)"; [[ -n "$LISTEN" ]] || LISTEN=:443
AUTHORITY="$(read_cfg authority)"
PATH_MIST="$(read_cfg path)"
DECOY="$(read_cfg decoy_root)"
V6CIDR="$(read_cfg tun_ipv6_cidr)"
mapfile -t PORT_HOPS < <(read_list port_hop_ports)

printf 'MIST edge verification: tun=%s mtu=%s listen=%s\n' "$TUN" "$MTU" "$LISTEN"

ip link show "$TUN" >/dev/null 2>&1 && pass "TUN exists" || fail "TUN exists"
ACTUAL_MTU="$(cat "/sys/class/net/$TUN/mtu" 2>/dev/null || true)"
[[ "$ACTUAL_MTU" == "$MTU" ]] && pass "TUN MTU=$MTU" || fail "TUN MTU expected=$MTU actual=${ACTUAL_MTU:-missing}"

[[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == 1 ]] && pass "IPv4 forwarding" || fail "IPv4 forwarding"
iptables -t nat -S POSTROUTING 2>/dev/null | grep -q 'MASQUERADE' && pass "IPv4 NAT rule present" || warn "IPv4 MASQUERADE not detected (may be intentional when enable_nat=false)"

if [[ -n "$V6CIDR" ]]; then
  [[ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)" == 1 ]] && pass "IPv6 forwarding" || fail "IPv6 forwarding"
  ip -6 addr show dev "$TUN" | grep -q "${V6CIDR%/*}" && pass "IPv6 TUN address" || fail "IPv6 TUN address"
  ip6tables -t nat -S POSTROUTING 2>/dev/null | grep -q 'MASQUERADE' && pass "IPv6 NAT rule present" || warn "IPv6 MASQUERADE not detected"
fi

PORT="${LISTEN##*:}"; [[ "$PORT" =~ ^[0-9]+$ ]] || PORT=443
ss -lunp 2>/dev/null | grep -Eq "[:.]${PORT}[[:space:]]" && pass "UDP/$PORT listening" || fail "UDP/$PORT listening"
ss -ltnp 2>/dev/null | grep -Eq "[:.]${PORT}[[:space:]]" && pass "TCP/$PORT listening" || fail "TCP/$PORT listening"

if [[ ${#PORT_HOPS[@]} -gt 0 ]]; then
  RULES="$(iptables -t nat -S PREROUTING 2>/dev/null || true)"
  for hop in "${PORT_HOPS[@]}"; do
    if [[ "$hop" == "$PORT" ]]; then continue; fi
    for proto in udp tcp; do
      if grep -Eq -- "-p ${proto} .*--dport ${hop} .*REDIRECT .*--to-ports ${PORT}" <<<"$RULES"; then
        pass "port-hop ${proto}/${hop} -> ${PORT}"
      else
        fail "port-hop ${proto}/${hop} -> ${PORT} rule missing"
      fi
    done
  done
fi

if [[ -n "$AUTHORITY" ]]; then
  if curl --version 2>/dev/null | grep -qi HTTP3; then
    CODE="$(curl --http3-only -ksS --resolve "${AUTHORITY}:${PORT}:127.0.0.1" -o /tmp/mist-decoy-body -w '%{http_code}' "https://${AUTHORITY}:${PORT}/" || true)"
    [[ "$CODE" =~ ^(200|301|302|404)$ ]] && pass "HTTP/3 public decoy responds ($CODE)" || fail "HTTP/3 public decoy response ($CODE)"
  else
    warn "curl lacks HTTP/3; HTTP/3 decoy probe skipped"
  fi
  CODE2="$(curl --http2 -ksS --resolve "${AUTHORITY}:${PORT}:127.0.0.1" -o /tmp/mist-decoy-body-h2 -w '%{http_code}' "https://${AUTHORITY}:${PORT}/" || true)"
  [[ "$CODE2" =~ ^(200|301|302|404)$ ]] && pass "HTTPS public decoy responds ($CODE2)" || fail "HTTPS public decoy response ($CODE2)"

  # Wrong credentials must look like ordinary web traffic, never an auth oracle.
  WRONG="$(curl --http2 -ksS --resolve "${AUTHORITY}:${PORT}:127.0.0.1" -X POST -H 'Authorization: Bearer definitely-wrong' -H 'X-MIST-Transport: stream' -o /tmp/mist-wrong-auth -w '%{http_code}' "https://${AUTHORITY}:${PORT}${PATH_MIST}" || true)"
  [[ "$WRONG" != 401 && "$WRONG" != 403 ]] && pass "Wrong token does not expose 401/403 auth oracle ($WRONG)" || fail "Wrong token leaks auth status ($WRONG)"
fi

if [[ -n "$DECOY" ]]; then
  [[ -d "$DECOY" ]] && pass "decoy_root exists: $DECOY" || fail "decoy_root missing: $DECOY"
fi

printf '\nFailures: %d, warnings: %d\n' "$FAIL" "$WARN"
[[ "$FAIL" -eq 0 ]]
