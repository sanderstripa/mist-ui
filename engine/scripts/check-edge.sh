#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

for cmd in ip iptables sysctl openssl; do
  command -v "$cmd" >/dev/null || { echo "missing dependency: $cmd" >&2; exit 1; }
done

if ! sysctl -n net.ipv4.ip_forward | grep -qx '1'; then
  echo "note: IPv4 forwarding is currently disabled; mist-edge enables it at startup"
fi

echo "edge prerequisites: OK"
