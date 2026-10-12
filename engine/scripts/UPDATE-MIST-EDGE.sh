#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$HERE/mist-edge-linux-amd64"
CONFIG=${MIST_CONFIG:-}
SERVICE=${MIST_SERVICE:-}
TARGET=${MIST_TARGET:-}

service_exists() {
  systemctl cat "$1" >/dev/null 2>&1
}

unit_matches_mist() {
  systemctl cat "$1" 2>/dev/null | grep -Eqi 'mist-edge|mist-fast|mist-edge-linux-amd64|/etc/mist|cmd/mist-edge'
}

detect_service() {
  if [ -n "$SERVICE" ] && service_exists "$SERVICE"; then
    return 0
  fi
  SERVICE=

  for candidate in mist-edge.service mist-fast.service mist-fast2.service mist-vpn.service mist.service; do
    if service_exists "$candidate"; then
      SERVICE=$candidate
      return 0
    fi
  done

  for candidate in $(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
    case "$candidate" in
      *.service) ;;
      *) continue ;;
    esac
    if unit_matches_mist "$candidate"; then
      SERVICE=$candidate
      return 0
    fi
  done

  for root in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [ -d "$root" ] || continue
    file=$(find "$root" -maxdepth 2 \( -type f -o -type l \) -name '*.service' -exec grep -El 'mist-edge|mist-fast|mist-edge-linux-amd64|/etc/mist|cmd/mist-edge' {} + 2>/dev/null | head -n1 || true)
    if [ -n "$file" ]; then
      candidate=$(basename "$file")
      if service_exists "$candidate"; then
        SERVICE=$candidate
        return 0
      fi
    fi
  done

  for pid in $(pgrep -f 'mist-edge|mist-fast|/etc/mist' 2>/dev/null || true); do
    [ -r "/proc/$pid/cgroup" ] || continue
    unit=$(awk -F/ '{for(i=NF;i>=1;i--) if($i ~ /\.service$/){print $i; exit}}' "/proc/$pid/cgroup" 2>/dev/null || true)
    if [ -n "$unit" ] && service_exists "$unit"; then
      SERVICE=$unit
      return 0
    fi
  done

  return 1
}

detect_target() {
  if [ -n "$TARGET" ] && [ "${TARGET#/}" != "$TARGET" ]; then
    return 0
  fi
  TARGET=

  unit_text=$(systemctl cat "$SERVICE" 2>/dev/null || true)
  exec_line=$(printf '%s\n' "$unit_text" | sed -n 's/^[[:space:]]*ExecStart=//p' | head -n1 || true)

  candidate=$(printf '%s\n' "$exec_line" | tr ' ' '\n' | tr -d '"' | tr -d "'" | grep -E '^/.*(mist-edge|mist-fast)' | head -n1 || true)
  if [ -n "$candidate" ] && [ "${candidate#/}" != "$candidate" ]; then
    TARGET=$candidate
    return 0
  fi

  pid=$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      if [ "$pid" -gt 0 ] && [ -e "/proc/$pid/exe" ]; then
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        case "$(basename "$exe" 2>/dev/null || true)" in
          *mist-edge*|*mist-fast*) TARGET=$exe; return 0 ;;
        esac
      fi
      ;;
  esac

  for candidate in \
    /usr/local/bin/mist-edge \
    /usr/local/bin/mist-edge-linux-amd64 \
    /usr/local/bin/mist-fast-edge \
    /usr/local/bin/mist-fast \
    /usr/bin/mist-edge \
    /opt/mist/mist-edge \
    /opt/mist/mist-edge-linux-amd64 \
    /root/mist/mist-edge \
    /root/mist/mist-edge-linux-amd64; do
    if [ -f "$candidate" ]; then
      TARGET=$candidate
      return 0
    fi
  done

  return 1
}

strip_outer_quotes() {
  value=$1
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  printf '%s\n' "$value"
}

config_from_exec() {
  printf '%s\n' "$1" | awk '
  {
    for (i = 1; i <= NF; i++) {
      if ($i == "-config" || $i == "--config") {
        if (i < NF) { print $(i+1); exit }
      }
      if ($i ~ /^-config=/) { sub(/^-config=/, "", $i); print $i; exit }
      if ($i ~ /^--config=/) { sub(/^--config=/, "", $i); print $i; exit }
    }
  }'
}

config_from_proc() {
  pid=$1
  [ -r "/proc/$pid/cmdline" ] || return 0
  tr '\000' '\n' < "/proc/$pid/cmdline" | awk '
  want { print; exit }
  $0 == "-config" || $0 == "--config" { want=1; next }
  /^-config=/ { sub(/^-config=/, ""); print; exit }
  /^--config=/ { sub(/^--config=/, ""); print; exit }
  '
}

detect_config() {
  if [ -n "$CONFIG" ]; then
    [ -f "$CONFIG" ] && return 0
    echo "[ERROR] Explicit MIST_CONFIG does not exist: $CONFIG" >&2
    return 1
  fi

  unit_text=$(systemctl cat "$SERVICE" 2>/dev/null || true)
  exec_lines=$(printf '%s\n' "$unit_text" | sed -n 's/^[[:space:]]*ExecStart=//p')

  candidate=$(config_from_exec "$exec_lines" | head -n1 || true)
  candidate=$(strip_outer_quotes "$candidate")
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    CONFIG=$candidate
    return 0
  fi

  candidate=$(printf '%s\n' "$exec_lines" | tr ' ' '\n' | tr -d '"' | tr -d "'" | grep -E '^/.*\.json$' | head -n1 || true)
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    CONFIG=$candidate
    return 0
  fi

  env_text=$(systemctl show "$SERVICE" -p Environment --value 2>/dev/null || true)
  candidate=$(printf '%s\n' "$env_text" | tr ' ' '\n' | sed -n 's/^MIST_CONFIG=//p' | head -n1 || true)
  candidate=$(strip_outer_quotes "$candidate")
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    CONFIG=$candidate
    return 0
  fi

  pid=$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      if [ "$pid" -gt 0 ]; then
        candidate=$(config_from_proc "$pid" | head -n1 || true)
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
          CONFIG=$candidate
          return 0
        fi
        candidate=$(tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -E '^/.*\.json$' | head -n1 || true)
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
          CONFIG=$candidate
          return 0
        fi
      fi
      ;;
  esac

  for candidate in \
    /etc/mist/server.json \
    /etc/mist/config.json \
    /etc/mist-fast/server.json \
    /etc/mist-fast/config.json \
    /etc/mist-fast.json \
    /usr/local/etc/mist/server.json \
    /usr/local/etc/mist-fast/server.json \
    /opt/mist/server.json \
    /opt/mist/config.json \
    /root/mist/server.json \
    /root/mist-fast/server.json; do
    if [ -f "$candidate" ]; then
      CONFIG=$candidate
      return 0
    fi
  done

  return 1
}

if ! detect_service; then
  echo "[ERROR] Could not auto-detect the installed MIST systemd service." >&2
  systemctl list-units --all --type=service --no-legend --no-pager 2>/dev/null | grep -i mist >&2 || true
  exit 3
fi

if ! detect_target; then
  echo "[ERROR] Found service $SERVICE, but could not determine its Edge binary path." >&2
  systemctl cat "$SERVICE" >&2 || true
  exit 4
fi

if ! detect_config; then
  echo "[ERROR] Found service $SERVICE and binary $TARGET, but could not determine the existing MIST config path." >&2
  echo "[DIAG] systemd unit follows:" >&2
  systemctl cat "$SERVICE" >&2 || true
  exit 5
fi

echo "[DETECT] service=$SERVICE"
echo "[DETECT] binary=$TARGET"
echo "[DETECT] config=$CONFIG"

if [ "${1:-}" = "--detect-only" ]; then
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E sh "$0" "$@"
  fi
  echo "[ERROR] Run this updater as root." >&2
  exit 1
fi

if [ ! -f "$SOURCE" ]; then
  echo "[ERROR] $SOURCE not found."
  exit 2
fi
chmod +x "$SOURCE"

if [ ! -f "$CONFIG" ]; then
  echo "[ERROR] Existing config $CONFIG was not found. Refusing to replace anything."
  exit 5
fi

# Validate the exact installed config with the NEW binary before the live
# service is stopped. A compatibility problem now leaves the working Edge
# completely untouched.
echo "[PRECHECK] Validating existing config with the new Edge..."
if ! "$SOURCE" -config "$CONFIG" -check-config; then
  echo "[ERROR] New Edge is not compatible with the installed config. Live service was NOT stopped or modified." >&2
  exit 9
fi
echo "[PRECHECK] OK"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="/var/backups/mist/$stamp"
mkdir -p "$backup_dir"
cp -a "$CONFIG" "$backup_dir/$(basename "$CONFIG")"
if [ -f "$TARGET" ]; then
  cp -a "$TARGET" "$backup_dir/$(basename "$TARGET")"
fi

new_file="${TARGET}.new"
install -D -m 0755 "$SOURCE" "$new_file"

rollback() {
  echo "[ROLLBACK] Restoring previous MIST Edge binary..." >&2
  old_binary="$backup_dir/$(basename "$TARGET")"
  if [ -f "$old_binary" ]; then
    cp -a "$old_binary" "$TARGET"
    chmod 0755 "$TARGET"
    systemctl daemon-reload || true
    systemctl restart "$SERVICE" || true
  fi
}
trap 'rm -f "$new_file"' 0

echo "MIST Edge update"
echo "  service : $SERVICE"
echo "  binary  : $TARGET"
echo "  config  : $CONFIG (preserved)"
echo "  backup  : $backup_dir"

echo "[1/4] Stopping $SERVICE..."
systemctl stop "$SERVICE"

echo "[2/4] Replacing Edge binary..."
mv -f "$new_file" "$TARGET"
chmod 0755 "$TARGET"
systemctl daemon-reload

echo "[3/4] Starting $SERVICE..."
if ! systemctl start "$SERVICE"; then
  rollback
  echo "[ERROR] New Edge failed to start; previous binary restored." >&2
  exit 6
fi
sleep 2
if ! systemctl is-active --quiet "$SERVICE"; then
  systemctl --no-pager -l status "$SERVICE" || true
  journalctl -u "$SERVICE" -n 50 --no-pager || true
  rollback
  echo "[ERROR] New Edge did not remain active; previous binary restored." >&2
  exit 7
fi

echo "[4/4] Verifying live service..."
systemctl --no-pager --full status "$SERVICE" | sed -n '1,12p'
if [ -f "$HERE/verify-edge.sh" ]; then
  chmod +x "$HERE/verify-edge.sh" 2>/dev/null || true
  if ! bash "$HERE/verify-edge.sh" "$CONFIG"; then
    echo "[WARN] Edge service is active, but verify-edge.sh reported a problem."
    echo "       Backup is at $backup_dir."
    exit 8
  fi
fi

echo
echo "[OK] MIST Edge updated successfully."
echo "Your existing $CONFIG was preserved."
echo "Backup: $backup_dir"
