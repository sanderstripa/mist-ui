#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' 0
mkdir -p "$TMP/bin" "$TMP/legacy"
TEST_CONFIG="$TMP/legacy/mist-fast.json"
export TEST_CONFIG
printf '%s\n' '{"authority":"edge.example","tun_cidr":"10.64.0.1/24"}' > "$TEST_CONFIG"

cat > "$TMP/bin/systemctl" <<'SH'
#!/bin/sh
set -eu
case "${1:-}" in
  cat)
    case "${2:-}" in
      mist-fast.service)
        printf '%s\n' '[Unit]' 'Description=MIST Fast legacy service' '[Service]'
        if [ "${TEST_STYLE:-separate}" = "equals" ]; then
          printf 'ExecStart=/usr/local/bin/mist-fast-edge --config="%s"\n' "$TEST_CONFIG"
        else
          printf 'ExecStart=/usr/local/bin/mist-fast-edge -config "%s"\n' "$TEST_CONFIG"
        fi
        exit 0
        ;;
      *) exit 1 ;;
    esac
    ;;
  list-unit-files)
    printf 'mist-fast.service enabled\nssh.service enabled\n'
    ;;
  list-units)
    printf 'mist-fast.service loaded active running MIST Fast legacy service\n'
    ;;
  show)
    # MainPID / Environment are only fallbacks in this fixture. ExecStart is
    # expected to provide both the binary and the non-default config path.
    if [ "${2:-}" = "mist-fast.service" ]; then
      printf '0\n'
    fi
    ;;
  *) exit 0 ;;
esac
SH
chmod +x "$TMP/bin/systemctl"

cat > "$TMP/bin/pgrep" <<'SH'
#!/bin/sh
exit 1
SH
chmod +x "$TMP/bin/pgrep"

check_output() {
  out=$1
  printf '%s\n' "$out" | grep -q '^\[DETECT\] service=mist-fast.service$'
  printf '%s\n' "$out" | grep -q '^\[DETECT\] binary=/usr/local/bin/mist-fast-edge$'
  printf '%s\n' "$out" | grep -Fq "[DETECT] config=$TEST_CONFIG"
}

out=$(PATH="$TMP/bin:$PATH" TEST_STYLE=separate MIST_SERVICE='' MIST_TARGET='' MIST_CONFIG='' sh "$ROOT/scripts/UPDATE-MIST-EDGE.sh" --detect-only)
check_output "$out"

out=$(PATH="$TMP/bin:$PATH" TEST_STYLE=equals MIST_SERVICE='' MIST_TARGET='' MIST_CONFIG='' sh "$ROOT/scripts/UPDATE-MIST-EDGE.sh" --detect-only)
check_output "$out"

echo "updater legacy mist-fast auto-detection test: PASS"
