#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

usage() {
  cat <<'EOF'
Usage: scripts/pi-manual-ring-read.sh [raw-rpa-loop args...]

Foreground manual Oura Ring 4 reader for Linux/BlueZ hosts.

It writes raw JSONL to a timestamped log file and prints a compact live summary
to the terminal. Stop with Ctrl-C. The script never sends the factory-reset
probe.

Useful environment overrides:
  LOGFILE=logs/custom.jsonl
  CONSOLE_MODE=summary|raw|quiet
  CONSOLE_VERBOSE=1
  SCAN_SECONDS=120
  SCAN_BACKEND=hci|btmgmt|auto
  STREAM_PROBES=setup_snapshot,events_walk:0:4:24,daytime_hr_latest,resting_hr_latest,live_hr_probe
  MANUFACTURER_HEX=04671b01,04661b01,04651b01,04621b01,04611b01,04601b01
  EMIT_ALL_MANUFACTURER_LINES=1

Extra arguments are passed through to scripts/pi-oura-raw-rpa-read-loop.py.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup_ble_helpers() {
  local signal="${1:-TERM}"
  sudo -n timeout 2 btmgmt stop-find >/dev/null 2>&1 || true
  sudo -n timeout 3 hcitool cmd 0x08 0x000c 00 00 >/dev/null 2>&1 || true
  sudo -n timeout 2 pkill "-$signal" -f "$repo_dir/scripts/pi-oura-raw-rpa-read-loop.py" >/dev/null 2>&1 || true
  sudo -n timeout 2 pkill "-$signal" -f "$repo_dir/scripts/pi-bluez-zeroauth-stream.py" >/dev/null 2>&1 || true
  kill_by_comm_args "$signal" script 'sudo -n btmon'
  kill_by_comm_args "$signal" sudo 'sudo -n btmon'
  kill_by_comm_args "$signal" btmon 'btmon'
  kill_by_comm_args "$signal" script 'sudo -n btmgmt find -l'
  kill_by_comm_args "$signal" sudo 'sudo -n btmgmt find -l'
  kill_by_comm_args "$signal" btmgmt 'btmgmt find -l'
}

kill_by_comm_args() {
  local signal="$1"
  local command_name="$2"
  local pattern="$3"
  local pids
  pids="$(
    ps -eo pid=,comm=,args= |
      awk -v command_name="$command_name" -v pattern="$pattern" \
        '$2 == command_name && $0 ~ pattern { print $1 }'
  )"
  if [[ -n "$pids" ]]; then
    sudo -n kill "-$signal" $pids >/dev/null 2>&1 || true
  fi
}

mkdir -p logs
timestamp="$(date +%Y%m%d-%H%M%S)"
logfile="${LOGFILE:-logs/pi-manual-ring-read-${timestamp}.jsonl}"
printf "%s\n" "$logfile" > logs/current-pi-manual-read.log
printf "%s\n" "$logfile" > logs/current-pi-bluez-read-result.log
: > "$logfile"

manufacturer_hex="${MANUFACTURER_HEX:-04671b01,04661b01,04651b01,04621b01,04611b01,04601b01}"
identity_address="${IDENTITY_ADDRESS:-AA:BB:CC:DD:EE:FF}"
stream_probes="${STREAM_PROBES:-setup_snapshot,events_walk:0:4:24,daytime_hr_latest,resting_hr_latest,live_hr_probe,firmware,battery,auth_nonce}"
scan_seconds="${SCAN_SECONDS:-120}"
scan_heartbeat_seconds="${SCAN_HEARTBEAT_SECONDS:-10}"
silent_scan_timeout_seconds="${SILENT_SCAN_TIMEOUT_SECONDS:-20}"
connect_timeout="${CONNECT_TIMEOUT:-8}"
connect_attempts="${CONNECT_ATTEMPTS:-1}"
connect_fallback_backend="${CONNECT_FALLBACK_BACKEND:-hcitool-lecc}"
connect_retry_delay="${CONNECT_RETRY_DELAY_SECONDS:-0.05}"
le_create_conn_min_interval="${LE_CREATE_CONN_MIN_INTERVAL:-0x0018}"
le_create_conn_max_interval="${LE_CREATE_CONN_MAX_INTERVAL:-0x0028}"
le_create_supervision_timeout="${LE_CREATE_SUPERVISION_TIMEOUT:-0x0258}"
read_timeout="${READ_TIMEOUT:-100}"
response_timeout="${RESPONSE_TIMEOUT:-3}"
stream_duration="${STREAM_DURATION:-20}"
stream_services_timeout="${STREAM_SERVICES_TIMEOUT:-25}"
probe_delay="${PROBE_DELAY_SECONDS:-0.8}"
scan_backend="${SCAN_BACKEND:-hci}"
cycles="${CYCLES:-0}"
reset_after_no_targets="${RESET_AFTER_NO_TARGETS:-1}"
reset_after_connect_failures="${RESET_AFTER_CONNECT_FAILURES:-1}"
console_mode="${CONSOLE_MODE:-summary}"
console_verbose="${CONSOLE_VERBOSE:-0}"
reader_pid=""
console_pid=""
pipe_path=""
cleanup_started=0

args=(
  --manufacturer-hex "$manufacturer_hex"
  --identity-address "$identity_address"
  --after-connect zeroauth-stream
  --stream-duration "$stream_duration"
  --stream-exit-after-probes
  --stream-services-timeout "$stream_services_timeout"
  --stream-probes "$stream_probes"
  --stream-probe-delay-seconds "$probe_delay"
  --stream-address-source rpa
  --stream-strict-address
  --stream-auto-confirm-agent
  --stream-agent-capability DisplayYesNo
  --fresh-bluez-cache
  --require-rpa-stream-address
  --continue-after-success
  --cycles "$cycles"
  --scan-seconds "$scan_seconds"
  --scan-heartbeat-seconds "$scan_heartbeat_seconds"
  --silent-scan-timeout-seconds "$silent_scan_timeout_seconds"
  --connect-timeout "$connect_timeout"
  --connect-attempts "$connect_attempts"
  --connect-fallback-backend "$connect_fallback_backend"
  --connect-retry-delay-seconds "$connect_retry_delay"
  --le-create-conn-min-interval "$le_create_conn_min_interval"
  --le-create-conn-max-interval "$le_create_conn_max_interval"
  --le-create-supervision-timeout "$le_create_supervision_timeout"
  --read-timeout "$read_timeout"
  --response-timeout "$response_timeout"
  --scan-backend "$scan_backend"
  --reset-bluetooth-after-no-targets "$reset_after_no_targets"
  --reset-bluetooth-after-connect-failures "$reset_after_connect_failures"
  --physical-toggle-hint-after-no-targets 1
)

if truthy "${STREAM_ALL_NOTIFY_CHARS:-0}"; then
  args+=(--stream-all-notify-chars)
fi

if truthy "${EMIT_ALL_MANUFACTURER_LINES:-0}"; then
  args+=(--emit-all-manufacturer-lines)
fi

printf 'manual reader log: %s\n' "$logfile" >&2
printf 'console mode: %s (raw JSONL still goes to the log)\n' "$console_mode" >&2
printf 'summary: PYTHONPATH=src /usr/bin/python3 -m oura_ring4_ble.cli pi-watch-summary %s\n' "$logfile" >&2
printf 'stop: Ctrl-C (stops scanner, btmon, btmgmt find, and HCI scan)\n' >&2

set +e
run_reader() {
  printf '{"event":"pi_manual_reader_launcher","payload":{"logfile":"%s","manufacturer_hex":"%s","stream_probes":"%s","scan_backend":"%s"}}\n' \
    "$logfile" "$manufacturer_hex" "$stream_probes" "$scan_backend"
  sudo -n timeout 3 hcitool cmd 0x08 0x000c 00 00 || true
  sudo -n timeout 3 hciconfig hci0 up || true
  PYTHONPATH=src /usr/bin/python3 scripts/pi-oura-raw-rpa-read-loop.py "${args[@]}" "$@"
}

stop_reader() {
  local status="${1:-130}"
  local signal="${2:-TERM}"
  if [[ "$cleanup_started" == "1" ]]; then
    return
  fi
  cleanup_started=1
  trap - INT TERM
  printf '\nstopping manual reader ...\n' >&2
  {
    if [[ -n "$reader_pid" ]] && kill -0 "$reader_pid" >/dev/null 2>&1; then
      kill "-$signal" "$reader_pid" >/dev/null 2>&1 || true
      pkill "-$signal" -P "$reader_pid" >/dev/null 2>&1 || true
      sleep 0.3
      if kill -0 "$reader_pid" >/dev/null 2>&1; then
        kill -KILL "$reader_pid" >/dev/null 2>&1 || true
        pkill -KILL -P "$reader_pid" >/dev/null 2>&1 || true
      fi
    fi
    cleanup_ble_helpers "$signal"
    sleep 0.2
    cleanup_ble_helpers KILL
  } 2>/dev/null
  if [[ -n "$pipe_path" ]]; then
    rm -f "$pipe_path"
  fi
  printf 'manual reader interrupted; log: %s\n' "$logfile" >&2
  exit "$status"
}

trap 'stop_reader 130 TERM' INT
trap 'stop_reader 143 TERM' TERM

pipe_path="$(mktemp -u "${TMPDIR:-/tmp}/pi-manual-ring-read.XXXXXX")"
mkfifo "$pipe_path"

case "$console_mode" in
  raw)
    tee -a "$logfile" < "$pipe_path" &
    console_pid="$!"
    ;;
  quiet)
    tee -a "$logfile" < "$pipe_path" >/dev/null &
    console_pid="$!"
    ;;
  summary|"")
    if truthy "$console_verbose"; then
      tee -a "$logfile" < "$pipe_path" | /usr/bin/python3 scripts/pi-manual-ring-read-console.py --verbose &
    else
      tee -a "$logfile" < "$pipe_path" | /usr/bin/python3 scripts/pi-manual-ring-read-console.py &
    fi
    console_pid="$!"
    ;;
  *)
    printf 'unknown CONSOLE_MODE=%s (expected summary, raw, or quiet)\n' "$console_mode" >&2
    status=2
    ;;
esac

if [[ "${status:-0}" == "0" ]]; then
  run_reader "$@" > "$pipe_path" 2>&1 &
  reader_pid="$!"
  wait "$reader_pid"
  status="$?"
  wait "$console_pid" >/dev/null 2>&1 || true
fi

trap - INT TERM
rm -f "$pipe_path"
set -e

printf 'manual reader exited with status %s; log: %s\n' "$status" "$logfile" >&2
exit "$status"
