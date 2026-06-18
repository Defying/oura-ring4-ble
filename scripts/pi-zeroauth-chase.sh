#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

mkdir -p logs
logfile="logs/pi-zeroauth-chase-product-$(date +%Y%m%d-%H%M%S).jsonl"
printf "%s\n" "$logfile" > logs/current-pi-zeroauth-chase.log
printf "%s\n" "$logfile" > logs/current-pi-bluez-read-result.log
: > "$logfile"

manufacturer_hex="${MANUFACTURER_HEX:-04671b01,04661b01,04651b01,04621b01,04611b01,04601b01}"
identity_address="${IDENTITY_ADDRESS:-AA:BB:CC:DD:EE:FF}"
stream_probes="${STREAM_PROBES:-firmware,auth_nonce,capabilities:0x00,capabilities:0x01,product_info_all,product_info_hex_stable,battery}"
extra_stream_probes="${EXTRA_STREAM_PROBES:-}"
if [[ -n "$extra_stream_probes" ]]; then
  stream_probes="${stream_probes},${extra_stream_probes}"
fi
scan_seconds="${SCAN_SECONDS:-300}"
scan_heartbeat_seconds="${SCAN_HEARTBEAT_SECONDS:-30}"
connect_timeout="${CONNECT_TIMEOUT:-8}"
connect_attempts="${CONNECT_ATTEMPTS:-1}"
connect_fallback_backend="${CONNECT_FALLBACK_BACKEND:-hcitool-lecc}"
connect_retry_delay="${CONNECT_RETRY_DELAY_SECONDS:-0.05}"
le_create_own_address_type="${LE_CREATE_OWN_ADDRESS_TYPE:-public}"
le_create_scan_interval="${LE_CREATE_SCAN_INTERVAL:-0x0010}"
le_create_scan_window="${LE_CREATE_SCAN_WINDOW:-0x0010}"
le_create_conn_min_interval="${LE_CREATE_CONN_MIN_INTERVAL:-0x0018}"
le_create_conn_max_interval="${LE_CREATE_CONN_MAX_INTERVAL:-0x0028}"
le_create_conn_latency="${LE_CREATE_CONN_LATENCY:-0x0000}"
le_create_supervision_timeout="${LE_CREATE_SUPERVISION_TIMEOUT:-0x0258}"
le_create_min_ce_length="${LE_CREATE_MIN_CE_LENGTH:-0x0000}"
le_create_max_ce_length="${LE_CREATE_MAX_CE_LENGTH:-0x0000}"
read_timeout="${READ_TIMEOUT:-140}"
response_timeout="${RESPONSE_TIMEOUT:-2}"
stream_duration="${STREAM_DURATION:-10}"
stream_exit_after_probes="${STREAM_EXIT_AFTER_PROBES:-0}"
stream_services_timeout="${STREAM_SERVICES_TIMEOUT:-25}"
probe_delay="${PROBE_DELAY_SECONDS:-1.25}"
stream_all_notify_chars="${STREAM_ALL_NOTIFY_CHARS:-0}"
stream_connect="${STREAM_CONNECT:-1}"
stream_address_source="${STREAM_ADDRESS_SOURCE:-rpa}"
stream_strict_address="${STREAM_STRICT_ADDRESS:-1}"
stream_auto_confirm_agent="${STREAM_AUTO_CONFIRM_AGENT:-1}"
stream_agent_capability="${STREAM_AGENT_CAPABILITY:-DisplayYesNo}"
stream_pair="${STREAM_PAIR:-0}"
stream_pair_timeout="${STREAM_PAIR_TIMEOUT:-45}"
fresh_bluez_cache="${FRESH_BLUEZ_CACHE:-1}"
require_rpa_stream_address="${REQUIRE_RPA_STREAM_ADDRESS:-1}"
cycle_delay="${CYCLE_DELAY_SECONDS:-0.5}"
find_restart_delay="${FIND_RESTART_DELAY:-0.35}"
scan_backend="${SCAN_BACKEND:-hci}"
cycles="${CYCLES:-0}"
continue_after_success="${CONTINUE_AFTER_SUCCESS:-1}"
reset_after_no_targets="${RESET_AFTER_NO_TARGETS:-20}"
reset_after_connect_failures="${RESET_AFTER_CONNECT_FAILURES:-3}"
toggle_hint_after_no_targets="${TOGGLE_HINT_AFTER_NO_TARGETS:-5}"

{
  printf '{"event":"pi_zeroauth_launcher","payload":{"logfile":"%s","manufacturer_hex":"%s","identity_address":"%s"}}\n' \
    "$logfile" "$manufacturer_hex" "$identity_address"
  sudo -n timeout 3 hcitool cmd 0x08 0x000c 00 00 || true
  sudo -n timeout 3 hciconfig hci0 up || true
  sudo -n hcitool con |
    sed -n "s/.*< LE ${identity_address} handle \([0-9][0-9]*\).*/\1/p" |
    while read -r handle; do
      sudo -n timeout 5 hcitool ledc "$handle" || true
    done
  sudo -n timeout 4 btmgmt info >/dev/null || true
  notify_args=()
  if [[ "$stream_all_notify_chars" == "1" || "$stream_all_notify_chars" == "true" || "$stream_all_notify_chars" == "yes" ]]; then
    notify_args+=(--stream-all-notify-chars)
  fi
  connect_args=()
  if [[ "$stream_connect" == "0" || "$stream_connect" == "false" || "$stream_connect" == "no" ]]; then
    connect_args+=(--no-stream-connect)
  fi
  address_args=(--stream-address-source "$stream_address_source")
  if [[ "$stream_strict_address" == "1" || "$stream_strict_address" == "true" || "$stream_strict_address" == "yes" ]]; then
    address_args+=(--stream-strict-address)
  fi
  pairing_args=()
  if [[ "$stream_auto_confirm_agent" == "1" || "$stream_auto_confirm_agent" == "true" || "$stream_auto_confirm_agent" == "yes" ]]; then
    pairing_args+=(--stream-auto-confirm-agent --stream-agent-capability "$stream_agent_capability")
  fi
  if [[ "$stream_pair" == "1" || "$stream_pair" == "true" || "$stream_pair" == "yes" ]]; then
    pairing_args+=(--stream-pair --stream-pair-timeout "$stream_pair_timeout")
  fi
  stream_exit_args=()
  if [[ "$stream_exit_after_probes" == "1" || "$stream_exit_after_probes" == "true" || "$stream_exit_after_probes" == "yes" ]]; then
    stream_exit_args+=(--stream-exit-after-probes)
  fi
  cache_args=()
  if [[ "$fresh_bluez_cache" == "1" || "$fresh_bluez_cache" == "true" || "$fresh_bluez_cache" == "yes" ]]; then
    cache_args+=(--fresh-bluez-cache)
  else
    cache_args+=(--no-fresh-bluez-cache)
  fi
  if [[ "$require_rpa_stream_address" == "1" || "$require_rpa_stream_address" == "true" || "$require_rpa_stream_address" == "yes" ]]; then
    cache_args+=(--require-rpa-stream-address)
  fi
  success_args=()
  if [[ "$continue_after_success" == "1" || "$continue_after_success" == "true" || "$continue_after_success" == "yes" ]]; then
    success_args+=(--continue-after-success)
  fi
  PYTHONPATH=src /usr/bin/python3 scripts/pi-oura-raw-rpa-read-loop.py \
    --manufacturer-hex "$manufacturer_hex" \
    --identity-address "$identity_address" \
    --after-connect zeroauth-stream \
    --stream-duration "$stream_duration" \
    --stream-services-timeout "$stream_services_timeout" \
    --stream-probes "$stream_probes" \
    --stream-probe-delay-seconds "$probe_delay" \
    "${notify_args[@]}" \
    "${connect_args[@]}" \
    "${address_args[@]}" \
    "${pairing_args[@]}" \
    "${stream_exit_args[@]}" \
    "${cache_args[@]}" \
    "${success_args[@]}" \
    --cycles "$cycles" \
    --scan-seconds "$scan_seconds" \
    --scan-heartbeat-seconds "$scan_heartbeat_seconds" \
    --connect-timeout "$connect_timeout" \
    --connect-attempts "$connect_attempts" \
    --connect-fallback-backend "$connect_fallback_backend" \
    --connect-retry-delay-seconds "$connect_retry_delay" \
    --le-create-own-address-type "$le_create_own_address_type" \
    --le-create-scan-interval "$le_create_scan_interval" \
    --le-create-scan-window "$le_create_scan_window" \
    --le-create-conn-min-interval "$le_create_conn_min_interval" \
    --le-create-conn-max-interval "$le_create_conn_max_interval" \
    --le-create-conn-latency "$le_create_conn_latency" \
    --le-create-supervision-timeout "$le_create_supervision_timeout" \
    --le-create-min-ce-length "$le_create_min_ce_length" \
    --le-create-max-ce-length "$le_create_max_ce_length" \
    --read-timeout "$read_timeout" \
    --response-timeout "$response_timeout" \
    --delay-seconds "$cycle_delay" \
    --find-restart-delay "$find_restart_delay" \
    --scan-backend "$scan_backend" \
    --reset-bluetooth-after-no-targets "$reset_after_no_targets" \
    --reset-bluetooth-after-connect-failures "$reset_after_connect_failures" \
    --physical-toggle-hint-after-no-targets "$toggle_hint_after_no_targets"
} 2>&1 | tee -a "$logfile"

exit "${PIPESTATUS[0]}"
