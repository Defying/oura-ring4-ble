#!/usr/bin/env python3
"""Capture Oura's raw RPA with btmon, connect with hcitool, then run a BlueZ probe."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ADDRESS_RE = re.compile(r"Address:\s+([0-9A-Fa-f:]{17})\s+\(([^)]+)\)")
ADDRESS_TYPE_RE = re.compile(r"Address type:\s+(.+)")
EVENT_TYPE_RE = re.compile(r"Event type:\s+(.+)")
COMPANY_RE = re.compile(r"Company:\s+(.+)")
MANUFACTURER_RE = re.compile(r"Data(?:\[\d+\])?:\s+([0-9A-Fa-f]+)")
NAME_RE = re.compile(r"Name \((?:complete|short)\):\s+(.+)")
RSSI_RE = re.compile(r"RSSI:\s+(-?\d+)\s+dBm")
LE_CONNECTION_RE = re.compile(
    r"<\s+LE\s+([0-9A-Fa-f:]{17})\s+handle\s+(\d+)\s+state\s+(\d+)"
)
SMP_FIELD_RE = re.compile(r"\s*([^:]+):\s+(.+?)(?:\s+\((0x[0-9a-fA-F]+)\))?$")
SMP_REASON_RE = re.compile(r"\s*Reason:\s+(.+?)\s+\((0x[0-9a-fA-F]+)\)")
HCI_STATUS_RE = re.compile(r"Status:\s+.+?\s+\((0x[0-9a-fA-F]+)\)")
HCI_EVENT_HEX_RE = re.compile(r"^\s*((?:[0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2})\s*$")
BTMGMT_DEV_FOUND_RE = re.compile(
    r"dev_found:\s+([0-9A-Fa-f:]{17})\s+type\s+(.+?)\s+rssi\s+(-?\d+)"
)
SMP_REQUEST_FIELDS = {
    "io_capability",
    "oob_data",
    "authentication_requirement",
    "max_encryption_key_size",
    "initiator_key_distribution",
    "responder_key_distribution",
}
KNOWN_OURA_MANUFACTURERS = {
    "04601b01",
    "04611b01",
    "04621b01",
    "04651b01",
    "04661b01",
    "04671b01",
}
NO_TARGET_PHYSICAL_NOTE = (
    "no target is not proof of a parser/client failure; the ring may simply not "
    "be advertising the target Oura state in its current physical/BLE state "
    "(worn, idle, connected elsewhere, or charger state) until that state changes"
)


@dataclass(frozen=True)
class ScanResult:
    rpa: str | None
    manufacturer_counts: dict[str, int]
    resolvable_counts: dict[str, int]
    oura_candidate_counts: dict[str, int]
    scan_active: bool
    address_type_counts: dict[str, int] = field(default_factory=dict)
    address_kind_counts: dict[str, int] = field(default_factory=dict)
    event_type_counts: dict[str, int] = field(default_factory=dict)
    manufacturer_rssi: dict[str, dict[str, int]] = field(default_factory=dict)
    manufacturer_addresses: dict[str, dict[str, Any]] = field(default_factory=dict)
    address_rssi: dict[str, dict[str, Any]] = field(default_factory=dict)
    unique_address_count: int = 0
    resolvable_address_count: int = 0
    scan_backend: str = ""
    last_address: str | None = None
    last_address_type: str = ""
    last_address_kind: str = ""
    last_event_type: str = ""
    inactive_reason: str = ""


@dataclass(frozen=True)
class ZeroAuthStreamStatus:
    read_results: int
    usable_read_results: int
    probe_errors: int
    probe_stops: int


@dataclass(frozen=True)
class RawConnectResult:
    success: bool
    stream_address: str | None = None


def main() -> int:
    signal.signal(signal.SIGINT, handle_stop_signal)
    signal.signal(signal.SIGTERM, handle_stop_signal)
    parser = argparse.ArgumentParser(
        description=(
            "Wait for a target Oura manufacturer payload, connect to the raw "
            "resolvable private address, and run the safe BlueZ D-Bus reader."
        )
    )
    parser.add_argument(
        "--manufacturer-hex",
        default="04671b01,04661b01,04651b01,04621b01,04611b01,04601b01",
        help=(
            "comma-separated target manufacturer payloads; defaults to observed "
            "zero-auth/GATT-oriented Oura states 04671b01, 04661b01, 04651b01, "
            "04621b01, 04611b01, and 04601b01"
        ),
    )
    parser.add_argument("--identity-address", default="AA:BB:CC:DD:EE:FF")
    parser.add_argument("--scan-seconds", type=float, default=120.0)
    parser.add_argument(
        "--scan-heartbeat-seconds",
        type=float,
        default=0.0,
        help="emit in-scan progress every N seconds; 0 disables",
    )
    parser.add_argument(
        "--silent-scan-timeout-seconds",
        type=float,
        default=0.0,
        help=(
            "mark a scan inactive if btmon sees no manufacturer data for this "
            "many seconds; 0 disables"
        ),
    )
    parser.add_argument("--connect-timeout", type=float, default=30.0)
    parser.add_argument(
        "--connect-settle-seconds",
        type=float,
        default=0.05,
        help="delay between scan stop and raw hcitool lecc",
    )
    parser.add_argument(
        "--connect-backend",
        choices=("hci-create", "hcitool-lecc"),
        default="hci-create",
        help="raw connect method after target RPA detection",
    )
    parser.add_argument(
        "--connect-attempts",
        type=int,
        default=1,
        help="number of raw connect attempts to make before declaring target failure",
    )
    parser.add_argument(
        "--connect-fallback-backend",
        choices=("", "hci-create", "hcitool-lecc"),
        default="",
        help="optional second raw connect backend to try after the primary backend",
    )
    parser.add_argument(
        "--connect-retry-delay-seconds",
        type=float,
        default=0.15,
        help="settle delay between raw connect attempts",
    )
    parser.add_argument(
        "--le-create-own-address-type",
        choices=("public", "random"),
        default="public",
        help="own address type byte for LE Create Connection",
    )
    parser.add_argument(
        "--le-create-scan-interval",
        type=parse_int,
        default=0x0010,
        help="LE Create Connection initiator scan interval",
    )
    parser.add_argument(
        "--le-create-scan-window",
        type=parse_int,
        default=0x0010,
        help="LE Create Connection initiator scan window",
    )
    parser.add_argument(
        "--le-create-conn-min-interval",
        type=parse_int,
        default=0x000F,
        help="LE Create Connection minimum connection interval",
    )
    parser.add_argument(
        "--le-create-conn-max-interval",
        type=parse_int,
        default=0x000F,
        help="LE Create Connection maximum connection interval",
    )
    parser.add_argument(
        "--le-create-conn-latency",
        type=parse_int,
        default=0x0000,
        help="LE Create Connection peripheral latency",
    )
    parser.add_argument(
        "--le-create-supervision-timeout",
        type=parse_int,
        default=0x0C80,
        help="LE Create Connection supervision timeout",
    )
    parser.add_argument(
        "--le-create-min-ce-length",
        type=parse_int,
        default=0x0001,
        help="LE Create Connection minimum connection event length",
    )
    parser.add_argument(
        "--le-create-max-ce-length",
        type=parse_int,
        default=0x0001,
        help="LE Create Connection maximum connection event length",
    )
    parser.add_argument("--read-timeout", type=float, default=20.0)
    parser.add_argument("--response-timeout", type=float, default=2.5)
    parser.add_argument(
        "--after-connect",
        choices=("packet-read", "zeroauth-stream", "none"),
        default="packet-read",
        help="probe to run immediately after raw HCI connect",
    )
    parser.add_argument("--stream-duration", type=float, default=24.0)
    parser.add_argument(
        "--stream-exit-after-probes",
        action="store_true",
        help="ask zeroauth-stream to emit read_result and exit as soon as probes finish",
    )
    parser.add_argument(
        "--stream-services-timeout",
        type=float,
        default=25.0,
        help="seconds to wait for BlueZ to resolve GATT services after raw connect",
    )
    parser.add_argument(
        "--stream-probes",
        default="firmware,auth_nonce,battery",
        help="comma-separated zero-auth stream probes",
    )
    parser.add_argument("--stream-probe-delay-seconds", type=float, default=0.8)
    parser.add_argument(
        "--stream-all-notify-chars",
        action="store_true",
        help="subscribe to all Oura notify chars in zeroauth-stream mode",
    )
    parser.add_argument(
        "--stream-connect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "let pi-bluez-zeroauth-stream call Device1.Connect if BlueZ does "
            "not mark the raw HCI link connected"
        ),
    )
    parser.add_argument(
        "--stream-address-source",
        choices=("identity", "rpa"),
        default="identity",
        help="address passed to pi-bluez-zeroauth-stream after raw connect",
    )
    parser.add_argument(
        "--stream-strict-address",
        action="store_true",
        help="require pi-bluez-zeroauth-stream to use the exact selected address",
    )
    parser.add_argument(
        "--require-rpa-stream-address",
        action="store_true",
        help=(
            "treat an identity-address raw connection as stale BlueZ cache when "
            "--stream-address-source=rpa is requested"
        ),
    )
    parser.add_argument(
        "--fresh-bluez-cache",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "remove the known BlueZ identity-address device before each scan so "
            "post-reset reads create a fresh RPA Device1/GATT object"
        ),
    )
    parser.add_argument(
        "--stream-auto-confirm-agent",
        action="store_true",
        help="register a temporary BlueZ pairing agent during zeroauth-stream",
    )
    parser.add_argument(
        "--stream-agent-capability",
        default="DisplayYesNo",
        help="BlueZ pairing agent capability for zeroauth-stream",
    )
    parser.add_argument(
        "--stream-pair",
        action="store_true",
        help="call Device1.Pair before zeroauth-stream subscriptions",
    )
    parser.add_argument("--stream-pair-timeout", type=float, default=45.0)
    parser.add_argument("--cycles", type=int, default=0, help="0 means until success")
    parser.add_argument(
        "--continue-after-success",
        action="store_true",
        help="keep scanning after a successful after-connect probe",
    )
    parser.add_argument(
        "--keep-connected-after-probe",
        action="store_true",
        help="leave the raw HCI connection up after the probe command exits",
    )
    parser.add_argument(
        "--no-disconnect-before-scan",
        action="store_true",
        help="do not clear stale identity-address LE links before each scan cycle",
    )
    parser.add_argument(
        "--reset-bluetooth-after-no-targets",
        type=int,
        default=0,
        help=(
            "restart bluetooth after this many consecutive no-target scan cycles; "
            "0 disables"
        ),
    )
    parser.add_argument(
        "--reset-bluetooth-after-connect-failures",
        type=int,
        default=0,
        help=(
            "restart bluetooth after this many consecutive raw connect failures; "
            "0 disables"
        ),
    )
    parser.add_argument(
        "--reset-sleep-seconds",
        type=float,
        default=1.5,
        help="settle delay after an in-loop bluetooth restart",
    )
    parser.add_argument(
        "--physical-toggle-hint-after-no-targets",
        type=int,
        default=5,
        help=(
            "emit an operator hint after this many consecutive no-target cycles; "
            "0 disables"
        ),
    )
    parser.add_argument("--delay-seconds", type=float, default=2.0)
    parser.add_argument("--find-restart-delay", type=float, default=1.0)
    parser.add_argument(
        "--scan-backend",
        choices=("auto", "btmgmt", "hci"),
        default="auto",
        help="scan backend: auto tries btmgmt then raw HCI; hci skips btmgmt entirely",
    )
    parser.add_argument(
        "--emit-all-manufacturer-lines",
        action="store_true",
        help=(
            "emit every manufacturer advertisement; default keeps non-Oura "
            "traffic in counts only"
        ),
    )
    parser.add_argument(
        "--scan-activation-grace-seconds",
        type=float,
        default=0.8,
        help="time to wait before checking that btmgmt find actually enabled discovery",
    )
    parser.add_argument(
        "--recover-if-scan-inactive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="restart Bluetooth immediately if the scan process does not enable discovery",
    )
    parser.add_argument(
        "--verify-btmgmt-discovering",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "verify btmgmt find via bluetoothctl Discovering; disable on controllers "
            "where btmgmt scans but bluetoothctl reports Discovering: no"
        ),
    )
    parser.add_argument(
        "--hci-command-timeout-seconds",
        type=float,
        default=3.0,
        help="per-command timeout for direct HCI scan enable/disable commands",
    )
    parser.add_argument(
        "--btmon-timestamps",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run btmon with timestamps; disable on BlueZ builds where btmon -t crashes",
    )
    parser.add_argument("--log-dir", default="logs")
    try:
        return run(parser.parse_args())
    except KeyboardInterrupt:
        return 130


def handle_stop_signal(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    cycle = 0
    target_manufacturers = parse_hex_list(args.manufacturer_hex)
    consecutive_no_targets = 0
    consecutive_connect_failures = 0
    saw_success = False
    emit(
        "raw_loop_start",
        {
            "manufacturer_hex": sorted(target_manufacturers),
            "identity_address": args.identity_address,
            "scan_seconds": args.scan_seconds,
            "scan_heartbeat_seconds": args.scan_heartbeat_seconds,
            "silent_scan_timeout_seconds": getattr(
                args, "silent_scan_timeout_seconds", 0.0
            ),
            "connect_timeout": args.connect_timeout,
            "connect_settle_seconds": args.connect_settle_seconds,
            "connect_backend": args.connect_backend,
            "connect_attempts": getattr(args, "connect_attempts", 1),
            "connect_fallback_backend": getattr(args, "connect_fallback_backend", ""),
            "connect_retry_delay_seconds": getattr(
                args, "connect_retry_delay_seconds", 0.15
            ),
            "le_create_own_address_type": getattr(
                args, "le_create_own_address_type", "public"
            ),
            "le_create_scan_interval": args.le_create_scan_interval,
            "le_create_scan_window": args.le_create_scan_window,
            "le_create_conn_min_interval": getattr(
                args, "le_create_conn_min_interval", 0x000F
            ),
            "le_create_conn_max_interval": getattr(
                args, "le_create_conn_max_interval", 0x000F
            ),
            "le_create_conn_latency": getattr(args, "le_create_conn_latency", 0x0000),
            "le_create_supervision_timeout": getattr(
                args, "le_create_supervision_timeout", 0x0C80
            ),
            "le_create_min_ce_length": getattr(args, "le_create_min_ce_length", 0x0001),
            "le_create_max_ce_length": getattr(args, "le_create_max_ce_length", 0x0001),
            "read_timeout": args.read_timeout,
            "stream_services_timeout": args.stream_services_timeout,
            "stream_duration": args.stream_duration,
            "stream_exit_after_probes": args.stream_exit_after_probes,
            "stream_address_source": args.stream_address_source,
            "stream_strict_address": args.stream_strict_address,
            "require_rpa_stream_address": args.require_rpa_stream_address,
            "fresh_bluez_cache": args.fresh_bluez_cache,
            "stream_auto_confirm_agent": args.stream_auto_confirm_agent,
            "stream_agent_capability": args.stream_agent_capability,
            "stream_pair": args.stream_pair,
            "cycles": args.cycles,
            "reset_bluetooth_after_no_targets": args.reset_bluetooth_after_no_targets,
            "reset_bluetooth_after_connect_failures": (
                args.reset_bluetooth_after_connect_failures
            ),
            "scan_backend": args.scan_backend,
            "emit_all_manufacturer_lines": args.emit_all_manufacturer_lines,
            "scan_activation_grace_seconds": args.scan_activation_grace_seconds,
            "recover_if_scan_inactive": args.recover_if_scan_inactive,
            "verify_btmgmt_discovering": args.verify_btmgmt_discovering,
            "hci_command_timeout_seconds": args.hci_command_timeout_seconds,
            "btmon_timestamps": args.btmon_timestamps,
        },
        started,
    )
    while args.cycles <= 0 or cycle < args.cycles:
        cycle += 1
        emit("raw_cycle_start", {"cycle": cycle}, started)
        if not args.no_disconnect_before_scan:
            disconnect_identity_connections(
                args.identity_address, cycle, started, "before_scan", emit_empty=False
            )
        if args.fresh_bluez_cache:
            remove_bluez_device(args.identity_address, cycle, started, "before_scan")
        scan_result = capture_rpa(args, cycle, started, target_manufacturers)
        if not scan_result.scan_active:
            emit(
                "raw_cycle_scan_inactive",
                {
                    "cycle": cycle,
                    "reason": scan_result.inactive_reason,
                    "manufacturer_counts": scan_result.manufacturer_counts,
                    "resolvable_counts": scan_result.resolvable_counts,
                    "oura_candidate_counts": scan_result.oura_candidate_counts,
                    "address_type_counts": scan_result.address_type_counts,
                    "address_kind_counts": scan_result.address_kind_counts,
                    "event_type_counts": scan_result.event_type_counts,
                    "manufacturer_rssi": scan_result.manufacturer_rssi,
                    "manufacturer_addresses": scan_result.manufacturer_addresses,
                    "address_rssi": scan_result.address_rssi,
                    "unique_address_count": scan_result.unique_address_count,
                    "resolvable_address_count": scan_result.resolvable_address_count,
                    "scan_backend": scan_result.scan_backend,
                    "last_address": scan_result.last_address,
                    "last_address_type": scan_result.last_address_type,
                    "last_address_kind": scan_result.last_address_kind,
                    "last_event_type": scan_result.last_event_type,
                },
                started,
            )
            if args.recover_if_scan_inactive:
                recover_bluetooth(args, cycle, started, "scan_inactive")
            time.sleep(args.delay_seconds)
            continue
        if not scan_result.rpa:
            consecutive_no_targets += 1
            emit(
                "raw_cycle_no_target",
                {
                    "cycle": cycle,
                    "consecutive_no_targets": consecutive_no_targets,
                    "manufacturer_counts": scan_result.manufacturer_counts,
                    "resolvable_counts": scan_result.resolvable_counts,
                    "oura_candidate_counts": scan_result.oura_candidate_counts,
                    "address_type_counts": scan_result.address_type_counts,
                    "address_kind_counts": scan_result.address_kind_counts,
                    "event_type_counts": scan_result.event_type_counts,
                    "manufacturer_rssi": scan_result.manufacturer_rssi,
                    "manufacturer_addresses": scan_result.manufacturer_addresses,
                    "address_rssi": scan_result.address_rssi,
                    "unique_address_count": scan_result.unique_address_count,
                    "resolvable_address_count": scan_result.resolvable_address_count,
                    "scan_backend": scan_result.scan_backend,
                    "last_address": scan_result.last_address,
                    "last_address_type": scan_result.last_address_type,
                    "last_address_kind": scan_result.last_address_kind,
                    "last_event_type": scan_result.last_event_type,
                    "no_target_classification": (
                        "oura_seen_without_target_payload"
                        if scan_result.oura_candidate_counts
                        else "no_oura_seen"
                    ),
                    "physical_state_note": NO_TARGET_PHYSICAL_NOTE,
                },
                started,
            )
            maybe_emit_physical_toggle_hint(
                args, cycle, started, consecutive_no_targets
            )
            maybe_recover_bluetooth(
                args,
                cycle,
                started,
                reason="no_target",
                count=consecutive_no_targets,
                threshold=args.reset_bluetooth_after_no_targets,
            )
            time.sleep(args.delay_seconds)
            continue
        consecutive_no_targets = 0
        btmon = start_phase_btmon(args, cycle, "connect-read", started)
        try:
            connect_result = raw_connect(scan_result.rpa, args, cycle, started)
            if not connect_result.success:
                consecutive_connect_failures += 1
                maybe_recover_bluetooth(
                    args,
                    cycle,
                    started,
                    reason="connect_failure",
                    count=consecutive_connect_failures,
                    threshold=args.reset_bluetooth_after_connect_failures,
                )
                time.sleep(args.delay_seconds)
                continue
            stream_address = connect_result.stream_address or scan_result.rpa
            if should_reject_stream_address(args, scan_result.rpa, stream_address):
                emit(
                    "raw_stale_bluez_identity_cache",
                    {
                        "cycle": cycle,
                        "rpa": scan_result.rpa,
                        "stream_address": stream_address,
                        "identity_address": args.identity_address,
                        "reason": "identity_address_selected_for_rpa_stream",
                    },
                    started,
                )
                remove_bluez_device(args.identity_address, cycle, started, "rpa_guard")
                disconnect_identity_connections(
                    args.identity_address,
                    cycle,
                    started,
                    "rpa_guard",
                    emit_empty=True,
                    extra_addresses=[scan_result.rpa, stream_address],
                )
                consecutive_connect_failures += 1
                time.sleep(args.delay_seconds)
                continue
            try:
                probe_returncode = run_after_connect(
                    args, cycle, started, stream_address
                )
            finally:
                if not args.keep_connected_after_probe:
                    disconnect_identity_connections(
                        args.identity_address,
                        cycle,
                        started,
                        "after_probe",
                        emit_empty=True,
                        extra_addresses=[scan_result.rpa, stream_address],
                    )
            if probe_returncode == 0:
                saw_success = True
                consecutive_connect_failures = 0
                emit(
                    "raw_loop_success",
                    {
                        "cycle": cycle,
                        "rpa": scan_result.rpa,
                        "stream_address": stream_address,
                    },
                    started,
                )
                if not args.continue_after_success:
                    return 0
            else:
                consecutive_connect_failures += 1
                maybe_recover_bluetooth(
                    args,
                    cycle,
                    started,
                    reason="probe_failure",
                    count=consecutive_connect_failures,
                    threshold=args.reset_bluetooth_after_connect_failures,
                )
        finally:
            stop_phase_btmon(btmon, cycle, started)
        time.sleep(args.delay_seconds)
    emit("raw_loop_done", {"cycles": cycle, "success": saw_success}, started)
    return 0 if saw_success else 1


def capture_rpa(
    args: argparse.Namespace,
    cycle: int,
    started: float,
    target_manufacturers: set[str],
) -> ScanResult:
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    btmon_path = log_dir / f"btmon-raw-rpa-cycle-{cycle:04d}-{timestamp()}.log"
    find_path = log_dir / f"btmgmt-find-raw-rpa-cycle-{cycle:04d}-{timestamp()}.log"
    emit(
        "raw_scan_start",
        {"cycle": cycle, "btmon_path": str(btmon_path), "find_path": str(find_path)},
        started,
    )
    stop_stale_btmgmt_find(cycle, started, "before_scan")

    btmon_write_handle = btmon_path.open("w", encoding="utf-8")
    btmon_read_handle = btmon_path.open("r", encoding="utf-8")
    find_handle = find_path.open("w", encoding="utf-8")
    btmon_timestamps = args.btmon_timestamps
    btmon = subprocess.Popen(
        btmon_command(args, timestamps=btmon_timestamps),
        stdout=btmon_write_handle,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    find: subprocess.Popen[str] | None = None
    found: str | None = None
    manufacturer_counts: dict[str, int] = {}
    resolvable_counts: dict[str, int] = {}
    oura_candidate_counts: dict[str, int] = {}
    address_type_counts: dict[str, int] = {}
    address_kind_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    manufacturer_rssi: dict[str, dict[str, int]] = {}
    manufacturer_addresses: dict[str, dict[str, Any]] = {}
    address_rssi: dict[str, dict[str, Any]] = {}
    seen_addresses: set[str] = set()
    resolvable_addresses: set[str] = set()
    current_manufacturers: list[str] = []
    emitted_oura_candidates: set[tuple[str, str, str | None]] = set()
    scan_active = True
    inactive_reason = ""
    last_address: str | None = None
    last_address_type = ""
    last_address_kind = ""
    last_resolvable_address: str | None = None
    last_oura_resolvable_address: str | None = None
    last_event_type = ""
    last_company = ""
    last_name = ""
    deadline = time.monotonic() + args.scan_seconds
    sample_window_started_at = time.monotonic()
    next_heartbeat = time.monotonic() + args.scan_heartbeat_seconds
    next_find_start = 0.0
    find_started_at = 0.0
    checked_discovery_for_pid: int | None = None
    hci_scan_enabled = False
    scan_backend = "btmgmt"
    try:
        if args.scan_backend == "hci":
            if enable_hci_le_scan(args, cycle, started, "configured_hci_backend"):
                hci_scan_enabled = True
                scan_backend = "hci_le_scan"
                sample_window_started_at = time.monotonic()
                next_find_start = float("inf")
                emit(
                    "raw_scan_backend_switch",
                    {"cycle": cycle, "backend": scan_backend, "reason": "configured"},
                    started,
                )
            else:
                scan_active = False
                inactive_reason = "hci_le_scan_enable_failed"
        while time.monotonic() < deadline:
            if not scan_active:
                break
            now = time.monotonic()
            if args.scan_heartbeat_seconds > 0 and now >= next_heartbeat:
                emit_scan_heartbeat(
                    cycle,
                    started,
                    manufacturer_counts,
                    resolvable_counts,
                    oura_candidate_counts,
                    address_type_counts,
                    address_kind_counts,
                    event_type_counts,
                    manufacturer_rssi,
                    manufacturer_addresses,
                    address_rssi,
                    seen_addresses,
                    resolvable_addresses,
                    last_address,
                    last_address_type,
                    last_address_kind,
                    last_event_type,
                    scan_backend,
                    deadline,
                )
                next_heartbeat = now + args.scan_heartbeat_seconds
            if (
                not hci_scan_enabled
                and args.scan_backend in {"auto", "btmgmt"}
                and (find is None or find.poll() is not None)
                and now >= next_find_start
            ):
                find = subprocess.Popen(
                    btmgmt_find_command(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                emit("raw_scan_find_start", {"cycle": cycle, "pid": find.pid}, started)
                find_started_at = now
                checked_discovery_for_pid = None
                next_find_start = now + max(0.0, args.find_restart_delay)
                latest = drain_btmgmt_find_output(
                    find,
                    find_handle,
                    seen_addresses,
                    address_type_counts,
                    address_kind_counts,
                    event_type_counts,
                    address_rssi,
                )
                if latest:
                    (
                        last_address,
                        last_address_type,
                        last_address_kind,
                        last_event_type,
                    ) = latest
            if (
                args.verify_btmgmt_discovering
                and find is not None
                and find.poll() is None
                and checked_discovery_for_pid != find.pid
                and find_started_at > 0
                and now - find_started_at >= args.scan_activation_grace_seconds
            ):
                checked_discovery_for_pid = find.pid
                discovery = adapter_discovering()
                find_started = btmgmt_find_started(find_path)
                emit(
                    "raw_scan_discovery_check",
                    {
                        "cycle": cycle,
                        "pid": find.pid,
                        "discovering": discovery["discovering"],
                        "find_started": find_started,
                        "raw": discovery["raw"],
                    },
                    started,
                )
                if discovery["discovering"] is False and not find_started:
                    if args.scan_backend == "btmgmt" and find.poll() is None:
                        emit(
                            "raw_scan_discovery_check_ignored",
                            {
                                "cycle": cycle,
                                "pid": find.pid,
                                "reason": "btmgmt_process_still_running",
                            },
                            started,
                        )
                    else:
                        inactive_reason = "btmgmt_find_did_not_enable_discovery"
                        emit(
                            "raw_scan_inactive",
                            {
                                "cycle": cycle,
                                "pid": find.pid,
                                "reason": inactive_reason,
                            },
                            started,
                        )
                        stop_process(find)
                        find = None
                        if args.scan_backend == "btmgmt":
                            scan_active = False
                            break
                        if enable_hci_le_scan(args, cycle, started, inactive_reason):
                            hci_scan_enabled = True
                            scan_backend = "hci_le_scan"
                            sample_window_started_at = time.monotonic()
                            inactive_reason = ""
                            checked_discovery_for_pid = None
                            next_find_start = float("inf")
                            emit(
                                "raw_scan_backend_switch",
                                {"cycle": cycle, "backend": scan_backend},
                                started,
                            )
                        else:
                            scan_active = False
                            inactive_reason = "hci_le_scan_enable_failed"
                            break
            timeout = max(0.0, min(0.25, deadline - time.monotonic()))
            line = btmon_read_handle.readline()
            if not line:
                time.sleep(timeout)
            now = time.monotonic()
            latest = drain_btmgmt_find_output(
                find,
                find_handle,
                seen_addresses,
                address_type_counts,
                address_kind_counts,
                event_type_counts,
                address_rssi,
            )
            if latest:
                (
                    last_address,
                    last_address_type,
                    last_address_kind,
                    last_event_type,
                ) = latest
            if silent_scan_timed_out(
                getattr(args, "silent_scan_timeout_seconds", 0.0),
                manufacturer_counts,
                len(seen_addresses),
                sample_window_started_at,
                now,
            ):
                inactive_reason = "silent_scan_no_manufacturer_samples"
                emit(
                    "raw_scan_inactive",
                    {
                        "cycle": cycle,
                        "reason": inactive_reason,
                        "scan_backend": scan_backend,
                        "seconds_without_samples": round(
                            now - sample_window_started_at, 3
                        ),
                    },
                    started,
                )
                if should_try_hci_silent_fallback(args.scan_backend, hci_scan_enabled):
                    if find is not None:
                        stop_process(find)
                        find = None
                    stop_stale_btmgmt_find(cycle, started, inactive_reason)
                    if enable_hci_le_scan(args, cycle, started, inactive_reason):
                        hci_scan_enabled = True
                        scan_backend = "hci_le_scan"
                        sample_window_started_at = time.monotonic()
                        inactive_reason = ""
                        checked_discovery_for_pid = None
                        next_find_start = float("inf")
                        emit(
                            "raw_scan_backend_switch",
                            {
                                "cycle": cycle,
                                "backend": scan_backend,
                                "reason": "silent_btmgmt_scan",
                            },
                            started,
                        )
                        continue
                    inactive_reason = "hci_le_scan_enable_failed"
                scan_active = False
                break
            if not line:
                if btmon.poll() is not None:
                    if btmon_timestamps:
                        restart_find = should_restart_find_after_btmon_timestamp_crash(
                            find is not None,
                            manufacturer_counts,
                        )
                        emit(
                            "raw_btmon_restart_without_timestamps",
                            {
                                "cycle": cycle,
                                "returncode": btmon.returncode,
                                "reason": "timestamped_btmon_exited",
                                "restart_find": restart_find,
                            },
                            started,
                        )
                        if restart_find:
                            stop_process(find)
                            find = None
                            find_started_at = 0.0
                            checked_discovery_for_pid = None
                            next_find_start = time.monotonic() + max(
                                0.5, args.find_restart_delay
                            )
                        btmon_write_handle.close()
                        btmon_timestamps = False
                        args.btmon_timestamps = False
                        btmon_write_handle = btmon_path.open("a", encoding="utf-8")
                        btmon = subprocess.Popen(
                            btmon_command(args, timestamps=False),
                            stdout=btmon_write_handle,
                            stderr=subprocess.STDOUT,
                            text=True,
                            start_new_session=True,
                        )
                        continue
                    scan_active = False
                    inactive_reason = f"btmon_exited_{btmon.returncode}"
                    emit(
                        "raw_scan_inactive",
                        {
                            "cycle": cycle,
                            "reason": inactive_reason,
                            "pid": btmon.pid,
                        },
                        started,
                    )
                    break
                continue
            line = clean_btmon_line(line)
            event_type_match = EVENT_TYPE_RE.search(line)
            if event_type_match:
                last_event_type = event_type_match.group(1).strip()
                increment_count(event_type_counts, last_event_type)
                continue
            address_type_match = ADDRESS_TYPE_RE.search(line)
            if address_type_match:
                last_address_kind = address_type_match.group(1).strip()
                continue
            match = ADDRESS_RE.search(line)
            if match:
                last_address = match.group(1).upper()
                last_address_type = match.group(2)
                last_company = ""
                last_name = ""
                current_manufacturers = []
                seen_addresses.add(last_address)
                increment_count(address_type_counts, last_address_type)
                if last_address_kind:
                    increment_count(address_kind_counts, last_address_kind)
                if last_address_type == "Resolvable":
                    last_resolvable_address = last_address
                    resolvable_addresses.add(last_address)
                continue
            company_match = COMPANY_RE.search(line)
            if company_match:
                last_company = company_match.group(1).strip()
                if is_oura_company(last_company):
                    record_oura_candidate(
                        oura_candidate_counts,
                        emitted_oura_candidates,
                        cycle,
                        started,
                        reason="company",
                        address=last_address,
                        address_type=last_address_type,
                        address_kind=last_address_kind,
                        event_type=last_event_type,
                        company=last_company,
                        name=last_name,
                        manufacturer_hex=None,
                    )
                    target_rpa, rpa_source = candidate_target_rpa(
                        last_address,
                        last_address_type,
                        last_oura_resolvable_address,
                    )
                    if target_rpa:
                        found = target_rpa
                        emit_raw_scan_target(
                            cycle,
                            started,
                            found,
                            manufacturer_hex=None,
                            raw_manufacturer_hex=None,
                            address_type=last_address_type,
                            address_kind=last_address_kind,
                            rpa_source=rpa_source,
                            company=last_company,
                            name=last_name,
                            scan_backend=scan_backend,
                            target_signal="company",
                        )
                        break
                continue
            name_match = NAME_RE.search(line)
            if name_match:
                last_name = name_match.group(1).strip()
                if is_oura_name(last_name):
                    if last_address_type == "Resolvable" and last_address:
                        last_oura_resolvable_address = last_address
                    record_oura_candidate(
                        oura_candidate_counts,
                        emitted_oura_candidates,
                        cycle,
                        started,
                        reason="name",
                        address=last_address,
                        address_type=last_address_type,
                        address_kind=last_address_kind,
                        event_type=last_event_type,
                        company=last_company,
                        name=last_name,
                        manufacturer_hex=None,
                    )
                    target_rpa, rpa_source = candidate_target_rpa(
                        last_address,
                        last_address_type,
                        last_oura_resolvable_address,
                    )
                    if target_rpa:
                        found = target_rpa
                        emit_raw_scan_target(
                            cycle,
                            started,
                            found,
                            manufacturer_hex=None,
                            raw_manufacturer_hex=None,
                            address_type=last_address_type,
                            address_kind=last_address_kind,
                            rpa_source=rpa_source,
                            company=last_company,
                            name=last_name,
                            scan_backend=scan_backend,
                            target_signal="name",
                        )
                        break
                continue
            if is_oura_service_line(line):
                record_oura_candidate(
                    oura_candidate_counts,
                    emitted_oura_candidates,
                    cycle,
                    started,
                    reason="service_uuid",
                    address=last_address,
                    address_type=last_address_type,
                    address_kind=last_address_kind,
                    event_type=last_event_type,
                    company=last_company,
                    name=last_name,
                    manufacturer_hex=None,
                )
                target_rpa, rpa_source = candidate_target_rpa(
                    last_address,
                    last_address_type,
                    last_oura_resolvable_address,
                )
                if target_rpa:
                    found = target_rpa
                    emit_raw_scan_target(
                        cycle,
                        started,
                        found,
                        manufacturer_hex=None,
                        raw_manufacturer_hex=None,
                        address_type=last_address_type,
                        address_kind=last_address_kind,
                        rpa_source=rpa_source,
                        company=last_company,
                        name=last_name,
                        scan_backend=scan_backend,
                        target_signal="service_uuid",
                    )
                    break
                continue
            rssi_match = RSSI_RE.search(line)
            if rssi_match:
                rssi = int(rssi_match.group(1))
                record_address_rssi(
                    address_rssi,
                    address=last_address,
                    address_type=last_address_type,
                    address_kind=last_address_kind,
                    event_type=last_event_type,
                    rssi=rssi,
                )
                for manufacturer in current_manufacturers:
                    record_manufacturer_rssi(manufacturer_rssi, manufacturer, rssi)
                    record_manufacturer_address(
                        manufacturer_addresses,
                        manufacturer,
                        address=last_address,
                        address_type=last_address_type,
                        address_kind=last_address_kind,
                        event_type=last_event_type,
                        company=last_company,
                        name=last_name,
                        rssi=rssi,
                    )
                continue
            manufacturer_match = MANUFACTURER_RE.search(line)
            if not manufacturer_match:
                continue
            value = normalize_hex(manufacturer_match.group(1))
            oura_payload = oura_manufacturer_payload(value)
            current_manufacturers.append(oura_payload or value)
            manufacturer_counts[value] = manufacturer_counts.get(value, 0) + 1
            if last_address_type == "Resolvable":
                resolvable_counts[value] = resolvable_counts.get(value, 0) + 1
            if is_oura_manufacturer(value, last_company):
                if last_address_type == "Resolvable" and last_address:
                    last_oura_resolvable_address = last_address
                record_oura_candidate(
                    oura_candidate_counts,
                    emitted_oura_candidates,
                    cycle,
                    started,
                    reason="manufacturer",
                    address=last_address,
                    address_type=last_address_type,
                    address_kind=last_address_kind,
                    event_type=last_event_type,
                    company=last_company,
                    name=last_name,
                    manufacturer_hex=oura_payload or value,
                )
            if args.emit_all_manufacturer_lines or is_oura_manufacturer(
                value, last_company
            ):
                emit(
                    "raw_scan_manufacturer",
                    {
                        "cycle": cycle,
                        "manufacturer_hex": value,
                        "oura_manufacturer_hex": oura_payload,
                        "address": last_address,
                        "address_type": last_address_type,
                        "address_kind": last_address_kind,
                        "event_type": last_event_type,
                        "company": last_company,
                        "name": last_name,
                        "scan_backend": scan_backend,
                    },
                    started,
                )
            target_rpa = None
            rpa_source = ""
            if last_address and last_address_type == "Resolvable":
                target_rpa = last_address
                rpa_source = "current_resolvable_address"
            elif is_oura_manufacturer(value, last_company) and last_oura_resolvable_address:
                target_rpa = last_oura_resolvable_address
                rpa_source = "last_oura_resolvable_address"
            elif (
                (oura_payload or value) in target_manufacturers
                and last_resolvable_address
            ):
                target_rpa = last_resolvable_address
                rpa_source = "last_resolvable_address"
            if (
                (oura_payload or value) in target_manufacturers
                and target_rpa
            ):
                found = target_rpa
                emit_raw_scan_target(
                    cycle,
                    started,
                    found,
                    manufacturer_hex=oura_payload or value,
                    raw_manufacturer_hex=value,
                    address_type=last_address_type,
                    address_kind=last_address_kind,
                    rpa_source=rpa_source,
                    company=last_company,
                    name=last_name,
                    scan_backend=scan_backend,
                    target_signal="manufacturer",
                )
                break
    finally:
        if find is not None:
            latest = drain_btmgmt_find_output(
                find,
                find_handle,
                seen_addresses,
                address_type_counts,
                address_kind_counts,
                event_type_counts,
                address_rssi,
            )
            if latest:
                (
                    last_address,
                    last_address_type,
                    last_address_kind,
                    last_event_type,
                ) = latest
            stop_process(find, terminate_timeout=0.2 if found else 2.0)
            latest = drain_btmgmt_find_output(
                find,
                find_handle,
                seen_addresses,
                address_type_counts,
                address_kind_counts,
                event_type_counts,
                address_rssi,
            )
            if latest:
                (
                    last_address,
                    last_address_type,
                    last_address_kind,
                    last_event_type,
                ) = latest
        stop_process(btmon, terminate_timeout=0.2 if found else 2.0)
        btmon_write_handle.close()
        btmon_read_handle.close()
        find_handle.close()
        if hci_scan_enabled:
            disable_hci_le_scan(args, cycle, started, "scan_end")
    return ScanResult(
        rpa=found,
        manufacturer_counts=manufacturer_counts,
        resolvable_counts=resolvable_counts,
        oura_candidate_counts=oura_candidate_counts,
        scan_active=scan_active,
        address_type_counts=address_type_counts,
        address_kind_counts=address_kind_counts,
        event_type_counts=event_type_counts,
        manufacturer_rssi=manufacturer_rssi,
        manufacturer_addresses=manufacturer_addresses,
        address_rssi=address_rssi,
        unique_address_count=len(seen_addresses),
        resolvable_address_count=len(resolvable_addresses),
        scan_backend=scan_backend,
        last_address=last_address,
        last_address_type=last_address_type,
        last_address_kind=last_address_kind,
        last_event_type=last_event_type,
        inactive_reason=inactive_reason,
    )


def candidate_target_rpa(
    address: str | None,
    address_type: str,
    last_oura_resolvable_address: str | None,
) -> tuple[str | None, str]:
    if address and address_type == "Resolvable":
        return address, "current_resolvable_address"
    if last_oura_resolvable_address:
        return last_oura_resolvable_address, "last_oura_resolvable_address"
    return None, ""


def emit_raw_scan_target(
    cycle: int,
    started: float,
    rpa: str,
    *,
    manufacturer_hex: str | None,
    raw_manufacturer_hex: str | None,
    address_type: str,
    address_kind: str,
    rpa_source: str,
    company: str,
    name: str,
    scan_backend: str,
    target_signal: str,
) -> None:
    emit(
        "raw_scan_target",
        {
            "cycle": cycle,
            "manufacturer_hex": manufacturer_hex,
            "raw_manufacturer_hex": raw_manufacturer_hex,
            "rpa": rpa,
            "address_type": address_type,
            "address_kind": address_kind,
            "rpa_source": rpa_source,
            "company": company,
            "name": name,
            "scan_backend": scan_backend,
            "target_signal": target_signal,
        },
        started,
    )


def drain_btmgmt_find_output(
    find: subprocess.Popen[str] | None,
    find_handle: Any,
    seen_addresses: set[str],
    address_type_counts: dict[str, int],
    address_kind_counts: dict[str, int],
    event_type_counts: dict[str, int],
    address_rssi: dict[str, dict[str, Any]],
) -> tuple[str, str, str, str] | None:
    if find is None or find.stdout is None:
        return None
    latest: tuple[str, str, str, str] | None = None
    while True:
        ready, _, _ = select.select([find.stdout], [], [], 0)
        if not ready:
            return latest
        line = find.stdout.readline()
        if not line:
            return latest
        find_handle.write(line)
        find_handle.flush()
        match = BTMGMT_DEV_FOUND_RE.search(line)
        if not match:
            continue
        address = match.group(1).upper()
        address_type = match.group(2).strip()
        rssi = int(match.group(3))
        seen_addresses.add(address)
        increment_count(address_type_counts, address_type)
        increment_count(address_kind_counts, "btmgmt_find")
        increment_count(event_type_counts, "btmgmt_dev_found")
        record_address_rssi(
            address_rssi,
            address=address,
            address_type=address_type,
            address_kind="btmgmt_find",
            event_type="btmgmt_dev_found",
            rssi=rssi,
        )
        latest = (address, address_type, "btmgmt_find", "btmgmt_dev_found")


def silent_scan_timed_out(
    timeout_seconds: float,
    manufacturer_counts: dict[str, int],
    address_sample_count: int,
    sample_window_started_at: float,
    now: float,
) -> bool:
    return (
        timeout_seconds > 0
        and not manufacturer_counts
        and address_sample_count <= 0
        and now - sample_window_started_at >= timeout_seconds
    )


def should_try_hci_silent_fallback(scan_backend: str, hci_scan_enabled: bool) -> bool:
    return scan_backend == "auto" and not hci_scan_enabled


def should_restart_find_after_btmon_timestamp_crash(
    find_running: bool, manufacturer_counts: dict[str, int]
) -> bool:
    return find_running and not manufacturer_counts


def clean_btmon_line(line: str) -> str:
    return ANSI_ESCAPE_RE.sub("", line).replace("\x00", "")


def increment_count(counts: dict[str, int], key: str) -> None:
    if not key:
        return
    counts[key] = counts.get(key, 0) + 1


def record_manufacturer_rssi(
    summaries: dict[str, dict[str, int]], manufacturer: str, rssi: int
) -> None:
    summary = summaries.setdefault(
        manufacturer,
        {"samples": 0, "min": rssi, "max": rssi, "last": rssi},
    )
    summary["samples"] += 1
    summary["min"] = min(summary["min"], rssi)
    summary["max"] = max(summary["max"], rssi)
    summary["last"] = rssi


def record_manufacturer_address(
    summaries: dict[str, dict[str, Any]],
    manufacturer: str,
    *,
    address: str | None,
    address_type: str,
    address_kind: str,
    event_type: str,
    company: str,
    name: str,
    rssi: int,
) -> None:
    if not address:
        return
    summary = summaries.setdefault(
        manufacturer,
        {
            "samples": 0,
            "latest_address": "",
            "latest_address_type": "",
            "latest_address_kind": "",
            "latest_event_type": "",
            "latest_company": "",
            "latest_name": "",
            "latest_rssi": None,
            "max_rssi": None,
            "max_rssi_address": "",
            "max_rssi_address_type": "",
            "max_rssi_address_kind": "",
            "max_rssi_event_type": "",
            "max_rssi_company": "",
            "max_rssi_name": "",
            "latest_resolvable_address": "",
            "max_rssi_resolvable_address": "",
        },
    )
    summary["samples"] += 1
    summary["latest_address"] = address
    summary["latest_address_type"] = address_type
    summary["latest_address_kind"] = address_kind
    summary["latest_event_type"] = event_type
    summary["latest_company"] = company
    summary["latest_name"] = name
    summary["latest_rssi"] = rssi
    previous_max = summary.get("max_rssi")
    if not isinstance(previous_max, int) or rssi > previous_max:
        summary["max_rssi"] = rssi
        summary["max_rssi_address"] = address
        summary["max_rssi_address_type"] = address_type
        summary["max_rssi_address_kind"] = address_kind
        summary["max_rssi_event_type"] = event_type
        summary["max_rssi_company"] = company
        summary["max_rssi_name"] = name
        if address_type == "Resolvable":
            summary["max_rssi_resolvable_address"] = address
    if address_type == "Resolvable":
        summary["latest_resolvable_address"] = address


def record_address_rssi(
    summaries: dict[str, dict[str, Any]],
    *,
    address: str | None,
    address_type: str,
    address_kind: str,
    event_type: str,
    rssi: int,
) -> None:
    if not address:
        return
    summary = summaries.setdefault(
        address,
        {
            "samples": 0,
            "min": rssi,
            "max": rssi,
            "last": rssi,
            "address_type": address_type,
            "address_kind": address_kind,
            "event_type": event_type,
        },
    )
    summary["samples"] += 1
    summary["min"] = min(int(summary["min"]), rssi)
    summary["max"] = max(int(summary["max"]), rssi)
    summary["last"] = rssi
    summary["address_type"] = address_type
    summary["address_kind"] = address_kind
    summary["event_type"] = event_type


def emit_scan_heartbeat(
    cycle: int,
    started: float,
    manufacturer_counts: dict[str, int],
    resolvable_counts: dict[str, int],
    oura_candidate_counts: dict[str, int],
    address_type_counts: dict[str, int],
    address_kind_counts: dict[str, int],
    event_type_counts: dict[str, int],
    manufacturer_rssi: dict[str, dict[str, int]],
    manufacturer_addresses: dict[str, dict[str, Any]],
    address_rssi: dict[str, dict[str, Any]],
    seen_addresses: set[str],
    resolvable_addresses: set[str],
    last_address: str | None,
    last_address_type: str,
    last_address_kind: str,
    last_event_type: str,
    scan_backend: str,
    deadline: float,
) -> None:
    emit(
        "raw_scan_heartbeat",
        {
            "cycle": cycle,
            "manufacturer_counts": manufacturer_counts,
            "manufacturer_sample_count": sum(manufacturer_counts.values()),
            "resolvable_counts": resolvable_counts,
            "oura_candidate_counts": oura_candidate_counts,
            "address_type_counts": address_type_counts,
            "address_kind_counts": address_kind_counts,
            "event_type_counts": event_type_counts,
            "manufacturer_rssi": manufacturer_rssi,
            "manufacturer_addresses": manufacturer_addresses,
            "address_rssi": address_rssi,
            "unique_address_count": len(seen_addresses),
            "resolvable_address_count": len(resolvable_addresses),
            "no_target_classification": (
                "oura_seen_without_target_payload"
                if oura_candidate_counts
                else "no_oura_seen"
            ),
            "physical_state_note": NO_TARGET_PHYSICAL_NOTE,
            "last_address": last_address,
            "last_address_type": last_address_type,
            "last_address_kind": last_address_kind,
            "last_event_type": last_event_type,
            "scan_backend": scan_backend,
            "seconds_remaining": round(max(0.0, deadline - time.monotonic()), 3),
        },
        started,
    )


def is_oura_company(company: str) -> bool:
    normalized = company.lower()
    return "jouzen" in normalized or "oura" in normalized or "(690)" in normalized


def is_oura_name(name: str) -> bool:
    return "oura" in name.lower()


def is_oura_service_line(line: str) -> bool:
    normalized = line.lower()
    return "98ed0001" in normalized or "a541-11e4-b6a0-0002a5d5c51b" in normalized


def is_oura_manufacturer(value: str, company: str) -> bool:
    payload = oura_manufacturer_payload(value)
    return bool(payload) or value in KNOWN_OURA_MANUFACTURERS or is_oura_company(company)


def oura_manufacturer_payload(value: str) -> str | None:
    try:
        data = bytes.fromhex(normalize_hex(value))
    except ValueError:
        return None
    candidates = [data]
    if len(data) >= 2 and data[:2] in {b"\xb2\x02", b"\x02\xb2"}:
        candidates.append(data[2:])
    for candidate in candidates:
        if (
            len(candidate) >= 4
            and candidate[0] == 0x04
            and candidate[2] == 0x1B
            and candidate[3] == 0x01
        ):
            return candidate[:4].hex()
    return None


def record_oura_candidate(
    counts: dict[str, int],
    emitted: set[tuple[str, str, str | None]],
    cycle: int,
    started: float,
    *,
    reason: str,
    address: str | None,
    address_type: str,
    address_kind: str,
    event_type: str,
    company: str,
    name: str,
    manufacturer_hex: str | None,
) -> None:
    key = manufacturer_hex or reason
    counts[key] = counts.get(key, 0) + 1
    emitted_key = (reason, key, address)
    if emitted_key in emitted:
        return
    emitted.add(emitted_key)
    emit(
        "raw_scan_oura_candidate",
        {
            "cycle": cycle,
            "reason": reason,
            "address": address,
            "address_type": address_type,
            "address_kind": address_kind,
            "event_type": event_type,
            "company": company,
            "name": name,
            "manufacturer_hex": manufacturer_hex,
        },
        started,
    )


def start_phase_btmon(
    args: argparse.Namespace, cycle: int, phase: str, started: float
) -> tuple[subprocess.Popen[str], Any, Path]:
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"btmon-raw-{phase}-cycle-{cycle:04d}-{timestamp()}.log"
    handle = path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        btmon_command(args),
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    emit(
        "raw_btmon_start",
        {"cycle": cycle, "phase": phase, "path": str(path), "pid": process.pid},
        started,
    )
    time.sleep(0.05)
    return process, handle, path


def btmon_command(args: argparse.Namespace, *, timestamps: bool | None = None) -> list[str]:
    btmon = "sudo -n btmon"
    use_timestamps = args.btmon_timestamps if timestamps is None else timestamps
    if use_timestamps:
        btmon += " -t"
    return ["script", "-qfec", btmon, "/dev/null"]


def stop_phase_btmon(
    btmon: tuple[subprocess.Popen[str], Any, Path], cycle: int, started: float
) -> None:
    process, handle, path = btmon
    stop_process(process)
    handle.close()
    emit(
        "raw_btmon_stop",
        {"cycle": cycle, "path": str(path), "returncode": process.returncode},
        started,
    )
    security_failure = summarize_setup_security_failure(path)
    if security_failure:
        emit(
            "raw_setup_security_failure",
            {"cycle": cycle, "path": str(path), **security_failure},
            started,
        )


def summarize_setup_security_failure(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return {}

    att_insufficient_encryption = any(
        "Error: Insufficient Encryption (0x0f)" in line for line in lines
    )
    request: dict[str, str] = {}
    in_pairing_request = False
    failure_reason = ""
    failure_reason_code = ""

    for index, line in enumerate(lines):
        if "SMP: Pairing Request" in line:
            in_pairing_request = True
            request = {}
            continue
        if in_pairing_request:
            if "SMP:" in line and "SMP: Pairing Request" not in line:
                in_pairing_request = False
            else:
                field = parse_smp_field(line)
                if field:
                    key, value = field
                    request[key] = value
                continue
        if "SMP: Pairing Failed" not in line:
            continue
        for reason_line in lines[index + 1 : index + 7]:
            match = SMP_REASON_RE.match(reason_line)
            if match:
                failure_reason = match.group(1)
                failure_reason_code = match.group(2).lower()
                break

    if not request or failure_reason_code != "0x08":
        return {}
    return {
        "classification": "setup_pairing_rejected",
        "att_insufficient_encryption": att_insufficient_encryption,
        "smp_pairing_request": request,
        "smp_pairing_failed_reason": failure_reason,
        "smp_pairing_failed_reason_code": failure_reason_code,
    }


def parse_smp_field(line: str) -> tuple[str, str] | None:
    match = SMP_FIELD_RE.match(line)
    if not match:
        return None
    label = match.group(1).strip().lower().replace(" ", "_")
    if label not in SMP_REQUEST_FIELDS:
        return None
    value = match.group(2).strip()
    if match.group(3):
        value = f"{value} ({match.group(3).lower()})"
    return label, value


def raw_connect(
    rpa: str, args: argparse.Namespace, cycle: int, started: float
) -> RawConnectResult:
    plan = raw_connect_plan(args)
    last_result = RawConnectResult(False)
    for index, (attempt, backend) in enumerate(plan, start=1):
        result = raw_connect_once(
            rpa,
            args,
            cycle,
            started,
            backend=backend,
            attempt=attempt,
            sequence=index,
            total=len(plan),
        )
        if result.success:
            return result
        last_result = result
        if index < len(plan):
            next_attempt, next_backend = plan[index]
            delay = max(0.0, getattr(args, "connect_retry_delay_seconds", 0.0))
            emit(
                "raw_connect_retry",
                {
                    "cycle": cycle,
                    "rpa": rpa,
                    "failed_attempt": attempt,
                    "failed_backend": backend,
                    "next_attempt": next_attempt,
                    "next_backend": next_backend,
                    "sequence": index,
                    "total": len(plan),
                    "delay_seconds": delay,
                },
                started,
            )
            time.sleep(delay)
    return last_result


def raw_connect_plan(args: argparse.Namespace) -> list[tuple[int, str]]:
    attempts = max(1, int(getattr(args, "connect_attempts", 1)))
    primary = args.connect_backend
    fallback = getattr(args, "connect_fallback_backend", "")
    backends = [primary]
    if fallback and fallback != primary:
        backends.append(fallback)
    return [
        (attempt, backend)
        for attempt in range(1, attempts + 1)
        for backend in backends
    ]


def raw_connect_once(
    rpa: str,
    args: argparse.Namespace,
    cycle: int,
    started: float,
    *,
    backend: str,
    attempt: int,
    sequence: int,
    total: int,
) -> RawConnectResult:
    emit(
        "raw_connect_start",
        {
            "cycle": cycle,
            "rpa": rpa,
            "backend": backend,
            "attempt": attempt,
            "sequence": sequence,
            "total": total,
        },
        started,
    )
    stop_discovery_before_connect(args, cycle, started)
    time.sleep(max(0.0, args.connect_settle_seconds))
    if backend == "hci-create":
        return raw_connect_hci_create(rpa, args, cycle, started)
    return raw_connect_hcitool_lecc(rpa, args, cycle, started)


def raw_connect_hcitool_lecc(
    rpa: str, args: argparse.Namespace, cycle: int, started: float
) -> RawConnectResult:
    returncode = 1
    stdout = ""
    stderr = ""
    try:
        result = subprocess.run(
            ["sudo", "-n", "hcitool", "lecc", "--random", rpa],
            text=True,
            capture_output=True,
            timeout=args.connect_timeout,
        )
        returncode = result.returncode
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
    except subprocess.TimeoutExpired:
        stderr = f"hcitool lecc timed out after {args.connect_timeout}s"
        emit(
            "raw_connect_timeout",
            {"cycle": cycle, "rpa": rpa, "timeout": args.connect_timeout},
            started,
        )
        cancel_pending_le_connection(args, cycle, started, rpa, "connect_timeout")
    con = subprocess.run(
        ["sudo", "-n", "hcitool", "con"],
        text=True,
        capture_output=True,
    )
    last_con = con.stdout.strip()
    stream_address = connected_stream_address(last_con, rpa, args.identity_address)
    success = stream_address is not None
    emit(
        "raw_connect_done",
        {
            "cycle": cycle,
            "rpa": rpa,
            "returncode": 0 if success else returncode,
            "stdout": (
                connection_summary_for_address(last_con, stream_address)
                if stream_address
                else stdout
            ),
            "stderr": "" if success else stderr,
            "connections_stdout": last_con,
            "connected_address": stream_address,
            "backend": "hcitool-lecc",
        },
        started,
    )
    if not success:
        cancel_pending_le_connection(args, cycle, started, rpa, "connect_failure")
    emit("raw_connections", {"cycle": cycle, "stdout": last_con}, started)
    return RawConnectResult(success, stream_address or (rpa if success else None))


def raw_connect_hci_create(
    rpa: str, args: argparse.Namespace, cycle: int, started: float
) -> RawConnectResult:
    command = build_le_create_connection_command(rpa, args)
    result = run_command(command, timeout=max(4.0, args.hci_command_timeout_seconds + 1))
    emit(
        "raw_connect_create_command",
        {
            "cycle": cycle,
            "rpa": rpa,
            "command": command,
            "result": result,
        },
        started,
    )
    deadline = time.monotonic() + max(0.0, args.connect_timeout)
    last_con = ""
    while time.monotonic() < deadline:
        con = subprocess.run(
            ["sudo", "-n", "hcitool", "con"],
            text=True,
            capture_output=True,
        )
        last_con = con.stdout.strip()
        stream_address = connected_stream_address(last_con, rpa, args.identity_address)
        if stream_address:
            emit(
                "raw_connect_done",
                {
                    "cycle": cycle,
                    "rpa": rpa,
                    "returncode": 0,
                    "stdout": connection_summary_for_address(last_con, stream_address),
                    "stderr": "",
                    "connections_stdout": last_con,
                    "connected_address": stream_address,
                    "backend": "hci-create",
                },
                started,
            )
            return RawConnectResult(True, stream_address)
        time.sleep(0.1)
    emit(
        "raw_connect_done",
        {
            "cycle": cycle,
            "rpa": rpa,
            "returncode": 1,
            "stdout": "",
            "stderr": "LE Create Connection timed out",
            "connections_stdout": last_con,
            "backend": "hci-create",
        },
        started,
    )
    cancel_pending_le_connection(args, cycle, started, rpa, "connect_failure")
    emit("raw_connections", {"cycle": cycle, "stdout": last_con}, started)
    return RawConnectResult(False)


def build_le_create_connection_command(rpa: str, args: argparse.Namespace) -> list[str]:
    payload = [
        *le16(args.le_create_scan_interval),
        *le16(args.le_create_scan_window),
        0x00,  # initiator filter policy: do not use accept list
        0x01,  # peer address type: random
        *bdaddr_to_hci_bytes(rpa),
        le_create_own_address_type(args),
        *le16(getattr(args, "le_create_conn_min_interval", 0x000F)),
        *le16(getattr(args, "le_create_conn_max_interval", 0x000F)),
        *le16(getattr(args, "le_create_conn_latency", 0x0000)),
        *le16(getattr(args, "le_create_supervision_timeout", 0x0C80)),
        *le16(getattr(args, "le_create_min_ce_length", 0x0001)),
        *le16(getattr(args, "le_create_max_ce_length", 0x0001)),
    ]
    return [
        "sudo",
        "-n",
        "timeout",
        str(max(3.0, args.hci_command_timeout_seconds)),
        "hcitool",
        "cmd",
        "0x08",
        "0x000d",
        *(f"{value:02x}" for value in payload),
    ]


def le_create_own_address_type(args: argparse.Namespace) -> int:
    if getattr(args, "le_create_own_address_type", "public") == "random":
        return 0x01
    return 0x00


def connection_summary_for_address(connections_stdout: str, address: str) -> str:
    for line in connections_stdout.splitlines():
        if address.upper() in line.upper():
            return line.strip()
    return connections_stdout


def connected_stream_address(
    connections_stdout: str, rpa: str, identity_address: str
) -> str | None:
    for address in (rpa, identity_address):
        if address and usable_connection_line_for_address(connections_stdout, address):
            return address
    return None


def should_reject_stream_address(
    args: argparse.Namespace, rpa: str, stream_address: str | None
) -> bool:
    return (
        bool(getattr(args, "require_rpa_stream_address", False))
        and getattr(args, "stream_address_source", "identity") == "rpa"
        and bool(stream_address)
        and stream_address.upper() != rpa.upper()
    )


def usable_connection_line_for_address(connections_stdout: str, address: str) -> str:
    for line in connections_stdout.splitlines():
        if address.upper() not in line.upper():
            continue
        match = LE_CONNECTION_RE.search(line)
        if not match:
            continue
        if match.group(3) != "1":
            continue
        return line.strip()
    return ""


def remove_bluez_device(
    address: str, cycle: int, started: float, reason: str
) -> dict[str, Any]:
    if not address:
        return {}
    command = ["timeout", "8", "bluetoothctl", "remove", address]
    result = run_command(command, timeout=10)
    emit(
        "raw_bluez_device_remove",
        {"cycle": cycle, "address": address, "reason": reason, "command": result},
        started,
    )
    return result


def cancel_pending_le_connection(
    args: argparse.Namespace,
    cycle: int,
    started: float,
    rpa: str,
    reason: str,
) -> None:
    timeout_seconds = max(1.0, args.hci_command_timeout_seconds)
    command = [
        "sudo",
        "-n",
        "timeout",
        str(timeout_seconds),
        "hcitool",
        "cmd",
        "0x08",
        "0x000e",
    ]
    emit(
        "raw_connect_cancel",
        {
            "cycle": cycle,
            "rpa": rpa,
            "reason": reason,
            "command": run_command(command, timeout=timeout_seconds + 2),
        },
        started,
    )
    time.sleep(0.25)


def run_after_connect(
    args: argparse.Namespace,
    cycle: int,
    started: float,
    rpa: str | None = None,
) -> int:
    if args.after_connect == "none":
        emit("raw_after_connect_skipped", {"cycle": cycle}, started)
        return 0
    if args.after_connect == "zeroauth-stream":
        return zeroauth_stream(args, cycle, started, rpa)
    return dbus_packet_read(args, cycle, started)


def stop_discovery_before_connect(
    args: argparse.Namespace, cycle: int, started: float
) -> None:
    commands = []
    if args.scan_backend != "hci":
        commands.append(["sudo", "-n", "timeout", "1", "btmgmt", "stop-find"])
    commands.append(
        ["sudo", "-n", "timeout", "3", "hcitool", "cmd", "0x08", "0x000c", "00", "00"]
    )
    rows: list[dict[str, Any]] = []
    for command in commands:
        rows.append(run_command(command, timeout=4))
    emit("raw_scan_disable", {"cycle": cycle, "commands": rows}, started)


def disconnect_identity_connections(
    identity_address: str,
    cycle: int,
    started: float,
    reason: str,
    *,
    emit_empty: bool,
    extra_addresses: list[str | None] | None = None,
) -> None:
    target_addresses = {
        address.upper()
        for address in [identity_address, *(extra_addresses or [])]
        if address
    }
    con = subprocess.run(
        ["sudo", "-n", "hcitool", "con"],
        text=True,
        capture_output=True,
    )
    handles: list[dict[str, Any]] = []
    for match in LE_CONNECTION_RE.finditer(con.stdout):
        address = match.group(1).upper()
        handle = match.group(2)
        if address not in target_addresses:
            continue
        result = subprocess.run(
            ["sudo", "-n", "hcitool", "ledc", handle],
            text=True,
            capture_output=True,
        )
        handles.append(
            {
                "address": address,
                "handle": handle,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        )
    fallbacks: list[dict[str, Any]] = []
    final_con = subprocess.run(
        ["sudo", "-n", "hcitool", "con"],
        text=True,
        capture_output=True,
    )
    for address in sorted(target_addresses):
        if address not in final_con.stdout.upper():
            continue
        fallback_result = subprocess.run(
            ["timeout", "8", "bluetoothctl", "disconnect", address],
            text=True,
            capture_output=True,
        )
        fallbacks.append(
            {
                "command": ["timeout", "8", "bluetoothctl", "disconnect", address],
                "returncode": fallback_result.returncode,
                "stdout": fallback_result.stdout.strip(),
                "stderr": fallback_result.stderr.strip(),
            }
        )
        final_con = subprocess.run(
            ["sudo", "-n", "hcitool", "con"],
            text=True,
            capture_output=True,
        )
    if not emit_empty and not handles and not fallbacks:
        return
    emit(
        "raw_disconnect_identity",
        {
            "cycle": cycle,
            "reason": reason,
            "target_addresses": sorted(target_addresses),
            "connections_stdout": con.stdout.strip(),
            "disconnects": handles,
            "fallbacks": fallbacks,
            "final_connections_stdout": final_con.stdout.strip(),
        },
        started,
    )


def maybe_recover_bluetooth(
    args: argparse.Namespace,
    cycle: int,
    started: float,
    *,
    reason: str,
    count: int,
    threshold: int,
) -> None:
    if threshold <= 0 or count < threshold or count % threshold:
        return
    recover_bluetooth(args, cycle, started, f"{reason}_{count}")


def maybe_emit_physical_toggle_hint(
    args: argparse.Namespace, cycle: int, started: float, consecutive_no_targets: int
) -> None:
    threshold = args.physical_toggle_hint_after_no_targets
    if threshold <= 0 or consecutive_no_targets < threshold:
        return
    if consecutive_no_targets % threshold:
        return
    emit(
        "raw_physical_toggle_hint",
        {
            "cycle": cycle,
            "consecutive_no_targets": consecutive_no_targets,
            "note": NO_TARGET_PHYSICAL_NOTE,
        },
        started,
    )


def recover_bluetooth(
    args: argparse.Namespace, cycle: int, started: float, reason: str
) -> None:
    commands = [
        ["sudo", "-n", "timeout", "2", "btmgmt", "stop-find"],
        [
            "sudo",
            "-n",
            "timeout",
            "2",
            "pkill",
            "-f",
            "^script -qfec sudo -n btmgmt find -l /dev/null$",
        ],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^btmgmt find -l$"],
        [
            "sudo",
            "-n",
            "timeout",
            "2",
            "pkill",
            "-f",
            "^sudo -n btmgmt find -l$",
        ],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^btmgmt power on$"],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^btmgmt bondable on$"],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^btmgmt info$"],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^hcitool cmd "],
        ["sudo", "-n", "timeout", "3", "hcitool", "cmd", "0x08", "0x000c", "00", "00"],
        ["sudo", "-n", "timeout", "15", "systemctl", "restart", "bluetooth"],
        ["sudo", "-n", "timeout", "3", "hciconfig", "hci0", "up"],
        ["sudo", "-n", "timeout", "4", "btmgmt", "power", "on"],
        ["sudo", "-n", "timeout", "4", "btmgmt", "bondable", "on"],
        ["sudo", "-n", "timeout", "4", "btmgmt", "info"],
    ]
    rows: list[dict[str, Any]] = []
    for command in commands:
        rows.append(run_command(command, timeout=17))
    emit(
        "raw_bluetooth_recovery",
        {"cycle": cycle, "reason": reason, "commands": rows},
        started,
    )
    time.sleep(max(0.0, args.reset_sleep_seconds))


def stop_stale_btmgmt_find(cycle: int, started: float, reason: str) -> None:
    commands = [
        [
            "sudo",
            "-n",
            "timeout",
            "2",
            "pkill",
            "-f",
            "^script -qfec sudo -n btmgmt find -l /dev/null$",
        ],
        ["sudo", "-n", "timeout", "2", "pkill", "-f", "^btmgmt find -l$"],
        [
            "sudo",
            "-n",
            "timeout",
            "2",
            "pkill",
            "-f",
            "^sudo -n btmgmt find -l$",
        ],
    ]
    rows = [run_command(command, timeout=4) for command in commands]
    emit(
        "raw_btmgmt_find_cleanup",
        {"cycle": cycle, "reason": reason, "commands": rows},
        started,
    )


def enable_hci_le_scan(
    args: argparse.Namespace, cycle: int, started: float, reason: str
) -> bool:
    timeout_seconds = max(1.0, args.hci_command_timeout_seconds)
    shell_timeout = str(timeout_seconds)
    commands = [
        [
            "sudo",
            "-n",
            "timeout",
            shell_timeout,
            "hcitool",
            "cmd",
            "0x08",
            "0x000c",
            "00",
            "00",
        ],
        [
            "sudo",
            "-n",
            "timeout",
            shell_timeout,
            "hcitool",
            "cmd",
            "0x08",
            "0x000b",
            "01",
            "10",
            "00",
            "10",
            "00",
            "00",
            "00",
        ],
        [
            "sudo",
            "-n",
            "timeout",
            shell_timeout,
            "hcitool",
            "cmd",
            "0x08",
            "0x000c",
            "01",
            "00",
        ],
    ]
    rows = [
        run_command(command, timeout=timeout_seconds + 2)
        for command in commands
    ]
    emit(
        "raw_hci_scan_enable",
        {"cycle": cycle, "reason": reason, "commands": rows},
        started,
    )
    return (
        hci_command_succeeded(rows[0], allow_command_disallowed=True)
        and hci_command_succeeded(rows[1])
        and hci_command_succeeded(rows[2])
    )


def hci_command_succeeded(
    row: dict[str, Any], *, allow_command_disallowed: bool = False
) -> bool:
    if row.get("returncode") != 0:
        return False
    status_code = hci_status_code(row)
    if status_code is None or status_code == "0x00":
        return True
    return allow_command_disallowed and status_code == "0x0c"


def hci_status_code(row: dict[str, Any]) -> str | None:
    text = f"{row.get('stdout', '')}\n{row.get('stderr', '')}"
    match = HCI_STATUS_RE.search(text)
    if match:
        return match.group(1).lower()
    event_bytes: list[int] | None = None
    for line in text.splitlines():
        hex_match = HCI_EVENT_HEX_RE.match(line)
        if not hex_match:
            continue
        values = [int(value, 16) for value in hex_match.group(1).split()]
        if len(values) >= 4 and values[0] == 0x01:
            event_bytes = values
    if event_bytes is None:
        return None
    return f"0x{event_bytes[3]:02x}"


def disable_hci_le_scan(
    args: argparse.Namespace, cycle: int, started: float, reason: str
) -> None:
    timeout_seconds = max(1.0, args.hci_command_timeout_seconds)
    command = [
        "sudo",
        "-n",
        "timeout",
        str(timeout_seconds),
        "hcitool",
        "cmd",
        "0x08",
        "0x000c",
        "00",
        "00",
    ]
    emit(
        "raw_hci_scan_disable",
        {
            "cycle": cycle,
            "reason": reason,
            "command": run_command(command, timeout=timeout_seconds + 2),
        },
        started,
    )


def btmgmt_find_command() -> list[str]:
    return ["script", "-qfec", "sudo -n btmgmt find -l", "/dev/null"]


def btmgmt_find_started(path: Path) -> bool:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "Discovery started" in raw or "discovering on" in raw


def adapter_discovering() -> dict[str, Any]:
    row = run_command(["bluetoothctl", "show"], timeout=4)
    raw = str(row.get("stdout", ""))
    if "Discovering: yes" in raw:
        return {"discovering": True, "raw": "Discovering: yes"}
    if "Discovering: no" in raw:
        return {"discovering": False, "raw": "Discovering: no"}
    return {"discovering": None, "raw": raw[-240:]}


def dbus_packet_read(args: argparse.Namespace, cycle: int, started: float) -> int:
    script = Path(__file__).with_name("pi-bluez-dbus-packet-read.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = "src" + os.pathsep + env.get("PYTHONPATH", "")
    command = [
        "/usr/bin/python3",
        str(script),
        "--address",
        args.identity_address,
        "--response-timeout",
        str(args.response_timeout),
    ]
    emit("raw_dbus_read_start", {"cycle": cycle, "command": command}, started)
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=args.read_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        emit(
            "raw_dbus_read_timeout",
            {"cycle": cycle, "timeout": args.read_timeout},
            started,
        )
        return 124
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            emit("raw_dbus_stdout", {"cycle": cycle, "line": line}, started)
            continue
        row["raw_cycle"] = cycle
        print(json.dumps(row, sort_keys=True), flush=True)
    if result.stderr.strip():
        emit("raw_dbus_stderr", {"cycle": cycle, "stderr": result.stderr.strip()}, started)
    emit("raw_dbus_read_done", {"cycle": cycle, "returncode": result.returncode}, started)
    return result.returncode


def zeroauth_stream(
    args: argparse.Namespace, cycle: int, started: float, rpa: str | None = None
) -> int:
    script = Path(__file__).with_name("pi-bluez-zeroauth-stream.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = "src" + os.pathsep + env.get("PYTHONPATH", "")
    stream_address = zeroauth_stream_address(args, rpa)
    command = build_zeroauth_stream_command(args, script, rpa)
    timeout = zeroauth_stream_timeout(args)
    agent_process: subprocess.Popen[str] | None = None
    emit(
        "raw_zeroauth_stream_start",
        {
            "cycle": cycle,
            "command": command,
            "stream_address": stream_address,
            "stream_address_source": args.stream_address_source,
            "stream_services_timeout": args.stream_services_timeout,
            "timeout": timeout,
        },
        started,
    )
    try:
        if args.stream_auto_confirm_agent:
            agent_process = start_stream_agent(args, cycle, started)
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        emit(
            "raw_zeroauth_stream_timeout",
            {
                "cycle": cycle,
                "timeout": timeout,
                "stream_services_timeout": args.stream_services_timeout,
            },
            started,
        )
        return 124
    finally:
        if agent_process is not None:
            stop_stream_agent(agent_process, cycle, started)
    status = ZeroAuthStreamStatus(0, 0, 0, 0)
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            emit("raw_zeroauth_stdout", {"cycle": cycle, "line": line}, started)
            continue
        status = update_zeroauth_stream_status(status, row)
        row["raw_cycle"] = cycle
        print(json.dumps(row, sort_keys=True), flush=True)
    if result.stderr.strip():
        emit(
            "raw_zeroauth_stderr",
            {"cycle": cycle, "stderr": result.stderr.strip()},
            started,
        )
    emit(
        "raw_zeroauth_stream_done",
        {
            "cycle": cycle,
            "returncode": result.returncode,
            "read_results": status.read_results,
            "usable_read_results": status.usable_read_results,
            "probe_errors": status.probe_errors,
            "probe_stops": status.probe_stops,
        },
        started,
    )
    if result.returncode == 0 and status.usable_read_results == 0:
        emit(
            "raw_zeroauth_stream_unusable",
            {
                "cycle": cycle,
                "read_results": status.read_results,
                "probe_errors": status.probe_errors,
                "probe_stops": status.probe_stops,
                "reason": "no usable read_result payload",
            },
            started,
        )
        return 2
    return result.returncode


def zeroauth_stream_timeout(args: argparse.Namespace) -> float:
    stream_duration = (
        0.0
        if getattr(args, "stream_exit_after_probes", False)
        else args.stream_duration
    )
    return args.stream_services_timeout + args.read_timeout + stream_duration + 5


def zeroauth_stream_address(args: argparse.Namespace, rpa: str | None = None) -> str:
    if getattr(args, "stream_address_source", "identity") == "rpa" and rpa:
        return rpa
    return args.identity_address


def build_zeroauth_stream_command(
    args: argparse.Namespace, script: Path, rpa: str | None = None
) -> list[str]:
    stream_address = zeroauth_stream_address(args, rpa)
    command = [
        "/usr/bin/python3",
        str(script),
        "--address",
        stream_address,
        "--duration",
        str(args.stream_duration),
        "--wait-services-timeout",
        str(args.stream_services_timeout),
        "--probes",
        args.stream_probes,
        "--probe-delay-seconds",
        str(args.stream_probe_delay_seconds),
        "--probe-response-timeout",
        str(args.response_timeout),
    ]
    if args.stream_connect:
        command.append("--connect")
    if args.stream_all_notify_chars:
        command.append("--all-notify-chars")
    if getattr(args, "stream_exit_after_probes", False):
        command.append("--exit-after-probes")
    if getattr(args, "stream_strict_address", False):
        command.append("--strict-address")
    if getattr(args, "stream_pair", False):
        command.append("--pair")
        command.extend(["--pair-timeout", str(args.stream_pair_timeout)])
    return command


def start_stream_agent(
    args: argparse.Namespace, cycle: int, started: float
) -> subprocess.Popen[str]:
    script = Path(__file__).with_name("pi-bluez-auto-agent.py")
    command = [
        "/usr/bin/python3",
        str(script),
        "--capability",
        args.stream_agent_capability,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    emit(
        "raw_stream_agent_start",
        {"cycle": cycle, "pid": process.pid, "command": command},
        started,
    )
    wait_for_stream_agent_ready(process, cycle, started)
    if process.stdout is not None:
        thread = threading.Thread(
            target=forward_stream_agent_output,
            args=(process, cycle),
            daemon=True,
        )
        thread.start()
    return process


def wait_for_stream_agent_ready(
    process: subprocess.Popen[str], cycle: int, started: float
) -> None:
    ready = False
    deadline = time.monotonic() + 2.0
    assert process.stdout is not None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            emit(
                "raw_stream_agent_exit",
                {"cycle": cycle, "pid": process.pid, "returncode": process.returncode},
                started,
            )
            return
        ready_streams, _, _ = select.select([process.stdout], [], [], 0.1)
        if not ready_streams:
            continue
        line = process.stdout.readline()
        if not line:
            continue
        forward_stream_agent_line(line, cycle)
        if '"event": "agent_ready"' in line or '"event":"agent_ready"' in line:
            ready = True
            break
    emit(
        "raw_stream_agent_ready",
        {"cycle": cycle, "pid": process.pid, "ready": ready},
        started,
    )


def forward_stream_agent_output(process: subprocess.Popen[str], cycle: int) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        forward_stream_agent_line(line, cycle)


def forward_stream_agent_line(line: str, cycle: int) -> None:
    text = line.rstrip("\n")
    if not text:
        return
    try:
        row = json.loads(text)
    except json.JSONDecodeError:
        print(
            json.dumps(
                {
                    "event": "raw_stream_agent_stdout",
                    "payload": {"cycle": cycle, "line": text},
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return
    row["raw_cycle"] = cycle
    print(json.dumps(row, sort_keys=True), flush=True)


def stop_stream_agent(
    process: subprocess.Popen[str], cycle: int, started: float
) -> None:
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    emit(
        "raw_stream_agent_stop",
        {"cycle": cycle, "pid": process.pid, "returncode": process.returncode},
        started,
    )


def update_zeroauth_stream_status(
    status: ZeroAuthStreamStatus, row: dict[str, Any]
) -> ZeroAuthStreamStatus:
    event = row.get("event")
    read_results = status.read_results
    usable_read_results = status.usable_read_results
    probe_errors = status.probe_errors
    probe_stops = status.probe_stops
    if event == "read_result":
        read_results += 1
        if is_usable_read_result(row.get("payload")):
            usable_read_results += 1
    elif event == "zeroauth_probe_error":
        probe_errors += 1
    elif event == "zeroauth_probe_stop":
        probe_stops += 1
    return ZeroAuthStreamStatus(
        read_results=read_results,
        usable_read_results=usable_read_results,
        probe_errors=probe_errors,
        probe_stops=probe_stops,
    )


def is_usable_read_result(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("firmware"), dict):
        return True
    if isinstance(payload.get("auth_nonce"), dict):
        return True
    if isinstance(payload.get("battery"), dict):
        return True
    if isinstance(payload.get("factory_reset"), dict):
        return True
    for key in ("product_info", "capabilities", "feature_status"):
        value = payload.get(key)
        if isinstance(value, dict) and bool(value):
            return True
    event_summary = payload.get("event_summary")
    if isinstance(event_summary, dict) and int(event_summary.get("count") or 0) > 0:
        return True
    for key in ("events", "events_done", "feature_set_results", "ring_mode_results"):
        value = payload.get(key)
        if isinstance(value, list) and bool(value):
            return True
    memory = payload.get("product_info_memory")
    return isinstance(memory, dict) and int(memory.get("byte_count") or 0) > 0


def stop_process(
    process: subprocess.Popen[Any], *, terminate_timeout: float = 2.0
) -> None:
    if process.poll() is not None:
        return
    signal_process(process, signal.SIGTERM)
    try:
        process.wait(timeout=max(0.0, terminate_timeout))
    except subprocess.TimeoutExpired:
        signal_process(process, signal.SIGKILL)
        process.wait()


def signal_process(process: subprocess.Popen[Any], sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):
        if os.getpgid(process.pid) == process.pid:
            os.killpg(process.pid, sig)
            return
    with contextlib.suppress(ProcessLookupError):
        process.send_signal(sig)


def run_command(
    command: list[str],
    *,
    timeout: float,
    stdout: Any = subprocess.PIPE,
    stderr: Any = subprocess.PIPE,
) -> dict[str, Any]:
    stdout_data: str | None = None
    stderr_data: str | None = None
    process = subprocess.Popen(
        command,
        text=True,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    try:
        stdout_data, stderr_data = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        signal_process(process, signal.SIGTERM)
        try:
            stdout_data, stderr_data = process.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            signal_process(process, signal.SIGKILL)
            stdout_data, stderr_data = process.communicate()
        row: dict[str, Any] = {"command": command, "timeout": True}
        if stdout == subprocess.PIPE and stdout_data is not None:
            row["stdout"] = stdout_data.strip()
        if stderr == subprocess.PIPE and stderr_data is not None:
            row["stderr"] = stderr_data.strip()
        return row
    row: dict[str, Any] = {"command": command, "returncode": process.returncode}
    if stdout == subprocess.PIPE:
        row["stdout"] = (stdout_data or "").strip()
    if stderr == subprocess.PIPE:
        row["stderr"] = (stderr_data or "").strip()
    return row


def parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError(f"integer out of uint16 range: {value}")
    return parsed


def le16(value: int) -> list[int]:
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"value out of uint16 range: {value}")
    return [value & 0xFF, (value >> 8) & 0xFF]


def bdaddr_to_hci_bytes(address: str) -> list[int]:
    parts = address.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid Bluetooth address: {address}")
    try:
        return [int(part, 16) for part in reversed(parts)]
    except ValueError as exc:
        raise ValueError(f"invalid Bluetooth address: {address}") from exc


def normalize_hex(value: str) -> str:
    compact = value.lower().strip()
    if compact.startswith("0x"):
        compact = compact[2:]
    return "".join(ch for ch in compact if ch in "0123456789abcdef")


def parse_hex_list(value: str) -> set[str]:
    values = {normalize_hex(part) for part in value.split(",") if part.strip()}
    if not values:
        raise SystemExit("at least one manufacturer payload is required")
    invalid = sorted(item for item in values if len(item) % 2)
    if invalid:
        raise SystemExit(f"manufacturer payload has odd hex length: {', '.join(invalid)}")
    return values


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def emit(event: str, payload: dict[str, Any], started: float) -> None:
    print(
        json.dumps(
            {
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "event": event,
                "payload": payload,
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    sys.exit(main())
