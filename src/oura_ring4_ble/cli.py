"""Command-line interface for the Oura Ring 4 BLE probe."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from bleak.exc import BleakError

from .client import (
    OuraBleError,
    OuraRingClient,
    find_device,
    find_oura_device,
    inspect_device,
    probe_devices,
    scan_devices,
)
from .permissions import PermissionFixError, fix_macos_bluetooth_permissions
from .protocol import (
    ProtocolError,
    build_factory_reset_request,
    build_get_battery_request,
    build_get_events_request,
    build_get_firmware_request,
    build_sync_time_request,
    bytes_from_user,
    key_fingerprint,
    packet_from_hex,
    parse_key,
    parse_packets,
    parse_response,
)


def parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError(f"integer out of uint16 range: {value}")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return asyncio.run(command_scan(args))
        if args.command == "probe":
            return asyncio.run(command_probe(args))
        if args.command == "inspect":
            return asyncio.run(command_inspect(args))
        if args.command == "read":
            return asyncio.run(command_read(args))
        if args.command == "pi-auth-read":
            return command_pi_auth_read(args)
        if args.command == "pi-zeroauth-read":
            return command_pi_zeroauth_read(args)
        if args.command == "pi-gatt-probe":
            return command_pi_gatt_probe(args)
        if args.command == "pi-watch":
            return command_pi_watch(args)
        if args.command == "pi-watch-summary":
            return command_pi_watch_summary(args)
        if args.command == "pi-rpa-read":
            return command_pi_rpa_read(args)
        if args.command == "pi-smp-probe":
            return command_pi_smp_probe(args)
        if args.command == "read-native":
            return command_read_native(args)
        if args.command == "listen-native":
            return command_listen_native(args)
        if args.command == "decode":
            return command_decode(args)
        if args.command == "decode-events":
            return command_decode_events(args)
        if args.command == "build-packet":
            return command_build_packet(args)
        if args.command == "fix-permissions":
            return command_fix_permissions(args)
    except (
        OuraBleError,
        ProtocolError,
        BleakError,
        PermissionFixError,
        TimeoutError,
    ) as exc:
        message = str(exc) or type(exc).__name__
        print(f"error: {message}", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oura-ring4-ble",
        description="Scan and read an Oura Ring 4 over its observed BLE protocol.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan for nearby BLE devices")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument(
        "--only-oura", action="store_true", help="show only Oura-like adverts"
    )
    scan.add_argument("--json", action="store_true", help="emit JSON instead of text")

    probe = subparsers.add_parser(
        "probe",
        help="scan and try GATT discovery on likely Oura candidates",
    )
    probe.add_argument("--timeout", type=float, default=15.0)
    probe.add_argument("--connect-timeout", type=float, default=6.0)
    probe.add_argument("--limit", type=int, default=12)

    inspect = subparsers.add_parser("inspect", help="connect and list GATT services")
    add_device_args(inspect)
    inspect.add_argument("--timeout", type=float, default=15.0)

    read = subparsers.add_parser("read", help="read safe Oura packets and print JSON")
    add_device_args(read)
    read.add_argument("--timeout", type=float, default=15.0)
    read.add_argument("--scan-timeout", type=float, default=12.0)
    read.add_argument("--connect-timeout", type=float, default=15.0)
    read.add_argument(
        "--pair",
        action="store_true",
        help="pair/trust through BlueZ before connecting on Linux",
    )
    read.add_argument(
        "--attempts",
        type=int,
        default=3,
        help="connection attempts within the timeout budget",
    )
    read.add_argument("--auth-key", help="16-byte Oura ring auth key as hex/base64")
    read.add_argument(
        "--events",
        action="store_true",
        help="authenticate if a key is available, then retrieve raw event packets",
    )
    read.add_argument(
        "--event-start", type=int, default=0, help="device boot timestamp start"
    )
    read.add_argument("--max-events", type=int, default=255)
    read.add_argument(
        "--sync-time",
        action="store_true",
        help="send a current-time packet before event retrieval",
    )
    read.add_argument("--verbose", action="store_true", help="print tx/rx hex lines")

    pi_auth = subparsers.add_parser(
        "pi-auth-read",
        help="run the Linux/BlueZ auth reader and print the latest read_result",
    )
    pi_auth.add_argument("--address", default="", help="preferred ring address")
    pi_auth.add_argument("--device-path", default="", help="preferred BlueZ Device1 path")
    pi_auth.add_argument("--state-path", default="state/ring-auth-key.json")
    pi_auth.add_argument("--log-dir", default="logs")
    pi_auth.add_argument("--scan-seconds", type=float, default=60.0)
    pi_auth.add_argument("--pair-timeout", type=float, default=45.0)
    pi_auth.add_argument("--connect-timeout", type=float, default=22.0)
    pi_auth.add_argument("--response-timeout", type=float, default=6.0)
    pi_auth.add_argument("--settle-seconds", type=float, default=1.0)
    pi_auth.add_argument("--agent-capability", default="NoInputNoOutput")
    pi_auth.add_argument("--restart-bluetooth-first", action="store_true", default=True)
    pi_auth.add_argument(
        "--no-restart-bluetooth-first",
        dest="restart_bluetooth_first",
        action="store_false",
    )
    pi_auth.add_argument("--clear-stale", action="store_true", default=True)
    pi_auth.add_argument("--no-clear-stale", dest="clear_stale", action="store_false")
    pi_auth.add_argument("--force-new-key", action="store_true")
    pi_auth.add_argument("--live-hr-seconds", type=float, default=75.0)
    pi_auth.add_argument("--meditation-hr-probe", action="store_true", default=True)
    pi_auth.add_argument(
        "--no-meditation-hr-probe",
        dest="meditation_hr_probe",
        action="store_false",
    )
    pi_auth.add_argument("--meditation-duration-minutes", type=int, default=1)
    pi_auth.add_argument("--meditation-listen-seconds", type=float, default=90.0)
    pi_auth.add_argument("--session-cleanup", action="store_true", default=True)
    pi_auth.add_argument(
        "--no-session-cleanup", dest="session_cleanup", action="store_false"
    )
    pi_auth.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    pi_zeroauth = subparsers.add_parser(
        "pi-zeroauth-read",
        help="run the Linux/BlueZ zero-auth stream and print the latest read_result",
    )
    pi_zeroauth.add_argument("--address", default="", help="preferred ring address")
    pi_zeroauth.add_argument(
        "--device-path", default="", help="preferred BlueZ Device1 path"
    )
    pi_zeroauth.add_argument("--log-dir", default="logs")
    pi_zeroauth.add_argument("--duration", type=float, default=25.0)
    pi_zeroauth.add_argument("--wait-services-timeout", type=float, default=16.0)
    pi_zeroauth.add_argument(
        "--probes",
        default="firmware,battery,auth_nonce,live_hr_probe",
        help="comma-separated probe list for pi-bluez-zeroauth-stream.py",
    )
    pi_zeroauth.add_argument("--probe-response-timeout", type=float, default=3.0)
    pi_zeroauth.add_argument("--probe-delay-seconds", type=float, default=0.4)
    pi_zeroauth.add_argument("--connect", action="store_true", default=True)
    pi_zeroauth.add_argument("--no-connect", dest="connect", action="store_false")
    pi_zeroauth.add_argument("--pair", action="store_true")
    pi_zeroauth.add_argument("--auto-confirm-agent", action="store_true")
    pi_zeroauth.add_argument("--all-notify-chars", action="store_true")
    pi_zeroauth.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    pi_gatt = subparsers.add_parser(
        "pi-gatt-probe",
        help="run Linux/BlueZ GATT discovery, packet, or matrix diagnostics",
    )
    pi_gatt.add_argument("--log-dir", default="logs")
    pi_gatt.add_argument("--scan-seconds", type=float, default=60.0)
    pi_gatt.add_argument("--connect-timeout", type=float, default=12.0)
    pi_gatt.add_argument("--connect-limit", type=int, default=1)
    pi_gatt.add_argument("--summary-limit", type=int, default=12)
    pi_gatt.add_argument("--non-oura-connect-limit", type=int, default=0)
    pi_gatt.add_argument("--address", action="append", default=[])
    pi_gatt.add_argument("--matrix-probe", action="store_true")
    pi_gatt.add_argument("--matrix-only", action="store_true")
    pi_gatt.add_argument("--packet-read-only", action="store_true")
    pi_gatt.add_argument("--restart-bluetooth-first", action="store_true", default=True)
    pi_gatt.add_argument(
        "--no-restart-bluetooth-first",
        dest="restart_bluetooth_first",
        action="store_false",
    )
    pi_gatt.add_argument("--clear-stale", action="store_true", default=True)
    pi_gatt.add_argument("--no-clear-stale", dest="clear_stale", action="store_false")
    pi_gatt.add_argument("--skip-standard-reads", action="store_true")
    pi_gatt.add_argument("--matrix-response-timeout", type=float, default=3.0)
    pi_gatt.add_argument("--matrix-read-timeout", type=float, default=1.0)
    pi_gatt.add_argument("--matrix-pre-read", action="store_true")
    pi_gatt.add_argument("--matrix-post-read", action="store_true")
    pi_gatt.add_argument("--matrix-skip-uuid", action="append", default=[])
    pi_gatt.add_argument("--scan-heartbeat-seconds", type=float, default=0.0)
    pi_gatt.add_argument("--connect-on-first-oura", action="store_true")
    pi_gatt.add_argument("--pair", action="store_true")
    pi_gatt.add_argument("--require-manufacturer-hex", action="append", default=[])
    pi_gatt.add_argument("--connectable-hint-only", action="store_true")
    pi_gatt.add_argument("--power-off-after", action="store_true", default=True)
    pi_gatt.add_argument(
        "--no-power-off-after",
        dest="power_off_after",
        action="store_false",
    )
    pi_gatt.add_argument("--passive-scan", action="store_true", default=True)
    pi_gatt.add_argument("--active-scan", dest="passive_scan", action="store_false")
    pi_gatt.add_argument("--no-device-summary", action="store_true")
    pi_gatt.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    pi_watch = subparsers.add_parser(
        "pi-watch",
        help="repeat low-power Linux/BlueZ watch cycles until a read_result appears",
    )
    pi_watch.add_argument("--log-dir", default="logs")
    pi_watch.add_argument("--cycle-scan-seconds", type=float, default=300.0)
    pi_watch.add_argument("--connect-timeout", type=float, default=8.0)
    pi_watch.add_argument("--connect-limit", type=int, default=1)
    pi_watch.add_argument("--summary-limit", type=int, default=5)
    pi_watch.add_argument("--scan-heartbeat-seconds", type=float, default=60.0)
    pi_watch.add_argument("--delay-seconds", type=float, default=2.0)
    pi_watch.add_argument("--cycles", type=int, default=0)
    pi_watch.add_argument("--require-manufacturer-hex", action="append", default=[])
    pi_watch.add_argument("--packet-read-only", action="store_true", default=True)
    pi_watch.add_argument(
        "--no-packet-read-only",
        dest="packet_read_only",
        action="store_false",
    )
    pi_watch.add_argument("--connectable-hint-only", action="store_true", default=True)
    pi_watch.add_argument(
        "--allow-presence-connects",
        dest="connectable_hint_only",
        action="store_false",
    )
    pi_watch.add_argument("--skip-standard-reads", action="store_true", default=True)
    pi_watch.add_argument(
        "--with-standard-reads",
        dest="skip_standard_reads",
        action="store_false",
    )
    pi_watch.add_argument("--power-off-after", action="store_true", default=True)
    pi_watch.add_argument(
        "--no-power-off-after",
        dest="power_off_after",
        action="store_false",
    )
    pi_watch.add_argument("--passive-scan", action="store_true", default=True)
    pi_watch.add_argument("--active-scan", dest="passive_scan", action="store_false")
    pi_watch.add_argument("--matrix-response-timeout", type=float, default=1.5)
    pi_watch.add_argument("--matrix-read-timeout", type=float, default=1.0)
    pi_watch.add_argument("--matrix-pre-read", action="store_true")
    pi_watch.add_argument("--matrix-post-read", action="store_true")
    pi_watch.add_argument("--matrix-only", dest="packet_read_only", action="store_false")
    pi_watch.add_argument("--no-matrix-only", action="store_true")
    pi_watch.set_defaults(no_matrix_only=False)
    pi_watch.add_argument("--pair", action="store_true")
    pi_watch.add_argument("--agent", action="store_true")
    pi_watch.add_argument("--agent-capability", default="KeyboardDisplay")
    pi_watch.add_argument("--btmon", action="store_true")
    pi_watch.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    pi_watch_summary = subparsers.add_parser(
        "pi-watch-summary",
        help="summarize Linux watcher JSONL logs and current pointer files",
    )
    pi_watch_summary.add_argument("logs", nargs="*", help="watch JSONL log paths")
    pi_watch_summary.add_argument("--log-dir", default="logs")
    pi_watch_summary.add_argument(
        "--pointer",
        action="append",
        default=[],
        help="pointer file containing a watch JSONL path; may be repeated",
    )
    pi_watch_summary.add_argument(
        "--json", action="store_true", help="emit JSON instead of text"
    )
    pi_watch_summary.add_argument(
        "--follow",
        action="store_true",
        help="refresh summaries until interrupted or --max-refreshes is reached",
    )
    pi_watch_summary.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="seconds between --follow refreshes",
    )
    pi_watch_summary.add_argument(
        "--max-refreshes",
        type=int,
        default=0,
        help="maximum --follow refreshes; 0 means unlimited",
    )
    pi_watch_summary.add_argument(
        "--until-read-result",
        action="store_true",
        help="in --follow mode, exit 0 as soon as any summary has a usable read_result",
    )

    pi_rpa = subparsers.add_parser(
        "pi-rpa-read",
        help="scan the current Oura RPA, raw-connect, and print read_result",
    )
    pi_rpa.add_argument("--log-dir", default="logs")
    pi_rpa.add_argument("--identity-address", default="")
    pi_rpa.add_argument("--manufacturer-hex", default="")
    pi_rpa.add_argument("--scan-seconds", type=float, default=90.0)
    pi_rpa.add_argument("--scan-heartbeat-seconds", type=float, default=10.0)
    pi_rpa.add_argument("--silent-scan-timeout-seconds", type=float, default=0.0)
    pi_rpa.add_argument("--connect-timeout", type=float, default=14.0)
    pi_rpa.add_argument("--connect-attempts", type=int, default=1)
    pi_rpa.add_argument(
        "--connect-fallback-backend",
        choices=("", "hci-create", "hcitool-lecc"),
        default="",
    )
    pi_rpa.add_argument("--connect-retry-delay-seconds", type=float, default=0.15)
    pi_rpa.add_argument(
        "--le-create-own-address-type",
        choices=("public", "random"),
        default="public",
    )
    pi_rpa.add_argument("--le-create-scan-interval", type=parse_int, default=0x0010)
    pi_rpa.add_argument("--le-create-scan-window", type=parse_int, default=0x0010)
    pi_rpa.add_argument("--le-create-conn-min-interval", type=parse_int, default=0x000F)
    pi_rpa.add_argument("--le-create-conn-max-interval", type=parse_int, default=0x000F)
    pi_rpa.add_argument("--le-create-conn-latency", type=parse_int, default=0x0000)
    pi_rpa.add_argument(
        "--le-create-supervision-timeout",
        type=parse_int,
        default=0x0C80,
    )
    pi_rpa.add_argument("--le-create-min-ce-length", type=parse_int, default=0x0001)
    pi_rpa.add_argument("--le-create-max-ce-length", type=parse_int, default=0x0001)
    pi_rpa.add_argument("--read-timeout", type=float, default=35.0)
    pi_rpa.add_argument("--response-timeout", type=float, default=3.0)
    pi_rpa.add_argument("--stream-duration", type=float, default=28.0)
    pi_rpa.add_argument("--stream-services-timeout", type=float, default=16.0)
    pi_rpa.add_argument(
        "--stream-probes",
        default="firmware,battery,auth_nonce,live_hr_probe",
    )
    pi_rpa.add_argument("--stream-probe-delay-seconds", type=float, default=0.4)
    pi_rpa.add_argument(
        "--stream-connect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="let zeroauth-stream call Device1.Connect after raw HCI connect",
    )
    pi_rpa.add_argument("--stream-all-notify-chars", action="store_true")
    pi_rpa.add_argument(
        "--stream-strict-address",
        action="store_true",
        help="require the zeroauth stream to use the selected RPA",
    )
    pi_rpa.add_argument(
        "--stream-auto-confirm-agent",
        action="store_true",
        help="register a temporary BlueZ pairing agent during zeroauth stream",
    )
    pi_rpa.add_argument(
        "--stream-agent-capability",
        default="DisplayYesNo",
        help="BlueZ pairing agent capability for zeroauth stream",
    )
    pi_rpa.add_argument(
        "--stream-pair",
        action="store_true",
        help="call Device1.Pair before zeroauth stream subscriptions",
    )
    pi_rpa.add_argument("--stream-pair-timeout", type=float, default=45.0)
    pi_rpa.add_argument("--cycles", type=int, default=1)
    pi_rpa.add_argument("--fresh-bluez-cache", action="store_true", default=True)
    pi_rpa.add_argument(
        "--no-fresh-bluez-cache", dest="fresh_bluez_cache", action="store_false"
    )
    pi_rpa.add_argument(
        "--stream-address-source", choices=["identity", "rpa"], default="rpa"
    )
    pi_rpa.add_argument("--require-rpa-stream-address", action="store_true", default=True)
    pi_rpa.add_argument(
        "--no-require-rpa-stream-address",
        dest="require_rpa_stream_address",
        action="store_false",
    )
    pi_rpa.add_argument("--reset-bluetooth-after-no-targets", type=int, default=1)
    pi_rpa.add_argument(
        "--reset-bluetooth-after-connect-failures", type=int, default=1
    )
    pi_rpa.add_argument(
        "--btmon-timestamps",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run btmon with timestamps; disable on BlueZ builds where btmon -t crashes",
    )
    pi_rpa.add_argument(
        "--verify-btmgmt-discovering",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "verify btmgmt find via bluetoothctl Discovering; disable on controllers "
            "where btmgmt scans but bluetoothctl reports Discovering: no"
        ),
    )
    pi_rpa.add_argument(
        "--scan-backend",
        choices=("auto", "btmgmt", "hci"),
        default="auto",
        help=(
            "raw advertisement scan backend; use hci on hosts where btmgmt "
            "discovery is stale or reports Discovering: no while btmon still sees traffic"
        ),
    )
    pi_rpa.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    pi_smp = subparsers.add_parser(
        "pi-smp-probe",
        help="run raw setup-state SMP pairing probes on Linux/BlueZ",
    )
    pi_smp.add_argument("--log-dir", default="logs")
    pi_smp.add_argument("--scan-seconds", type=float, default=25.0)
    pi_smp.add_argument("--connect-timeout", type=float, default=5.0)
    pi_smp.add_argument("--listen-seconds", type=float, default=1.5)
    pi_smp.add_argument("--pre-smp-delay-seconds", type=float, default=0.0)
    pi_smp.add_argument("--hci-index", type=int, default=0)
    pi_smp.add_argument("--manufacturer-hex", default="")
    pi_smp.add_argument(
        "--own-address-type",
        choices=["public", "random"],
        default="public",
    )
    pi_smp.add_argument("--random-address", default="")
    pi_smp.add_argument(
        "--variants",
        default=(
            "display_yesno_bond_sc_mitm_ct2_keys,"
            "display_only_bond_sc_mitm_ct2_keys,"
            "keyboard_only_bond_sc_mitm_ct2_keys,"
            "keyboard_display_bond_sc_mitm_ct2_keys,"
            "no_input_output_bond_sc_mitm_ct2_keys"
        ),
        help="comma-separated raw SMP Pairing Request variants",
    )
    pi_smp.add_argument(
        "--stop-bluetoothd",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="stop bluetooth.service during probes and restore it afterward",
    )
    pi_smp.add_argument(
        "--raw-log",
        action="store_true",
        help="print the JSONL path instead of a parsed summary",
    )

    native = subparsers.add_parser(
        "read-native",
        help="read using low-latency macOS CoreBluetooth directly",
    )
    native.add_argument("--timeout", type=float, default=20.0)
    native.add_argument("--connect-timeout", type=float, default=8.0)
    native.add_argument("--attempts", type=int, default=3)
    native.add_argument(
        "--address",
        help="CoreBluetooth UUID from scan/listen-native output; skips initial scan",
    )
    native.add_argument("--verbose", action="store_true", help="print tx/rx hex lines")

    listen_native = subparsers.add_parser(
        "listen-native",
        help="print Oura advertisements using macOS CoreBluetooth directly",
    )
    listen_native.add_argument("--timeout", type=float, default=30.0)

    decode = subparsers.add_parser(
        "decode", help="decode one or more raw packet hex strings"
    )
    decode.add_argument("hex", nargs="+")

    decode_events = subparsers.add_parser(
        "decode-events", help="decode one or more raw event packet hex strings"
    )
    decode_events.add_argument("hex", nargs="+")

    build = subparsers.add_parser("build-packet", help="print known request packet hex")
    build.add_argument(
        "name",
        choices=[
            "firmware",
            "battery",
            "events",
            "sync-time",
            "factory-reset",
            "factory_reset",
        ],
        help="request packet to build",
    )
    build.add_argument("--event-start", type=int, default=0)
    build.add_argument("--max-events", type=int, default=255)

    permissions = subparsers.add_parser(
        "fix-permissions",
        help="grant macOS Bluetooth TCC access for this command runner",
    )
    permissions.add_argument(
        "--dry-run",
        action="store_true",
        help="show the TCC identities that would be granted without writing",
    )
    permissions.add_argument(
        "--no-restart-tccd",
        action="store_true",
        help="write grants but do not restart the user tccd cache",
    )

    return parser


def add_device_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--address", help="BLE address/UUID from scan output")
    group.add_argument("--name", help="case-insensitive substring of BLE device name")


async def command_scan(args: argparse.Namespace) -> int:
    devices = await scan_devices(args.timeout, only_oura=args.only_oura)
    rows = [device.to_json() for device in devices]
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    for row in rows:
        marker = " *" if row["is_oura_candidate"] else "  "
        name = row["name"] or "(unnamed)"
        rssi = row["rssi"] if row["rssi"] is not None else "?"
        services = ",".join(row["service_uuids"]) or "-"
        print(f"{marker} {row['address']}  rssi={rssi}  name={name}  services={services}")
    if not rows:
        print("no BLE devices discovered")
    return 0


async def command_probe(args: argparse.Namespace) -> int:
    rows = await probe_devices(
        args.timeout,
        connect_timeout=args.connect_timeout,
        limit=args.limit,
    )
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


async def command_inspect(args: argparse.Namespace) -> int:
    entry = await find_device(address=args.address, name=args.name, timeout=args.timeout)
    if not entry:
        raise OuraBleError("device not found; put the ring on its charger and run scan")
    print(
        json.dumps(
            await inspect_device(entry.device, timeout=args.timeout),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


async def command_read(args: argparse.Namespace) -> int:
    if args.attempts < 1:
        raise OuraBleError("--attempts must be >= 1")
    auth_key = read_auth_key(args.auth_key)
    deadline = time.monotonic() + args.timeout
    errors: list[str] = []
    for attempt in range(1, args.attempts + 1):
        remaining = max(1.0, deadline - time.monotonic())
        entry = await find_read_target(args, timeout=min(args.scan_timeout, remaining))
        if not entry:
            if time.monotonic() >= deadline:
                break
            continue
        try:
            result = await read_once(
                args,
                entry,
                auth_key,
                timeout=min(args.connect_timeout, max(1.0, deadline - time.monotonic())),
            )
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            errors.append(f"attempt {attempt}: {message}")
            if time.monotonic() >= deadline:
                break
            continue
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if errors:
        raise OuraBleError("; ".join(errors))
    raise OuraBleError(
        "device not found; put the ring on its charger or close the Oura app"
    )


async def find_read_target(args: argparse.Namespace, *, timeout: float) -> Any:
    if args.address or args.name:
        return await find_device(address=args.address, name=args.name, timeout=timeout)
    return await find_oura_device(timeout)


async def read_once(
    args: argparse.Namespace,
    entry: Any,
    auth_key: bytes | None,
    *,
    timeout: float,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "device": entry.to_json(),
        "auth_key": (
            {"present": True, "sha256_prefix": key_fingerprint(auth_key)}
            if auth_key
            else {"present": False}
        ),
    }
    async with OuraRingClient(
        entry.device, timeout=timeout, verbose=args.verbose, pair=args.pair
    ) as ring:
        read_errors: dict[str, str] = {}
        for name, reader in (
            ("firmware", ring.firmware),
            ("auth_nonce", ring.auth_nonce),
            ("battery", ring.battery),
        ):
            try:
                result[name] = await reader()
            except Exception as exc:
                read_errors[name] = str(exc) or type(exc).__name__
        if read_errors:
            result["read_errors"] = read_errors
        if not any(name in result for name in ("firmware", "auth_nonce", "battery")):
            raise OuraBleError("no Oura packet responses received")
        if args.sync_time:
            packet = build_current_sync_time_packet()
            response = await ring.request(packet, expect_tag=0x13)
            result["sync_time"] = parse_response(response)
        if args.events:
            if not auth_key:
                raise OuraBleError(
                    "event retrieval needs an auth key; pass --auth-key "
                    "or set OURA_RING_AUTH_KEY"
                )
            result["authentication"] = await ring.authenticate(auth_key)
            result["events"] = await ring.events(
                start_timestamp=args.event_start, max_events=args.max_events
            )
    return result


def read_auth_key(arg: str | None) -> bytes | None:
    value = arg or os.environ.get("OURA_RING_AUTH_KEY")
    if not value:
        return None
    return parse_key(value)


def build_current_sync_time_packet() -> bytes:
    # Protocol uses half-hour offsets from UTC. localtime().tm_gmtoff is available on macOS.
    local = time.localtime()
    offset_seconds = getattr(local, "tm_gmtoff", 0)
    half_hours = int(offset_seconds / 1800)
    if half_hours < 0:
        half_hours = 256 + half_hours
    return build_sync_time_request(int(time.time()), half_hours)


def command_pi_auth_read(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-oura-provision-auth-key.py")
    log_path = new_log_path(args.log_dir, "pi-auth-read-cli")
    pointer_path = Path(args.log_dir) / "current-pi-auth-read-result.log"
    command = [
        sys.executable,
        str(script),
        "--scan-seconds",
        str(args.scan_seconds),
        "--pair-timeout",
        str(args.pair_timeout),
        "--connect-timeout",
        str(args.connect_timeout),
        "--response-timeout",
        str(args.response_timeout),
        "--settle-seconds",
        str(args.settle_seconds),
        "--state-path",
        args.state_path,
        "--agent-capability",
        args.agent_capability,
        "--live-hr-probe",
        "--live-hr-seconds",
        str(args.live_hr_seconds),
        "--meditation-duration-minutes",
        str(args.meditation_duration_minutes),
        "--meditation-listen-seconds",
        str(args.meditation_listen_seconds),
    ]
    add_optional_arg(command, "--address", args.address)
    add_optional_arg(command, "--device-path", args.device_path)
    command.append(
        "--restart-bluetooth-first"
        if args.restart_bluetooth_first
        else "--no-restart-bluetooth-first"
    )
    command.append("--clear-stale" if args.clear_stale else "--no-clear-stale")
    command.append(
        "--meditation-hr-probe"
        if args.meditation_hr_probe
        else "--no-meditation-hr-probe"
    )
    command.append("--session-cleanup" if args.session_cleanup else "--no-session-cleanup")
    if args.force_new_key:
        command.append("--force-new-key")
    return run_pi_jsonl_command(command, log_path, pointer_path, raw_log=args.raw_log)


def command_pi_zeroauth_read(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-bluez-zeroauth-stream.py")
    log_path = new_log_path(args.log_dir, "pi-zeroauth-read-cli")
    pointer_path = Path(args.log_dir) / "current-pi-bluez-read-result.log"
    command = [
        sys.executable,
        str(script),
        "--duration",
        str(args.duration),
        "--wait-services-timeout",
        str(args.wait_services_timeout),
        "--probes",
        args.probes,
        "--probe-delay-seconds",
        str(args.probe_delay_seconds),
        "--probe-response-timeout",
        str(args.probe_response_timeout),
        "--exit-after-probes",
    ]
    add_optional_arg(command, "--address", args.address)
    add_optional_arg(command, "--device-path", args.device_path)
    if args.connect:
        command.append("--connect")
    if args.pair:
        command.append("--pair")
    if args.auto_confirm_agent:
        command.append("--auto-confirm-agent")
    if args.all_notify_chars:
        command.append("--all-notify-chars")
    return run_pi_jsonl_command(command, log_path, pointer_path, raw_log=args.raw_log)


def command_pi_gatt_probe(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-oura-gatt-diagnostic.py")
    log_path = new_log_path(args.log_dir, "pi-gatt-probe")
    pointer_path = Path(args.log_dir) / "current-pi-gatt-probe.log"
    command = [
        sys.executable,
        str(script),
        "--scan-seconds",
        str(args.scan_seconds),
        "--connect-timeout",
        str(args.connect_timeout),
        "--connect-limit",
        str(args.connect_limit),
        "--summary-limit",
        str(args.summary_limit),
        "--non-oura-connect-limit",
        str(args.non_oura_connect_limit),
        "--matrix-response-timeout",
        str(args.matrix_response_timeout),
        "--matrix-read-timeout",
        str(args.matrix_read_timeout),
        "--scan-heartbeat-seconds",
        str(args.scan_heartbeat_seconds),
    ]
    add_repeated_arg(command, "--address", args.address)
    add_repeated_arg(command, "--matrix-skip-uuid", args.matrix_skip_uuid)
    add_repeated_arg(
        command, "--require-manufacturer-hex", args.require_manufacturer_hex
    )
    for enabled, flag in (
        (args.matrix_probe, "--matrix-probe"),
        (args.matrix_only, "--matrix-only"),
        (args.packet_read_only, "--packet-read-only"),
        (args.restart_bluetooth_first, "--restart-bluetooth-first"),
        (not args.restart_bluetooth_first, "--no-restart-bluetooth-first"),
        (args.clear_stale, "--clear-stale"),
        (not args.clear_stale, "--no-clear-stale"),
        (args.skip_standard_reads, "--skip-standard-reads"),
        (args.matrix_pre_read, "--matrix-pre-read"),
        (args.matrix_post_read, "--matrix-post-read"),
        (args.connect_on_first_oura, "--connect-on-first-oura"),
        (args.connectable_hint_only, "--connectable-hint-only"),
        (args.power_off_after, "--power-off-after"),
        (args.passive_scan, "--passive-scan"),
        (args.pair, "--pair"),
        (args.no_device_summary, "--no-device-summary"),
    ):
        if enabled:
            command.append(flag)
    return run_pi_jsonl_command(
        command,
        log_path,
        pointer_path,
        raw_log=args.raw_log,
        success_summary_key="diagnostic_summary",
        require_zero_returncode_for_summary=False,
    )


def command_pi_watch(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-oura-watch-loop.py")
    log_path = new_log_path(args.log_dir, "pi-watch")
    pointer_path = Path(args.log_dir) / "current-pi-watch.log"
    command = [
        sys.executable,
        str(script),
        "--cycle-scan-seconds",
        str(args.cycle_scan_seconds),
        "--connect-timeout",
        str(args.connect_timeout),
        "--connect-limit",
        str(args.connect_limit),
        "--summary-limit",
        str(args.summary_limit),
        "--scan-heartbeat-seconds",
        str(args.scan_heartbeat_seconds),
        "--delay-seconds",
        str(args.delay_seconds),
        "--cycles",
        str(args.cycles),
        "--matrix-response-timeout",
        str(args.matrix_response_timeout),
        "--matrix-read-timeout",
        str(args.matrix_read_timeout),
    ]
    add_repeated_arg(
        command, "--require-manufacturer-hex", args.require_manufacturer_hex
    )
    for enabled, flag in (
        (args.packet_read_only, "--packet-read-only"),
        (not args.packet_read_only, "--no-packet-read-only"),
        (args.connectable_hint_only, "--connectable-hint-only"),
        (not args.connectable_hint_only, "--allow-presence-connects"),
        (args.skip_standard_reads, "--skip-standard-reads"),
        (not args.skip_standard_reads, "--with-standard-reads"),
        (args.power_off_after, "--power-off-after"),
        (not args.power_off_after, "--no-power-off-after"),
        (args.passive_scan, "--passive-scan"),
        (not args.passive_scan, "--active-scan"),
        (args.no_matrix_only, "--no-matrix-only"),
        (args.matrix_pre_read, "--matrix-pre-read"),
        (args.matrix_post_read, "--matrix-post-read"),
        (args.pair, "--pair"),
        (args.agent, "--agent"),
        (args.btmon, "--btmon"),
    ):
        if enabled:
            command.append(flag)
    add_optional_arg(command, "--agent-capability", args.agent_capability)
    return run_pi_jsonl_command(
        command,
        log_path,
        pointer_path,
        raw_log=args.raw_log,
        success_summary_key="read_result_usable",
    )


def command_pi_watch_summary(args: argparse.Namespace) -> int:
    if args.follow:
        return command_pi_watch_summary_follow(args)
    paths = resolve_watch_summary_paths(
        args.logs,
        args.pointer,
        log_dir=Path(args.log_dir),
    )
    summaries = [watch_log_summary(path) for path in paths]
    if args.json:
        print(json.dumps(summaries, indent=2, sort_keys=True))
    else:
        print_watch_summaries(summaries)
    return 0


def command_pi_watch_summary_follow(args: argparse.Namespace) -> int:
    if args.interval <= 0:
        raise OuraBleError("--interval must be > 0")
    if args.max_refreshes < 0:
        raise OuraBleError("--max-refreshes must be >= 0")
    refreshes = 0
    try:
        while True:
            refreshes += 1
            paths = resolve_watch_summary_paths(
                args.logs,
                args.pointer,
                log_dir=Path(args.log_dir),
            )
            summaries = [watch_log_summary(path) for path in paths]
            if args.json:
                print(
                    json.dumps(
                        {
                            "refreshed_at_unix": time.time(),
                            "summaries": summaries,
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                if refreshes > 1:
                    print()
                print(time.strftime("== %Y-%m-%d %H:%M:%S =="))
                print_watch_summaries(summaries)
            sys.stdout.flush()
            if args.until_read_result and any(
                summary.get("read_result_usable") for summary in summaries
            ):
                return 0
            if args.max_refreshes and refreshes >= args.max_refreshes:
                return (
                    2
                    if args.until_read_result
                    and not any(
                        summary.get("read_result_usable") for summary in summaries
                    )
                    else 0
                )
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130


def command_pi_rpa_read(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-oura-raw-rpa-read-loop.py")
    log_path = new_log_path(args.log_dir, "pi-rpa-read-cli")
    pointer_path = Path(args.log_dir) / "current-pi-bluez-read-result.log"
    command = [
        sys.executable,
        str(script),
        "--scan-seconds",
        str(args.scan_seconds),
        "--scan-heartbeat-seconds",
        str(args.scan_heartbeat_seconds),
        "--silent-scan-timeout-seconds",
        str(args.silent_scan_timeout_seconds),
        "--connect-timeout",
        str(args.connect_timeout),
        "--connect-attempts",
        str(args.connect_attempts),
        "--connect-fallback-backend",
        args.connect_fallback_backend,
        "--connect-retry-delay-seconds",
        str(args.connect_retry_delay_seconds),
        "--le-create-own-address-type",
        args.le_create_own_address_type,
        "--le-create-scan-interval",
        str(args.le_create_scan_interval),
        "--le-create-scan-window",
        str(args.le_create_scan_window),
        "--le-create-conn-min-interval",
        str(args.le_create_conn_min_interval),
        "--le-create-conn-max-interval",
        str(args.le_create_conn_max_interval),
        "--le-create-conn-latency",
        str(args.le_create_conn_latency),
        "--le-create-supervision-timeout",
        str(args.le_create_supervision_timeout),
        "--le-create-min-ce-length",
        str(args.le_create_min_ce_length),
        "--le-create-max-ce-length",
        str(args.le_create_max_ce_length),
        "--read-timeout",
        str(args.read_timeout),
        "--response-timeout",
        str(args.response_timeout),
        "--after-connect",
        "zeroauth-stream",
        "--stream-duration",
        str(args.stream_duration),
        "--stream-exit-after-probes",
        "--stream-services-timeout",
        str(args.stream_services_timeout),
        "--stream-probes",
        args.stream_probes,
        "--stream-probe-delay-seconds",
        str(args.stream_probe_delay_seconds),
        "--stream-address-source",
        args.stream_address_source,
        "--cycles",
        str(args.cycles),
        "--reset-bluetooth-after-no-targets",
        str(args.reset_bluetooth_after_no_targets),
        "--reset-bluetooth-after-connect-failures",
        str(args.reset_bluetooth_after_connect_failures),
        "--scan-backend",
        args.scan_backend,
        "--log-dir",
        args.log_dir,
    ]
    command.append(
        "--btmon-timestamps" if args.btmon_timestamps else "--no-btmon-timestamps"
    )
    command.append(
        "--verify-btmgmt-discovering"
        if args.verify_btmgmt_discovering
        else "--no-verify-btmgmt-discovering"
    )
    add_optional_arg(command, "--identity-address", args.identity_address)
    add_optional_arg(command, "--manufacturer-hex", args.manufacturer_hex)
    command.append(
        "--fresh-bluez-cache" if args.fresh_bluez_cache else "--no-fresh-bluez-cache"
    )
    if args.require_rpa_stream_address:
        command.append("--require-rpa-stream-address")
    command.append("--stream-connect" if args.stream_connect else "--no-stream-connect")
    if args.stream_all_notify_chars:
        command.append("--stream-all-notify-chars")
    if args.stream_strict_address:
        command.append("--stream-strict-address")
    if args.stream_auto_confirm_agent:
        command.append("--stream-auto-confirm-agent")
    add_optional_arg(command, "--stream-agent-capability", args.stream_agent_capability)
    if args.stream_pair:
        command.append("--stream-pair")
        command.extend(["--stream-pair-timeout", str(args.stream_pair_timeout)])
    return run_pi_jsonl_command(command, log_path, pointer_path, raw_log=args.raw_log)


def command_pi_smp_probe(args: argparse.Namespace) -> int:
    script = repo_script_path("pi-oura-raw-smp-probe.py")
    log_path = new_log_path(args.log_dir, "pi-raw-smp-probe")
    pointer_path = Path(args.log_dir) / "current-pi-raw-smp-probe.log"
    command = [
        "sudo",
        "-E",
        "/usr/bin/python3",
        str(script),
        "--log-dir",
        args.log_dir,
        "--scan-seconds",
        str(args.scan_seconds),
        "--connect-timeout",
        str(args.connect_timeout),
        "--listen-seconds",
        str(args.listen_seconds),
        "--pre-smp-delay-seconds",
        str(args.pre_smp_delay_seconds),
        "--hci-index",
        str(args.hci_index),
        "--own-address-type",
        args.own_address_type,
        "--variants",
        args.variants,
    ]
    add_optional_arg(command, "--manufacturer-hex", args.manufacturer_hex)
    add_optional_arg(command, "--random-address", args.random_address)
    command.append(
        "--stop-bluetoothd" if args.stop_bluetoothd else "--no-stop-bluetoothd"
    )
    return run_pi_jsonl_command(
        command,
        log_path,
        pointer_path,
        raw_log=args.raw_log,
        success_summary_key="raw_smp_probe_done",
    )


def repo_script_path(name: str) -> Path:
    root = Path(__file__).resolve().parents[2]
    script = root / "scripts" / name
    if not script.exists():
        raise OuraBleError(f"cannot find script next to source tree: {script}")
    return script


def new_log_path(log_dir: str, prefix: str) -> Path:
    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{prefix}-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"


def add_optional_arg(command: list[str], flag: str, value: str) -> None:
    if value:
        command.extend([flag, value])


def add_repeated_arg(command: list[str], flag: str, values: list[str]) -> None:
    for value in values:
        if value:
            command.extend([flag, value])


def run_pi_jsonl_command(
    command: list[str],
    log_path: Path,
    pointer_path: Path,
    *,
    raw_log: bool,
    success_summary_key: str = "read_result_usable",
    require_zero_returncode_for_summary: bool = True,
) -> int:
    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    pointer_path.write_text(f"{log_path}\n")
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1])
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_path
        if not existing_pythonpath
        else f"{src_path}{os.pathsep}{existing_pythonpath}"
    )
    with log_path.open("w") as handle:
        process = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, env=env)
    if raw_log:
        print(log_path)
        return process.returncode
    summary = latest_jsonl_summary(log_path)
    summary["command_returncode"] = process.returncode
    summary["log_path"] = str(log_path)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if success_summary_key != "read_result_usable":
        if summary.get(success_summary_key) and (
            not require_zero_returncode_for_summary or process.returncode == 0
        ):
            return 0
        return process.returncode or 2
    return 0 if summary.get("read_result_usable") else process.returncode or 2


def latest_jsonl_summary(path: Path) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    latest: dict[str, Any] = {}
    for line in path.read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = str(row.get("event", ""))
        event_counts[event] = event_counts.get(event, 0) + 1
        if event in {
            "read_result",
            "provision_done",
            "provision_error",
            "zeroauth_error",
            "zeroauth_stream_done",
            "raw_loop_done",
            "raw_zeroauth_stream_done",
            "raw_setup_security_failure",
            "raw_smp_probe_done",
            "diagnostic_summary",
            "matrix_summary",
            "watch_success",
            "watch_done",
        }:
            latest[event] = row.get("payload")
    read_result = latest.get("read_result")
    raw_setup_security_failure = latest.get("raw_setup_security_failure")
    return {
        "event_counts": event_counts,
        "read_result": read_result,
        "read_result_usable": is_usable_read_result(read_result),
        "read_failure": classify_read_failure(read_result, raw_setup_security_failure),
        "provision_done": latest.get("provision_done"),
        "provision_error": latest.get("provision_error"),
        "zeroauth_error": latest.get("zeroauth_error"),
        "zeroauth_stream_done": latest.get("zeroauth_stream_done"),
        "raw_loop_done": latest.get("raw_loop_done"),
        "raw_zeroauth_stream_done": latest.get("raw_zeroauth_stream_done"),
        "raw_setup_security_failure": raw_setup_security_failure,
        "raw_smp_probe_done": latest.get("raw_smp_probe_done"),
        "diagnostic_summary": latest.get("diagnostic_summary"),
        "matrix_summary": latest.get("matrix_summary"),
        "watch_success": latest.get("watch_success"),
        "watch_done": latest.get("watch_done"),
    }


def resolve_watch_summary_paths(
    logs: list[str], pointers: list[str], *, log_dir: Path
) -> list[Path]:
    paths = [Path(path) for path in logs if path]
    pointer_paths = [Path(pointer) for pointer in pointers if pointer]
    if not paths and not pointer_paths:
        pointer_paths = [
            log_dir / "current-pi-watch.log",
            log_dir / "current-active-watch.log",
            log_dir / "current-orange-watch.log",
            log_dir / "current-pi-gatt-probe.log",
            log_dir / "current-pi-bluez-read-result.log",
        ]

    for pointer_path in pointer_paths:
        if not pointer_path.exists():
            continue
        target = pointer_path.read_text(errors="replace").splitlines()[0].strip()
        if not target:
            continue
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = Path.cwd() / target_path
        paths.append(target_path)

    existing: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path if path.is_absolute() else Path.cwd() / path
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.exists():
            existing.append(resolved)
    if not existing:
        raise OuraBleError("no watch logs found; pass a JSONL path or --pointer")
    return existing


def watch_log_summary(path: Path) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    latest_scan: dict[str, Any] | None = None
    latest_scan_done: dict[str, Any] | None = None
    latest_raw_scan: dict[str, Any] | None = None
    latest_target: dict[str, Any] | None = None
    latest_raw_target: dict[str, Any] | None = None
    latest_read_result: dict[str, Any] | None = None
    latest_diagnostic: dict[str, Any] | None = None
    latest_watch_cycle_start: dict[str, Any] | None = None
    latest_watch_cycle_done: dict[str, Any] | None = None
    latest_watch_success: dict[str, Any] | None = None
    latest_watch_done: dict[str, Any] | None = None
    latest_raw_loop_success: dict[str, Any] | None = None
    latest_raw_loop_done: dict[str, Any] | None = None
    latest_raw_scan_inactive: dict[str, Any] | None = None
    latest_raw_hci_scan_enable: dict[str, Any] | None = None
    latest_raw_bluetooth_recovery: dict[str, Any] | None = None
    latest_raw_scan_backend_switch: dict[str, Any] | None = None
    latest_top_devices: list[dict[str, Any]] = []
    device_summaries: list[dict[str, Any]] = []
    last_elapsed: float | None = None
    invalid_lines = 0

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(row, dict):
                continue
            event = str(row.get("event", ""))
            payload = row.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            event_counts[event] = event_counts.get(event, 0) + 1
            elapsed = row.get("elapsed_seconds")
            if isinstance(elapsed, int | float) and not isinstance(elapsed, bool):
                last_elapsed = float(elapsed)
            if event == "scan_heartbeat":
                latest_scan = payload
                latest_top_devices = payload_list(payload.get("top_devices"))
            elif event == "scan_done":
                latest_scan_done = payload
            elif event in {"raw_scan_heartbeat", "raw_cycle_no_target"}:
                latest_raw_scan = payload
            elif event == "raw_scan_inactive":
                latest_raw_scan = payload
                latest_raw_scan_inactive = payload
            elif event == "raw_cycle_scan_inactive":
                latest_raw_scan = payload
                latest_raw_scan_inactive = payload
            elif event == "raw_hci_scan_enable":
                latest_raw_hci_scan_enable = payload
            elif event == "raw_bluetooth_recovery":
                latest_raw_bluetooth_recovery = payload
            elif event == "raw_scan_backend_switch":
                latest_raw_scan_backend_switch = payload
            elif event == "scan_target_selected":
                latest_target = payload
            elif event == "raw_scan_target":
                latest_raw_target = payload
            elif event == "read_result":
                latest_read_result = payload
            elif event == "diagnostic_summary":
                latest_diagnostic = payload
            elif event == "watch_cycle_start":
                latest_watch_cycle_start = payload
            elif event == "watch_cycle_done":
                latest_watch_cycle_done = payload
            elif event == "watch_success":
                latest_watch_success = payload
            elif event == "watch_done":
                latest_watch_done = payload
            elif event == "raw_loop_success":
                latest_raw_loop_success = payload
            elif event == "raw_loop_done":
                latest_raw_loop_done = payload
            elif event == "device_summary":
                device_summaries.append(payload)

    read_result: Any = latest_read_result
    top_devices = latest_top_devices or device_summaries[-5:]
    latest_scan_status = latest_scan or latest_scan_done
    return {
        "log": str(path),
        "event_counts": event_counts,
        "invalid_json_lines": invalid_lines,
        "last_elapsed_seconds": last_elapsed,
        "read_result": latest_read_result,
        "read_result_usable": is_usable_read_result(read_result),
        "read_result_summary": summarize_read_result(read_result),
        "wake_stats": watch_wake_stats(event_counts),
        "latest_target": latest_target,
        "latest_raw_target": latest_raw_target,
        "latest_scan_status": compact_watch_scan_status(latest_scan_status),
        "latest_raw_scan_status": compact_raw_scan_status(latest_raw_scan),
        "controller_status": compact_watch_controller_status(
            event_counts,
            latest_raw_scan_inactive,
            latest_raw_hci_scan_enable,
            latest_raw_bluetooth_recovery,
            latest_raw_scan_backend_switch,
        ),
        "latest_diagnostic_summary": latest_diagnostic,
        "latest_watch_cycle_start": latest_watch_cycle_start,
        "latest_watch_cycle_done": latest_watch_cycle_done,
        "latest_watch_success": latest_watch_success,
        "latest_watch_done": latest_watch_done,
        "latest_raw_loop_success": latest_raw_loop_success,
        "latest_raw_loop_done": latest_raw_loop_done,
        "top_devices": [compact_watch_device(row) for row in top_devices],
    }


def payload_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def watch_wake_stats(event_counts: dict[str, int]) -> dict[str, int]:
    return {
        "raw_heartbeats": event_counts.get("raw_scan_heartbeat", 0),
        "raw_no_target_windows": event_counts.get("raw_cycle_no_target", 0),
        "raw_oura_candidates": event_counts.get("raw_scan_oura_candidate", 0),
        "raw_targets": event_counts.get("raw_scan_target", 0),
        "read_results": event_counts.get("read_result", 0),
    }


def compact_watch_scan_status(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    keys = (
        "advertisement_events",
        "unique_devices",
        "oura_candidates",
        "selected_target",
        "oura_manufacturer_counts",
        "oura_state_hint_counts",
    )
    return {key: payload.get(key) for key in keys if key in payload}


def compact_raw_scan_status(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    keys = (
        "cycle",
        "manufacturer_sample_count",
        "manufacturer_counts",
        "resolvable_counts",
        "oura_candidate_counts",
        "address_type_counts",
        "address_kind_counts",
        "event_type_counts",
        "manufacturer_rssi",
        "manufacturer_addresses",
        "address_rssi",
        "unique_address_count",
        "resolvable_address_count",
        "consecutive_no_targets",
        "no_target_classification",
        "reason",
        "last_address",
        "last_address_type",
        "last_address_kind",
        "last_event_type",
        "scan_backend",
        "seconds_remaining",
        "physical_state_note",
    )
    compact = {key: payload.get(key) for key in keys if key in payload}
    counts = compact.get("manufacturer_counts")
    if "manufacturer_sample_count" not in compact and isinstance(counts, dict):
        compact["manufacturer_sample_count"] = sum(
            value for value in counts.values() if isinstance(value, int | float)
        )
    probe_candidates = ranked_manual_probe_candidates(
        compact.get("manufacturer_rssi"), compact.get("manufacturer_addresses")
    )
    if probe_candidates:
        compact["manual_probe_candidates"] = probe_candidates
    hint = raw_scan_operator_hint(compact)
    if hint:
        compact["operator_hint"] = hint
    return compact


HCI_STATUS_NAMES = {
    "00": "success",
    "0C": "command_disallowed",
}


def compact_watch_controller_status(
    event_counts: dict[str, int],
    scan_inactive: dict[str, Any] | None,
    hci_scan_enable: dict[str, Any] | None,
    bluetooth_recovery: dict[str, Any] | None,
    backend_switch: dict[str, Any] | None,
) -> dict[str, Any] | None:
    status: dict[str, Any] = {}
    scan_inactive_count = event_counts.get("raw_scan_inactive", 0) + event_counts.get(
        "raw_cycle_scan_inactive", 0
    )
    if scan_inactive_count:
        status["scan_inactive_events"] = scan_inactive_count
    count_map = {
        "hci_scan_enable_events": "raw_hci_scan_enable",
        "bluetooth_recovery_events": "raw_bluetooth_recovery",
        "backend_switch_events": "raw_scan_backend_switch",
    }
    for output_key, event in count_map.items():
        count = event_counts.get(event, 0)
        if count:
            status[output_key] = count

    if isinstance(scan_inactive, dict):
        for source_key, output_key in (
            ("reason", "latest_inactive_reason"),
            ("scan_backend", "latest_inactive_backend"),
            ("seconds_without_samples", "latest_seconds_without_samples"),
        ):
            if source_key in scan_inactive:
                status[output_key] = scan_inactive.get(source_key)
    if isinstance(hci_scan_enable, dict):
        reason = hci_scan_enable.get("reason")
        if reason:
            status["latest_hci_reason"] = reason
        sequence = extract_hci_status_sequence(hci_scan_enable)
        codes = unique_hci_status_codes(sequence)
        if codes:
            status["latest_hci_status_codes"] = [f"0x{code}" for code in codes]
            status["latest_hci_status_names"] = [
                HCI_STATUS_NAMES.get(code, "unknown") for code in codes
            ]
        if sequence:
            final_code = sequence[-1]
            status["latest_hci_final_status_code"] = f"0x{final_code}"
            status["latest_hci_final_status_name"] = HCI_STATUS_NAMES.get(
                final_code, "unknown"
            )
    if isinstance(bluetooth_recovery, dict):
        reason = bluetooth_recovery.get("reason")
        if reason:
            status["latest_recovery_reason"] = reason
    if isinstance(backend_switch, dict):
        for source_key, output_key in (
            ("scan_backend", "latest_backend"),
            ("backend", "latest_backend"),
            ("reason", "latest_backend_reason"),
        ):
            value = backend_switch.get(source_key)
            if value:
                status[output_key] = value
    return status or None


def extract_hci_status_codes(payload: dict[str, Any]) -> list[str]:
    return unique_hci_status_codes(extract_hci_status_sequence(payload))


def unique_hci_status_codes(codes: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for code in codes:
        if code in seen:
            continue
        seen.add(code)
        unique.append(code)
    return unique


def extract_hci_status_sequence(payload: dict[str, Any]) -> list[str]:
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return []
    codes: list[str] = []
    for command in commands:
        if not isinstance(command, dict):
            continue
        stdout = command.get("stdout")
        if not isinstance(stdout, str):
            continue
        tokens = [token.upper() for token in stdout.replace("\n", " ").split()]
        for index in range(len(tokens) - 3):
            code = tokens[index + 3]
            if (
                tokens[index] == "01"
                and tokens[index + 2] == "20"
                and len(code) == 2
                and all(char in "0123456789ABCDEF" for char in code)
            ):
                codes.append(code)
    return codes


def raw_scan_operator_hint(raw_scan: dict[str, Any]) -> str | None:
    reason = raw_scan.get("reason")
    classification = raw_scan.get("no_target_classification")
    samples = numeric_value(raw_scan.get("manufacturer_sample_count"))
    addresses = numeric_value(raw_scan.get("unique_address_count"))
    if reason in {
        "silent_scan_no_manufacturer_samples",
        "btmgmt_find_did_not_enable_discovery",
        "hci_le_scan_enable_failed",
    }:
        return (
            "scanner/controller issue: recover BlueZ or switch scan backend before "
            "treating this as a ring protocol result"
        )
    if classification == "oura_seen_without_target_payload":
        return (
            "ring presence seen, but not a connect/read target payload; keep "
            "watching for a setup/reset/app wake state or broaden the target set"
        )
    if classification == "no_oura_seen":
        if samples > 0 or addresses > 0:
            return (
                "scanner is receiving BLE advertisements, but no Oura state is "
                "visible; trigger a ring wake/charger transition/app activity"
            )
        return (
            "no Oura and no manufacturer samples yet; verify controller scanning "
            "before changing protocol probes"
        )
    return None


def numeric_value(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int | float):
        return float(value)
    return 0.0


def top_count_items(counts: Any, *, limit: int = 5) -> list[tuple[str, int | float]]:
    if not isinstance(counts, dict):
        return []
    numeric_counts = [
        (str(key), value)
        for key, value in counts.items()
        if isinstance(value, int | float) and not isinstance(value, bool)
    ]
    return sorted(numeric_counts, key=lambda item: (-item[1], item[0]))[:limit]


def format_top_counts(counts: Any, *, limit: int = 3) -> str:
    items = top_count_items(counts, limit=limit)
    return ",".join(f"{key}:{value}" for key, value in items) if items else "-"


def format_near_manufacturers(value: Any, *, limit: int = 5) -> str:
    if not isinstance(value, dict):
        return ""
    rows: list[tuple[str, int, int]] = []
    for manufacturer, summary in value.items():
        if not isinstance(summary, dict):
            continue
        max_rssi = summary.get("max")
        samples = summary.get("samples")
        if isinstance(max_rssi, bool) or isinstance(samples, bool):
            continue
        if isinstance(max_rssi, int) and isinstance(samples, int):
            rows.append((str(manufacturer), max_rssi, samples))
    rows.sort(key=lambda row: (-row[1], -row[2], row[0]))
    return ", ".join(
        f"{manufacturer}:{max_rssi}dBm/{samples}"
        for manufacturer, max_rssi, samples in rows[:limit]
    )


def format_near_manufacturer_addresses(
    rssi_value: Any, address_value: Any, *, limit: int = 3
) -> str:
    if not isinstance(rssi_value, dict) or not isinstance(address_value, dict):
        return ""
    rows: list[tuple[str, int, str, str, str, str]] = []
    for manufacturer, rssi_summary in rssi_value.items():
        if not isinstance(rssi_summary, dict):
            continue
        max_rssi = rssi_summary.get("max")
        if isinstance(max_rssi, bool) or not isinstance(max_rssi, int):
            continue
        address_summary = address_value.get(manufacturer)
        if not isinstance(address_summary, dict):
            continue
        address = (
            address_summary.get("max_rssi_resolvable_address")
            or address_summary.get("max_rssi_address")
            or address_summary.get("latest_resolvable_address")
            or address_summary.get("latest_address")
        )
        if not address:
            continue
        address_type = (
            address_summary.get("max_rssi_address_type")
            or address_summary.get("latest_address_type")
            or "?"
        )
        event_type = (
            address_summary.get("max_rssi_event_type")
            or address_summary.get("latest_event_type")
            or "?"
        )
        company = short_company_name(
            str(
                address_summary.get("max_rssi_company")
                or address_summary.get("latest_company")
                or ""
            )
        )
        rows.append(
            (
                str(manufacturer),
                max_rssi,
                str(address),
                str(address_type),
                short_ble_event_type(str(event_type)),
                company,
            )
        )
    rows.sort(key=lambda row: (-row[1], row[0], row[2]))
    return ", ".join(
        format_near_address_row(row) for row in rows[:limit]
    )


def format_near_address_row(row: tuple[str, int, str, str, str, str]) -> str:
    manufacturer, max_rssi, address, address_type, event_type, company = row
    company_part = f"/{company}" if company else ""
    return (
        f"{manufacturer}:{max_rssi}dBm/{address}/{address_type}/"
        f"{event_type}{company_part}"
    )


def format_near_devices(value: Any, *, limit: int = 5) -> str:
    if not isinstance(value, dict):
        return ""
    rows: list[tuple[str, int, int, str, str]] = []
    for address, summary in value.items():
        if not isinstance(summary, dict):
            continue
        max_rssi = summary.get("max")
        samples = summary.get("samples")
        if isinstance(max_rssi, bool) or isinstance(samples, bool):
            continue
        if not isinstance(max_rssi, int) or not isinstance(samples, int):
            continue
        address_type = str(summary.get("address_type") or "?")
        event_type = short_ble_event_type(str(summary.get("event_type") or "?"))
        rows.append((str(address), max_rssi, samples, address_type, event_type))
    rows.sort(key=lambda row: (-row[1], -row[2], row[0]))
    return ", ".join(
        (
            f"{address}:{max_rssi}dBm/{address_type}/"
            f"{event_type}/{samples}"
        )
        for address, max_rssi, samples, address_type, event_type in rows[:limit]
    )


def ranked_manual_probe_candidates(
    rssi_value: Any, address_value: Any, *, limit: int = 3
) -> list[dict[str, Any]]:
    if not isinstance(rssi_value, dict) or not isinstance(address_value, dict):
        return []
    rows: list[tuple[int, int, str, dict[str, Any]]] = []
    for manufacturer, rssi_summary in rssi_value.items():
        if not isinstance(rssi_summary, dict):
            continue
        max_rssi = rssi_summary.get("max")
        if isinstance(max_rssi, bool) or not isinstance(max_rssi, int):
            continue
        address_summary = address_value.get(manufacturer)
        if not isinstance(address_summary, dict):
            continue
        event_type = str(
            address_summary.get("max_rssi_event_type")
            or address_summary.get("latest_event_type")
            or ""
        )
        address_type = str(
            address_summary.get("max_rssi_address_type")
            or address_summary.get("latest_address_type")
            or ""
        )
        company = str(
            address_summary.get("max_rssi_company")
            or address_summary.get("latest_company")
            or ""
        )
        if is_likely_non_oura_company(company):
            continue
        address = (
            address_summary.get("max_rssi_resolvable_address")
            or (
                address_summary.get("max_rssi_address")
                if address_type == "Resolvable"
                else None
            )
            or address_summary.get("latest_resolvable_address")
        )
        if not address:
            continue
        connectable = "Connectable undirected" in event_type
        candidate = {
            "manufacturer_hex": str(manufacturer),
            "rssi": max_rssi,
            "address": str(address),
            "address_type": "Resolvable",
            "event_type": event_type,
            "event_type_short": short_ble_event_type(event_type),
            "company": company,
            "company_short": short_company_name(company),
            "connectable_hint": connectable,
        }
        rows.append((0 if connectable else 1, -max_rssi, str(manufacturer), candidate))
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    return [candidate for _, _, _, candidate in rows[:limit]]


def format_manual_probe_candidates(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    parts: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        manufacturer = item.get("manufacturer_hex")
        address = item.get("address")
        rssi = item.get("rssi")
        event = item.get("event_type_short") or "?"
        company = item.get("company_short")
        if not manufacturer or not address or not isinstance(rssi, int):
            continue
        suffix = "" if item.get("connectable_hint") else "/not-connectable"
        company_part = f"/{company}" if company else ""
        parts.append(
            f"{manufacturer}:{rssi}dBm/{event}/{address}{company_part}{suffix}"
        )
    return ", ".join(parts)


def short_ble_event_type(value: str) -> str:
    if "Connectable undirected" in value:
        return "ADV_IND"
    if "Scan response" in value:
        return "SCAN_RSP"
    if "Non connectable" in value:
        return "ADV_NONCONN"
    return value or "?"


def short_company_name(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    value = value.split(" (", 1)[0]
    if value == "Apple, Inc.":
        return "Apple"
    return value


def is_likely_non_oura_company(value: str) -> bool:
    normalized = value.lower()
    if not normalized:
        return False
    if "oura" in normalized or "jouzen" in normalized:
        return False
    return any(
        marker in normalized
        for marker in (
            "apple",
            "microsoft",
            "google",
            "samsung",
            "tencent",
        )
    )


def summarize_read_result(result: Any) -> list[str]:
    if not isinstance(result, dict):
        return []
    parts: list[str] = []
    firmware = result.get("firmware")
    if isinstance(firmware, dict):
        version = firmware.get("firmware_version")
        api = firmware.get("api_version")
        ble = firmware.get("bluetooth_stack_version")
        detail = f"fw={version}" if version else "fw=present"
        if api:
            detail += f" api={api}"
        if ble:
            detail += f" ble={ble}"
        parts.append(detail)
    battery = result.get("battery")
    if isinstance(battery, dict):
        parts.append(format_battery_summary(battery))
    auth_nonce = result.get("auth_nonce")
    if isinstance(auth_nonce, dict):
        nonce = auth_nonce.get("nonce_hex")
        parts.append(f"auth_nonce={len(str(nonce)) // 2}B" if nonce else "auth_nonce")
    snapshot = result.get("device_snapshot")
    if isinstance(snapshot, dict):
        snapshot_summary = summarize_device_snapshot(snapshot)
        if snapshot_summary:
            parts.append(snapshot_summary)
    for key in ("daytime_hr_latest", "resting_hr_latest"):
        summary = summarize_feature_latest_payload(key, result.get(key))
        if summary:
            parts.append(summary)
    feature_latest = result.get("feature_latest")
    if isinstance(feature_latest, dict):
        for key, payload in sorted(feature_latest.items()):
            summary = summarize_feature_latest_payload(str(key), payload)
            if summary and summary not in parts:
                parts.append(summary)
    feature_status = result.get("feature_status")
    if isinstance(feature_status, dict) and feature_status:
        active = [
            feature_status_name(row)
            for _key, row in sorted(feature_status.items())
            if isinstance(row, dict)
            and row.get("mode_name") not in {None, "", "off"}
        ]
        if active:
            parts.append("active_features=" + ",".join(active[:8]))
    events = result.get("events")
    if isinstance(events, list) and events:
        parts.append(f"events={len(events)}")
    event_summary = result.get("event_summary")
    if isinstance(event_summary, dict):
        health_summary = summarize_health_events(event_summary.get("health_events"))
        if health_summary:
            parts.append(health_summary)
        count = event_summary.get("count") or event_summary.get("event_count")
        if count is not None:
            parts.append(f"event_summary_count={count}")
    auth_gated = result.get("auth_gated")
    if isinstance(auth_gated, list) and auth_gated:
        visible = ",".join(str(item) for item in auth_gated[:8])
        suffix = f",...({len(auth_gated)} total)" if len(auth_gated) > 8 else ""
        parts.append(f"auth_gated={visible}{suffix}")
    return parts


def format_battery_summary(battery: dict[str, Any]) -> str:
    pieces = [f"battery={battery.get('battery_level_percent')}%"]
    progress = battery.get("charging_progress")
    if progress is not None:
        pieces.append(f"charge={progress}%")
    voltage = battery.get("voltage_mv")
    if voltage is not None:
        pieces.append(f"voltage={voltage}mV")
    status = battery.get("battery_status_hex")
    if status is not None:
        pieces.append(f"status={status}")
    return " ".join(pieces)


def summarize_health_events(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return ""
    pieces: list[str] = []
    event_counts = value.get("event_counts")
    if isinstance(event_counts, dict) and event_counts:
        pieces.append("events=" + format_top_counts(event_counts, limit=5))
    ibi_count = value.get("ibi_record_count")
    if isinstance(ibi_count, int) and not isinstance(ibi_count, bool):
        pieces.append(f"ibi={ibi_count}")
    bpm_min = value.get("bpm_estimate_min")
    bpm_max = value.get("bpm_estimate_max")
    bpm_latest = value.get("bpm_estimate_latest")
    if bpm_min is not None and bpm_max is not None:
        pieces.append(f"bpm={bpm_min}-{bpm_max}")
    if bpm_latest is not None:
        pieces.append(f"latest_bpm={bpm_latest}")
    spo2_count = value.get("spo2_sample_count")
    if isinstance(spo2_count, int) and not isinstance(spo2_count, bool):
        spo2_min = value.get("spo2_value_min")
        spo2_max = value.get("spo2_value_max")
        pieces.append(f"spo2_raw={spo2_count}:{spo2_min}-{spo2_max}")
    temp_count = value.get("temperature_sample_count")
    if isinstance(temp_count, int) and not isinstance(temp_count, bool):
        temp_min = value.get("temperature_c_min")
        temp_max = value.get("temperature_c_max")
        pieces.append(f"temp_c={temp_count}:{temp_min}-{temp_max}")
    quality_count = value.get("green_ibi_quality_sample_count")
    if isinstance(quality_count, int) and not isinstance(quality_count, bool):
        pieces.append(f"green_quality={quality_count}")
    ppg_count = value.get("ppg_amplitude_count")
    if isinstance(ppg_count, int) and not isinstance(ppg_count, bool):
        pieces.append(f"ppg_amp={ppg_count}")
    return "health_events=" + " ".join(pieces) if pieces else ""


def summarize_device_snapshot(snapshot: dict[str, Any]) -> str | None:
    pieces: list[str] = []
    for key, label in (
        ("hardware_id", "hw"),
        ("firmware_git", "git"),
        ("setup_transition", "transition"),
    ):
        value = snapshot.get(key)
        if value:
            pieces.append(f"{label}={value}")
    battery = snapshot.get("battery")
    if isinstance(battery, dict):
        level = battery.get("level_percent")
        if level is not None:
            pieces.append(f"battery={level}%")
    setup = snapshot.get("setup_state")
    if isinstance(setup, dict):
        state = setup.get("state") or setup.get("name") or setup.get("raw")
        if state:
            pieces.append(f"setup={state}")
    return "snapshot: " + " ".join(pieces) if pieces else None


def summarize_feature_latest_payload(label: str, payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    feature = str(payload.get("feature_name") or label).replace("feature_latest:", "")
    bpm = payload.get("daytime_hr_bpm_estimate")
    if isinstance(bpm, int | float) and not isinstance(bpm, bool):
        return f"{feature}~{bpm}bpm"
    latest_values = payload.get("latest_values")
    if isinstance(latest_values, list) and latest_values:
        values = [
            row.get("value") if isinstance(row, dict) else row
            for row in latest_values[:5]
        ]
        values_text = ",".join(str(value) for value in values if value is not None)
        if values_text:
            suffix = "" if feature.endswith("_latest") else "_latest"
            return f"{feature}{suffix}={values_text}"
    state = payload.get("state_name")
    status = payload.get("status_name")
    if state or status:
        return f"{feature}={status or '?'}:{state or '?'}"
    return None


def feature_status_name(row: dict[str, Any]) -> str:
    feature = row.get("feature_name")
    if feature and feature != "unknown":
        return str(feature)
    feature_id = row.get("feature_id")
    if isinstance(feature_id, int):
        return f"feature_0x{feature_id:02x}"
    return "feature_unknown"


def compact_watch_device(row: dict[str, Any]) -> dict[str, Any]:
    device = row.get("device")
    if not isinstance(device, dict):
        device = row
    compact = {
        "count": row.get("count"),
        "address": device.get("address"),
        "name": device.get("name"),
        "rssi": device.get("rssi"),
        "is_oura_candidate": device.get("is_oura_candidate"),
        "oura_state_hint": device.get("oura_state_hint"),
        "oura_connectable_hint": device.get("oura_connectable_hint"),
        "manufacturer_data": device.get("manufacturer_data"),
        "service_uuids": device.get("service_uuids"),
    }
    return {key: value for key, value in compact.items() if value not in (None, [], {})}


def print_watch_summaries(summaries: list[dict[str, Any]]) -> None:
    for index, summary in enumerate(summaries):
        if index:
            print()
        print(summary["log"])
        print(f"  read_result_usable: {summary['read_result_usable']}")
        read_result_summary = summary.get("read_result_summary") or []
        if read_result_summary:
            print(f"  latest_read_result: {'; '.join(read_result_summary)}")
        wake_stats = summary.get("wake_stats") or {}
        if any(wake_stats.values()):
            print(
                "  wake: "
                f"raw_oura={wake_stats.get('raw_oura_candidates', 0)} "
                f"targets={wake_stats.get('raw_targets', 0)} "
                f"read_results={wake_stats.get('read_results', 0)} "
                f"heartbeats={wake_stats.get('raw_heartbeats', 0)} "
                f"no_target_windows={wake_stats.get('raw_no_target_windows', 0)}"
            )
        scan = summary.get("latest_scan_status") or {}
        print(
            "  scan: "
            f"events={scan.get('advertisement_events', 0)} "
            f"unique={scan.get('unique_devices', 0)} "
            f"oura_candidates={scan.get('oura_candidates', 0)}"
        )
        raw_scan = summary.get("latest_raw_scan_status") or {}
        if raw_scan:
            raw_oura = raw_scan.get("oura_candidate_counts") or {}
            print(
                "  raw: "
                f"samples={raw_scan.get('manufacturer_sample_count', 0)} "
                f"oura={sum(raw_oura.values()) if isinstance(raw_oura, dict) else 0} "
                f"class={raw_scan.get('no_target_classification')} "
                f"backend={raw_scan.get('scan_backend')}"
            )
            top_manufacturers = top_count_items(raw_scan.get("manufacturer_counts"))
            if top_manufacturers:
                formatted = ", ".join(
                    f"{key}:{value}" for key, value in top_manufacturers
                )
                print(f"  raw_top_mfg: {formatted}")
            if (
                raw_scan.get("unique_address_count") is not None
                or raw_scan.get("event_type_counts")
                or raw_scan.get("address_type_counts")
            ):
                print(
                    "  raw_seen: "
                    f"unique={raw_scan.get('unique_address_count', 0)} "
                    f"resolvable={raw_scan.get('resolvable_address_count', 0)} "
                    f"events={format_top_counts(raw_scan.get('event_type_counts'))} "
                    f"address_types={format_top_counts(raw_scan.get('address_type_counts'))}"
                )
            near_manufacturers = format_near_manufacturers(
                raw_scan.get("manufacturer_rssi")
            )
            if near_manufacturers:
                print(f"  raw_near_mfg: {near_manufacturers}")
            near_addresses = format_near_manufacturer_addresses(
                raw_scan.get("manufacturer_rssi"),
                raw_scan.get("manufacturer_addresses"),
            )
            if near_addresses:
                print(f"  raw_near_addr: {near_addresses}")
            near_devices = format_near_devices(raw_scan.get("address_rssi"))
            if near_devices:
                print(f"  raw_near_dev: {near_devices}")
            probe_candidates = format_manual_probe_candidates(
                raw_scan.get("manual_probe_candidates")
            )
            if probe_candidates:
                print(f"  raw_probe_candidates: {probe_candidates}")
            if raw_scan.get("operator_hint"):
                print(f"  raw_hint: {raw_scan['operator_hint']}")
        controller = summary.get("controller_status") or {}
        if controller:
            print(
                "  controller: "
                f"inactive={controller.get('scan_inactive_events', 0)} "
                f"hci_enable={controller.get('hci_scan_enable_events', 0)} "
                f"recoveries={controller.get('bluetooth_recovery_events', 0)} "
                f"backend_switches={controller.get('backend_switch_events', 0)}"
            )
            detail_parts = []
            if controller.get("latest_inactive_reason"):
                detail_parts.append(f"inactive={controller['latest_inactive_reason']}")
            if controller.get("latest_recovery_reason"):
                detail_parts.append(f"recovery={controller['latest_recovery_reason']}")
            final_status_name = controller.get("latest_hci_final_status_name")
            if final_status_name:
                detail_parts.append(f"hci_final={final_status_name}")
            else:
                status_names = controller.get("latest_hci_status_names")
                if isinstance(status_names, list) and status_names:
                    hci_status_detail = ",".join(str(v) for v in status_names)
                    detail_parts.append(f"hci_status={hci_status_detail}")
            status_names = controller.get("latest_hci_status_names")
            if (
                final_status_name
                and final_status_name != "success"
                and isinstance(status_names, list)
                and len(status_names) > 1
            ):
                hci_status_detail = ",".join(str(v) for v in status_names)
                detail_parts.append(f"hci_status={hci_status_detail}")
            if controller.get("latest_backend"):
                detail_parts.append(f"backend={controller['latest_backend']}")
            if detail_parts:
                print(f"  controller_detail: {' '.join(detail_parts)}")
        raw_target = summary.get("latest_raw_target") or {}
        if raw_target:
            print(
                "  raw_target: "
                f"rpa={raw_target.get('rpa')} "
                f"mfg={raw_target.get('manufacturer_hex')} "
                f"backend={raw_target.get('scan_backend')}"
            )
        diagnostic = summary.get("latest_diagnostic_summary") or {}
        if diagnostic:
            print(
                "  diagnostic: "
                f"targets={diagnostic.get('targets', 0)} "
                f"gatt_successes={diagnostic.get('gatt_successes', 0)} "
                f"read_successes={diagnostic.get('read_successes', 0)}"
            )
        cycle_start = summary.get("latest_watch_cycle_start") or {}
        cycle_done = summary.get("latest_watch_cycle_done") or {}
        if cycle_start or cycle_done:
            print(
                "  watch: "
                f"cycle_start={cycle_start.get('cycle')} "
                f"cycle_done={cycle_done.get('cycle')} "
                f"last_exit={cycle_done.get('exit_code')}"
            )
        raw_success = summary.get("latest_raw_loop_success") or {}
        raw_done = summary.get("latest_raw_loop_done") or {}
        if raw_success or raw_done:
            print(
                "  raw_loop: "
                f"success_cycle={raw_success.get('cycle')} "
                f"done_cycles={raw_done.get('cycles')} "
                f"done_success={raw_done.get('success')}"
            )
        for device in summary.get("top_devices", [])[:5]:
            print(
                "  device: "
                f"count={device.get('count')} "
                f"rssi={device.get('rssi')} "
                f"oura={device.get('is_oura_candidate')} "
                f"address={device.get('address')} "
                f"mfg={device.get('manufacturer_data', {})}"
            )


def classify_read_failure(
    read_result: Any, raw_setup_security_failure: Any
) -> dict[str, Any] | None:
    if not isinstance(raw_setup_security_failure, dict):
        return None
    if raw_setup_security_failure.get("classification") != "setup_pairing_rejected":
        return None
    failure: dict[str, Any] = {
        "classification": "setup_pairing_rejected",
        "detail": "ring rejected SMP pairing before Oura packet reads could run",
    }
    for key in (
        "smp_pairing_failed_reason_code",
        "smp_pairing_failed_reason",
        "att_insufficient_encryption",
    ):
        if key in raw_setup_security_failure:
            failure[key] = raw_setup_security_failure[key]
    probe_error = first_probe_error(read_result)
    if probe_error:
        failure["first_probe_error"] = probe_error
    return failure


def first_probe_error(read_result: Any) -> dict[str, Any] | None:
    if not isinstance(read_result, dict):
        return None
    for probe in read_result.get("probes", []):
        if not isinstance(probe, dict):
            continue
        errors = probe.get("errors")
        if not errors:
            continue
        error = errors[0]
        if isinstance(error, dict):
            return {
                "packet": probe.get("packet"),
                "error": error.get("error"),
                "error_type": error.get("error_type"),
            }
    return None


def is_usable_read_result(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if any(
        result.get(key)
        for key in (
            "firmware",
            "battery",
            "auth_nonce",
            "auth_gated",
            "authentication",
            "capabilities",
            "device_snapshot",
            "daytime_hr",
            "daytime_hr_latest",
            "feature_set_results",
            "feature_latest",
            "feature_status",
            "resting_hr_latest",
            "events",
        )
    ):
        return True
    for probe in result.get("probes", []):
        if not isinstance(probe, dict):
            continue
        if probe.get("classification") in {"open_response", "auth_gated"}:
            return True
        if probe.get("raw_responses"):
            return True
    return False


def command_decode(args: argparse.Namespace) -> int:
    decoded = []
    for value in args.hex:
        for packet in parse_packets(bytes_from_user(value)):
            decoded.append(parse_response(packet))
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0


def command_decode_events(args: argparse.Namespace) -> int:
    decoded = []
    for value in args.hex:
        for packet in parse_packets(bytes_from_user(value)):
            if packet.tag < 0x41:
                raise ProtocolError(f"not an event packet: 0x{packet.tag:02X}")
            decoded.append(parse_response(packet))
    print(json.dumps(decoded, indent=2, sort_keys=True))
    return 0


def command_build_packet(args: argparse.Namespace) -> int:
    if args.name == "firmware":
        data = build_get_firmware_request()
    elif args.name == "battery":
        data = build_get_battery_request()
    elif args.name == "events":
        data = build_get_events_request(args.event_start, args.max_events)
    elif args.name == "sync-time":
        data = build_current_sync_time_packet()
    elif args.name in {"factory-reset", "factory_reset"}:
        data = build_factory_reset_request()
    else:
        raise ProtocolError(f"unknown packet name: {args.name}")
    print(data.hex())
    print(json.dumps(parse_response(packet_from_hex(data.hex())), indent=2, sort_keys=True))
    return 0


def command_read_native(args: argparse.Namespace) -> int:
    try:
        from .corebluetooth import CoreBluetoothError, native_read
    except ModuleNotFoundError as exc:
        raise OuraBleError("read-native requires macOS CoreBluetooth") from exc

    if args.attempts < 1:
        raise OuraBleError("--attempts must be >= 1")
    if args.connect_timeout <= 0:
        raise OuraBleError("--connect-timeout must be > 0")
    try:
        result = native_read(
            args.timeout,
            verbose=args.verbose,
            connect_timeout=args.connect_timeout,
            attempts=args.attempts,
            address=args.address,
        )
    except CoreBluetoothError as exc:
        raise OuraBleError(str(exc) or type(exc).__name__) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_listen_native(args: argparse.Namespace) -> int:
    try:
        from .corebluetooth import CoreBluetoothError, native_listen
    except ModuleNotFoundError as exc:
        raise OuraBleError("listen-native requires macOS CoreBluetooth") from exc

    try:
        rows = native_listen(args.timeout)
    except CoreBluetoothError as exc:
        raise OuraBleError(str(exc) or type(exc).__name__) from exc
    if not rows:
        print("[]")
    return 0


def command_fix_permissions(args: argparse.Namespace) -> int:
    result = fix_macos_bluetooth_permissions(
        dry_run=args.dry_run,
        restart_tccd=not args.no_restart_tccd,
    )
    print(json.dumps(result.to_json(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
