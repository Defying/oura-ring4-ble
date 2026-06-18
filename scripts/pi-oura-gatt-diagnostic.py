#!/usr/bin/env python3
"""Pi/Linux BLE diagnostic for Oura Ring 4 discovery and GATT reads."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import signal
import subprocess
import time
import warnings
from collections import defaultdict
from typing import Any, NamedTuple

from bleak import BleakClient, BleakScanner
from bleak.assigned_numbers import AdvertisementDataType
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from oura_ring4_ble import protocol as p
from oura_ring4_ble.client import (
    DeviceAdvertisement,
    OuraBleError,
    is_oura_candidate,
    oura_connectable_hint,
    oura_state_hint,
    service_to_json,
)


class PacketProbe(NamedTuple):
    name: str
    data: bytes
    expected_tags: frozenset[int]
    expected_extended_names: frozenset[str] = frozenset()


PACKET_PROBES = [
    PacketProbe(
        "firmware",
        p.build_get_firmware_request(),
        frozenset({p.TAG_FIRMWARE_RESPONSE}),
    ),
    PacketProbe(
        "battery",
        p.build_get_battery_request(),
        frozenset({p.TAG_BATTERY_RESPONSE}),
    ),
    PacketProbe(
        "auth_nonce",
        p.build_get_auth_nonce_request(),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"auth_nonce_response"}),
    ),
    PacketProbe(
        "capabilities:0x00",
        p.build_get_capabilities_request(0x00),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"capabilities_response"}),
    ),
    PacketProbe(
        "capabilities:0x01",
        p.build_get_capabilities_request(0x01),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"capabilities_response"}),
    ),
    PacketProbe(
        "feature_status:daytime_hr",
        p.build_get_feature_status_request(0x02),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_status_response"}),
    ),
    PacketProbe(
        "feature_status:resting_hr",
        p.build_get_feature_status_request(0x08),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_status_response"}),
    ),
    PacketProbe(
        "feature_status:spo2",
        p.build_get_feature_status_request(0x04),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_status_response"}),
    ),
    PacketProbe(
        "feature_status:real_steps",
        p.build_get_feature_status_request(0x0B),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_status_response"}),
    ),
    PacketProbe(
        "feature_latest:daytime_hr",
        p.build_get_feature_latest_values_request(0x02),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_latest_values_response"}),
    ),
    PacketProbe(
        "feature_latest:resting_hr",
        p.build_get_feature_latest_values_request(0x08),
        frozenset({p.TAG_EXTENDED}),
        frozenset({"feature_latest_values_response"}),
    ),
    PacketProbe(
        "legacy_firmware_zero_payload",
        bytes.fromhex("0803000000"),
        frozenset({p.TAG_FIRMWARE_RESPONSE}),
    ),
]

STANDARD_GATT_READS = [
    (
        "gap_peripheral_preferred_connection_parameters",
        "00002a04-0000-1000-8000-00805f9b34fb",
    ),
    ("gap_central_address_resolution", "00002aa6-0000-1000-8000-00805f9b34fb"),
    ("gap_resolvable_private_address_only", "00002ac9-0000-1000-8000-00805f9b34fb"),
    ("gap_appearance", "00002a01-0000-1000-8000-00805f9b34fb"),
    ("gap_device_name", "00002a00-0000-1000-8000-00805f9b34fb"),
    (
        "device_information_manufacturer_name",
        "00002a29-0000-1000-8000-00805f9b34fb",
    ),
    ("device_information_model_number", "00002a24-0000-1000-8000-00805f9b34fb"),
    ("device_information_serial_number", "00002a25-0000-1000-8000-00805f9b34fb"),
    ("device_information_firmware_revision", "00002a26-0000-1000-8000-00805f9b34fb"),
    ("device_information_hardware_revision", "00002a27-0000-1000-8000-00805f9b34fb"),
    ("device_information_software_revision", "00002a28-0000-1000-8000-00805f9b34fb"),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan from Linux/BlueZ, enumerate GATT, and read Oura packets."
    )
    parser.add_argument("--scan-seconds", type=float, default=60.0)
    parser.add_argument("--connect-timeout", type=float, default=12.0)
    parser.add_argument("--connect-limit", type=int, default=8)
    parser.add_argument("--summary-limit", type=int, default=20)
    parser.add_argument("--no-device-summary", action="store_true")
    parser.add_argument(
        "--non-oura-connect-limit",
        type=int,
        default=0,
        help="also enumerate this many strongest non-Oura devices as adapter proof",
    )
    parser.add_argument("--verbose-adverts", action="store_true")
    parser.add_argument(
        "--address",
        action="append",
        default=[],
        help="BLE address to prioritize or try even if it is not detected as Oura",
    )
    parser.add_argument(
        "--matrix-probe",
        action="store_true",
        help=(
            "after the normal read path fails, subscribe/read/write across every "
            "Oura vendor characteristic and emit packet-level evidence"
        ),
    )
    parser.add_argument(
        "--matrix-only",
        action="store_true",
        help="skip the normal read path and run only the Oura characteristic matrix",
    )
    parser.add_argument(
        "--packet-read-only",
        action="store_true",
        help=(
            "skip broad matrix probing and run the proven safe packet reader: "
            "subscribe 98ed0003, write 0800 and 2f012b to 98ed0002, emit read_result"
        ),
    )
    parser.add_argument(
        "--restart-bluetooth-first",
        action="store_true",
        default=True,
        help="restart bluetoothd and power-cycle hci0 before scanning",
    )
    parser.add_argument(
        "--no-restart-bluetooth-first",
        dest="restart_bluetooth_first",
        action="store_false",
    )
    parser.add_argument(
        "--clear-stale",
        action="store_true",
        default=True,
        help="remove visible BlueZ Device1 entries before scanning",
    )
    parser.add_argument("--no-clear-stale", dest="clear_stale", action="store_false")
    parser.add_argument(
        "--skip-standard-reads",
        action="store_true",
        help=(
            "skip Generic Access/Device Information reads before Oura packet probes; "
            "useful when setup-state firmware disconnects on ordinary GAP reads"
        ),
    )
    parser.add_argument("--matrix-response-timeout", type=float, default=3.0)
    parser.add_argument(
        "--matrix-read-timeout",
        type=float,
        default=1.0,
        help="maximum seconds for each optional matrix GATT read",
    )
    parser.add_argument(
        "--matrix-pre-read",
        action="store_true",
        help="read readable vendor characteristics before subscribing/writing",
    )
    parser.add_argument(
        "--matrix-post-read",
        action="store_true",
        help="read readable vendor characteristics after writes with no notification",
    )
    parser.add_argument(
        "--matrix-skip-uuid",
        action="append",
        default=[],
        help=(
            "skip matrix characteristics by full UUID or 8-hex UUID prefix; "
            "repeat to bypass known setup-state disconnect triggers"
        ),
    )
    parser.add_argument(
        "--scan-heartbeat-seconds",
        type=float,
        default=0.0,
        help="emit periodic scan heartbeat JSON while waiting for a target",
    )
    parser.add_argument(
        "--connect-on-first-oura",
        action="store_true",
        help=(
            "stop scanning and connect as soon as a matching Oura advertisement "
            "arrives, instead of waiting for the full scan window"
        ),
    )
    parser.add_argument(
        "--pair",
        action="store_true",
        help="pair/trust Oura devices through BlueZ before GATT discovery",
    )
    parser.add_argument(
        "--require-manufacturer-hex",
        action="append",
        default=[],
        help=(
            "with --connect-on-first-oura, only stop on Oura manufacturer data "
            "matching this hex payload; may be repeated"
        ),
    )
    parser.add_argument(
        "--connectable-hint-only",
        action="store_true",
        help=(
            "only select Oura advertisements whose manufacturer payload has the "
            "observed connectable/readiness hint bit; useful for paired/worn scans "
            "where 04601b01 presence adverts time out on connect"
        ),
    )
    parser.add_argument(
        "--power-off-after",
        action="store_true",
        help="power off hci0 after diagnostics so no BLE scan/connect state lingers",
    )
    parser.add_argument(
        "--passive-scan",
        action="store_true",
        help="listen for advertisements without requesting scan responses",
    )
    return asyncio.run(run(parser.parse_args()))


async def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    seen: dict[str, DeviceAdvertisement] = {}
    counts: defaultdict[str, int] = defaultdict(int)
    first_target: DeviceAdvertisement | None = None
    first_target_event = asyncio.Event()
    matrix_skip_uuid = normalize_uuid_filters(args.matrix_skip_uuid)
    required_manufacturer_hex = normalize_hex_filters(args.require_manufacturer_hex)

    def emit(event: str, payload: dict[str, Any]) -> None:
        print(
            json.dumps(
                {
                    "event": event,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "payload": payload,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    prepare_bluez(args, emit)

    def callback(device: BLEDevice, advertisement: AdvertisementData) -> None:
        nonlocal first_target
        entry = DeviceAdvertisement(device, advertisement)
        address = device.address
        counts[address] += 1
        previous = seen.get(address)
        seen[address] = entry
        row = entry.to_json()
        changed = previous is None or advert_signature(previous) != advert_signature(entry)
        if args.verbose_adverts or row["is_oura_candidate"] or (changed and row["name"]):
            emit(
                "advertisement",
                {
                    "count": counts[address],
                    "device": row,
                    "reason": candidate_reason(device, advertisement),
                },
            )
        if (
            args.connect_on_first_oura
            and first_target is None
            and row["is_oura_candidate"]
            and target_state_filter_matches(
                entry,
                required_manufacturer_hex,
                connectable_hint_only=args.connectable_hint_only,
            )
        ):
            first_target = entry
            emit(
                "scan_target_selected",
                {
                    "count": counts[address],
                    "device": row,
                    "reason": candidate_reason(device, advertisement),
                    "required_manufacturer_hex": sorted(required_manufacturer_hex),
                },
            )
            first_target_event.set()

    emit(
        "scan_start",
        {
            "scan_seconds": args.scan_seconds,
            "oura_service_uuid": p.OURA_SERVICE_UUID,
            "oura_company_id": f"0x{p.OURA_COMPANY_ID:04X}",
            "connect_on_first_oura": args.connect_on_first_oura,
            "connectable_hint_only": args.connectable_hint_only,
            "required_manufacturer_hex": sorted(required_manufacturer_hex),
            "scan_heartbeat_seconds": args.scan_heartbeat_seconds,
            "scanning_mode": "passive" if args.passive_scan else "active",
        },
    )
    try:
        scanner = BleakScanner(callback, **scanner_kwargs(args))
    except Exception:
        if args.power_off_after:
            power_off_bluez_after(emit)
        raise
    heartbeat_task: asyncio.Task[None] | None = None
    try:
        await scanner.start()
    except Exception:
        if args.power_off_after:
            power_off_bluez_after(emit)
        raise
    try:
        if args.scan_heartbeat_seconds > 0:
            heartbeat_task = asyncio.create_task(
                scan_heartbeat_loop(
                    args.scan_heartbeat_seconds,
                    seen,
                    counts,
                    first_target_event,
                    emit,
                )
            )
        if args.connect_on_first_oura:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(first_target_event.wait(), args.scan_seconds)
        else:
            await asyncio.sleep(args.scan_seconds)
    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task
        await scanner.stop()

    emit(
        "scan_done",
        {
            "unique_devices": len(seen),
            "advertisement_events": sum(counts.values()),
            "oura_candidates": sum(
                1
                for entry in seen.values()
                if is_oura_candidate(entry.device, entry.advertisement)
            ),
            "selected_target": first_target.to_json() if first_target else None,
        },
    )

    if not args.no_device_summary:
        for entry in ranked_entries(seen, counts)[: args.summary_limit]:
            emit(
                "device_summary",
                {
                    "count": counts[entry.device.address],
                    "device": entry.to_json(),
                    "reason": candidate_reason(entry.device, entry.advertisement),
                },
            )

    targets = select_targets(seen, counts, args)
    if first_target:
        targets = [first_target] + [
            entry
            for entry in targets
            if entry.device.address.lower() != first_target.device.address.lower()
        ]
        targets = targets[: args.connect_limit]
    read_successes = 0
    gatt_successes = 0
    for index, entry in enumerate(targets, 1):
        is_oura = is_oura_candidate(entry.device, entry.advertisement)
        emit(
            "connect_attempt",
            {
                "index": index,
                "device": entry.to_json(),
                "reason": candidate_reason(entry.device, entry.advertisement),
            },
        )
        if is_oura:
            if args.packet_read_only:
                if await try_oura_packet_read(
                    entry.device,
                    args.connect_timeout,
                    args.matrix_response_timeout,
                    emit,
                    pair=args.pair,
                ):
                    read_successes += 1
                continue
            if args.matrix_only:
                if await try_oura_matrix_probe(
                    entry.device,
                    args.connect_timeout,
                    args.matrix_response_timeout,
                    args.matrix_read_timeout,
                    emit,
                    pair=args.pair,
                    pre_read=args.matrix_pre_read,
                    post_read=args.matrix_post_read,
                    skip_uuid=matrix_skip_uuid,
                ):
                    read_successes += 1
                continue
            if await try_oura_read(
                entry.device,
                args.connect_timeout,
                emit,
                matrix_probe=args.matrix_probe,
                matrix_response_timeout=args.matrix_response_timeout,
                matrix_read_timeout=args.matrix_read_timeout,
                matrix_pre_read=args.matrix_pre_read,
                matrix_post_read=args.matrix_post_read,
                pair=args.pair,
                matrix_skip_uuid=matrix_skip_uuid,
                skip_standard_reads=args.skip_standard_reads,
            ):
                read_successes += 1
            continue
        if await try_gatt_proof(entry.device, args.connect_timeout, emit):
            gatt_successes += 1

    emit(
        "diagnostic_summary",
        {
            "targets": len(targets),
            "gatt_successes": gatt_successes,
            "read_successes": read_successes,
        },
    )
    status = 0 if read_successes else 1
    if args.power_off_after:
        power_off_bluez_after(emit)
    return status


def scanner_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    if not args.passive_scan:
        return {"scanning_mode": "active"}
    return {
        "scanning_mode": "passive",
        "bluez": {
            "or_patterns": [
                (
                    0,
                    AdvertisementDataType(0xFF),
                    p.OURA_COMPANY_ID.to_bytes(2, "little"),
                )
            ]
        },
    }


def prepare_bluez(args: argparse.Namespace, emit: Any) -> None:
    if not args.restart_bluetooth_first and not args.clear_stale:
        return
    emit(
        "bluez_prepare_start",
        {
            "restart_bluetooth_first": args.restart_bluetooth_first,
            "clear_stale": args.clear_stale,
        },
    )
    if args.restart_bluetooth_first:
        run_control_command(
            ["sudo", "-n", "systemctl", "restart", "bluetooth"],
            emit,
            "restart_bluetooth",
            timeout=8,
        )
        time.sleep(2.0)

    removed: list[str] = []
    if args.clear_stale:
        for address in visible_bluez_device_addresses():
            result = run_control_command(
                ["bluetoothctl", "remove", address],
                emit,
                "remove_device",
                timeout=8,
            )
            if result.returncode == 0:
                removed.append(address)

    if args.restart_bluetooth_first:
        for name, command in (
            ("power_off", ["sudo", "-n", "btmgmt", "power", "off"]),
            ("power_on", ["sudo", "-n", "btmgmt", "power", "on"]),
            ("bondable_on", ["sudo", "-n", "btmgmt", "bondable", "on"]),
        ):
            run_control_command(command, emit, name, timeout=6)
            if name == "power_off":
                time.sleep(1.0)

    emit(
        "bluez_prepare_done",
        {
            "removed_devices": len(removed),
            "removed_addresses": removed,
            "connections": command_output(["hcitool", "con"], timeout=4),
        },
    )


def power_off_bluez_after(emit: Any) -> None:
    run_control_command(
        ["sudo", "-n", "btmgmt", "power", "off"],
        emit,
        "power_off_after",
        timeout=6,
    )
    emit(
        "bluez_power_off_after_done",
        {"connections": command_output(["hcitool", "con"], timeout=4)},
    )


def visible_bluez_device_addresses() -> list[str]:
    row = command_output(["bluetoothctl", "devices"], timeout=6)
    addresses: list[str] = []
    for line in row.get("stdout", "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "Device":
            addresses.append(fields[1])
    return addresses


def run_control_command(
    command: list[str], emit: Any, name: str, *, timeout: float
) -> subprocess.CompletedProcess[str]:
    result = run_command(command, timeout=timeout)
    emit(
        "bluez_prepare_command",
        {
            "name": name,
            "command": command,
            "returncode": result.returncode,
            "stdout": truncate_text(result.stdout),
            "stderr": truncate_text(result.stderr),
        },
    )
    return result


def command_output(command: list[str], *, timeout: float) -> dict[str, Any]:
    result = run_command(command, timeout=timeout)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": truncate_text(result.stdout),
        "stderr": truncate_text(result.stderr),
    }


def run_command(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            stdout, stderr = process.communicate(timeout=1)
            return subprocess.CompletedProcess(
                command,
                127,
                stdout,
                append_timeout_stderr(stderr, exc),
            )
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return subprocess.CompletedProcess(
            command,
            127,
            stdout,
            append_timeout_stderr(stderr, exc),
        )


def append_timeout_stderr(stderr: str | None, exc: BaseException) -> str:
    timeout_text = str(exc)
    if not stderr:
        return timeout_text
    return f"{stderr.rstrip()}\n{timeout_text}"


def truncate_text(value: str, limit: int = 2000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...<truncated>"


async def scan_heartbeat_loop(
    interval: float,
    seen: dict[str, DeviceAdvertisement],
    counts: defaultdict[str, int],
    first_target_event: asyncio.Event,
    emit: Any,
) -> None:
    while not first_target_event.is_set():
        await asyncio.sleep(interval)
        emit("scan_heartbeat", scan_stats(seen, counts))


def scan_stats(
    seen: dict[str, DeviceAdvertisement], counts: defaultdict[str, int]
) -> dict[str, Any]:
    oura_entries = [
        entry
        for entry in seen.values()
        if is_oura_candidate(entry.device, entry.advertisement)
    ]
    manufacturer_counts: defaultdict[str, int] = defaultdict(int)
    state_hint_counts: defaultdict[str, int] = defaultdict(int)
    for entry in oura_entries:
        advertisement = entry.advertisement
        manufacturer = (
            advertisement.manufacturer_data.get(p.OURA_COMPANY_ID)
            if advertisement
            else None
        )
        manufacturer_counts[manufacturer.hex() if manufacturer else "none"] += counts[
            entry.device.address
        ]
        state_hint_counts[oura_state_hint(advertisement) or "unknown"] += counts[
            entry.device.address
        ]
    strongest = ranked_entries(seen, counts)[:5]
    return {
        "unique_devices": len(seen),
        "advertisement_events": sum(counts.values()),
        "oura_candidates": len(oura_entries),
        "oura_manufacturer_counts": dict(sorted(manufacturer_counts.items())),
        "oura_state_hint_counts": dict(sorted(state_hint_counts.items())),
        "top_devices": [
            {
                "count": counts[entry.device.address],
                "device": entry.to_json(),
                "reason": candidate_reason(entry.device, entry.advertisement),
            }
            for entry in strongest
        ],
    }


def ranked_entries(
    seen: dict[str, DeviceAdvertisement], counts: dict[str, int]
) -> list[DeviceAdvertisement]:
    return sorted(
        seen.values(),
        key=lambda entry: (
            not is_oura_candidate(entry.device, entry.advertisement),
            not has_oura_connectable_hint(entry),
            not bool(entry.to_json()["name"]),
            -(entry.to_json()["rssi"] or -999),
            -counts[entry.device.address],
            entry.device.address,
        ),
    )


def advert_signature(entry: DeviceAdvertisement) -> tuple[Any, ...]:
    row = entry.to_json()
    return (
        row["name"],
        tuple(row["service_uuids"]),
        tuple(row["manufacturer_data"].items()),
        tuple(row["service_data"].items()),
        row["tx_power"],
        row["is_oura_candidate"],
    )


def select_targets(
    seen: dict[str, DeviceAdvertisement],
    counts: dict[str, int],
    args: argparse.Namespace,
) -> list[DeviceAdvertisement]:
    targets: list[DeviceAdvertisement] = []
    forced = {address.lower() for address in args.address}
    required_manufacturer_hex = normalize_hex_filters(args.require_manufacturer_hex)
    for entry in ranked_entries(seen, counts):
        if entry.device.address.lower() in forced:
            targets.append(entry)
            forced.discard(entry.device.address.lower())
    for entry in ranked_entries(seen, counts):
        if (
            is_oura_candidate(entry.device, entry.advertisement)
            and entry not in targets
            and target_state_filter_matches(
                entry,
                required_manufacturer_hex,
                connectable_hint_only=args.connectable_hint_only,
            )
        ):
            targets.append(entry)
    non_oura_added = 0
    for entry in ranked_entries(seen, counts):
        if entry in targets or is_oura_candidate(entry.device, entry.advertisement):
            continue
        if non_oura_added >= args.non_oura_connect_limit:
            break
        targets.append(entry)
        non_oura_added += 1
    return targets[: args.connect_limit]


def normalize_hex_filters(values: list[str]) -> set[str]:
    filters: set[str] = set()
    for value in values:
        compact = value.lower().strip()
        if compact.startswith("0x"):
            compact = compact[2:]
        compact = "".join(char for char in compact if char in "0123456789abcdef")
        if not compact:
            continue
        if len(compact) % 2:
            raise ValueError(f"manufacturer hex has an odd number of nibbles: {value}")
        filters.add(compact)
    return filters


def normalize_uuid_filters(values: list[str]) -> set[str]:
    filters: set[str] = set()
    for value in values:
        compact = value.lower().strip()
        if compact.startswith("0x"):
            compact = compact[2:]
        compact = compact.strip("{}")
        if not compact:
            continue
        if len(compact) == 8:
            filters.add(compact)
            continue
        filters.add(compact)
    return filters


def manufacturer_filter_matches(
    entry: DeviceAdvertisement, required_manufacturer_hex: set[str]
) -> bool:
    if not required_manufacturer_hex:
        return True
    advertisement = entry.advertisement
    if not advertisement:
        return False
    manufacturer = advertisement.manufacturer_data.get(p.OURA_COMPANY_ID)
    if not manufacturer:
        return False
    return manufacturer.hex() in required_manufacturer_hex


def target_state_filter_matches(
    entry: DeviceAdvertisement,
    required_manufacturer_hex: set[str],
    *,
    connectable_hint_only: bool,
) -> bool:
    if not manufacturer_filter_matches(entry, required_manufacturer_hex):
        return False
    if connectable_hint_only and not has_oura_connectable_hint(entry):
        return False
    return True


async def try_oura_read(
    device: BLEDevice,
    timeout: float,
    emit: Any,
    *,
    matrix_probe: bool,
    matrix_response_timeout: float,
    matrix_read_timeout: float,
    matrix_pre_read: bool,
    matrix_post_read: bool,
    pair: bool,
    matrix_skip_uuid: set[str],
    skip_standard_reads: bool,
) -> bool:
    stage_ref = {"stage": "connect"}
    try:
        async with BleakClient(device, timeout=timeout, pair=pair) as client:
            stage_ref["stage"] = "standard_gatt_reads"
            standard_gatt_reads = (
                []
                if skip_standard_reads
                else await read_standard_gatt(client)
            )
            emit(
                "gatt_services",
                {
                    "address": device.address,
                    "pair": pair,
                    "services": [service_to_json(service) for service in client.services],
                    "standard_gatt_reads": standard_gatt_reads,
                    "standard_gatt_reads_skipped": skip_standard_reads,
                },
            )
            stage_ref["stage"] = "packet_read"
            if await try_oura_packet_read_with_client(
                client,
                device,
                matrix_response_timeout,
                emit,
                pair=pair,
                stage_ref=stage_ref,
            ):
                return True
            raise OuraBleError("no Oura packet responses received")
    except Exception as exc:
        emit(
            "gatt_error",
            {
                "address": device.address,
                "stage": stage_ref["stage"],
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        emit(
            "read_error",
            {
                "address": device.address,
                "stage": stage_ref["stage"],
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        if matrix_probe:
            return await try_oura_matrix_probe(
                device,
                timeout,
                matrix_response_timeout,
                matrix_read_timeout,
                emit,
                pair=pair,
                pre_read=matrix_pre_read,
                post_read=matrix_post_read,
                skip_uuid=matrix_skip_uuid,
            )
        return False


async def try_oura_packet_read(
    device: BLEDevice,
    timeout: float,
    response_timeout: float,
    emit: Any,
    *,
    pair: bool,
) -> bool:
    stage_ref = {"stage": "connect"}
    try:
        async with BleakClient(device, timeout=timeout, pair=pair) as client:
            return await try_oura_packet_read_with_client(
                client,
                device,
                response_timeout,
                emit,
                pair=pair,
                stage_ref=stage_ref,
            )
    except Exception as exc:
        emit(
            "packet_read_error",
            {
                "address": device.address,
                "stage": stage_ref["stage"],
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return False


async def try_oura_packet_read_with_client(
    client: BleakClient,
    device: BLEDevice,
    response_timeout: float,
    emit: Any,
    *,
    pair: bool,
    stage_ref: dict[str, str],
) -> bool:
    notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    result: dict[str, Any] = {
        "device": {"address": device.address, "name": device.name},
        "pair": pair,
    }
    read_errors: dict[str, str] = {}
    stage_ref["stage"] = "discover_characteristics"
    chars = vendor_characteristics(client.services)
    write_char = find_characteristic(chars, p.OURA_WRITE_UUID, p.WRITE_HANDLE)
    notify_char = find_characteristic(chars, p.OURA_NOTIFY_UUID, p.NOTIFY_HANDLE)
    if write_char is None or notify_char is None:
        raise RuntimeError("could not find 98ed0002 write and 98ed0003 notify")
    emit(
        "packet_read_start",
        {
            "address": device.address,
            "connected": is_client_connected(client),
            "pair": pair,
            "write_characteristic": char_to_json(write_char),
            "notify_characteristic": char_to_json(notify_char),
        },
    )
    stage_ref["stage"] = "start_notify"
    await client.start_notify(
        notify_char,
        notify_callback(notify_char, emit, notifications),
    )
    emit(
        "packet_read_subscribed",
        {
            "address": device.address,
            "connected": is_client_connected(client),
            "notify_characteristic": char_to_json(notify_char),
        },
    )
    try:
        for probe in PACKET_PROBES:
            drain_queue(notifications)
            stage_ref["stage"] = f"write_{probe.name}"
            emit(
                "packet_read_tx",
                {"packet": probe.name, "tx_hex": probe.data.hex()},
            )
            await client.write_gatt_char(write_char, probe.data, response=True)
            stage_ref["stage"] = f"collect_{probe.name}"
            rows = await collect_packet_notifications(
                notifications,
                probe.name,
                probe.expected_tags,
                probe.expected_extended_names,
                response_timeout,
                emit,
            )
            if rows:
                apply_packet_read_rows(result, probe.name, probe.data, rows)
            else:
                read_errors[probe.name] = "no matching notification"
    finally:
        with contextlib.suppress(Exception):
            await client.stop_notify(notify_char)

    if read_errors:
        result["read_errors"] = read_errors
    if not any(
        name in result
        for name in (
            "firmware",
            "battery",
            "auth_nonce",
            "capabilities",
            "feature_status",
            "feature_latest",
            "auth_gated",
        )
    ):
        emit(
            "packet_read_error",
            {
                "address": device.address,
                "stage": stage_ref["stage"],
                "error_type": "OuraBleError",
                "error": "no Oura packet responses received",
            },
        )
        return False
    emit("read_result", result)
    return True


def apply_packet_read_rows(
    result: dict[str, Any],
    packet_name: str,
    packet: bytes,
    rows: list[dict[str, Any]],
) -> None:
    probes = result.setdefault("probes", [])
    probes.append(
        {
            "packet": packet_name,
            "tx_hex": packet.hex(),
            "raw_responses": [row.get("raw_hex") for row in rows if row.get("raw_hex")],
            "decoded": [
                decoded
                for row in rows
                for decoded in row.get("packets", [])
                if isinstance(decoded, dict)
            ],
        }
    )
    for row in rows:
        for decoded_packet in row.get("packets", []):
            if not isinstance(decoded_packet, dict):
                continue
            decoded = decoded_packet.get("decoded")
            if not isinstance(decoded, dict):
                continue
            apply_packet_read_decoded(result, packet_name, row, decoded)


def apply_packet_read_decoded(
    result: dict[str, Any],
    packet_name: str,
    row: dict[str, Any],
    decoded: dict[str, Any],
) -> None:
    if "firmware_version" in decoded:
        result["firmware"] = row
        return
    if "battery_level_percent" in decoded:
        result["battery"] = row
        return
    extended_name = decoded.get("extended_name")
    if extended_name == "auth_nonce_response":
        result["auth_nonce"] = row
        return
    if extended_name == "auth_status_response":
        auth_gated = result.setdefault("auth_gated", [])
        if packet_name not in auth_gated:
            auth_gated.append(packet_name)
        return
    if extended_name == "capabilities_response":
        result.setdefault("capabilities", {})[packet_name] = decoded
        return
    if extended_name == "feature_status_response":
        result.setdefault("feature_status", {})[packet_name] = decoded
        return
    if extended_name == "feature_latest_values_response":
        result.setdefault("feature_latest", {})[packet_name] = decoded
        feature_name = decoded.get("feature_name")
        if feature_name == "daytime_hr":
            result["daytime_hr_latest"] = decoded
        elif feature_name == "resting_hr":
            result["resting_hr_latest"] = decoded


async def try_oura_matrix_probe(
    device: BLEDevice,
    timeout: float,
    response_timeout: float,
    read_timeout: float,
    emit: Any,
    *,
    pair: bool,
    pre_read: bool,
    post_read: bool,
    skip_uuid: set[str],
) -> bool:
    notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    expected_hits = 0
    subscribed: list[Any] = []
    aborted = False

    try:
        async with BleakClient(device, timeout=timeout, pair=pair) as client:
            services = client.services
            all_chars = vendor_characteristics(services)
            chars = filter_matrix_characteristics(all_chars, skip_uuid)
            read_targets = [char for char in chars if "read" in set(char.properties)]
            emit(
                "matrix_start",
                {
                    "address": device.address,
                    "connected": is_client_connected(client),
                    "skipped_characteristics": [
                        char_to_json(char)
                        for char in all_chars
                        if char not in chars
                    ],
                    "skip_uuid": sorted(skip_uuid),
                    "characteristics": [char_to_json(char) for char in chars],
                    "packet_probes": [
                        {
                            "name": probe.name,
                            "hex": probe.data.hex(),
                            "expected_extended_names": sorted(
                                probe.expected_extended_names
                            ),
                        }
                        for probe in PACKET_PROBES
                    ],
                    "response_timeout": response_timeout,
                    "read_timeout": read_timeout,
                    "pre_read": pre_read,
                    "post_read": post_read,
                    "pair": pair,
                },
            )

            if pre_read:
                if not await read_matrix_characteristics(
                    client,
                    read_targets,
                    read_timeout,
                    emit,
                    "matrix_char_read",
                ):
                    aborted = True
                    emit("matrix_disconnected", {"stage": "pre_read"})

            for char in chars:
                if aborted:
                    break
                props = set(char.properties)
                if not ({"notify", "indicate"} & props):
                    continue
                try:
                    await client.start_notify(
                        char,
                        notify_callback(char, emit, notifications),
                    )
                    subscribed.append(char)
                    emit("matrix_subscribe", {"characteristic": char_to_json(char)})
                except Exception as exc:
                    emit(
                        "matrix_subscribe_error",
                        {
                            "characteristic": char_to_json(char),
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        },
                    )
                    if disconnect_like_exception(exc) or not is_client_connected(client):
                        aborted = True
                        emit(
                            "matrix_disconnected",
                            {
                                "stage": "subscribe",
                                "characteristic": char_to_json(char),
                            },
                        )
                        break

            emit(
                "matrix_subscription_summary",
                {
                    "connected": False if aborted else is_client_connected(client),
                    "subscribed": [char_to_json(char) for char in subscribed],
                },
            )

            write_targets = [
                char
                for char in chars
                if {"write", "write-without-response"} & set(char.properties)
            ]

            for probe in PACKET_PROBES:
                if aborted:
                    break
                for write_char in write_targets:
                    if aborted:
                        break
                    for response in write_modes(write_char):
                        if not is_client_connected(client):
                            aborted = True
                            emit(
                                "matrix_disconnected",
                                {
                                    "stage": "before_write",
                                    "packet": probe.name,
                                    "write_characteristic": char_to_json(write_char),
                                    "write_response": response,
                                },
                            )
                            break
                        drain_queue(notifications)
                        emit(
                            "matrix_tx",
                            {
                                "packet": probe.name,
                                "tx_hex": probe.data.hex(),
                                "write_response": response,
                                "write_characteristic": char_to_json(write_char),
                            },
                        )
                        try:
                            await client.write_gatt_char(
                                write_char, probe.data, response=response
                            )
                        except Exception as exc:
                            emit(
                                "matrix_write_error",
                                {
                                    "packet": probe.name,
                                    "tx_hex": probe.data.hex(),
                                    "write_response": response,
                                    "write_characteristic": char_to_json(write_char),
                                    "error_type": type(exc).__name__,
                                    "error": str(exc),
                                },
                            )
                            if disconnect_like_exception(exc) or not is_client_connected(
                                client
                            ):
                                aborted = True
                                emit(
                                    "matrix_disconnected",
                                    {
                                        "stage": "write_error",
                                        "packet": probe.name,
                                        "write_characteristic": char_to_json(write_char),
                                        "write_response": response,
                                    },
                                )
                                break
                            continue

                        emit(
                            "matrix_write_success",
                            {
                                "packet": probe.name,
                                "tx_hex": probe.data.hex(),
                                "write_response": response,
                                "write_characteristic": char_to_json(write_char),
                                "connected": is_client_connected(client),
                            },
                        )
                        hits = await collect_matrix_notifications(
                            notifications,
                            probe.name,
                            probe.expected_tags,
                            probe.expected_extended_names,
                            response_timeout,
                            emit,
                        )
                        expected_hits += hits
                        if post_read and not hits:
                            await read_after_matrix_write(
                                client,
                                read_targets,
                                probe.name,
                                write_char,
                                response,
                                probe.expected_tags,
                                probe.expected_extended_names,
                                read_timeout,
                                emit,
                            )
                        if not is_client_connected(client):
                            aborted = True
                            emit(
                                    "matrix_disconnected",
                                    {
                                        "stage": "after_write",
                                        "packet": probe.name,
                                        "write_characteristic": char_to_json(write_char),
                                        "write_response": response,
                                    },
                            )
                            break

            emit(
                "matrix_summary",
                {
                    "address": device.address,
                    "connected": False if aborted else is_client_connected(client),
                    "expected_response_hits": expected_hits,
                    "aborted": aborted,
                },
            )
    except Exception as exc:
        emit(
            "matrix_error",
            {
                "address": device.address,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return False
    finally:
        for char in subscribed:
            with contextlib.suppress(Exception):
                await client.stop_notify(char)

    return expected_hits > 0


def vendor_characteristics(services: Any) -> list[Any]:
    chars: list[Any] = []
    for service in services:
        service_uuid = str(service.uuid).lower()
        if service_uuid != p.OURA_SERVICE_UUID and not service_uuid.startswith("00060000-"):
            continue
        chars.extend(service.characteristics)
    return sorted(
        chars,
        key=lambda char: (
            0 if str(char.uuid).lower().startswith("98ed") else 1,
            getattr(char, "handle", 9999),
            str(char.uuid).lower(),
        ),
    )


def filter_matrix_characteristics(chars: list[Any], skip_uuid: set[str]) -> list[Any]:
    if not skip_uuid:
        return chars
    return [char for char in chars if not characteristic_uuid_matches(char, skip_uuid)]


def characteristic_uuid_matches(char: Any, filters: set[str]) -> bool:
    uuid = str(char.uuid).lower()
    for value in filters:
        if len(value) == 8 and uuid.startswith(value):
            return True
        if uuid == value:
            return True
    return False


def has_oura_connectable_hint(entry: DeviceAdvertisement) -> bool:
    return oura_connectable_hint(entry.advertisement)


def char_to_json(char: Any) -> dict[str, Any]:
    return {
        "uuid": str(char.uuid).lower(),
        "handle": getattr(char, "handle", None),
        "description": getattr(char, "description", None),
        "properties": sorted(char.properties),
    }


def write_modes(char: Any) -> list[bool]:
    props = set(char.properties)
    modes: list[bool] = []
    if "write" in props:
        modes.append(True)
    if "write-without-response" in props:
        modes.append(False)
    return modes


def find_characteristic(chars: list[Any], uuid: str, handle: int) -> Any | None:
    wanted_uuid = uuid.lower()
    for char in chars:
        if str(char.uuid).lower() == wanted_uuid:
            return char
    for char in chars:
        if getattr(char, "handle", None) == handle:
            return char
    return None


async def read_matrix_characteristics(
    client: BleakClient,
    read_targets: list[Any],
    read_timeout: float,
    emit: Any,
    event_name: str,
) -> bool:
    for char in read_targets:
        try:
            raw = bytes(
                await asyncio.wait_for(
                    client.read_gatt_char(char),
                    timeout=read_timeout,
                )
            )
        except Exception as exc:
            emit(
                f"{event_name}_error",
                {
                    "characteristic": char_to_json(char),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            if disconnect_like_exception(exc):
                return False
            continue
        emit(
            event_name,
            {
                "characteristic": char_to_json(char),
                "raw_hex": raw.hex(),
                "packets": decode_packets(raw),
            },
        )
    return True


def is_client_connected(client: BleakClient) -> bool | None:
    value = getattr(client, "is_connected", None)
    if callable(value):
        with contextlib.suppress(Exception):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                return bool(value())
        return None
    if value is None:
        return None
    return bool(value)


def disconnect_like_exception(exc: Exception) -> bool:
    return isinstance(exc, EOFError) or is_disconnect_like_error(str(exc))


def is_disconnect_like_error(text: str) -> bool:
    return "Not connected" in text or "Software caused connection abort" in text


def notify_callback(char: Any, emit: Any, queue: asyncio.Queue[dict[str, Any]]) -> Any:
    char_row = char_to_json(char)

    def callback(_sender: Any, data: bytearray) -> None:
        raw = bytes(data)
        row = {
            "characteristic": char_row,
            "raw_hex": raw.hex(),
            "packets": decode_packets(raw),
        }
        emit("matrix_rx", row)
        queue.put_nowait(row)

    return callback


def drain_queue(queue: asyncio.Queue[dict[str, Any]]) -> None:
    while True:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            return


async def collect_matrix_notifications(
    queue: asyncio.Queue[dict[str, Any]],
    packet_name: str,
    expected_tags: frozenset[int],
    expected_extended_names: frozenset[str],
    response_timeout: float,
    emit: Any,
) -> int:
    deadline = time.monotonic() + response_timeout
    total = 0
    hits = 0
    while time.monotonic() < deadline:
        try:
            row = await asyncio.wait_for(
                queue.get(), timeout=max(0.1, deadline - time.monotonic())
            )
        except TimeoutError:
            break
        total += 1
        row_hits = matching_expected_packets(
            row, expected_tags, expected_extended_names
        )
        hits += row_hits
        if row_hits:
            emit("matrix_expected_response", {"packet": packet_name, "response": row})
    if total == 0:
        emit("matrix_no_notification", {"packet": packet_name})
    return hits


async def collect_packet_notifications(
    queue: asyncio.Queue[dict[str, Any]],
    packet_name: str,
    expected_tags: frozenset[int],
    expected_extended_names: frozenset[str],
    response_timeout: float,
    emit: Any,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + response_timeout
    matches: list[dict[str, Any]] = []
    total = 0
    while time.monotonic() < deadline:
        try:
            row = await asyncio.wait_for(
                queue.get(), timeout=max(0.1, deadline - time.monotonic())
            )
        except TimeoutError:
            break
        total += 1
        if matching_expected_packets(row, expected_tags, expected_extended_names):
            matches.append(row)
            emit(
                "packet_read_expected_response",
                {"packet": packet_name, "response": row},
            )
            break
    if total == 0:
        emit("packet_read_no_notification", {"packet": packet_name})
    elif not matches:
        emit("packet_read_no_match", {"packet": packet_name, "notifications": total})
    return matches


async def read_after_matrix_write(
    client: BleakClient,
    read_targets: list[Any],
    packet_name: str,
    write_char: Any,
    response: bool,
    expected_tags: frozenset[int],
    expected_extended_names: frozenset[str],
    read_timeout: float,
    emit: Any,
) -> None:
    for read_char in read_targets:
        try:
            raw = bytes(
                await asyncio.wait_for(
                    client.read_gatt_char(read_char),
                    timeout=read_timeout,
                )
            )
        except Exception as exc:
            emit(
                "matrix_post_write_read_error",
                {
                    "packet": packet_name,
                    "write_characteristic": char_to_json(write_char),
                    "read_characteristic": char_to_json(read_char),
                    "write_response": response,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            continue
        row = {
            "packet": packet_name,
            "write_characteristic": char_to_json(write_char),
            "read_characteristic": char_to_json(read_char),
            "write_response": response,
            "raw_hex": raw.hex(),
            "packets": decode_packets(raw),
        }
        emit("matrix_post_write_read", row)
        if matching_expected_packets(row, expected_tags, expected_extended_names):
            emit("matrix_expected_response", {"packet": packet_name, "response": row})


def matching_expected_packets(
    row: dict[str, Any],
    expected_tags: frozenset[int],
    expected_extended_names: frozenset[str] = frozenset(),
) -> int:
    hits = 0
    for packet in row.get("packets", []):
        tag = packet.get("tag") if isinstance(packet, dict) else None
        if not isinstance(tag, str) or not tag.startswith("0x"):
            continue
        try:
            tag_value = int(tag, 16)
        except ValueError:
            continue
        if tag_value not in expected_tags:
            continue
        if expected_extended_names:
            decoded = packet.get("decoded") if isinstance(packet, dict) else None
            extended_name = (
                decoded.get("extended_name") if isinstance(decoded, dict) else None
            )
            if extended_name == "auth_status_response":
                hits += 1
                continue
            if extended_name not in expected_extended_names:
                continue
        hits += 1
    return hits


def decode_packets(raw: bytes) -> list[dict[str, Any]]:
    try:
        return [p.parse_response(packet) for packet in p.parse_packets(raw)]
    except Exception as exc:
        return [
            {
                "parse_error_type": type(exc).__name__,
                "parse_error": str(exc),
                "raw_hex": raw.hex(),
            }
        ]


async def try_gatt_proof(device: BLEDevice, timeout: float, emit: Any) -> bool:
    try:
        async with BleakClient(device, timeout=timeout) as client:
            services = [service_to_json(service) for service in client.services]
            reads = await read_standard_gatt(client)
        emit(
            "gatt_services",
            {
                "address": device.address,
                "name": device.name,
                "service_count": len(services),
                "characteristic_count": sum(
                    len(service["characteristics"]) for service in services
                ),
                "services": services,
                "standard_gatt_reads": reads,
            },
        )
        return True
    except Exception as exc:
        emit(
            "gatt_error",
            {
                "address": device.address,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        return False


async def read_standard_gatt(client: BleakClient) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label, uuid in STANDARD_GATT_READS:
        try:
            raw = bytes(await client.read_gatt_char(uuid))
        except Exception as exc:
            rows.append(
                {
                    "label": label,
                    "uuid": uuid,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            continue
        rows.append(
            {
                "label": label,
                "uuid": uuid,
                "hex": raw.hex(),
                "decoded": decode_standard_gatt_value(label, raw),
                "text": decode_text(raw),
            }
        )
    return rows


def decode_standard_gatt_value(label: str, raw: bytes) -> Any:
    if label == "gap_peripheral_preferred_connection_parameters" and len(raw) == 8:
        values = [
            int.from_bytes(raw[index : index + 2], "little")
            for index in range(0, 8, 2)
        ]
        return {
            "min_connection_interval_units": values[0],
            "max_connection_interval_units": values[1],
            "slave_latency": values[2],
            "supervision_timeout_units": values[3],
            "min_connection_interval_ms": values[0] * 1.25,
            "max_connection_interval_ms": values[1] * 1.25,
            "supervision_timeout_ms": values[3] * 10,
        }
    if label in {
        "gap_central_address_resolution",
        "gap_resolvable_private_address_only",
    } and len(raw) == 1:
        return bool(raw[0])
    if label == "gap_appearance" and len(raw) == 2:
        return {"appearance": int.from_bytes(raw, "little")}
    return None


def decode_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if all(char.isprintable() or char.isspace() for char in text):
        return text
    return None


def candidate_reason(device: BLEDevice, advertisement: AdvertisementData | None) -> str:
    names = [device.name or ""]
    if advertisement:
        names.append(advertisement.local_name or "")
        manufacturer = advertisement.manufacturer_data.get(p.OURA_COMPANY_ID)
        if manufacturer and oura_connectable_hint(advertisement):
            return "oura_connectable_manufacturer_data"
        if manufacturer:
            return "oura_manufacturer_data"
        if any(
            str(uuid).lower() == p.OURA_SERVICE_UUID
            for uuid in advertisement.service_uuids
        ):
            return "oura_service_uuid"
    if any("oura" in name.lower() for name in names):
        return "oura_name"
    if any(name for name in names):
        return "named_device"
    return "generic"


if __name__ == "__main__":
    raise SystemExit(main())
