#!/usr/bin/env python3
"""Provision a reset Oura Ring 4 auth key through BlueZ D-Bus.

This mirrors the APK-confirmed fresh-ring path:

1. Pair/bond at the BLE layer.
2. Generate a local 16-byte auth key.
3. Write SetAuthKey (`24 10 <key>`).
4. Persist the key locally.
5. Authenticate with nonce + AES.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from oura_ring4_ble import protocol as p

BLUEZ = "org.bluez"
OBJ_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPS = "org.freedesktop.DBus.Properties"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
CHAR = "org.bluez.GattCharacteristic1"
AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
AGENT_PATH = "/com/carve/oura/ProvisionAgent"
SET_AUTH_KEY_COMPLETED = {0x00, 0x05}
DEFAULT_STATE_PATH = "state/ring-auth-key.json"


def main() -> int:
    args = parse_args()
    if args.restart_bluetooth_first:
        restart_bluetooth()

    import dbus
    import dbus.mainloop.glib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    emit = make_emitter()
    agent = None
    try:
        setup_adapter(bus, args.adapter, pairable=True)
        if args.auto_confirm_agent:
            agent = register_auto_confirm_agent(bus, args.agent_capability, emit)
        result = provision(args, bus, emit)
        emit("read_result", build_authenticated_read_result(result))
        emit("provision_done", result)
        return 0
    except Exception as exc:
        emit(
            "provision_error",
            {"error_type": type(exc).__name__, "error": str(exc)},
        )
        return 1
    finally:
        if agent is not None:
            agent.unregister()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pair a reset Oura Ring 4 and install a local auth key."
    )
    parser.add_argument("--adapter", default="/org/bluez/hci0")
    parser.add_argument("--address", default="", help="preferred ring address")
    parser.add_argument("--device-path", default="", help="preferred BlueZ Device1 path")
    parser.add_argument("--scan-seconds", type=float, default=20.0)
    parser.add_argument("--pair-timeout", type=float, default=45.0)
    parser.add_argument("--connect-timeout", type=float, default=12.0)
    parser.add_argument("--response-timeout", type=float, default=5.0)
    parser.add_argument("--settle-seconds", type=float, default=0.2)
    parser.add_argument(
        "--state-path",
        default=DEFAULT_STATE_PATH,
        help="local JSON file for the generated raw auth key",
    )
    parser.add_argument(
        "--clear-stale",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="remove matching stale Oura Device1 objects before discovery",
    )
    parser.add_argument(
        "--force-new-key",
        action="store_true",
        help="ignore an existing state file and send a new SetAuthKey",
    )
    parser.add_argument(
        "--auto-confirm-agent",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="register a temporary BlueZ pairing agent",
    )
    parser.add_argument(
        "--agent-capability",
        default="KeyboardDisplay",
        choices=[
            "DisplayOnly",
            "DisplayYesNo",
            "KeyboardOnly",
            "NoInputNoOutput",
            "KeyboardDisplay",
        ],
    )
    parser.add_argument(
        "--restart-bluetooth-first",
        action="store_true",
        help="run sudo -n systemctl restart bluetooth before D-Bus setup",
    )
    parser.add_argument(
        "--live-hr-probe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="after auth, request daytime HR connected-live/latest mode",
    )
    parser.add_argument("--live-hr-seconds", type=float, default=12.0)
    parser.add_argument(
        "--meditation-hr-probe",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="after auth, try the APK-confirmed daytime-HR meditation session path",
    )
    parser.add_argument("--meditation-duration-minutes", type=int, default=1)
    parser.add_argument("--meditation-listen-seconds", type=float, default=45.0)
    parser.add_argument(
        "--session-cleanup",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="restore daytime HR automatic/off subscription after meditation probing",
    )
    return parser.parse_args()


def provision(args: argparse.Namespace, bus: Any, emit: Any) -> dict[str, Any]:
    if args.clear_stale:
        removed = remove_stale_oura_devices(bus, args.adapter, args.address, emit)
        if removed:
            pump(args.settle_seconds)

    objects = discover_objects(bus, args.adapter, args.scan_seconds, emit)
    device_path, device_props = find_device(objects, args.address, args.device_path)
    emit("provision_device", device_summary(device_path, device_props))

    pair_and_connect(args, bus, device_path, device_props, emit)
    objects, device_props, notify_path, write_path = wait_for_io_characteristics(
        bus,
        device_path,
        args.connect_timeout,
        emit,
    )
    emit(
        "provision_characteristics",
        {
            "notify_path": notify_path,
            "write_path": write_path,
            "bluez_connected": bool(device_props.get("Connected", False)),
            "services_resolved": bool(device_props.get("ServicesResolved", False)),
        },
    )

    notifications: list[bytes] = []
    active_request: dict[str, str] = {}

    def on_props_changed(
        interface: str,
        changed: dict[str, Any],
        _invalidated: list[str],
        path: str | None = None,
    ) -> None:
        if path != notify_path or interface != CHAR or "Value" not in changed:
            return
        raw = bytes(changed["Value"])
        notifications.append(raw)
        emit(
            "provision_notify",
            {
                "path": path,
                "context": dict(active_request),
                "raw_hex": raw.hex(),
                "decoded": decode_raw(raw),
            },
        )

    bus.add_signal_receiver(
        on_props_changed,
        dbus_interface=PROPS,
        signal_name="PropertiesChanged",
        path=notify_path,
        path_keyword="path",
    )

    notify = dbus_interface(bus, notify_path, CHAR)
    write = dbus_interface(bus, write_path, CHAR)
    with suppress_dbus_error("org.bluez.Error.Failed", "Already notifying"):
        notify.StartNotify()
    pump(args.settle_seconds)

    key, state_source = load_or_create_key(args, device_path, device_props, emit)
    set_auth_status: dict[str, Any] | None = None
    if state_source == "generated":
        set_auth_status = send_set_auth_key(
            write,
            notifications,
            active_request,
            key,
            args.response_timeout,
            emit,
        )
        write_state_file(
            Path(args.state_path),
            build_state_record(key, device_path, device_props, set_auth_status),
        )
        emit(
            "provision_state_written",
            {
                "path": args.state_path,
                "auth_key_sha256_16": key_fingerprint(key),
                "set_auth_key_status": set_auth_status,
            },
        )

    auth = authenticate(
        write,
        notifications,
        active_request,
        key,
        args.response_timeout,
        emit,
    )
    live_hr = None
    if args.live_hr_probe and auth.get("auth_result") == "success":
        live_hr = run_live_hr_probe(
            write,
            notifications,
            active_request,
            args.response_timeout,
            args.live_hr_seconds,
            emit,
        )
    meditation_hr = None
    if args.meditation_hr_probe and auth.get("auth_result") == "success":
        meditation_hr = run_meditation_hr_probe(
            write,
            notifications,
            active_request,
            args.response_timeout,
            args.meditation_duration_minutes,
            args.meditation_listen_seconds,
            args.session_cleanup,
            emit,
        )

    return {
        "device": device_summary(device_path, device_props),
        "state_path": args.state_path,
        "state_source": state_source,
        "auth_key_sha256_16": key_fingerprint(key),
        "set_auth_key": set_auth_status,
        "authentication": auth,
        "live_hr_probe": live_hr,
        "meditation_hr_probe": meditation_hr,
    }


def build_authenticated_read_result(result: dict[str, Any]) -> dict[str, Any]:
    live_hr = result.get("live_hr_probe") or {}
    meditation_hr = result.get("meditation_hr_probe") or {}
    live_latest = response_payload(live_hr.get("latest_values"))
    meditation_latest = response_payload(meditation_hr.get("latest_values"))
    latest_values = meditation_latest or live_latest

    return {
        "source": "authenticated_provision",
        "device": result.get("device"),
        "authentication": result.get("authentication"),
        "feature_set_results": collect_feature_results(live_hr, meditation_hr),
        "daytime_hr": {
            "latest_values": latest_values,
            "live_latest_values": live_latest,
            "meditation_latest_values": meditation_latest,
            "live_notification_count": live_hr.get("notification_count", 0),
            "meditation_notification_count": meditation_hr.get(
                "notification_count", 0
            ),
        },
        "realtime_measurements": {
            "on_demand_start": response_payload(
                meditation_hr.get("realtime_on_demand_start")
            ),
            "cleanup": [
                response_payload(row)
                for row in meditation_hr.get("cleanup_packets", [])
                if response_payload(row) is not None
            ],
        },
        "probes": collect_probe_summaries(live_hr, meditation_hr),
    }


def response_payload(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    if row.get("ok") is False:
        return {
            "ok": False,
            "packet": row.get("packet"),
            "tx_hex": row.get("tx_hex"),
            "error_type": row.get("error_type"),
            "error": row.get("error"),
        }
    response = row.get("response")
    if isinstance(response, dict):
        return {
            "ok": row.get("ok", True),
            "packet": row.get("packet"),
            "tx_hex": row.get("tx_hex"),
            "response": response,
        }
    if "decoded" in row or "raw_hex" in row:
        return {"ok": True, "response": row}
    return None


def collect_feature_results(*probe_sections: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in probe_sections:
        if not isinstance(section, dict):
            continue
        for key in ("enabled_packets", "start_packets", "cleanup_packets"):
            for item in section.get(key, []):
                payload = response_payload(item)
                if payload is None:
                    continue
                decoded = payload.get("response", {}).get("decoded", {})
                if str(decoded.get("extended_name", "")).startswith("set_feature_"):
                    rows.append(payload)
    return rows


def collect_probe_summaries(*probe_sections: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in probe_sections:
        if not isinstance(section, dict):
            continue
        for key in (
            "latest_values",
            "realtime_on_demand_start",
            "enabled_packets",
            "start_packets",
            "cleanup_packets",
        ):
            value = section.get(key)
            items = value if isinstance(value, list) else [value]
            for item in items:
                payload = response_payload(item)
                if payload is not None:
                    rows.append(payload)
    return rows


def pair_and_connect(
    args: argparse.Namespace,
    bus: Any,
    device_path: str,
    device_props: dict[str, Any],
    emit: Any,
) -> None:
    device = dbus_interface(bus, device_path, DEVICE)
    props = dbus_interface(bus, device_path, PROPS)
    if not bool(device_props.get("Paired", False)):
        emit("provision_pair_start", {"path": device_path})
        device.Pair(timeout=args.pair_timeout)
        pump(args.settle_seconds)
        device_props = current_device_props(bus, device_path)
        emit(
            "provision_pair_done",
            {
                "paired": bool(device_props.get("Paired", False)),
                "bonded": bool(device_props.get("Bonded", False)),
            },
        )
    props.Set(DEVICE, "Trusted", dbus_bool(True))
    device_props = current_device_props(bus, device_path)
    if not bool(device_props.get("Connected", False)):
        emit("provision_connect_start", {"path": device_path})
        device.Connect(timeout=args.connect_timeout)
        pump(args.settle_seconds)


def send_set_auth_key(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    key: bytes,
    timeout: float,
    emit: Any,
) -> dict[str, Any]:
    packet = request_packet(
        write,
        notifications,
        active_request,
        "set_auth_key",
        p.build_set_auth_key_request(key),
        expect_tag=p.TAG_SET_AUTH_KEY_STATUS,
        extended_id=None,
        timeout=timeout,
        emit=emit,
    )
    decoded = p.parse_response(packet)["decoded"]
    status = int(decoded["status"])
    if status not in SET_AUTH_KEY_COMPLETED:
        raise RuntimeError(f"SetAuthKey failed: {decoded}")
    return decoded


def authenticate(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    key: bytes,
    timeout: float,
    emit: Any,
) -> dict[str, Any]:
    nonce_packet = request_packet(
        write,
        notifications,
        active_request,
        "auth_nonce",
        p.build_get_auth_nonce_request(),
        expect_tag=p.TAG_EXTENDED,
        extended_id=p.EXT_AUTH_NONCE_RESPONSE,
        timeout=timeout,
        emit=emit,
    )
    nonce_decoded = p.parse_extended_response(nonce_packet.payload)
    nonce = bytes.fromhex(str(nonce_decoded["nonce_hex"]))
    auth_packet = request_packet(
        write,
        notifications,
        active_request,
        "authenticate",
        p.build_authenticate_request(key, nonce),
        expect_tag=p.TAG_EXTENDED,
        extended_id=p.EXT_AUTHENTICATE_RESPONSE,
        timeout=timeout,
        emit=emit,
    )
    auth_decoded = p.parse_extended_response(auth_packet.payload)
    return {
        "nonce_length": nonce_decoded["nonce_length"],
        "auth_state": auth_decoded["auth_state"],
        "auth_result": auth_decoded["auth_result"],
    }


def run_live_hr_probe(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    response_timeout: float,
    live_seconds: float,
    emit: Any,
) -> dict[str, Any]:
    responses: list[dict[str, Any]] = []
    for packet_name, packet, extended_id in (
        (
            "feature_mode:daytime_hr:connected_live",
            p.build_set_feature_mode_request(0x02, 0x03),
            p.EXT_SET_FEATURE_MODE_RESPONSE,
        ),
        (
            "feature_subscription:daytime_hr:latest",
            p.build_set_feature_subscription_request(0x02, 0x02),
            p.EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE,
        ),
    ):
        response = request_packet(
            write,
            notifications,
            active_request,
            packet_name,
            packet,
            expect_tag=p.TAG_EXTENDED,
            extended_id=extended_id,
            timeout=response_timeout,
            emit=emit,
        )
        responses.append(p.parse_response(response))

    started = len(notifications)
    deadline = time.monotonic() + max(0.0, live_seconds)
    while time.monotonic() < deadline:
        pump(min(0.1, max(0.0, deadline - time.monotonic())))
    live_raw = notifications[started:]
    latest_values = request_packet_result(
        write,
        notifications,
        active_request,
        "feature_latest:daytime_hr",
        p.build_get_feature_latest_values_request(0x02),
        expect_tag=p.TAG_EXTENDED,
        extended_id=p.EXT_FEATURE_LATEST_VALUES_RESPONSE,
        timeout=response_timeout,
        emit=emit,
    )
    return {
        "enabled_packets": responses,
        "listen_seconds": live_seconds,
        "notification_count": len(live_raw),
        "notifications": [decode_raw(raw) for raw in live_raw[:20]],
        "truncated": len(live_raw) > 20,
        "latest_values": latest_values,
    }


def run_meditation_hr_probe(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    response_timeout: float,
    duration_minutes: int,
    listen_seconds: float,
    cleanup: bool,
    emit: Any,
) -> dict[str, Any]:
    start_packets = [
        (
            f"feature_parameters:daytime_hr:meditation:{duration_minutes}m",
            p.build_set_daytime_hr_meditation_parameters_request(duration_minutes),
            p.TAG_EXTENDED,
            p.EXT_SET_FEATURE_PARAMETERS_RESPONSE,
        ),
        (
            "feature_mode:daytime_hr:requested",
            p.build_set_feature_mode_request(0x02, 0x02),
            p.TAG_EXTENDED,
            p.EXT_SET_FEATURE_MODE_RESPONSE,
        ),
        (
            "feature_subscription:daytime_hr:latest",
            p.build_set_feature_subscription_request(0x02, 0x02),
            p.TAG_EXTENDED,
            p.EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE,
        ),
    ]
    start_responses = [
        request_packet_result(
            write,
            notifications,
            active_request,
            packet_name,
            packet,
            expect_tag=expect_tag,
            extended_id=extended_id,
            timeout=response_timeout,
            emit=emit,
        )
        for packet_name, packet, expect_tag, extended_id in start_packets
    ]

    realtime_start = request_packet_result(
        write,
        notifications,
        active_request,
        "realtime_measurements:on_demand:start",
        p.build_set_realtime_measurements_request(
            ["on_demand"],
            maximum_duration_minutes=duration_minutes,
            delay=10,
        ),
        expect_tag=p.TAG_REALTIME_MEASUREMENTS_STATUS,
        extended_id=None,
        timeout=response_timeout,
        emit=emit,
    )

    # Keep unmatched notifications seen while waiting for the optional realtime
    # status; a ring may stream data even if it never returns the legacy 0x07 ack.
    started = 0
    deadline = time.monotonic() + max(0.0, listen_seconds)
    while time.monotonic() < deadline:
        pump(min(0.1, max(0.0, deadline - time.monotonic())))
    live_raw = notifications[started:]
    latest_values = request_packet_result(
        write,
        notifications,
        active_request,
        "feature_latest:daytime_hr",
        p.build_get_feature_latest_values_request(0x02),
        expect_tag=p.TAG_EXTENDED,
        extended_id=p.EXT_FEATURE_LATEST_VALUES_RESPONSE,
        timeout=response_timeout,
        emit=emit,
    )

    cleanup_responses: list[dict[str, Any]] = []
    if cleanup:
        cleanup_packets = [
            (
                "realtime_measurements:disable",
                p.build_disable_realtime_measurements_request(),
                p.TAG_REALTIME_MEASUREMENTS_STATUS,
                None,
            ),
            (
                "feature_mode:daytime_hr:off",
                p.build_set_feature_mode_request(0x02, 0x00),
                p.TAG_EXTENDED,
                p.EXT_SET_FEATURE_MODE_RESPONSE,
            ),
            (
                "feature_parameters:daytime_hr:meditation:0m",
                p.build_set_daytime_hr_meditation_parameters_request(0),
                p.TAG_EXTENDED,
                p.EXT_SET_FEATURE_PARAMETERS_RESPONSE,
            ),
            (
                "feature_mode:daytime_hr:automatic",
                p.build_set_feature_mode_request(0x02, 0x01),
                p.TAG_EXTENDED,
                p.EXT_SET_FEATURE_MODE_RESPONSE,
            ),
            (
                "feature_subscription:daytime_hr:off",
                p.build_set_feature_subscription_request(0x02, 0x00),
                p.TAG_EXTENDED,
                p.EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE,
            ),
        ]
        cleanup_responses = [
            request_packet_result(
                write,
                notifications,
                active_request,
                packet_name,
                packet,
                expect_tag=expect_tag,
                extended_id=extended_id,
                timeout=response_timeout,
                emit=emit,
            )
            for packet_name, packet, expect_tag, extended_id in cleanup_packets
        ]

    return {
        "duration_minutes": duration_minutes,
        "start_packets": start_responses,
        "realtime_on_demand_start": realtime_start,
        "listen_seconds": listen_seconds,
        "notification_count": len(live_raw),
        "notifications": [decode_raw(raw) for raw in live_raw[:50]],
        "truncated": len(live_raw) > 50,
        "latest_values": latest_values,
        "cleanup_packets": cleanup_responses,
    }


def request_packet_result(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    packet_name: str,
    packet: bytes,
    *,
    expect_tag: int,
    extended_id: int | None,
    timeout: float,
    emit: Any,
) -> dict[str, Any]:
    try:
        response = request_packet(
            write,
            notifications,
            active_request,
            packet_name,
            packet,
            expect_tag=expect_tag,
            extended_id=extended_id,
            timeout=timeout,
            emit=emit,
        )
    except Exception as exc:
        error = {
            "packet": packet_name,
            "tx_hex": request_context(packet_name, packet)["tx_hex"],
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        emit("provision_request_error", error)
        return error
    return {
        "packet": packet_name,
        "tx_hex": request_context(packet_name, packet)["tx_hex"],
        "ok": True,
        "response": p.parse_response(response),
    }


def request_packet(
    write: Any,
    notifications: list[bytes],
    active_request: dict[str, str],
    packet_name: str,
    packet: bytes,
    *,
    expect_tag: int,
    extended_id: int | None,
    timeout: float,
    emit: Any,
) -> p.Packet:
    notifications.clear()
    active_request.clear()
    active_request.update(request_context(packet_name, packet))
    emit("provision_tx", dict(active_request))
    write.WriteValue(
        dbus_array(packet),
        dbus_dict({"type": "request"}),
    )
    deadline = time.monotonic() + max(0.0, timeout)
    seen = 0
    while time.monotonic() < deadline:
        pump(0.03)
        for raw in notifications[seen:]:
            seen += 1
            try:
                packets = p.parse_packets(raw)
            except p.ProtocolError:
                continue
            for packet_obj in packets:
                if packet_matches(packet_obj, expect_tag, extended_id):
                    active_request.clear()
                    return packet_obj
    active_request.clear()
    raise TimeoutError(f"timed out waiting for {packet_name}")


def request_context(packet_name: str, packet: bytes) -> dict[str, Any]:
    context: dict[str, Any] = {"packet": packet_name, "tx_length": len(packet)}
    if packet_name == "set_auth_key":
        context["tx_hex"] = "2410<redacted-auth-key>"
    else:
        context["tx_hex"] = packet.hex()
    return context


def packet_matches(packet: p.Packet, expect_tag: int, extended_id: int | None) -> bool:
    if packet.tag != expect_tag:
        return False
    if extended_id is None:
        return True
    return bool(packet.payload and packet.payload[0] == extended_id)


def load_or_create_key(
    args: argparse.Namespace,
    device_path: str,
    device_props: dict[str, Any],
    emit: Any,
) -> tuple[bytes, str]:
    state_path = Path(args.state_path)
    if state_path.exists() and not args.force_new_key:
        record = json.loads(state_path.read_text())
        key = bytes.fromhex(str(record["auth_key_hex"]))
        if len(key) != 16:
            raise RuntimeError(f"state key is not 16 bytes: {state_path}")
        emit(
            "provision_state_loaded",
            {
                "path": str(state_path),
                "auth_key_sha256_16": key_fingerprint(key),
                "ring_address": record.get("ring_address"),
            },
        )
        return key, "state"

    key = p.generate_auth_key()
    emit(
        "provision_key_generated",
        {
            "auth_key_sha256_16": key_fingerprint(key),
            "ring_address": str(device_props.get("Address", "")),
            "ring_device_path": device_path,
        },
    )
    return key, "generated"


def build_state_record(
    key: bytes,
    device_path: str,
    device_props: dict[str, Any],
    set_auth_status: dict[str, Any],
) -> dict[str, Any]:
    return {
        "created_at_unix": int(time.time()),
        "ring_address": str(device_props.get("Address", "")),
        "ring_address_type": str(device_props.get("AddressType", "")),
        "ring_name": str(device_props.get("Name", "")),
        "ring_device_path": device_path,
        "auth_key_hex": key.hex(),
        "auth_key_sha256_16": key_fingerprint(key),
        "source": "local_uuid_random_apk_layout",
        "set_auth_key_status": set_auth_status,
    }


def write_state_file(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def discover_objects(bus: Any, adapter_path: str, scan_seconds: float, emit: Any) -> dict:
    adapter = dbus_interface(bus, adapter_path, ADAPTER)
    emit("provision_scan_start", {"adapter": adapter_path, "scan_seconds": scan_seconds})
    with suppress_dbus_error("org.bluez.Error.InProgress", ""):
        adapter.StartDiscovery()
    deadline = time.monotonic() + max(0.0, scan_seconds)
    objects = get_managed_objects(bus)
    while time.monotonic() < deadline:
        objects = get_managed_objects(bus)
        if find_oura_candidates(objects):
            break
        pump(0.1)
    with suppress_dbus_error("org.bluez.Error.Failed", ""):
        adapter.StopDiscovery()
    candidates = [
        device_summary(path, props)
        for _score, path, props in sorted(
            find_oura_candidates(objects),
            key=lambda row: (-row[0], row[1]),
        )
    ]
    emit("provision_scan_done", {"candidates": candidates})
    return objects


def find_device(
    objects: dict[str, dict[str, dict[str, Any]]],
    address: str,
    device_path: str,
) -> tuple[str, dict[str, Any]]:
    if device_path:
        props = objects.get(device_path, {}).get(DEVICE)
        if not props:
            raise RuntimeError(f"Device1 path not found: {device_path}")
        return device_path, props
    candidates = find_oura_candidates(objects, address=address)
    if not candidates:
        raise RuntimeError("no Oura Ring 4 BlueZ Device1 object found")
    candidates.sort(key=lambda row: (-row[0], row[1]))
    _score, path, props = candidates[0]
    return path, props


def find_oura_candidates(
    objects: dict[str, dict[str, dict[str, Any]]],
    *,
    address: str = "",
) -> list[tuple[int, str, dict[str, Any]]]:
    normalized = address.lower()
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for path, interfaces in objects.items():
        props = interfaces.get(DEVICE)
        if not props:
            continue
        score = device_score(props, normalized)
        if score:
            candidates.append((score, path, props))
    return candidates


def device_score(props: dict[str, Any], normalized_address: str = "") -> int:
    props_address = str(props.get("Address", "")).lower()
    name = str(props.get("Name", ""))
    uuids = {str(uuid).lower() for uuid in props.get("UUIDs", [])}
    manufacturer_data = props.get("ManufacturerData", {})
    score = 0
    if normalized_address and props_address == normalized_address:
        score += 100
    if p.OURA_SERVICE_UUID in uuids:
        score += 30
    if p.OURA_COMPANY_ID in {int(key) for key in manufacturer_data.keys()}:
        score += 25
    if "oura" in name.lower():
        score += 20
    if bool(props.get("Connected", False)):
        score += 5
    if bool(props.get("Paired", False)):
        score += 5
    return score


def remove_stale_oura_devices(
    bus: Any,
    adapter_path: str,
    address: str,
    emit: Any,
) -> list[dict[str, Any]]:
    adapter = dbus_interface(bus, adapter_path, ADAPTER)
    objects = get_managed_objects(bus)
    removed: list[dict[str, Any]] = []
    for _score, path, props in find_oura_candidates(objects, address=address):
        if address and str(props.get("Address", "")).lower() != address.lower():
            continue
        summary = device_summary(path, props)
        emit("provision_remove_stale_start", summary)
        adapter.RemoveDevice(dbus_object_path(path))
        removed.append(summary)
    if removed:
        emit("provision_remove_stale_done", {"removed": removed})
    return removed


def wait_for_io_characteristics(
    bus: Any,
    device_path: str,
    timeout: float,
    emit: Any,
) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, Any], str, str]:
    deadline = time.monotonic() + max(0.0, timeout)
    last_error = ""
    while True:
        objects = get_managed_objects(bus)
        device_props = objects.get(device_path, {}).get(DEVICE)
        if not device_props:
            raise RuntimeError(f"Device1 path disappeared: {device_path}")
        try:
            notify_path, write_path = find_io_characteristics(objects, device_path)
            return objects, device_props, notify_path, write_path
        except RuntimeError as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            emit(
                "provision_services_timeout",
                {
                    "connected": bool(device_props.get("Connected", False)),
                    "services_resolved": bool(device_props.get("ServicesResolved", False)),
                    "error": last_error,
                },
            )
            raise RuntimeError(last_error)
        pump(0.05)


def find_io_characteristics(
    objects: dict[str, dict[str, dict[str, Any]]],
    device_path: str,
) -> tuple[str, str]:
    notify_path = ""
    write_path = ""
    for path, interfaces in objects.items():
        if not path.startswith(device_path + "/"):
            continue
        props = interfaces.get(CHAR)
        if not props:
            continue
        uuid = str(props.get("UUID", "")).lower()
        if uuid == p.OURA_NOTIFY_UUID:
            notify_path = path
        elif uuid == p.OURA_WRITE_UUID:
            write_path = path
    if not notify_path or not write_path:
        raise RuntimeError("could not find Oura write/notify characteristics")
    return notify_path, write_path


def current_device_props(bus: Any, device_path: str) -> dict[str, Any]:
    objects = get_managed_objects(bus)
    props = objects.get(device_path, {}).get(DEVICE)
    if not props:
        raise RuntimeError(f"Device1 path disappeared: {device_path}")
    return props


def get_managed_objects(bus: Any) -> dict[str, dict[str, dict[str, Any]]]:
    manager = dbus_interface(bus, "/", OBJ_MANAGER)
    return manager.GetManagedObjects()


def setup_adapter(bus: Any, adapter_path: str, *, pairable: bool) -> None:
    props = dbus_interface(bus, adapter_path, PROPS)
    props.Set(ADAPTER, "Powered", dbus_bool(True))
    props.Set(ADAPTER, "Pairable", dbus_bool(pairable))


def register_auto_confirm_agent(bus: Any, capability: str, emit: Any) -> Any:
    import dbus.service

    class AutoConfirmAgent(dbus.service.Object):
        def __init__(self) -> None:
            super().__init__(bus, AGENT_PATH)
            self.manager = dbus_interface(bus, "/org/bluez", AGENT_MANAGER)
            self.registered = False

        @dbus.service.method(AGENT, in_signature="", out_signature="")
        def Release(self) -> None:
            emit("provision_agent_release", {})

        @dbus.service.method(AGENT, in_signature="os", out_signature="")
        def AuthorizeService(self, device: str, uuid: str) -> None:
            emit("provision_agent_authorize_service", {"device": device, "uuid": uuid})

        @dbus.service.method(AGENT, in_signature="o", out_signature="")
        def RequestAuthorization(self, device: str) -> None:
            emit("provision_agent_authorize", {"device": device})

        @dbus.service.method(AGENT, in_signature="ou", out_signature="")
        def RequestConfirmation(self, device: str, passkey: int) -> None:
            emit(
                "provision_agent_confirm",
                {"device": device, "passkey": int(passkey), "accepted": True},
            )

        @dbus.service.method(AGENT, in_signature="o", out_signature="s")
        def RequestPinCode(self, device: str) -> str:
            emit("provision_agent_pin_code", {"device": device})
            return "0000"

        @dbus.service.method(AGENT, in_signature="o", out_signature="u")
        def RequestPasskey(self, device: str) -> Any:
            emit("provision_agent_passkey", {"device": device})
            return dbus_uint32(0)

        @dbus.service.method(AGENT, in_signature="ouq", out_signature="")
        def DisplayPasskey(self, device: str, passkey: int, entered: int) -> None:
            emit(
                "provision_agent_display_passkey",
                {"device": device, "passkey": int(passkey), "entered": int(entered)},
            )

        @dbus.service.method(AGENT, in_signature="os", out_signature="")
        def DisplayPinCode(self, device: str, pincode: str) -> None:
            emit("provision_agent_display_pin_code", {"device": device, "pincode": pincode})

        @dbus.service.method(AGENT, in_signature="", out_signature="")
        def Cancel(self) -> None:
            emit("provision_agent_cancel", {})

        def register(self) -> None:
            self.manager.RegisterAgent(AGENT_PATH, capability)
            self.manager.RequestDefaultAgent(AGENT_PATH)
            self.registered = True
            emit(
                "provision_agent_registered",
                {"path": AGENT_PATH, "capability": capability},
            )

        def unregister(self) -> None:
            if self.registered:
                with suppress_dbus_error("", ""):
                    self.manager.UnregisterAgent(AGENT_PATH)
            self.remove_from_connection()

    agent = AutoConfirmAgent()
    agent.register()
    return agent


def make_emitter() -> Any:
    started = time.monotonic()

    def emit(event: str, payload: dict[str, Any]) -> None:
        print(
            json.dumps(
                {
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "event": event,
                    "payload": json_safe(payload),
                },
                sort_keys=True,
            ),
            flush=True,
        )

    return emit


def decode_raw(raw: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {"raw_hex": raw.hex()}
    try:
        row["packets"] = [p.parse_response(packet) for packet in p.parse_packets(raw)]
    except Exception as exc:
        row["decode_error"] = f"{type(exc).__name__}: {exc}"
    return row


def device_summary(path: str, props: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": path,
        "address": str(props.get("Address", "")),
        "address_type": str(props.get("AddressType", "")),
        "name": str(props.get("Name", "")),
        "alias": str(props.get("Alias", "")),
        "paired": bool(props.get("Paired", False)),
        "bonded": bool(props.get("Bonded", False)),
        "trusted": bool(props.get("Trusted", False)),
        "connected": bool(props.get("Connected", False)),
        "services_resolved": bool(props.get("ServicesResolved", False)),
        "rssi": int(props["RSSI"]) if "RSSI" in props else None,
        "uuids": sorted(str(uuid).lower() for uuid in props.get("UUIDs", [])),
        "manufacturer_data": json_safe(props.get("ManufacturerData", {})),
    }


def json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return str(value)


def restart_bluetooth() -> None:
    subprocess.run(["sudo", "-n", "systemctl", "restart", "bluetooth"], check=True)
    time.sleep(1.5)


def pump(seconds: float) -> None:
    from gi.repository import GLib

    context = GLib.MainContext.default()
    deadline = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < deadline:
        while context.pending():
            context.iteration(False)
        time.sleep(0.01)


def dbus_interface(bus: Any, path: str, interface: str) -> Any:
    import dbus

    return dbus.Interface(bus.get_object(BLUEZ, path), interface)


def dbus_array(data: bytes) -> Any:
    import dbus

    return dbus.Array([dbus.Byte(value) for value in data], signature="y")


def dbus_dict(value: dict[str, Any]) -> Any:
    import dbus

    converted = {
        key: dbus.String(item) if isinstance(item, str) else item
        for key, item in value.items()
    }
    return dbus.Dictionary(
        converted,
        signature="sv",
    )


def dbus_bool(value: bool) -> Any:
    import dbus

    return dbus.Boolean(value)


def dbus_uint32(value: int) -> Any:
    import dbus

    return dbus.UInt32(value)


def dbus_object_path(path: str) -> Any:
    import dbus

    return dbus.ObjectPath(path)


class suppress_dbus_error:
    def __init__(self, name: str, message_part: str) -> None:
        self.name = name
        self.message_part = message_part

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if exc is None:
            return False
        if not hasattr(exc, "get_dbus_name"):
            return False
        name_matches = not self.name or self.name in exc.get_dbus_name()
        message_matches = not self.message_part or self.message_part in str(exc)
        return bool(name_matches and message_matches)


if __name__ == "__main__":
    sys.exit(main())
