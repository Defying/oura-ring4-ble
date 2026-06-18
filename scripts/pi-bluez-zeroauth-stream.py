#!/usr/bin/env python3
"""Stream unauthenticated Oura Ring 4 GATT notifications through BlueZ D-Bus."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from oura_ring4_ble import protocol as p

BLUEZ = "org.bluez"
OBJ_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPS = "org.freedesktop.DBus.Properties"
DEVICE = "org.bluez.Device1"
CHAR = "org.bluez.GattCharacteristic1"
AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
AGENT_PATH = "/com/openai/oura_ring4_ble/agent"
EXTRA_PRODUCT_INFO_TYPES = [
    bytes([offset, 0x00, 0x10])
    for offset in range(0x00, 0x40, 0x04)
    if bytes([offset, 0x00, 0x10]) not in p.PRODUCT_INFO_TYPES
]
STABLE_EXTRA_PRODUCT_INFO_TYPES = [
    bytes.fromhex(value)
    for value in (
        "000010",
        "0c0010",
        "100010",
        "1c0010",
        "200010",
        "240010",
    )
]
OBSERVED_FEATURE_STATUS_IDS = sorted(set(p.FEATURE_IDS) | {0x0E, 0x10, 0x12, 0x16})
UNATTRIBUTED_PACKET = "unattributed_notification"
HEALTH_FEATURE_NAMES = {"daytime_hr", "exercise_hr", "resting_hr", "spo2", "real_steps"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Subscribe to zero-auth Oura notifications and emit JSONL."
    )
    parser.add_argument("--address", default="", help="identity address to prefer")
    parser.add_argument("--device-path", default="", help="BlueZ Device1 object path")
    parser.add_argument(
        "--strict-address",
        action="store_true",
        help="fail if --address does not exactly match a BlueZ Device1 address",
    )
    parser.add_argument(
        "--auto-confirm-agent",
        action="store_true",
        help="register a temporary BlueZ agent that accepts BLE numeric confirmation",
    )
    parser.add_argument(
        "--agent-capability",
        default="DisplayYesNo",
        help="BlueZ AgentManager1 capability for --auto-confirm-agent",
    )
    parser.add_argument(
        "--pair",
        action="store_true",
        help="call Device1.Pair before subscribing",
    )
    parser.add_argument("--pair-timeout", type=float, default=45.0)
    parser.add_argument("--connect", action="store_true", help="call Device1.Connect")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument(
        "--exit-after-probes",
        action="store_true",
        help="emit read_result and exit immediately after configured probes finish",
    )
    parser.add_argument("--wait-services-timeout", type=float, default=8.0)
    parser.add_argument(
        "--all-services",
        action="store_true",
        help="subscribe to every notifiable characteristic, not just Oura services",
    )
    parser.add_argument(
        "--all-notify-chars",
        action="store_true",
        help="subscribe to every Oura notify characteristic; default is response char only",
    )
    parser.add_argument(
        "--probes",
        default="",
        help=(
            "comma-separated safe request packets to write once after subscribing; "
            "supported: firmware,battery,auth_nonce,capabilities,capabilities_all,"
            "capabilities_tail,capabilities:0x02,"
            "feature_status_all,feature_status:0x0c,product_info_all,"
            "product_info:serial_number,product_info_hex:080010,"
            "product_info_hex_stable,product_info_hex_scan,"
            "product_info_hex_range:0x40:0x80:0x10,feature_status_observed,"
            "setup_snapshot,"
            "feature_mode:0x02:connected_live,"
            "feature_subscription:0x02:latest,daytime_hr_latest,"
            "daytime_hr_restore,live_hr_probe,ring_mode:fast_heart_rate,"
            "ring_mode_fast_hr,ring_mode_normal,events,events:0:4,"
            "events_range:6306:7000:194:24,"
            "factory_reset"
        ),
    )
    parser.add_argument("--settle-seconds", type=float, default=0.25)
    parser.add_argument("--probe-delay-seconds", type=float, default=0.5)
    parser.add_argument(
        "--probe-response-timeout",
        type=float,
        default=1.0,
        help=(
            "seconds to keep a probe active while waiting for its first response; "
            "prevents a slow response from being attributed to the next probe"
        ),
    )
    args = parser.parse_args()
    probes = parse_probe_names(args.probes)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    emit = make_emitter()

    try:
        if args.auto_confirm_agent:
            register_auto_confirm_agent(bus, args.agent_capability, emit)
        objects = get_managed_objects(bus)
        device_path, device_props = find_device(
            objects, args.address, args.device_path, args.strict_address
        )
        emit(
            "zeroauth_device",
            {"path": device_path, "properties": json_safe(device_props)},
        )
        if args.connect and not bool(device_props.get("Connected", False)):
            emit("zeroauth_connect_start", {"path": device_path})
            device = dbus.Interface(bus.get_object(BLUEZ, device_path), DEVICE)
            device.Connect(timeout=args.wait_services_timeout)
            pump(args.settle_seconds)
            objects = get_managed_objects(bus)
            device_props = objects.get(device_path, {}).get(DEVICE, device_props)

        if args.pair and not bool(device_props.get("Paired", False)):
            emit("zeroauth_pair_start", {"path": device_path})
            device = dbus.Interface(bus.get_object(BLUEZ, device_path), DEVICE)
            device.Pair(timeout=args.pair_timeout)
            pump(args.settle_seconds)
            objects = get_managed_objects(bus)
            device_props = objects.get(device_path, {}).get(DEVICE, device_props)
            emit(
                "zeroauth_pair_done",
                {
                    "path": device_path,
                    "paired": bool(device_props.get("Paired", False)),
                    "bonded": bool(device_props.get("Bonded", False)),
                    "connected": bool(device_props.get("Connected", False)),
                },
            )

        objects, device_props = wait_for_characteristics(
            bus, device_path, args.wait_services_timeout, emit
        )
        chars = sorted(
            notifiable_characteristics(
                objects,
                device_path,
                all_services=args.all_services,
                response_only=not args.all_notify_chars,
            ),
            key=lambda row: row["path"],
        )
        emit(
            "zeroauth_subscribe_plan",
            {
                "bluez_connected": bool(device_props.get("Connected", False)),
                "services_resolved": bool(device_props.get("ServicesResolved", False)),
                "characteristics": [
                    {
                        "path": row["path"],
                        "uuid": row["uuid"],
                        "flags": row["flags"],
                        "handle": row["handle"],
                    }
                    for row in chars
                ],
            },
        )

        notification_count = 0
        active_probe: dict[str, str] = {}
        probe_results: dict[str, dict[str, Any]] = {}

        def on_props_changed(
            interface: str,
            changed: dict[str, Any],
            _invalidated: list[str],
            path: str | None = None,
        ) -> None:
            nonlocal notification_count
            if interface != CHAR or "Value" not in changed:
                return
            char = next((row for row in chars if row["path"] == path), None)
            if char is None:
                return
            notification_count += 1
            raw = bytes(changed["Value"])
            probe_context = dict(active_probe)
            decoded = decode_notification(char["uuid"], raw, probe_context)
            record_probe_response(probe_results, probe_context, raw.hex(), decoded)
            emit(
                "zeroauth_notify",
                {
                    "path": path,
                    "uuid": char["uuid"],
                    "handle": char["handle"],
                    "probe_context": probe_context,
                    "raw_hex": raw.hex(),
                    "decoded": decoded,
                },
            )

        for row in chars:
            bus.add_signal_receiver(
                on_props_changed,
                dbus_interface=PROPS,
                signal_name="PropertiesChanged",
                path=row["path"],
                path_keyword="path",
            )

        subscribed: list[dict[str, Any]] = []
        for row in chars:
            notify = dbus.Interface(bus.get_object(BLUEZ, row["path"]), CHAR)
            try:
                notify.StartNotify()
                subscribed.append(row)
                emit(
                    "zeroauth_subscribed",
                    {"path": row["path"], "uuid": row["uuid"], "handle": row["handle"]},
                )
            except Exception as exc:
                emit(
                    "zeroauth_subscribe_error",
                    {
                        "path": row["path"],
                        "uuid": row["uuid"],
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )

        pump(args.settle_seconds)
        if probes:
            run_probes(
                bus,
                objects,
                device_path,
                probes,
                args.probe_delay_seconds,
                args.probe_response_timeout,
                active_probe,
                probe_results,
                emit,
            )
            if args.exit_after_probes:
                emit_stream_result(
                    emit,
                    probe_results,
                    notification_count=notification_count,
                    subscribed_count=len(subscribed),
                    duration_seconds=args.duration,
                    exit_after_probes=True,
                )
                return 0

        deadline = time.monotonic() + max(0.0, args.duration)
        while time.monotonic() < deadline:
            pump(min(0.1, max(0.0, deadline - time.monotonic())))

        emit_stream_result(
            emit,
            probe_results,
            notification_count=notification_count,
            subscribed_count=len(subscribed),
            duration_seconds=args.duration,
            exit_after_probes=False,
        )
        return 0
    except Exception as exc:
        emit("zeroauth_error", {"error_type": type(exc).__name__, "error": str(exc)})
        return 1


def make_emitter():
    started = time.monotonic()

    def emit(event: str, payload: dict[str, Any]) -> None:
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

    return emit


def emit_stream_result(
    emit: Any,
    probe_results: dict[str, dict[str, Any]],
    *,
    notification_count: int,
    subscribed_count: int,
    duration_seconds: float,
    exit_after_probes: bool,
) -> None:
    emit(
        "read_result",
        build_read_result(
            probe_results,
            notification_count=notification_count,
            subscribed_count=subscribed_count,
        ),
    )
    emit(
        "zeroauth_stream_done",
        {
            "duration_seconds": duration_seconds,
            "exit_after_probes": exit_after_probes,
            "notification_count": notification_count,
            "subscribed_count": subscribed_count,
        },
    )


def get_managed_objects(bus: dbus.SystemBus) -> dict[str, dict[str, dict[str, Any]]]:
    manager = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJ_MANAGER)
    return manager.GetManagedObjects()


class AutoConfirmAgent(dbus.service.Object):
    def __init__(self, bus: dbus.SystemBus, path: str, emit: Any) -> None:
        super().__init__(bus, path)
        self.emit = emit

    @dbus.service.method(AGENT, in_signature="", out_signature="")
    def Release(self) -> None:
        self.emit("zeroauth_agent_release", {})

    @dbus.service.method(AGENT, in_signature="os", out_signature="")
    def AuthorizeService(self, device: str, uuid: str) -> None:
        self.emit(
            "zeroauth_agent_authorize_service",
            {"device": str(device), "uuid": str(uuid)},
        )

    @dbus.service.method(AGENT, in_signature="o", out_signature="")
    def RequestAuthorization(self, device: str) -> None:
        self.emit("zeroauth_agent_authorize", {"device": str(device)})

    @dbus.service.method(AGENT, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device: str, passkey: int) -> None:
        self.emit(
            "zeroauth_agent_confirm",
            {"device": str(device), "passkey": int(passkey)},
        )

    @dbus.service.method(AGENT, in_signature="o", out_signature="s")
    def RequestPinCode(self, device: str) -> str:
        self.emit("zeroauth_agent_pin_code", {"device": str(device)})
        return "0000"

    @dbus.service.method(AGENT, in_signature="o", out_signature="u")
    def RequestPasskey(self, device: str) -> dbus.UInt32:
        self.emit("zeroauth_agent_passkey", {"device": str(device)})
        return dbus.UInt32(0)

    @dbus.service.method(AGENT, in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device: str, passkey: int, entered: int) -> None:
        self.emit(
            "zeroauth_agent_display_passkey",
            {"device": str(device), "passkey": int(passkey), "entered": int(entered)},
        )

    @dbus.service.method(AGENT, in_signature="os", out_signature="")
    def DisplayPinCode(self, device: str, pincode: str) -> None:
        self.emit(
            "zeroauth_agent_display_pin_code",
            {"device": str(device), "pincode": str(pincode)},
        )

    @dbus.service.method(AGENT, in_signature="o", out_signature="")
    def Cancel(self, device: str) -> None:
        self.emit("zeroauth_agent_cancel", {"device": str(device)})


def register_auto_confirm_agent(
    bus: dbus.SystemBus, capability: str, emit: Any
) -> AutoConfirmAgent:
    agent = AutoConfirmAgent(bus, AGENT_PATH, emit)
    manager = dbus.Interface(bus.get_object(BLUEZ, "/org/bluez"), AGENT_MANAGER)
    manager.RegisterAgent(AGENT_PATH, capability)
    manager.RequestDefaultAgent(AGENT_PATH)
    emit(
        "zeroauth_agent_registered",
        {"path": AGENT_PATH, "capability": capability},
    )
    return agent


def find_device(
    objects: dict[str, dict[str, dict[str, Any]]],
    address: str,
    device_path: str,
    strict_address: bool = False,
) -> tuple[str, dict[str, Any]]:
    if device_path:
        props = objects.get(device_path, {}).get(DEVICE)
        if not props:
            raise RuntimeError(f"Device1 path not found: {device_path}")
        return device_path, props

    normalized = address.lower()
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    seen: list[dict[str, Any]] = []
    for path, interfaces in objects.items():
        props = interfaces.get(DEVICE)
        if not props:
            continue
        props_address = str(props.get("Address", "")).lower()
        name = str(props.get("Name", ""))
        uuids = {str(uuid).lower() for uuid in props.get("UUIDs", [])}
        score = 0
        if normalized and props_address == normalized:
            score += 100
        seen.append(
            {
                "path": path,
                "address": str(props.get("Address", "")),
                "name": name,
                "connected": bool(props.get("Connected", False)),
                "services_resolved": bool(props.get("ServicesResolved", False)),
                "is_oura": p.OURA_SERVICE_UUID in uuids or "oura" in name.lower(),
            }
        )
        if strict_address and normalized and props_address != normalized:
            continue
        if p.OURA_SERVICE_UUID in uuids:
            score += 20
        if "oura" in name.lower():
            score += 10
        if bool(props.get("Connected", False)):
            score += 5
        if score:
            candidates.append((score, path, props))
    if not candidates:
        if strict_address and normalized:
            visible_oura = [
                row
                for row in seen
                if row["is_oura"] or normalized in str(row["address"]).lower()
            ]
            raise RuntimeError(
                "no exact BlueZ Device1 object for address "
                f"{address}; visible Oura candidates: "
                f"{json.dumps(visible_oura, sort_keys=True)}"
            )
        raise RuntimeError("no Oura BlueZ Device1 object found")
    candidates.sort(key=lambda row: (-row[0], row[1]))
    _, path, props = candidates[0]
    return path, props


def wait_for_characteristics(
    bus: dbus.SystemBus,
    device_path: str,
    timeout: float,
    emit: Any,
) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, Any]]:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        objects = get_managed_objects(bus)
        device_props = objects.get(device_path, {}).get(DEVICE)
        if not device_props:
            raise RuntimeError(f"Device1 path disappeared: {device_path}")
        if notifiable_characteristics(
            objects, device_path, all_services=False, response_only=True
        ):
            return objects, device_props
        if time.monotonic() >= deadline:
            emit(
                "zeroauth_services_timeout",
                {
                    "connected": bool(device_props.get("Connected", False)),
                    "services_resolved": bool(device_props.get("ServicesResolved", False)),
                },
            )
            raise RuntimeError("no Oura notifiable characteristics published by BlueZ")
        pump(0.05)


def notifiable_characteristics(
    objects: dict[str, dict[str, dict[str, Any]]],
    device_path: str,
    *,
    all_services: bool,
    response_only: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    oura_service_paths = {
        path
        for path, interfaces in objects.items()
        if path.startswith(device_path + "/")
        and str(interfaces.get("org.bluez.GattService1", {}).get("UUID", "")).lower()
        in {p.OURA_SERVICE_UUID, "00060000-f8ce-11e4-abf4-0002a5d5c51b"}
    }
    for path, interfaces in objects.items():
        if not path.startswith(device_path + "/"):
            continue
        props = interfaces.get(CHAR)
        if not props:
            continue
        service_path = str(props.get("Service", ""))
        if not all_services and service_path not in oura_service_paths:
            continue
        flags = [str(flag) for flag in props.get("Flags", [])]
        if "notify" not in flags and "indicate" not in flags:
            continue
        uuid = str(props.get("UUID", "")).lower()
        if response_only and uuid != p.OURA_NOTIFY_UUID:
            continue
        rows.append(
            {
                "path": path,
                "uuid": uuid,
                "flags": flags,
                "handle": int(props.get("Handle", 0)),
                "service_path": service_path,
            }
        )
    return rows


def parse_probe_names(value: str) -> list[str]:
    names = [part.strip().lower() for part in value.split(",") if part.strip()]
    supported = {
        "firmware",
        "battery",
        "auth_nonce",
        "capabilities",
        "capabilities_all",
        "capabilities_tail",
        "feature_status_all",
        "feature_status_observed",
        "setup_snapshot",
        "daytime_hr_latest",
        "daytime_hr_restore",
        "live_hr_probe",
        "resting_hr_latest",
        "resting_hr_restore",
        "ring_mode_fast_hr",
        "ring_mode_normal",
        "product_info_all",
        "product_info_hex_stable",
        "product_info_hex_scan",
        "events",
        "factory_reset",
    }
    unsupported = sorted(
        name
        for name in set(names)
        if name not in supported
        and not name.startswith("feature_status:")
        and not name.startswith("feature_mode:")
        and not name.startswith("feature_subscription:")
        and not name.startswith("ring_mode:")
        and not name.startswith("capabilities:")
        and not name.startswith("product_info:")
        and not name.startswith("product_info_hex:")
        and not name.startswith("product_info_hex_range:")
        and not name.startswith("events:")
        and not name.startswith("events_range:")
        and not name.startswith("events_walk:")
    )
    if unsupported:
        raise SystemExit(f"unsupported probe name(s): {', '.join(unsupported)}")
    for name in names:
        if name.startswith("feature_status:"):
            parse_feature_id(name.split(":", 1)[1])
        elif name.startswith("feature_mode:"):
            parse_feature_mode_probe(name)
        elif name.startswith("feature_subscription:"):
            parse_feature_subscription_probe(name)
        elif name.startswith("ring_mode:"):
            parse_ring_mode_probe(name)
        elif name.startswith("capabilities:"):
            parse_capabilities_page(name.split(":", 1)[1])
        elif name.startswith("product_info:"):
            parse_product_info_type(name.split(":", 1)[1])
        elif name.startswith("product_info_hex:"):
            parse_product_info_hex(name.split(":", 1)[1])
        elif name.startswith("product_info_hex_range:"):
            parse_product_info_hex_range(name)
        elif name.startswith("events:"):
            parse_events_probe(name)
        elif name.startswith("events_range:"):
            parse_events_range_probe(name)
        elif name.startswith("events_walk:"):
            parse_events_walk_probe(name)
    return names


def run_probes(
    bus: dbus.SystemBus,
    objects: dict[str, dict[str, dict[str, Any]]],
    device_path: str,
    probes: list[str],
    delay_seconds: float,
    response_timeout_seconds: float,
    active_probe: dict[str, str],
    probe_results: dict[str, dict[str, Any]],
    emit: Any,
) -> None:
    write_path = find_write_characteristic(objects, device_path)
    write = dbus.Interface(bus.get_object(BLUEZ, write_path), CHAR)
    for name in probes:
        if name.startswith("events_walk:"):
            if not run_events_walk(
                write,
                name,
                delay_seconds,
                response_timeout_seconds,
                active_probe,
                probe_results,
                emit,
            ):
                return
            continue
        for packet_name, packet in build_probe_packets(name):
            keep_going, _result = run_probe_packet(
                write,
                packet_name,
                packet,
                delay_seconds,
                response_timeout_seconds,
                active_probe,
                probe_results,
                emit,
            )
            if not keep_going:
                return


def run_probe_packet(
    write: Any,
    packet_name: str,
    packet: bytes,
    delay_seconds: float,
    response_timeout_seconds: float,
    active_probe: dict[str, str],
    probe_results: dict[str, dict[str, Any]],
    emit: Any,
) -> tuple[bool, dict[str, Any]]:
    tx_hex = packet.hex()
    active_probe.clear()
    active_probe.update({"packet": packet_name, "tx_hex": tx_hex})
    result = get_probe_result(probe_results, packet_name, tx_hex)
    result["tx_count"] += 1
    emit("zeroauth_probe_tx", {"packet": packet_name, "tx_hex": tx_hex})
    try:
        write.WriteValue(
            dbus.Array([dbus.Byte(value) for value in packet], signature="y"),
            dbus.Dictionary({"type": dbus.String("request")}, signature="sv"),
        )
    except Exception as exc:
        emit(
            "zeroauth_probe_error",
            {
                "packet": packet_name,
                "tx_hex": tx_hex,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        result["errors"].append(
            {
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        active_probe.clear()
        if should_stop_after_probe_error(exc):
            emit(
                "zeroauth_probe_stop",
                {
                    "packet": packet_name,
                    "tx_hex": tx_hex,
                    "reason": "connection_unusable_after_probe_error",
                },
            )
            return False, result
        return True, result

    wait_for_probe_response(
        result,
        packet_name=packet_name,
        response_count_before=len(result["raw_responses"]),
        delay_seconds=delay_seconds,
        response_timeout_seconds=response_timeout_seconds,
    )
    active_probe.clear()
    return True, result


def run_events_walk(
    write: Any,
    name: str,
    delay_seconds: float,
    response_timeout_seconds: float,
    active_probe: dict[str, str],
    probe_results: dict[str, dict[str, Any]],
    emit: Any,
) -> bool:
    start_timestamp, page_count, max_events = parse_events_walk_probe(name)
    cursor = start_timestamp
    for page_index in range(page_count):
        packet_name = f"events:0x{cursor:08x}:{max_events}"
        keep_going, result = run_probe_packet(
            write,
            packet_name,
            p.build_get_events_request(cursor, max_events),
            delay_seconds,
            response_timeout_seconds,
            active_probe,
            probe_results,
            emit,
        )
        progress = event_probe_progress(result)
        emit(
            "zeroauth_events_walk_page",
            {
                "walk": name,
                "page_index": page_index + 1,
                "page_count": page_count,
                "request_start_timestamp": cursor,
                "request_start_hex": f"0x{cursor:08x}",
                "request_max_events": max_events,
                **progress,
            },
        )
        if not keep_going:
            return False
        if not result.get("raw_responses"):
            emit(
                "zeroauth_events_walk_stop",
                {
                    "walk": name,
                    "page_index": page_index + 1,
                    "reason": "no_response",
                    "request_start_timestamp": cursor,
                    "request_start_hex": f"0x{cursor:08x}",
                },
            )
            return True
        if progress.get("complete") is True:
            emit(
                "zeroauth_events_walk_stop",
                {
                    "walk": name,
                    "page_index": page_index + 1,
                    "reason": "complete",
                    "next_start_timestamp": progress.get("next_start_timestamp"),
                    "next_start_hex": progress.get("next_start_hex"),
                },
            )
            return True
        next_cursor = progress.get("next_start_timestamp")
        if not isinstance(next_cursor, int) or next_cursor <= cursor:
            emit(
                "zeroauth_events_walk_stop",
                {
                    "walk": name,
                    "page_index": page_index + 1,
                    "reason": "no_cursor_progress",
                    "request_start_timestamp": cursor,
                    "request_start_hex": f"0x{cursor:08x}",
                },
            )
            return True
        cursor = next_cursor
    return True


def wait_for_probe_response(
    result: dict[str, Any],
    *,
    packet_name: str,
    response_count_before: int,
    delay_seconds: float,
    response_timeout_seconds: float,
) -> None:
    if is_events_probe_name(packet_name):
        wait_for_event_probe_response(
            result,
            response_count_before=response_count_before,
            delay_seconds=delay_seconds,
            response_timeout_seconds=response_timeout_seconds,
        )
        return

    min_deadline = time.monotonic() + max(0.0, delay_seconds)
    response_deadline = time.monotonic() + max(0.0, response_timeout_seconds)
    while True:
        now = time.monotonic()
        has_response = len(result["raw_responses"]) > response_count_before
        if has_response and now >= min_deadline:
            return
        if not has_response and now >= response_deadline:
            return
        target = min_deadline if has_response else response_deadline
        pump(min(0.05, max(0.0, target - now)))


def wait_for_event_probe_response(
    result: dict[str, Any],
    *,
    response_count_before: int,
    delay_seconds: float,
    response_timeout_seconds: float,
) -> None:
    min_deadline = time.monotonic() + max(0.0, delay_seconds)
    quiet_timeout = max(0.0, response_timeout_seconds)
    quiet_deadline = time.monotonic() + quiet_timeout
    last_response_count = response_count_before
    saw_response = len(result["raw_responses"]) > response_count_before

    while True:
        now = time.monotonic()
        response_count = len(result["raw_responses"])
        if response_count > last_response_count:
            last_response_count = response_count
            saw_response = True
            quiet_deadline = now + quiet_timeout

        if saw_response and probe_has_events_done(result) and now >= min_deadline:
            return
        if now >= quiet_deadline:
            return

        target = min_deadline if saw_response and now < min_deadline else quiet_deadline
        pump(min(0.05, max(0.0, target - now)))


def probe_has_events_done(result: dict[str, Any]) -> bool:
    for row in result.get("decoded", []):
        if not isinstance(row, dict):
            continue
        decoded = row.get("decoded")
        if isinstance(decoded, dict) and "events_received" in decoded:
            return True
    return False


def is_events_probe_name(packet_name: str) -> bool:
    return packet_name == "events" or packet_name.startswith("events:")


def event_probe_progress(result: dict[str, Any]) -> dict[str, Any]:
    timestamps: list[int] = []
    latest_done: dict[str, Any] | None = None
    for row in result.get("decoded", []):
        if not isinstance(row, dict):
            continue
        decoded = row.get("decoded")
        if not isinstance(decoded, dict):
            continue
        timestamp = decoded.get("device_boot_timestamp")
        if isinstance(timestamp, int):
            timestamps.append(timestamp)
        if "events_received" in decoded:
            latest_done = decoded

    progress: dict[str, Any] = {
        "event_count": len(timestamps),
    }
    if timestamps:
        last = max(timestamps)
        progress.update(
            {
                "first_boot_timestamp": min(timestamps),
                "last_boot_timestamp": last,
                "next_start_timestamp": last + 1,
                "next_start_hex": f"0x{last + 1:08x}",
            }
        )
    if latest_done:
        for key in (
            "events_received",
            "bytes_left",
            "sleep_analysis_progress",
            "unknown_u16",
        ):
            if key in latest_done:
                progress[key] = latest_done[key]
        progress["complete"] = (
            latest_done.get("events_received") == 0
            and latest_done.get("bytes_left") == 0
        )
    return progress


def find_write_characteristic(
    objects: dict[str, dict[str, dict[str, Any]]], device_path: str
) -> str:
    for path, interfaces in objects.items():
        if not path.startswith(device_path + "/"):
            continue
        props = interfaces.get(CHAR)
        if not props:
            continue
        if str(props.get("UUID", "")).lower() == p.OURA_WRITE_UUID:
            return path
    raise RuntimeError("could not find Oura write characteristic")


def build_probe_packets(name: str) -> list[tuple[str, bytes]]:
    if name == "setup_snapshot":
        packets: list[tuple[str, bytes]] = []
        for group in (
            "firmware",
            "battery",
            "auth_nonce",
            "capabilities:0x00",
            "capabilities:0x01",
            "capabilities_tail",
            "feature_status_observed",
            "product_info_all",
            "product_info_hex_stable",
            "events:0:24",
        ):
            packets.extend(build_probe_packets(group))
        return packets
    if name == "firmware":
        return [(name, p.build_get_firmware_request())]
    if name == "battery":
        return [(name, p.build_get_battery_request())]
    if name == "auth_nonce":
        return [(name, p.build_get_auth_nonce_request())]
    if name == "factory_reset":
        return [(name, p.build_factory_reset_request())]
    if name == "capabilities":
        return [(name, p.build_get_capabilities_request())]
    if name == "capabilities_all":
        return [
            (
                f"capabilities:0x{page:02x}",
                p.build_get_capabilities_request(page),
            )
            for page in range(0x00, 0x10)
        ]
    if name == "capabilities_tail":
        return [
            (
                f"capabilities:0x{page:02x}",
                p.build_get_capabilities_request(page),
            )
            for page in range(0x02, 0x10)
        ]
    if name.startswith("capabilities:"):
        page = parse_capabilities_page(name.split(":", 1)[1])
        return [
            (
                f"capabilities:0x{page:02x}",
                p.build_get_capabilities_request(page),
            )
        ]
    if name == "feature_status_all":
        return [
            (
                f"feature_status:0x{feature_id:02x}",
                p.build_get_feature_status_request(feature_id),
            )
            for feature_id in p.FEATURE_IDS
        ]
    if name == "feature_status_observed":
        return [
            (
                f"feature_status:0x{feature_id:02x}",
                p.build_get_feature_status_request(feature_id),
            )
            for feature_id in OBSERVED_FEATURE_STATUS_IDS
        ]
    if name.startswith("feature_status:"):
        feature_id = parse_feature_id(name.split(":", 1)[1])
        return [
            (
                f"feature_status:0x{feature_id:02x}",
                p.build_get_feature_status_request(feature_id),
            )
        ]
    if name.startswith("feature_mode:"):
        feature_id, mode = parse_feature_mode_probe(name)
        return [
            (
                f"feature_mode:0x{feature_id:02x}:{feature_mode_name(mode)}",
                p.build_set_feature_mode_request(feature_id, mode),
            )
        ]
    if name.startswith("feature_subscription:"):
        feature_id, subscription_mode = parse_feature_subscription_probe(name)
        return [
            (
                "feature_subscription:"
                f"0x{feature_id:02x}:{feature_subscription_name(subscription_mode)}",
                p.build_set_feature_subscription_request(feature_id, subscription_mode),
            )
        ]
    if name == "daytime_hr_latest":
        return build_feature_latest_probe_packets(0x02)
    if name == "daytime_hr_restore":
        return build_feature_restore_probe_packets(0x02)
    if name == "live_hr_probe":
        return build_live_hr_probe_packets()
    if name == "resting_hr_latest":
        return build_feature_latest_probe_packets(0x08)
    if name == "resting_hr_restore":
        return build_feature_restore_probe_packets(0x08)
    if name == "ring_mode_fast_hr":
        return [("ring_mode:fast_heart_rate", p.build_set_ring_mode_request(0x01))]
    if name == "ring_mode_normal":
        return [("ring_mode:normal", p.build_set_ring_mode_request(0x00))]
    if name.startswith("ring_mode:"):
        mode = parse_ring_mode_probe(name)
        return [
            (
                f"ring_mode:{ring_mode_name(mode)}",
                p.build_set_ring_mode_request(mode),
            )
        ]
    if name == "product_info_all":
        return [
            (
                f"product_info:{info_name}",
                p.build_get_product_info_request(info_name),
            )
            for info_name in p.PRODUCT_INFO_TYPES.values()
        ]
    if name == "product_info_hex_scan":
        return [
            (
                f"product_info_hex:{info_type.hex()}",
                p.build_get_product_info_request(info_type),
            )
            for info_type in EXTRA_PRODUCT_INFO_TYPES
        ]
    if name == "product_info_hex_stable":
        return [
            (
                f"product_info_hex:{info_type.hex()}",
                p.build_get_product_info_request(info_type),
            )
            for info_type in STABLE_EXTRA_PRODUCT_INFO_TYPES
        ]
    if name.startswith("product_info_hex_range:"):
        return [
            (
                f"product_info_hex:{info_type.hex()}",
                p.build_get_product_info_request(info_type),
            )
            for info_type in parse_product_info_hex_range(name)
        ]
    if name.startswith("product_info:"):
        info_name = parse_product_info_type(name.split(":", 1)[1])
        return [
            (
                f"product_info:{info_name}",
                p.build_get_product_info_request(info_name),
            )
        ]
    if name.startswith("product_info_hex:"):
        info_type = parse_product_info_hex(name.split(":", 1)[1])
        return [
            (
                f"product_info_hex:{info_type.hex()}",
                p.build_get_product_info_request(info_type),
            )
        ]
    if name == "events":
        start_timestamp, max_events = 0, 8
        return [
            (
                f"events:0x{start_timestamp:08x}:{max_events}",
                p.build_get_events_request(start_timestamp, max_events),
            )
        ]
    if name.startswith("events_range:"):
        return [
            (
                f"events:0x{start_timestamp:08x}:{max_events}",
                p.build_get_events_request(start_timestamp, max_events),
            )
            for start_timestamp, max_events in parse_events_range_probe(name)
        ]
    if name.startswith("events:"):
        start_timestamp, max_events = parse_events_probe(name)
        return [
            (
                f"events:0x{start_timestamp:08x}:{max_events}",
                p.build_get_events_request(start_timestamp, max_events),
            )
        ]
    raise RuntimeError(f"unsupported probe: {name}")


def get_probe_result(
    probe_results: dict[str, dict[str, Any]], packet_name: str, tx_hex: str
) -> dict[str, Any]:
    key = f"{packet_name}|{tx_hex}"
    if key not in probe_results:
        probe_results[key] = {
            "packet": packet_name,
            "tx_hex": tx_hex,
            "tx_count": 0,
            "raw_responses": [],
            "decoded": [],
            "errors": [],
        }
    return probe_results[key]


def record_probe_response(
    probe_results: dict[str, dict[str, Any]],
    probe_context: dict[str, str],
    raw_hex: str,
    decoded: dict[str, Any],
) -> None:
    packet_name = str(probe_context.get("packet", "") or UNATTRIBUTED_PACKET)
    tx_hex = str(probe_context.get("tx_hex", "") or "")
    result = get_probe_result(probe_results, packet_name, tx_hex)
    result["raw_responses"].append(raw_hex)
    result["decoded"].extend(decoded.get("packets", []))


def build_read_result(
    probe_results: dict[str, dict[str, Any]],
    *,
    notification_count: int,
    subscribed_count: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "notification_count": notification_count,
        "subscribed_count": subscribed_count,
        "firmware": None,
        "auth_nonce": None,
        "battery": None,
        "product_info": {},
        "product_info_memory": {
            "byte_count": 0,
            "source_count": 0,
            "segments": [],
            "conflicts": [],
        },
        "capabilities": {},
        "feature_status": {},
        "feature_summary": {},
        "feature_set_results": [],
        "ring_mode_results": [],
        "device_snapshot": {},
        "event_summary": {},
        "events": [],
        "events_done": [],
        "factory_reset": None,
        "unattributed_notifications": [],
        "auth_gated": [],
        "probes": [],
    }
    all_decoded_rows: list[dict[str, Any]] = []
    for probe in sorted(probe_results.values(), key=lambda row: row["packet"]):
        decoded_rows = [
            row.get("decoded", {})
            for row in probe.get("decoded", [])
            if isinstance(row, dict)
        ]
        all_decoded_rows.extend(decoded_rows)
        classification = classify_probe_result(probe, decoded_rows)
        result["probes"].append(
            {
                "packet": probe["packet"],
                "tx_hex": probe["tx_hex"],
                "tx_count": probe["tx_count"],
                "classification": classification,
                "raw_responses": probe["raw_responses"],
                "errors": probe["errors"],
            }
        )
        for decoded in decoded_rows:
            apply_decoded_result(result, str(probe["packet"]), decoded)
    result["product_info_memory"] = p.reconstruct_product_info_memory(all_decoded_rows)
    result["device_snapshot"] = build_device_snapshot(result)
    result["feature_summary"] = build_feature_summary(result)
    result["event_summary"] = build_event_summary(result)
    return result


def classify_probe_result(probe: dict[str, Any], decoded_rows: list[dict[str, Any]]) -> str:
    if probe.get("packet") == UNATTRIBUTED_PACKET:
        if any(
            decoded.get("extended_name") == "auth_status_response"
            for decoded in decoded_rows
        ):
            return "unattributed_auth_status"
        return "unattributed_notification"
    if any(
        decoded.get("extended_name") == "auth_status_response"
        for decoded in decoded_rows
    ):
        return "auth_gated"
    if probe.get("raw_responses"):
        return "open_response"
    if probe.get("errors"):
        return "write_error"
    return "no_response"


def apply_decoded_result(
    result: dict[str, Any], packet_name: str, decoded: dict[str, Any]
) -> None:
    if "event_name" in decoded:
        result["events"].append(decoded)
        return
    if "firmware_version" in decoded:
        result["firmware"] = decoded
        return
    if "battery_level_percent" in decoded:
        result["battery"] = decoded
        return
    if decoded.get("extended_name") == "auth_nonce_response":
        result["auth_nonce"] = decoded
        return
    if decoded.get("extended_name") == "auth_status_response":
        if packet_name == UNATTRIBUTED_PACKET:
            result["unattributed_notifications"].append(decoded)
            return
        auth_gated = result["auth_gated"]
        if packet_name not in auth_gated:
            auth_gated.append(packet_name)
        return
    if decoded.get("response_name") == "factory_reset_status":
        result["factory_reset"] = decoded
        return
    if decoded.get("response_name") == "set_ring_mode_status":
        result["ring_mode_results"].append(
            {
                "packet": packet_name,
                **decoded,
            }
        )
        return
    if "events_received" in decoded:
        result["events_done"].append(
            {
                **decoded,
                **event_request_from_packet_name(packet_name),
            }
        )
        return
    if packet_name == UNATTRIBUTED_PACKET:
        result["unattributed_notifications"].append(decoded)
        return
    if decoded.get("extended_name") == "capabilities_response":
        result["capabilities"][packet_name] = decoded
        return
    if decoded.get("extended_name") == "feature_status_response":
        result["feature_status"][feature_status_result_key(packet_name, decoded)] = decoded
        return
    if decoded.get("extended_name") in {
        "set_feature_mode_response",
        "set_feature_subscription_response",
    }:
        result["feature_set_results"].append(
            {
                "packet": packet_name,
                **decoded,
            }
        )
        return
    if "info_type_name" in decoded:
        value = decoded.get("value_text")
        if value is None and decoded.get("printable_runs"):
            value = "/".join(decoded["printable_runs"])
        if value is None:
            value = decoded.get("value_hex", "")
        key = decoded["info_type_name"]
        if key == "unknown":
            key = f"product_info:{decoded.get('request_type_hex', 'unknown')}"
        result["product_info"][key] = value


def build_device_snapshot(result: dict[str, Any]) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}
    firmware = result.get("firmware")
    if isinstance(firmware, dict):
        for key in (
            "firmware_version",
            "api_version",
            "bootloader_version",
            "bluetooth_stack_version",
            "mac_fragment_hex",
        ):
            if firmware.get(key) is not None:
                snapshot[key] = firmware[key]

    battery = result.get("battery")
    if isinstance(battery, dict):
        snapshot["battery"] = {
            "level_percent": battery.get("battery_level_percent"),
            "charging_progress": battery.get("charging_progress"),
            "charging_recommended": battery.get("charging_recommended"),
        }
        for key in ("battery_status_byte", "battery_status_hex", "voltage_mv"):
            if key in battery:
                snapshot["battery"][key] = battery[key]

    product_info = result.get("product_info")
    if isinstance(product_info, dict):
        for key in (
            "serial_number",
            "serial_number_old",
            "hardware_id",
            "hardware_id_frodo",
            "product_code",
            "product_code_frodo",
        ):
            if product_info.get(key) is not None:
                snapshot[key] = product_info[key]

    events = result.get("events")
    debug_values: dict[str, dict[str, Any]] = {}
    battery_debug_rows: list[dict[str, Any]] = []
    power_debug_rows: list[dict[str, Any]] = []
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            debug_battery = event.get("debug_data_battery")
            if isinstance(debug_battery, dict):
                battery_debug_rows.append(
                    {
                        **debug_battery,
                        "device_boot_timestamp": event.get("device_boot_timestamp"),
                    }
                )
            power_sample = event.get("debug_data_power_sample_candidate")
            if isinstance(power_sample, dict):
                power_debug_rows.append(
                    {
                        **power_sample,
                        "device_boot_timestamp": event.get("device_boot_timestamp"),
                    }
                )
            if event.get("event_name") == "ring_start":
                snapshot["ring_start"] = {
                    key: event[key]
                    for key in (
                        "device_boot_timestamp",
                        "ring_start_marker_u32",
                        "ring_start_code_hex",
                        "firmware_version",
                        "bootloader_version",
                        "api_version",
                    )
                    if key in event
                }
            if event.get("payload_text") == "Sw to App":
                snapshot["setup_transition"] = "Sw to App"
            key = event.get("debug_key")
            values = event.get("debug_values")
            if isinstance(key, str) and isinstance(values, list):
                row: dict[str, Any] = {
                    "values": values,
                    "device_boot_timestamp": event.get("device_boot_timestamp"),
                }
                numeric_values = event.get("debug_numeric_values")
                if isinstance(numeric_values, list):
                    row["numeric_values"] = numeric_values
                for meta_key in ("debug_category", "debug_label", "debug_fields"):
                    if meta_key in event:
                        row[meta_key.removeprefix("debug_")] = event[meta_key]
                debug_values[key] = row

    if battery_debug_rows:
        snapshot["battery_debug"] = build_debug_battery_snapshot(battery_debug_rows)
    if power_debug_rows:
        snapshot["power_debug_candidate"] = build_power_debug_candidate_snapshot(
            power_debug_rows
        )

    if "serial_number" not in snapshot:
        serial_low = first_debug_value(debug_values, "SNL")
        serial_high = first_debug_value(debug_values, "SNH")
        if serial_low and serial_high:
            snapshot["serial_number_from_debug"] = f"{serial_low}{serial_high}"
    firmware_git = first_debug_value(debug_values, "git")
    if firmware_git:
        snapshot["firmware_git"] = firmware_git
    hardware_id = first_debug_value(debug_values, "HWID")
    if hardware_id:
        snapshot["hardware_id_from_debug"] = hardware_id

    charger_debug = {
        key: row
        for key, row in sorted(debug_values.items())
        if isinstance(row, dict) and row.get("category") == "charger"
    }
    if charger_debug:
        snapshot["charger_debug"] = charger_debug
        charger_state = build_charger_state(charger_debug)
        if charger_state:
            snapshot["charger_state"] = charger_state

    health_debug = {
        key: row
        for key, row in sorted(debug_values.items())
        if isinstance(row, dict) and row.get("category") in {"daytime_hr"}
    }
    if health_debug:
        snapshot["health_debug"] = health_debug
        health_debug_state = build_health_debug_state(health_debug)
        if health_debug_state:
            snapshot["health_debug_state"] = health_debug_state

    fuel_gauge_debug = {
        key: row
        for key, row in sorted(debug_values.items())
        if isinstance(row, dict) and row.get("category") == "fuel_gauge"
    }
    if fuel_gauge_debug:
        snapshot["fuel_gauge_debug"] = fuel_gauge_debug
        fuel_gauge_state = build_fuel_gauge_state(fuel_gauge_debug)
        if fuel_gauge_state:
            snapshot["fuel_gauge_state"] = fuel_gauge_state

    setup_debug = {
        key: row
        for key, row in sorted(debug_values.items())
        if key not in charger_debug
        and key not in health_debug
        and key not in fuel_gauge_debug
    }
    if setup_debug:
        snapshot["setup_debug"] = setup_debug
        setup_state = build_setup_state(
            setup_debug,
            transition=snapshot.get("setup_transition"),
        )
        if setup_state:
            snapshot["setup_state"] = setup_state

    feature_status = result.get("feature_status")
    health_features: dict[str, str] = {}
    if isinstance(feature_status, dict):
        for row in feature_status.values():
            if not isinstance(row, dict):
                continue
            feature = row.get("feature_name")
            if feature in {"daytime_hr", "resting_hr", "spo2", "real_steps"}:
                health_features[str(feature)] = "{mode}/{status}/{state}/{sub}".format(
                    mode=row.get("mode_name", ""),
                    status=row.get("status_name", ""),
                    state=row.get("state_name", ""),
                    sub=row.get("subscription_mode_name", ""),
                )
    if health_features:
        snapshot["health_features"] = health_features

    return snapshot


def build_debug_battery_snapshot(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable_rows = [row for row in rows if isinstance(row, dict)]
    if not usable_rows:
        return {}
    latest = max(
        usable_rows,
        key=lambda row: row.get("device_boot_timestamp")
        if isinstance(row.get("device_boot_timestamp"), int)
        else -1,
    )
    snapshot = {
        key: latest[key]
        for key in (
            "battery_level_percent",
            "voltage_mv",
            "status",
            "status_hex",
            "device_boot_timestamp",
        )
        if key in latest
    }
    voltages = [
        row.get("voltage_mv")
        for row in usable_rows
        if isinstance(row.get("voltage_mv"), int)
    ]
    if voltages:
        snapshot["min_voltage_mv"] = min(voltages)
        snapshot["max_voltage_mv"] = max(voltages)
    percents = [
        row.get("battery_level_percent")
        for row in usable_rows
        if isinstance(row.get("battery_level_percent"), int)
    ]
    if percents:
        snapshot["min_battery_level_percent"] = min(percents)
        snapshot["max_battery_level_percent"] = max(percents)
    snapshot["sample_count"] = len(usable_rows)
    return snapshot


def build_power_debug_candidate_snapshot(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable_rows = [row for row in rows if isinstance(row, dict)]
    if not usable_rows:
        return {}
    latest = max(
        usable_rows,
        key=lambda row: row.get("device_boot_timestamp")
        if isinstance(row.get("device_boot_timestamp"), int)
        else -1,
    )
    snapshot = {
        key: latest[key]
        for key in (
            "source",
            "inferred",
            "raw0_u16",
            "voltage_mv_candidate",
            "signed2_i16",
            "signed3_i16",
            "raw4_u16",
            "raw5_u16",
            "status_byte_candidate",
            "status_hex_candidate",
            "extra_hex",
            "device_boot_timestamp",
        )
        if key in latest
    }
    update_snapshot_range(
        snapshot,
        usable_rows,
        source_key="voltage_mv_candidate",
        low_key="min_voltage_mv_candidate",
        high_key="max_voltage_mv_candidate",
    )
    update_snapshot_range(
        snapshot,
        usable_rows,
        source_key="signed2_i16",
        low_key="min_signed2_i16",
        high_key="max_signed2_i16",
    )
    snapshot["sample_count"] = len(usable_rows)
    return snapshot


def update_snapshot_range(
    snapshot: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    source_key: str,
    low_key: str,
    high_key: str,
) -> None:
    values = [
        row.get(source_key)
        for row in rows
        if isinstance(row.get(source_key), int)
        and not isinstance(row.get(source_key), bool)
    ]
    if values:
        snapshot[low_key] = min(values)
        snapshot[high_key] = max(values)


def build_charger_state(charger_debug: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}
    latest_timestamps = [
        row.get("device_boot_timestamp")
        for row in charger_debug.values()
        if isinstance(row, dict)
        and isinstance(row.get("device_boot_timestamp"), int)
    ]
    if latest_timestamps:
        state["latest_boot_timestamp"] = max(latest_timestamps)

    chg_ind = debug_numbers(charger_debug, "chg_ind")
    if len(chg_ind) >= 1:
        state["indicator_percent"] = chg_ind[0]
    if len(chg_ind) >= 2:
        state["indicator_flag"] = chg_ind[1]

    chg_rp = debug_numbers(charger_debug, "chg_rp")
    if len(chg_rp) >= 1:
        state["rp_state"] = chg_rp[0]
    if len(chg_rp) >= 2:
        state["rp_raw"] = chg_rp[1]

    chg_rc = debug_numbers(charger_debug, "chg_rc")
    if len(chg_rc) >= 1:
        state["rc_state"] = chg_rc[0]
    if len(chg_rc) >= 2:
        state["rc_flag"] = chg_rc[1]

    chg_hs = debug_numbers(charger_debug, "chg_hs")
    if chg_hs:
        state["hs_raw"] = chg_hs[0]

    chgv = debug_numbers(charger_debug, "chgv")
    if len(chgv) >= 1:
        state["chgv_raw_a"] = chgv[0]
    if len(chgv) >= 2:
        state["chgv_raw_b"] = chgv[1]

    chg_bc = debug_numbers(charger_debug, "chg_bc")
    if chg_bc:
        state["bc_state"] = chg_bc[0]

    brx_values = debug_values(charger_debug, "brx")
    if brx_values:
        state["brx_state"] = brx_values[0]
    brx_numbers = debug_numbers(charger_debug, "brx")
    if brx_numbers:
        state["brx_raw"] = brx_numbers[0]
    if len(brx_numbers) >= 2:
        state["brx_flag"] = brx_numbers[1]

    charger_status = first_hex_debug_value(charger_debug, "ChgSt")
    if charger_status is not None:
        state["charger_status_hex"] = charger_status[0]
        state["charger_status_value"] = charger_status[1]
        state["charger_status_bits"] = set_bit_indexes(charger_status[1])

    rcell = first_hex_debug_value(charger_debug, "rcell")
    if rcell is not None:
        state["rcell_hex"] = rcell[0]
        state["rcell_raw"] = rcell[1]

    if state:
        state["source_keys"] = sorted(charger_debug)
    return state


def build_setup_state(
    setup_debug: dict[str, Any], *, transition: Any = None
) -> dict[str, Any]:
    state: dict[str, Any] = {}
    latest_timestamps = [
        row.get("device_boot_timestamp")
        for row in setup_debug.values()
        if isinstance(row, dict)
        and isinstance(row.get("device_boot_timestamp"), int)
    ]
    if latest_timestamps:
        state["latest_boot_timestamp"] = max(latest_timestamps)
    if isinstance(transition, str) and transition:
        state["transition"] = transition

    simple_numeric_fields = {
        "in_bed": ("in_bed_flag", 0),
        "i_info": ("info_state", 0),
        "bc": ("boot_context", 0),
        "pf": ("platform_flags", 0),
        "EFLO": ("eflo_flag", 0),
        "BLS": ("bls_state", 0),
        "CcM": ("ccm", 0),
        "CcV": ("ccv_value", 0),
        "blestda": ("ble_setup_state_a", 0),
        "bleseck": ("ble_security_state", 0),
        "blep256": ("ble_p256_state", 0),
    }
    for key, (field, index) in simple_numeric_fields.items():
        numbers = debug_numbers(setup_debug, key)
        if len(numbers) > index:
            state[field] = numbers[index]

    ccp_values = debug_values(setup_debug, "CcP")
    if ccp_values:
        state["ccp_value"] = ccp_values[0]
    if len(ccp_values) >= 2:
        state["ccp_status"] = ccp_values[1]

    mfc_values = debug_values(setup_debug, "MFC")
    if mfc_values:
        state["mfc_value"] = mfc_values[0]
    if len(mfc_values) >= 2:
        state["mfc_status"] = mfc_values[1]

    tef_values = debug_values(setup_debug, "tef")
    if tef_values:
        state["tef_code"] = tef_values[0]
    if len(tef_values) >= 2:
        state["tef_status"] = tef_values[1]

    setup_source_keys = [
        key
        for key, row in sorted(setup_debug.items())
        if isinstance(row, dict)
        and row.get("category") in {"setup_state", "ble_setup"}
    ]
    if setup_source_keys:
        state["source_keys"] = setup_source_keys
    meaningful_keys = set(state) - {"latest_boot_timestamp"}
    return state if meaningful_keys else {}


def build_health_debug_state(health_debug: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}
    latest_timestamps = [
        row.get("device_boot_timestamp")
        for row in health_debug.values()
        if isinstance(row, dict)
        and isinstance(row.get("device_boot_timestamp"), int)
    ]
    if latest_timestamps:
        state["latest_boot_timestamp"] = max(latest_timestamps)

    dhr_mode = debug_numbers(health_debug, "DHR_mode")
    if dhr_mode:
        state["daytime_hr_mode"] = dhr_mode[0]

    if state:
        state["source_keys"] = sorted(health_debug)
    return state


def build_fuel_gauge_state(fuel_gauge_debug: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}
    latest_timestamps = [
        row.get("device_boot_timestamp")
        for row in fuel_gauge_debug.values()
        if isinstance(row, dict)
        and isinstance(row.get("device_boot_timestamp"), int)
    ]
    if latest_timestamps:
        state["latest_boot_timestamp"] = max(latest_timestamps)

    vf_percent = debug_numbers(fuel_gauge_debug, "FGVf%")
    if vf_percent:
        state["vf_percent_candidate"] = vf_percent[0]

    lcu = debug_numbers(fuel_gauge_debug, "FGlcu")
    if lcu:
        state["lcu_value_a_candidate"] = lcu[0]
    if len(lcu) >= 2:
        state["lcu_value_b_candidate"] = lcu[1]

    design_capacity = debug_numbers(fuel_gauge_debug, "FGdcap")
    if design_capacity:
        state["design_capacity_candidate"] = design_capacity[0]

    if state:
        state["source_keys"] = sorted(fuel_gauge_debug)
    return state


def debug_numbers(debug_rows: dict[str, Any], key: str) -> list[int]:
    row = debug_rows.get(key)
    if not isinstance(row, dict):
        return []
    values = row.get("numeric_values")
    if not isinstance(values, list):
        return []
    return [
        value
        for value in values
        if isinstance(value, int) and not isinstance(value, bool)
    ]


def debug_values(debug_rows: dict[str, Any], key: str) -> list[str]:
    row = debug_rows.get(key)
    if not isinstance(row, dict):
        return []
    values = row.get("values")
    if not isinstance(values, list):
        return []
    return [str(value) for value in values]


def first_hex_debug_value(
    debug_rows: dict[str, Any], key: str
) -> tuple[str, int] | None:
    values = debug_values(debug_rows, key)
    if not values:
        return None
    parsed = parse_debug_hex_int(values[0])
    if parsed is None:
        return None
    normalized = normalize_debug_hex(values[0])
    return normalized, parsed


def parse_debug_hex_int(value: str) -> int | None:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text or any(char not in "0123456789abcdef" for char in text):
        return None
    return int(text, 16)


def normalize_debug_hex(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    width = max(2, len(text))
    return "0x" + text.zfill(width)


def set_bit_indexes(value: int) -> list[int]:
    return [index for index in range(value.bit_length()) if value & (1 << index)]


def first_debug_value(
    debug_values: dict[str, dict[str, Any]], key: str
) -> str | None:
    values = debug_values.get(key, {}).get("values")
    if isinstance(values, list) and values:
        return str(values[0])
    return None


def build_feature_summary(result: dict[str, Any]) -> dict[str, Any]:
    feature_status = result.get("feature_status")
    if not isinstance(feature_status, dict) or not feature_status:
        return {}

    features: dict[str, str] = {}
    health_features: dict[str, str] = {}
    modes: dict[str, int] = {}
    statuses: dict[str, int] = {}
    states: dict[str, int] = {}
    subscriptions: dict[str, int] = {}
    active_features: list[str] = []

    for row in feature_status.values():
        if not isinstance(row, dict):
            continue
        feature = feature_label(row)
        mode = str(row.get("mode_name", ""))
        status = str(row.get("status_name", ""))
        state = str(row.get("state_name", ""))
        subscription = str(row.get("subscription_mode_name", ""))
        label = f"{mode}/{status}/{state}/{subscription}"
        features[feature] = label
        if feature in HEALTH_FEATURE_NAMES:
            health_features[feature] = label
        increment_count(modes, mode)
        increment_count(statuses, status)
        increment_count(states, state)
        increment_count(subscriptions, subscription)
        if status != "off" or state != "idle" or subscription != "off":
            active_features.append(feature)

    summary: dict[str, Any] = {
        "count": len(features),
        "features": dict(sorted(features.items())),
        "modes": dict(sorted(modes.items())),
        "statuses": dict(sorted(statuses.items())),
        "states": dict(sorted(states.items())),
        "subscriptions": dict(sorted(subscriptions.items())),
    }
    if health_features:
        summary["health_features"] = dict(sorted(health_features.items()))
    if active_features:
        summary["active_features"] = sorted(active_features)
    return summary


def feature_label(decoded: dict[str, Any]) -> str:
    feature = decoded.get("feature_name")
    if isinstance(feature, str) and feature and feature != "unknown":
        return feature
    feature_id = decoded.get("feature_id")
    if isinstance(feature_id, int):
        return f"feature_0x{feature_id:02x}"
    return "feature_unknown"


def increment_count(counts: dict[str, int], key: str) -> None:
    key = key or "unknown"
    counts[key] = counts.get(key, 0) + 1


def build_event_summary(result: dict[str, Any]) -> dict[str, Any]:
    events = result.get("events")
    if not isinstance(events, list) or not events:
        return {}

    unique_events: list[dict[str, Any]] = []
    seen_events: set[tuple[Any, Any, Any]] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        key = (
            event.get("event_tag"),
            event.get("device_boot_timestamp"),
            event.get("payload_hex"),
        )
        if key in seen_events:
            continue
        seen_events.add(key)
        unique_events.append(event)

    timestamps = [
        event.get("device_boot_timestamp")
        for event in unique_events
        if isinstance(event.get("device_boot_timestamp"), int)
    ]
    summary: dict[str, Any] = {
        "count": len(events),
        "unique_count": len(unique_events),
        "duplicate_count": len(events) - len(unique_events),
    }
    if timestamps:
        first = min(timestamps)
        last = max(timestamps)
        summary.update(
            {
                "first_boot_timestamp": first,
                "last_boot_timestamp": last,
                "next_start_timestamp": last + 1,
                "span_seconds": last - first,
            }
        )

    event_names: dict[str, int] = {}
    debug_keys: dict[str, int] = {}
    debug_categories: dict[str, int] = {}
    debug_labels: dict[str, int] = {}
    debug_data_codes: dict[str, int] = {}
    debug_value_stats: dict[str, dict[str, Any]] = {}
    charger_activity = build_charger_activity(unique_events)
    health_events = build_health_event_summary(unique_events)
    for event in unique_events:
        event_name = event.get("event_name")
        if isinstance(event_name, str):
            event_names[event_name] = event_names.get(event_name, 0) + 1
        debug_key = event.get("debug_key")
        if isinstance(debug_key, str):
            debug_keys[debug_key] = debug_keys.get(debug_key, 0) + 1
            values = event.get("debug_values")
            update_debug_value_stats(
                debug_value_stats,
                debug_key,
                values if isinstance(values, list) else [],
                event.get("debug_numeric_values"),
                event.get("device_boot_timestamp"),
            )
        debug_category = event.get("debug_category")
        if isinstance(debug_category, str):
            debug_categories[debug_category] = debug_categories.get(debug_category, 0) + 1
        debug_label = event.get("debug_label")
        if isinstance(debug_label, str):
            debug_labels[debug_label] = debug_labels.get(debug_label, 0) + 1
        debug_code = event.get("debug_data_code_hex")
        if isinstance(debug_code, str):
            debug_data_codes[debug_code] = debug_data_codes.get(debug_code, 0) + 1
    if event_names:
        summary["event_names"] = dict(sorted(event_names.items()))
    if debug_keys:
        summary["debug_keys"] = dict(sorted(debug_keys.items()))
    if debug_categories:
        summary["debug_categories"] = dict(sorted(debug_categories.items()))
    if debug_labels:
        summary["debug_labels"] = dict(sorted(debug_labels.items()))
    if debug_data_codes:
        summary["debug_data_codes"] = dict(sorted(debug_data_codes.items()))
    if debug_value_stats:
        summary["debug_value_stats"] = dict(sorted(debug_value_stats.items()))
    if charger_activity:
        summary["charger_activity"] = charger_activity
    if health_events:
        summary["health_events"] = health_events

    events_done = result.get("events_done")
    if isinstance(events_done, list) and events_done:
        latest_done = next(
            (row for row in reversed(events_done) if isinstance(row, dict)),
            {},
        )
        if latest_done:
            summary["latest_events_done"] = {
                key: latest_done.get(key)
                for key in (
                    "request_start_timestamp",
                    "request_start_hex",
                    "request_max_events",
                    "events_received",
                    "bytes_left",
                    "sleep_analysis_progress",
                    "unknown_u16",
                )
                if key in latest_done
            }
            summary["complete"] = (
                latest_done.get("events_received") == 0
                and latest_done.get("bytes_left") == 0
            )
    return summary


def build_health_event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    ibi_values: list[int] = []
    bpm_values: list[float] = []
    spo2_values: list[int] = []
    temperature_values: list[float] = []
    ppg_amplitudes: list[float] = []
    green_quality_count = 0

    for event in events:
        found = False
        for key in (
            "ibi_amplitude_records",
            "green_ibi_amplitude_records",
            "spo2_ibi_records",
        ):
            records = event.get(key)
            if isinstance(records, list):
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    ibi = record.get("ibi_ms")
                    if (
                        isinstance(ibi, int | float)
                        and not isinstance(ibi, bool)
                        and ibi > 0
                    ):
                        ibi_values.append(int(ibi))
                        found = True
                    bpm = record.get("bpm_estimate")
                    if (
                        isinstance(bpm, int | float)
                        and not isinstance(bpm, bool)
                        and bpm > 0
                    ):
                        bpm_values.append(round(float(bpm), 1))
                        found = True

        quality = event.get("green_ibi_quality_samples")
        if isinstance(quality, list) and quality:
            green_quality_count += len(
                [row for row in quality if isinstance(row, dict)]
            )
            found = True

        samples = event.get("spo2_samples")
        if isinstance(samples, list):
            values = [
                int(value)
                for value in samples
                if isinstance(value, int) and not isinstance(value, bool)
            ]
            if values:
                spo2_values.extend(values)
                found = True
        stable = event.get("spo2_stable_raw")
        if isinstance(stable, int) and not isinstance(stable, bool):
            spo2_values.append(stable)
            found = True

        temperatures = event.get("temperature_c_samples")
        if isinstance(temperatures, list):
            values = [
                round(float(value), 2)
                for value in temperatures
                if isinstance(value, int | float) and not isinstance(value, bool)
            ]
            if values:
                temperature_values.extend(values)
                found = True
        temperature = event.get("temperature_c")
        if isinstance(temperature, int | float) and not isinstance(temperature, bool):
            temperature_values.append(round(float(temperature), 2))
            found = True
        sleep_temperatures = event.get("sleep_temperature_samples")
        if isinstance(sleep_temperatures, list):
            for sample in sleep_temperatures:
                if not isinstance(sample, dict):
                    continue
                value = sample.get("temperature_c")
                if isinstance(value, int | float) and not isinstance(value, bool):
                    temperature_values.append(round(float(value), 2))
                    found = True

        amplitude = event.get("ppg_amplitude_ratio")
        if isinstance(amplitude, int | float) and not isinstance(amplitude, bool):
            ppg_amplitudes.append(round(float(amplitude), 6))
            found = True

        if found:
            event_name = event.get("event_name")
            if isinstance(event_name, str) and event_name:
                increment_count(event_counts, event_name)

    summary: dict[str, Any] = {}
    if event_counts:
        summary["event_counts"] = dict(sorted(event_counts.items()))
    if ibi_values:
        summary["ibi_record_count"] = len(ibi_values)
        summary["ibi_ms_min"] = min(ibi_values)
        summary["ibi_ms_max"] = max(ibi_values)
        summary["ibi_ms_latest"] = ibi_values[-1]
    if bpm_values:
        summary["bpm_estimate_min"] = min(bpm_values)
        summary["bpm_estimate_max"] = max(bpm_values)
        summary["bpm_estimate_latest"] = bpm_values[-1]
    if green_quality_count:
        summary["green_ibi_quality_sample_count"] = green_quality_count
    if spo2_values:
        summary["spo2_sample_count"] = len(spo2_values)
        summary["spo2_value_min"] = min(spo2_values)
        summary["spo2_value_max"] = max(spo2_values)
        summary["spo2_value_latest"] = spo2_values[-1]
    if temperature_values:
        summary["temperature_sample_count"] = len(temperature_values)
        summary["temperature_c_min"] = min(temperature_values)
        summary["temperature_c_max"] = max(temperature_values)
        summary["temperature_c_latest"] = temperature_values[-1]
    if ppg_amplitudes:
        summary["ppg_amplitude_count"] = len(ppg_amplitudes)
        summary["ppg_amplitude_latest"] = ppg_amplitudes[-1]
    return summary


def build_charger_activity(events: list[dict[str, Any]]) -> dict[str, Any]:
    activity: dict[str, Any] = {}
    key_counts: dict[str, int] = {}
    timestamps: list[int] = []
    for event in events:
        key = event.get("debug_key")
        if not isinstance(key, str) or key not in {
            "chg_ind",
            "chg_rp",
            "chg_rc",
            "chg_hs",
            "chgv",
            "chg_bc",
            "ChgSt",
            "rcell",
            "brx",
        }:
            continue
        key_counts[key] = key_counts.get(key, 0) + 1
        timestamp = event.get("device_boot_timestamp")
        if isinstance(timestamp, int):
            timestamps.append(timestamp)
        numeric_values = event.get("debug_numeric_values")
        numbers = (
            [
                value
                for value in numeric_values
                if isinstance(value, int) and not isinstance(value, bool)
            ]
            if isinstance(numeric_values, list)
            else []
        )
        if key == "chg_ind":
            update_numeric_range(activity, "indicator_percent", numbers, 0)
            update_value_counts(activity, "indicator_flag_counts", numbers, 1)
        elif key == "chg_rp":
            update_value_counts(activity, "rp_state_counts", numbers, 0)
            update_numeric_range(activity, "rp_raw", numbers, 1)
        elif key == "chg_rc":
            update_value_counts(activity, "rc_state_counts", numbers, 0)
            update_value_counts(activity, "rc_flag_counts", numbers, 1)
        elif key == "chg_hs":
            update_numeric_range(activity, "hs_raw", numbers, 0)
        elif key == "chgv":
            update_numeric_range(activity, "chgv_raw_a", numbers, 0)
            update_numeric_range(activity, "chgv_raw_b", numbers, 1)
        elif key == "chg_bc":
            update_value_counts(activity, "bc_state_counts", numbers, 0)
        elif key == "brx":
            text_values = event.get("debug_values")
            if isinstance(text_values, list) and text_values:
                update_string_counts(activity, "brx_state_counts", str(text_values[0]))
            update_numeric_range(activity, "brx_raw", numbers, 0)
            update_value_counts(activity, "brx_flag_counts", numbers, 1)
        elif key in {"ChgSt", "rcell"}:
            text_values = event.get("debug_values")
            if not isinstance(text_values, list) or not text_values:
                continue
            parsed = parse_debug_hex_int(str(text_values[0]))
            if parsed is None:
                continue
            if key == "ChgSt":
                update_string_counts(
                    activity,
                    "charger_status_counts",
                    normalize_debug_hex(str(text_values[0])),
                )
            else:
                update_numeric_range_value(activity, "rcell_raw", parsed)

    if not key_counts:
        return {}
    activity["event_count"] = sum(key_counts.values())
    activity["key_counts"] = dict(sorted(key_counts.items()))
    if timestamps:
        first = min(timestamps)
        last = max(timestamps)
        activity["first_boot_timestamp"] = first
        activity["last_boot_timestamp"] = last
        activity["span_seconds"] = last - first
    return normalize_charger_activity(activity)


def update_numeric_range(
    activity: dict[str, Any], key: str, numbers: list[int], index: int
) -> None:
    if index >= len(numbers):
        return
    value = numbers[index]
    activity[f"{key}_latest"] = value
    low_key = f"{key}_min"
    high_key = f"{key}_max"
    activity[low_key] = min(activity.get(low_key, value), value)
    activity[high_key] = max(activity.get(high_key, value), value)


def update_numeric_range_value(activity: dict[str, Any], key: str, value: int) -> None:
    activity[f"{key}_latest"] = value
    low_key = f"{key}_min"
    high_key = f"{key}_max"
    activity[low_key] = min(activity.get(low_key, value), value)
    activity[high_key] = max(activity.get(high_key, value), value)


def update_value_counts(
    activity: dict[str, Any], key: str, numbers: list[int], index: int
) -> None:
    if index >= len(numbers):
        return
    counts = activity.setdefault(key, {})
    value = str(numbers[index])
    counts[value] = counts.get(value, 0) + 1


def update_string_counts(activity: dict[str, Any], key: str, value: str) -> None:
    counts = activity.setdefault(key, {})
    counts[value] = counts.get(value, 0) + 1


def normalize_charger_activity(activity: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in activity.items():
        if isinstance(value, dict):
            normalized[key] = dict(
                sorted(value.items(), key=lambda item: (-int(item[1]), item[0]))
            )
        else:
            normalized[key] = value
    return normalized


def update_debug_value_stats(
    stats: dict[str, dict[str, Any]],
    key: str,
    values: list[Any],
    numeric_values: Any,
    timestamp: Any,
) -> None:
    row = stats.setdefault(key, {"count": 0})
    row["count"] += 1
    row["latest_values"] = [str(value) for value in values]
    if isinstance(timestamp, int):
        row["latest_boot_timestamp"] = timestamp

    if not isinstance(numeric_values, list):
        return
    numbers = [
        value
        for value in numeric_values
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    if not numbers:
        return

    row["latest_numeric_values"] = numbers
    min_values = row.setdefault("min_numeric_values", list(numbers))
    max_values = row.setdefault("max_numeric_values", list(numbers))
    for index, value in enumerate(numbers):
        if index >= len(min_values):
            min_values.append(value)
            max_values.append(value)
            continue
        min_values[index] = min(min_values[index], value)
        max_values[index] = max(max_values[index], value)


def feature_status_result_key(packet_name: str, decoded: dict[str, Any]) -> str:
    if packet_name.startswith("feature_status:"):
        return packet_name
    feature_id = decoded.get("feature_id")
    if isinstance(feature_id, int):
        return f"feature_status:0x{feature_id:02x}"
    return packet_name or "feature_status:unknown"


def build_feature_latest_probe_packets(feature_id: int) -> list[tuple[str, bytes]]:
    return [
        (
            f"feature_status:0x{feature_id:02x}",
            p.build_get_feature_status_request(feature_id),
        ),
        (
            f"feature_mode:0x{feature_id:02x}:connected_live",
            p.build_set_feature_mode_request(feature_id, 0x03),
        ),
        (
            f"feature_subscription:0x{feature_id:02x}:latest",
            p.build_set_feature_subscription_request(feature_id, 0x02),
        ),
        (
            f"feature_status:0x{feature_id:02x}",
            p.build_get_feature_status_request(feature_id),
        ),
    ]


def build_live_hr_probe_packets() -> list[tuple[str, bytes]]:
    packets: list[tuple[str, bytes]] = []
    for group in (
        "battery",
        "feature_status:0x02",
        "feature_status:0x08",
        "ring_mode_fast_hr",
        "daytime_hr_latest",
        "resting_hr_latest",
        "feature_status:0x02",
        "feature_status:0x08",
    ):
        packets.extend(build_probe_packets(group))
    return packets


def build_feature_restore_probe_packets(feature_id: int) -> list[tuple[str, bytes]]:
    return [
        (
            f"feature_subscription:0x{feature_id:02x}:off",
            p.build_set_feature_subscription_request(feature_id, 0x00),
        ),
        (
            f"feature_mode:0x{feature_id:02x}:automatic",
            p.build_set_feature_mode_request(feature_id, 0x01),
        ),
        (
            f"feature_status:0x{feature_id:02x}",
            p.build_get_feature_status_request(feature_id),
        ),
    ]


def parse_feature_id(value: str) -> int:
    try:
        feature_id = int(value, 0)
    except ValueError as exc:
        raise SystemExit(f"invalid feature id: {value}") from exc
    if not 0 <= feature_id <= 0xFF:
        raise SystemExit(f"feature id out of range: {value}")
    return feature_id


def parse_feature_mode_probe(name: str) -> tuple[int, int]:
    parts = name.split(":")
    if len(parts) != 3:
        raise SystemExit("feature_mode format is feature_mode:<feature_id>:<mode>")
    return parse_feature_id(parts[1]), parse_feature_mode(parts[2])


def parse_feature_subscription_probe(name: str) -> tuple[int, int]:
    parts = name.split(":")
    if len(parts) != 3:
        raise SystemExit(
            "feature_subscription format is "
            "feature_subscription:<feature_id>:<subscription_mode>"
        )
    return parse_feature_id(parts[1]), parse_feature_subscription_mode(parts[2])


def parse_feature_mode(value: str) -> int:
    if value.strip().lower().replace("-", "_") == "requested_subscription":
        return 0x03
    return parse_named_byte(value, p.FEATURE_MODES, "feature mode")


def parse_feature_subscription_mode(value: str) -> int:
    return parse_named_byte(
        value,
        p.FEATURE_SUBSCRIPTION_MODES,
        "feature subscription mode",
    )


def parse_ring_mode_probe(name: str) -> int:
    parts = name.split(":")
    if len(parts) != 2:
        raise SystemExit("ring_mode format is ring_mode:<mode>")
    return parse_ring_mode(parts[1])


def parse_ring_mode(value: str) -> int:
    return parse_named_byte(value, p.RING_MODES, "ring mode")


def parse_named_byte(value: str, names: dict[int, str], label: str) -> int:
    normalized = value.strip().lower().replace("-", "_")
    for number, name in names.items():
        if normalized == name:
            return int(number)
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        choices = ", ".join(sorted(names.values()))
        raise SystemExit(f"invalid {label}: {value}; use one of: {choices}") from exc
    if not 0 <= parsed <= 0xFF:
        raise SystemExit(f"{label} out of range: {value}")
    return parsed


def feature_mode_name(mode: int) -> str:
    return p.FEATURE_MODES.get(mode, f"0x{mode:02x}")


def feature_subscription_name(subscription_mode: int) -> str:
    return p.FEATURE_SUBSCRIPTION_MODES.get(
        subscription_mode,
        f"0x{subscription_mode:02x}",
    )


def ring_mode_name(mode: int) -> str:
    return p.RING_MODES.get(mode, f"0x{mode:02x}")


def parse_capabilities_page(value: str) -> int:
    try:
        page = int(value, 0)
    except ValueError as exc:
        raise SystemExit(f"invalid capabilities page: {value}") from exc
    if not 0 <= page <= 0xFF:
        raise SystemExit(f"capabilities page out of range: {value}")
    return page


def parse_product_info_type(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in set(p.PRODUCT_INFO_TYPES.values()):
        raise SystemExit(f"unsupported product info type: {value}")
    return normalized


def parse_product_info_hex(value: str) -> bytes:
    compact = "".join(char for char in value.strip().lower() if char in "0123456789abcdef")
    if len(compact) != 6:
        raise SystemExit(f"product info hex must be exactly 3 bytes: {value}")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise SystemExit(f"invalid product info hex: {value}") from exc


def parse_product_info_hex_range(name: str) -> list[bytes]:
    parts = name.split(":")
    if len(parts) not in {4, 5}:
        raise SystemExit(
            "product_info_hex_range format is "
            "product_info_hex_range:<start>:<end>:<length>[:step]"
        )
    try:
        start = int(parts[1], 0)
        end = int(parts[2], 0)
        length = int(parts[3], 0)
        step = int(parts[4], 0) if len(parts) == 5 else 4
    except ValueError as exc:
        raise SystemExit(f"invalid product info hex range: {name}") from exc
    if not 0 <= start <= 0xFFFF:
        raise SystemExit(f"product info range start out of range: {parts[1]}")
    if not 0 <= end <= 0x10000:
        raise SystemExit(f"product info range end out of range: {parts[2]}")
    if end < start:
        raise SystemExit(f"product info range end precedes start: {name}")
    if not 1 <= length <= 0xFF:
        raise SystemExit(f"product info range length out of range: {parts[3]}")
    if not 1 <= step <= 0xFF:
        value = parts[4] if len(parts) == 5 else str(step)
        raise SystemExit(f"product info range step out of range: {value}")
    return [
        offset.to_bytes(2, "little") + bytes([length])
        for offset in range(start, end, step)
    ]


def should_stop_after_probe_error(exc: Exception) -> bool:
    text = str(exc)
    return "Not connected" in text or "ATT error: 0x0e" in text


def parse_events_probe(name: str) -> tuple[int, int]:
    parts = name.split(":")
    if len(parts) == 1:
        return 0, 8
    if len(parts) != 3:
        raise SystemExit("events probe format is events:<start_timestamp>:<max_events>")
    try:
        start_timestamp = int(parts[1], 0)
        max_events = int(parts[2], 0)
    except ValueError as exc:
        raise SystemExit(f"invalid events probe: {name}") from exc
    if not 0 <= start_timestamp <= 0xFFFFFFFF:
        raise SystemExit(f"events start timestamp out of range: {parts[1]}")
    if not 1 <= max_events <= 0xFF:
        raise SystemExit(f"events max out of range: {parts[2]}")
    return start_timestamp, max_events


def event_request_from_packet_name(packet_name: str) -> dict[str, Any]:
    if not is_events_probe_name(packet_name):
        return {}
    try:
        start_timestamp, max_events = parse_events_probe(packet_name)
    except SystemExit:
        return {}
    return {
        "request_start_timestamp": start_timestamp,
        "request_start_hex": f"0x{start_timestamp:08x}",
        "request_max_events": max_events,
    }


def parse_events_walk_probe(name: str) -> tuple[int, int, int]:
    parts = name.split(":")
    if len(parts) != 4:
        raise SystemExit(
            "events_walk format is events_walk:<start_timestamp>:<page_count>:<max_events>"
        )
    try:
        start_timestamp = int(parts[1], 0)
        page_count = int(parts[2], 0)
        max_events = int(parts[3], 0)
    except ValueError as exc:
        raise SystemExit(f"invalid events walk: {name}") from exc
    if not 0 <= start_timestamp <= 0xFFFFFFFF:
        raise SystemExit(f"events walk start timestamp out of range: {parts[1]}")
    if not 1 <= page_count <= 0x100:
        raise SystemExit(f"events walk page count out of range: {parts[2]}")
    if not 1 <= max_events <= 0xFF:
        raise SystemExit(f"events walk max events out of range: {parts[3]}")
    return start_timestamp, page_count, max_events


def parse_events_range_probe(name: str) -> list[tuple[int, int]]:
    parts = name.split(":")
    if len(parts) != 5:
        raise SystemExit(
            "events_range format is events_range:<start>:<end>:<step>:<max_events>"
        )
    try:
        start = int(parts[1], 0)
        end = int(parts[2], 0)
        step = int(parts[3], 0)
        max_events = int(parts[4], 0)
    except ValueError as exc:
        raise SystemExit(f"invalid events range: {name}") from exc
    if not 0 <= start <= 0xFFFFFFFF:
        raise SystemExit(f"events range start out of range: {parts[1]}")
    if not 0 <= end <= 0x100000000:
        raise SystemExit(f"events range end out of range: {parts[2]}")
    if end < start:
        raise SystemExit(f"events range end precedes start: {name}")
    if not 1 <= step <= 0xFFFFFFFF:
        raise SystemExit(f"events range step out of range: {parts[3]}")
    if not 1 <= max_events <= 0xFF:
        raise SystemExit(f"events range max out of range: {parts[4]}")
    return [(timestamp, max_events) for timestamp in range(start, end, step)]


def decode_notification(
    uuid: str,
    raw: bytes,
    probe_context: dict[str, str],
) -> dict[str, Any]:
    if uuid not in {
        p.OURA_NOTIFY_UUID,
        "98ed0004-a541-11e4-b6a0-0002a5d5c51b",
        "98ed0005-a541-11e4-b6a0-0002a5d5c51b",
        "98ed0006-a541-11e4-b6a0-0002a5d5c51b",
        "00060001-f8ce-11e4-abf4-0002a5d5c51b",
    }:
        return {}
    try:
        product_info_type = product_info_type_from_context(probe_context)
        return {
            "packets": [
                p.parse_response(packet, product_info_type=product_info_type)
                for packet in p.parse_packets(raw)
            ]
        }
    except Exception as exc:
        return {"decode_error": f"{type(exc).__name__}: {exc}"}


def product_info_type_from_context(probe_context: dict[str, str]) -> str | bytes | None:
    packet_name = probe_context.get("packet", "")
    if not packet_name.startswith("product_info:"):
        if packet_name.startswith("product_info_hex:"):
            return parse_product_info_hex(packet_name.split(":", 1)[1])
        return None
    return packet_name.split(":", 1)[1]


def pump(seconds: float) -> None:
    context = GLib.MainContext.default()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while context.pending():
            context.iteration(False)
        time.sleep(0.01)


def json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple, dbus.Array)):
        return [json_safe(item) for item in value]
    if isinstance(value, (dict, dbus.Dictionary)):
        return {str(key): json_safe(item) for key, item in value.items()}
    return str(value)


if __name__ == "__main__":
    sys.exit(main())
