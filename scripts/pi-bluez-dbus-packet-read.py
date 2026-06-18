#!/usr/bin/env python3
"""Read safe Oura packets through BlueZ D-Bus GATT objects.

This bypasses Bleak's Linux device lookup path and operates on the BlueZ
Device1/GattCharacteristic1 objects that already exist after pairing.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

from oura_ring4_ble import protocol as p

BLUEZ = "org.bluez"
OBJ_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPS = "org.freedesktop.DBus.Properties"
DEVICE = "org.bluez.Device1"
CHAR = "org.bluez.GattCharacteristic1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Use BlueZ D-Bus objects to write safe Oura packets."
    )
    parser.add_argument("--address", default="", help="identity address to prefer")
    parser.add_argument("--device-path", default="", help="BlueZ Device1 object path")
    parser.add_argument("--response-timeout", type=float, default=2.0)
    parser.add_argument("--settle-seconds", type=float, default=0.15)
    parser.add_argument(
        "--packets",
        default="firmware,battery,auth_nonce",
        help=(
            "comma-separated safe packets to request, in order; supported: "
            "firmware,battery,auth_nonce"
        ),
    )
    parser.add_argument(
        "--wait-services-timeout",
        type=float,
        default=8.0,
        help="seconds to wait for BlueZ to publish Oura GATT characteristics",
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help="call Device1.Connect before GATT writes if not already connected",
    )
    parser.add_argument(
        "--require-connected",
        action="store_true",
        help=(
            "fail before GATT writes unless Device1.Connected is true; by default "
            "the reader still tries cached GATT objects after a raw HCI connect"
        ),
    )
    args = parser.parse_args()
    packet_names = parse_packet_names(args.packets)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    emit = make_emitter()

    try:
        objects = get_managed_objects(bus)
        device_path, device_props = find_device(objects, args.address, args.device_path)
        emit("dbus_device", {"path": device_path, "properties": json_safe(device_props)})
        if args.connect and not bool(device_props.get("Connected", False)):
            device = dbus.Interface(bus.get_object(BLUEZ, device_path), DEVICE)
            device.Connect()
            time.sleep(args.settle_seconds)
            objects = get_managed_objects(bus)
            device_props = objects[device_path][DEVICE]
        connected = bool(device_props.get("Connected", False))
        if args.require_connected and not connected:
            raise RuntimeError("BlueZ device is not connected")

        objects, device_props, notify_path, write_path = wait_for_packet_characteristics(
            bus,
            device_path,
            args.wait_services_timeout,
            emit,
        )
        connected = bool(device_props.get("Connected", False))
        emit(
            "dbus_characteristics",
            {
                "notify_path": notify_path,
                "write_path": write_path,
                "bluez_connected": connected,
            },
        )

        notifications: list[bytes] = []

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
            emit("dbus_notify", decode_payload(raw))

        bus.add_signal_receiver(
            on_props_changed,
            dbus_interface=PROPS,
            signal_name="PropertiesChanged",
            path=notify_path,
            path_keyword="path",
        )

        notify = dbus.Interface(bus.get_object(BLUEZ, notify_path), CHAR)
        write = dbus.Interface(bus.get_object(BLUEZ, write_path), CHAR)
        with suppress_dbus_error("org.bluez.Error.Failed", "Already notifying"):
            notify.StartNotify()
        pump(args.settle_seconds)

        result: dict[str, Any] = {
            "device": {
                "address": str(device_props.get("Address", "")),
                "name": str(device_props.get("Name", "")),
                "path": device_path,
            },
            "transport": "bluez-dbus",
            "bluez_connected": connected,
        }
        read_errors: dict[str, str] = {}
        unexpected_notifications: dict[str, list[dict[str, Any]]] = {}
        for packet_name, packet, expected_tags in build_request_specs(packet_names):
            notifications.clear()
            emit("dbus_tx", {"packet": packet_name, "tx_hex": packet.hex()})
            write.WriteValue(
                dbus.Array([dbus.Byte(value) for value in packet], signature="y"),
                dbus.Dictionary({"type": dbus.String("request")}, signature="sv"),
            )
            match = wait_for_packet(notifications, expected_tags, args.response_timeout)
            if match is None:
                read_errors[packet_name] = "no matching notification"
                if notifications:
                    unexpected_notifications[packet_name] = [
                        decode_payload(raw) for raw in notifications
                    ]
                continue
            result[packet_name] = decode_payload(match)

        if read_errors:
            result["read_errors"] = read_errors
        if unexpected_notifications:
            result["unexpected_notifications"] = unexpected_notifications
        if not any(key in result for key in ("firmware", "battery", "auth_nonce")):
            raise RuntimeError("no Oura packet responses received")
        emit("read_result", result)
        return 0
    except Exception as exc:
        emit("dbus_read_error", {"error_type": type(exc).__name__, "error": str(exc)})
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


def get_managed_objects(bus: dbus.SystemBus) -> dict[str, dict[str, dict[str, Any]]]:
    manager = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJ_MANAGER)
    return manager.GetManagedObjects()


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

    normalized = address.lower()
    candidates: list[tuple[int, str, dict[str, Any]]] = []
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
        if p.OURA_SERVICE_UUID in uuids:
            score += 20
        if "oura" in name.lower():
            score += 10
        if bool(props.get("Connected", False)):
            score += 5
        if score:
            candidates.append((score, path, props))
    if not candidates:
        raise RuntimeError("no Oura BlueZ Device1 object found")
    candidates.sort(key=lambda row: (-row[0], row[1]))
    _, path, props = candidates[0]
    return path, props


def find_packet_characteristics(
    objects: dict[str, dict[str, dict[str, Any]]], device_path: str
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
        raise RuntimeError("could not find Oura notify/write characteristics")
    return notify_path, write_path


def parse_packet_names(value: str) -> list[str]:
    names = [part.strip().lower() for part in value.split(",") if part.strip()]
    supported = {"firmware", "battery", "auth_nonce"}
    unsupported = sorted(set(names) - supported)
    if unsupported:
        raise SystemExit(f"unsupported packet name(s): {', '.join(unsupported)}")
    if not names:
        raise SystemExit("at least one packet name is required")
    return names


def build_request_specs(
    packet_names: list[str],
) -> list[tuple[str, bytes, set[int]]]:
    specs: list[tuple[str, bytes, set[int]]] = []
    for name in packet_names:
        if name == "firmware":
            specs.append((name, p.build_get_firmware_request(), {p.TAG_FIRMWARE_RESPONSE}))
        elif name == "battery":
            specs.append((name, p.build_get_battery_request(), {p.TAG_BATTERY_RESPONSE}))
        elif name == "auth_nonce":
            specs.append((name, p.build_get_auth_nonce_request(), {p.TAG_EXTENDED}))
    return specs


def wait_for_packet_characteristics(
    bus: dbus.SystemBus,
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
            notify_path, write_path = find_packet_characteristics(objects, device_path)
            return objects, device_props, notify_path, write_path
        except RuntimeError as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            emit(
                "dbus_services_timeout",
                {
                    "device_path": device_path,
                    "services_resolved": bool(device_props.get("ServicesResolved", False)),
                    "connected": bool(device_props.get("Connected", False)),
                    "error": last_error,
                },
            )
            raise RuntimeError(last_error)
        pump(0.05)


def wait_for_packet(
    notifications: list[bytes], expected_tags: set[int], timeout: float
) -> bytes | None:
    deadline = time.monotonic() + timeout
    seen = 0
    while time.monotonic() < deadline:
        pump(0.03)
        for raw in notifications[seen:]:
            seen += 1
            try:
                packets = p.parse_packets(raw)
            except p.ProtocolError:
                continue
            if any(packet.tag in expected_tags for packet in packets):
                return raw
    return None


def pump(seconds: float) -> None:
    context = GLib.MainContext.default()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while context.pending():
            context.iteration(False)
        time.sleep(0.01)


def decode_payload(raw: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {"raw_hex": raw.hex()}
    try:
        row["packets"] = [p.parse_response(packet) for packet in p.parse_packets(raw)]
    except Exception as exc:
        row["decode_error"] = f"{type(exc).__name__}: {exc}"
    return row


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


class suppress_dbus_error:
    def __init__(self, name: str, message_part: str) -> None:
        self.name = name
        self.message_part = message_part

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if exc is None:
            return False
        if not isinstance(exc, dbus.exceptions.DBusException):
            return False
        return self.name in exc.get_dbus_name() and self.message_part in str(exc)


if __name__ == "__main__":
    sys.exit(main())
