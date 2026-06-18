#!/usr/bin/env python3
"""Dump read-only BlueZ GATT values for the paired Oura ring."""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from typing import Any

import dbus

from oura_ring4_ble import protocol as p

BLUEZ = "org.bluez"
OBJ_MANAGER = "org.freedesktop.DBus.ObjectManager"
DEVICE = "org.bluez.Device1"
SERVICE = "org.bluez.GattService1"
CHAR = "org.bluez.GattCharacteristic1"
DESC = "org.bluez.GattDescriptor1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read only GATT values already exposed by BlueZ."
    )
    parser.add_argument("--address", default="", help="identity address to prefer")
    parser.add_argument("--device-path", default="", help="BlueZ Device1 object path")
    parser.add_argument("--connect", action="store_true", help="call Device1.Connect")
    parser.add_argument("--wait-services-timeout", type=float, default=8.0)
    parser.add_argument("--read-timeout", type=float, default=5.0)
    args = parser.parse_args()

    emit = make_emitter()
    bus = dbus.SystemBus()

    try:
        objects = get_managed_objects(bus)
        device_path, device_props = find_device(objects, args.address, args.device_path)
        emit("gatt_device", {"path": device_path, "properties": json_safe(device_props)})

        if args.connect and not bool(device_props.get("Connected", False)):
            device = dbus.Interface(bus.get_object(BLUEZ, device_path), DEVICE)
            device.Connect(timeout=args.read_timeout)
            time.sleep(0.2)

        objects, device_props = wait_for_gatt_objects(
            bus, device_path, args.wait_services_timeout, emit
        )
        emit(
            "gatt_summary",
            {
                "connected": bool(device_props.get("Connected", False)),
                "services_resolved": bool(device_props.get("ServicesResolved", False)),
                "service_count": count_iface(objects, device_path, SERVICE),
                "characteristic_count": count_iface(objects, device_path, CHAR),
                "descriptor_count": count_iface(objects, device_path, DESC),
            },
        )

        for service_path in sorted(paths_with_iface(objects, device_path, SERVICE)):
            service_props = objects[service_path][SERVICE]
            emit(
                "gatt_service",
                {
                    "path": service_path,
                    "uuid": str(service_props.get("UUID", "")).lower(),
                    "primary": bool(service_props.get("Primary", False)),
                },
            )
            for char_path in sorted(characteristics_for_service(objects, service_path)):
                char_props = objects[char_path][CHAR]
                char_row: dict[str, Any] = {
                    "path": char_path,
                    "service_path": service_path,
                    "uuid": str(char_props.get("UUID", "")).lower(),
                    "flags": [str(flag) for flag in char_props.get("Flags", [])],
                    "handle": int(char_props.get("Handle", 0)),
                }
                if "read" in char_row["flags"]:
                    char_row["read"] = read_value(
                        bus, char_path, CHAR, args.read_timeout, char_row["uuid"]
                    )
                emit("gatt_characteristic", char_row)

                for desc_path in sorted(descriptors_for_char(objects, char_path)):
                    desc_props = objects[desc_path][DESC]
                    desc_row: dict[str, Any] = {
                        "path": desc_path,
                        "char_path": char_path,
                        "uuid": str(desc_props.get("UUID", "")).lower(),
                        "flags": [str(flag) for flag in desc_props.get("Flags", [])],
                        "handle": int(desc_props.get("Handle", 0)),
                    }
                    if "read" in desc_row["flags"]:
                        desc_row["read"] = read_value(
                            bus, desc_path, DESC, args.read_timeout, desc_row["uuid"]
                        )
                    emit("gatt_descriptor", desc_row)
        return 0
    except Exception as exc:
        emit("gatt_read_error", {"error_type": type(exc).__name__, "error": str(exc)})
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


def wait_for_gatt_objects(
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
        if count_iface(objects, device_path, CHAR):
            return objects, device_props
        if time.monotonic() >= deadline:
            emit(
                "gatt_services_timeout",
                {
                    "connected": bool(device_props.get("Connected", False)),
                    "services_resolved": bool(device_props.get("ServicesResolved", False)),
                },
            )
            raise RuntimeError("no GATT characteristics published by BlueZ")
        time.sleep(0.05)


def count_iface(
    objects: dict[str, dict[str, dict[str, Any]]], device_path: str, iface: str
) -> int:
    return len(paths_with_iface(objects, device_path, iface))


def paths_with_iface(
    objects: dict[str, dict[str, dict[str, Any]]], device_path: str, iface: str
) -> list[str]:
    return [
        path
        for path, interfaces in objects.items()
        if path.startswith(device_path + "/") and iface in interfaces
    ]


def characteristics_for_service(
    objects: dict[str, dict[str, dict[str, Any]]], service_path: str
) -> list[str]:
    return [
        path
        for path, interfaces in objects.items()
        if interfaces.get(CHAR, {}).get("Service") == service_path
    ]


def descriptors_for_char(
    objects: dict[str, dict[str, dict[str, Any]]], char_path: str
) -> list[str]:
    return [
        path
        for path, interfaces in objects.items()
        if interfaces.get(DESC, {}).get("Characteristic") == char_path
    ]


def read_value(
    bus: dbus.SystemBus,
    path: str,
    interface_name: str,
    timeout: float,
    uuid: str,
) -> dict[str, Any]:
    iface = dbus.Interface(bus.get_object(BLUEZ, path), interface_name)
    try:
        value = bytes(
            iface.ReadValue(
                dbus.Dictionary({}, signature="sv"),
                timeout=timeout,
            )
        )
    except Exception as exc:
        return {"error_type": type(exc).__name__, "error": str(exc)}
    row: dict[str, Any] = {
        "hex": value.hex(),
        "utf8": decode_utf8(value),
        "length": len(value),
    }
    decoded = decode_known_value(uuid, value)
    if decoded:
        row["decoded"] = decoded
    return row


def decode_utf8(value: bytes) -> str | None:
    value = value.rstrip(b"\x00")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        return None
    return text


def decode_known_value(uuid: str, value: bytes) -> dict[str, Any] | None:
    if uuid == "00002a00-0000-1000-8000-00805f9b34fb":
        return {"device_name": decode_utf8(value)}
    if uuid == "00002a01-0000-1000-8000-00805f9b34fb" and len(value) >= 2:
        return {"appearance": struct.unpack_from("<H", value, 0)[0]}
    if uuid == "00002a04-0000-1000-8000-00805f9b34fb" and len(value) >= 8:
        min_interval, max_interval, latency, supervision_timeout = struct.unpack_from(
            "<HHHH", value, 0
        )
        return {
            "min_connection_interval_ms": round(min_interval * 1.25, 2),
            "max_connection_interval_ms": round(max_interval * 1.25, 2),
            "slave_latency": latency,
            "supervision_timeout_ms": supervision_timeout * 10,
        }
    if uuid == "00002aa6-0000-1000-8000-00805f9b34fb" and value:
        return {"central_address_resolution_supported": bool(value[0])}
    if uuid == "00002ac9-0000-1000-8000-00805f9b34fb" and value:
        return {"resolvable_private_address_only": bool(value[0])}
    if uuid in {
        p.OURA_NOTIFY_UUID,
        "98ed0004-a541-11e4-b6a0-0002a5d5c51b",
    }:
        return decode_oura_buffer(value)
    return None


def decode_oura_buffer(value: bytes) -> dict[str, Any] | None:
    if len(value) < 2:
        return None
    packet_length = 2 + value[1]
    if packet_length > len(value):
        return {"decode_error": "buffer starts with a truncated Oura packet"}
    raw_packet = value[:packet_length]
    trailing = value[packet_length:]
    row: dict[str, Any] = {
        "first_packet_raw_hex": raw_packet.hex(),
        "trailing_zero_bytes": len(trailing) if all(byte == 0 for byte in trailing) else 0,
    }
    if trailing and any(byte != 0 for byte in trailing):
        row["trailing_nonzero_hex"] = trailing.hex()
    try:
        row["first_packet"] = [
            p.parse_response(packet) for packet in p.parse_packets(raw_packet)
        ]
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


if __name__ == "__main__":
    sys.exit(main())
