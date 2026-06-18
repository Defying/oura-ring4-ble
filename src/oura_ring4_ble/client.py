"""Async BLE transport for Oura Ring 4."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError

from . import protocol as p

OURA_MANUFACTURER_STATE_HINTS = {
    "04601b01": "observed_restricted_or_reset_prompt",
    "04621b01": "observed_setup_ready_to_pair",
    "04671b01": "observed_reset_connectable_hint",
}


class OuraBleError(RuntimeError):
    """Raised when the BLE transport cannot complete the requested operation."""


@dataclass(frozen=True)
class DeviceAdvertisement:
    device: BLEDevice
    advertisement: AdvertisementData | None

    def to_json(self) -> dict[str, Any]:
        adv = self.advertisement
        service_uuids = sorted(
            str(uuid).lower() for uuid in (adv.service_uuids if adv else [])
        )
        return {
            "address": self.device.address,
            "name": self.device.name or (adv.local_name if adv else None),
            "rssi": adv.rssi if adv else None,
            "tx_power": getattr(adv, "tx_power", None) if adv else None,
            "service_uuids": service_uuids,
            "manufacturer_data": manufacturer_data_json(
                adv.manufacturer_data if adv else {}
            ),
            "oura_manufacturer_payload": oura_manufacturer_payload(adv),
            "oura_state_hint": oura_state_hint(adv),
            "oura_connectable_hint": oura_connectable_hint(adv),
            "service_data": {
                str(uuid).lower(): value.hex()
                for uuid, value in sorted(
                    (adv.service_data if adv else {}).items(),
                    key=lambda item: str(item[0]),
                )
            },
            "is_oura_candidate": is_oura_candidate(self.device, adv),
        }


@dataclass(frozen=True)
class IoCharacteristics:
    write: BleakGATTCharacteristic
    notify: BleakGATTCharacteristic


def manufacturer_data_json(data: dict[int, bytes]) -> dict[str, str]:
    return {
        f"0x{company_id:04X}": value.hex() for company_id, value in sorted(data.items())
    }


def oura_manufacturer_bytes(advertisement: AdvertisementData | None) -> bytes | None:
    if not advertisement:
        return None
    value = advertisement.manufacturer_data.get(p.OURA_COMPANY_ID)
    return bytes(value) if value else None


def oura_manufacturer_payload(advertisement: AdvertisementData | None) -> str | None:
    value = oura_manufacturer_bytes(advertisement)
    if not value:
        return None
    if (
        len(value) >= 4
        and value[0] == 0x04
        and value[2] == 0x1B
        and value[3] == 0x01
    ):
        return value[:4].hex()
    return value.hex()


def oura_state_hint(advertisement: AdvertisementData | None) -> str | None:
    payload = oura_manufacturer_payload(advertisement)
    if not payload:
        return None
    return OURA_MANUFACTURER_STATE_HINTS.get(payload)


def oura_connectable_hint(advertisement: AdvertisementData | None) -> bool:
    value = oura_manufacturer_bytes(advertisement)
    if not value or len(value) < 2:
        return False
    # In live Ring 4 captures, payloads with bit 0x04 in byte 1 were the
    # Oura adverts most worth immediate GATT attempts. Keep this as a hint.
    return bool(value[1] & 0x04)


def is_oura_candidate(
    device: BLEDevice, advertisement: AdvertisementData | None = None
) -> bool:
    names = [device.name or ""]
    service_uuids: Iterable[str] = []
    if advertisement:
        names.append(advertisement.local_name or "")
        service_uuids = advertisement.service_uuids
    if any("oura" in name.lower() for name in names):
        return True
    if advertisement and p.OURA_COMPANY_ID in advertisement.manufacturer_data:
        return True
    return any(str(uuid).lower() == p.OURA_SERVICE_UUID for uuid in service_uuids)


async def scan_devices(
    timeout: float, *, only_oura: bool = False
) -> list[DeviceAdvertisement]:
    if only_oura:
        discovered = await BleakScanner.discover(
            timeout=timeout,
            return_adv=True,
            service_uuids=[p.OURA_SERVICE_UUID],
        )
    else:
        discovered = await BleakScanner.discover(timeout=timeout, return_adv=True)
    devices = [DeviceAdvertisement(device, adv) for device, adv in discovered.values()]
    if only_oura:
        devices = [
            entry
            for entry in devices
            if is_oura_candidate(entry.device, entry.advertisement)
        ]
    return sorted(
        devices,
        key=lambda entry: (
            not is_oura_candidate(entry.device, entry.advertisement),
            -(entry.advertisement.rssi if entry.advertisement else -999),
            entry.device.name or "",
        ),
    )


async def find_device(
    *, address: str | None, name: str | None, timeout: float
) -> DeviceAdvertisement | None:
    if address:
        device = await BleakScanner.find_device_by_address(address, timeout=timeout)
        if device:
            return DeviceAdvertisement(device, None)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(1.0, deadline - time.monotonic())
        if not address and not name:
            scan_timeout = min(3.0, max(0.5, remaining / 2))
            entries = merge_device_advertisements(
                await scan_devices(scan_timeout),
                await scan_devices(scan_timeout, only_oura=True),
            )
        else:
            scan_timeout = min(3.0, remaining)
            entries = await scan_devices(scan_timeout)
        for entry in entries:
            if address and entry.device.address.lower() == address.lower():
                return entry
            if name and name.lower() in ((entry.device.name or "").lower()):
                return entry
            if (
                not address
                and not name
                and is_oura_candidate(entry.device, entry.advertisement)
            ):
                return entry
    return None


async def find_oura_device(timeout: float) -> DeviceAdvertisement | None:
    return await find_device(address=None, name=None, timeout=timeout)


async def inspect_device(device: BLEDevice, *, timeout: float = 10.0) -> dict[str, Any]:
    async with BleakClient(
        device,
        timeout=timeout,
        services=[p.OURA_SERVICE_UUID],
    ) as client:
        services = client.services
        return {
            "device": {"address": device.address, "name": device.name},
            "services": [service_to_json(service) for service in services],
        }


def service_to_json(service: Any) -> dict[str, Any]:
    return {
        "uuid": str(service.uuid).lower(),
        "description": getattr(service, "description", None),
        "characteristics": [
            {
                "uuid": str(char.uuid).lower(),
                "handle": getattr(char, "handle", None),
                "description": getattr(char, "description", None),
                "properties": sorted(char.properties),
            }
            for char in service.characteristics
        ],
    }


class OuraRingClient:
    def __init__(
        self,
        device: BLEDevice,
        *,
        timeout: float = 8.0,
        verbose: bool = False,
        pair: bool = False,
    ):
        self.device = device
        self.timeout = timeout
        self.verbose = verbose
        self.pair = pair
        self._client: BleakClient | None = None
        self._io: IoCharacteristics | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def __aenter__(self) -> OuraRingClient:
        self._client = BleakClient(
            self.device,
            timeout=self.timeout,
            services=[p.OURA_SERVICE_UUID],
            pair=self.pair,
        )
        await self._client.connect()
        self._io = find_io_characteristics(self._client)
        await self._client.start_notify(self._io.notify, self._on_notify)
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._client and self._io:
            try:
                await self._client.stop_notify(self._io.notify)
            except BleakError:
                pass
        if self._client:
            await self._client.disconnect()

    async def firmware(self) -> dict[str, Any]:
        packet = await self.request(
            p.build_get_firmware_request(), expect_tag=p.TAG_FIRMWARE_RESPONSE
        )
        return p.parse_response(packet)

    async def battery(self) -> dict[str, Any]:
        packet = await self.request(
            p.build_get_battery_request(), expect_tag=p.TAG_BATTERY_RESPONSE
        )
        return p.parse_response(packet)

    async def auth_nonce(self) -> dict[str, Any]:
        packet = await self.request(
            p.build_get_auth_nonce_request(),
            expect_tag=p.TAG_EXTENDED,
            extended_id=p.EXT_AUTH_NONCE_RESPONSE,
        )
        return p.parse_response(packet)

    async def authenticate(self, key: bytes) -> dict[str, Any]:
        nonce_packet = await self.request_auth_nonce_packet()
        nonce_decoded = p.parse_extended_response(nonce_packet.payload)
        nonce = bytes.fromhex(str(nonce_decoded["nonce_hex"]))
        auth_packet = await self.request(
            p.build_authenticate_request(key, nonce),
            expect_tag=p.TAG_EXTENDED,
            extended_id=p.EXT_AUTHENTICATE_RESPONSE,
        )
        auth_decoded = p.parse_extended_response(auth_packet.payload)
        return {
            "nonce": {
                "tag": nonce_packet.tag_hex,
                "nonce_length": nonce_decoded["nonce_length"],
                "nonce_hex": nonce_decoded["nonce_hex"],
            },
            "auth": auth_decoded,
        }

    async def request_auth_nonce_packet(self) -> p.Packet:
        return await self.request(
            p.build_get_auth_nonce_request(),
            expect_tag=p.TAG_EXTENDED,
            extended_id=p.EXT_AUTH_NONCE_RESPONSE,
        )

    async def events(
        self, *, start_timestamp: int = 0, max_events: int = 0xFF
    ) -> dict[str, Any]:
        await self.write(p.build_get_events_request(start_timestamp, max_events))
        events: list[dict[str, Any]] = []
        done: dict[str, Any] | None = None
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            timeout = max(0.1, deadline - time.monotonic())
            try:
                raw = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except TimeoutError as exc:
                raise OuraBleError("timed out waiting for event response") from exc
            for packet in p.parse_packets(raw):
                if packet.tag >= 0x41:
                    events.append(p.parse_response(packet))
                elif packet.tag == p.TAG_EVENTS_DONE:
                    done = p.parse_response(packet)
                    return {"events": events, "done": done}
                elif self.verbose:
                    events.append({"unexpected": p.parse_response(packet)})
        raise OuraBleError("timed out waiting for event completion")

    async def request(
        self, data: bytes, *, expect_tag: int, extended_id: int | None = None
    ) -> p.Packet:
        await self.write(data)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            timeout = max(0.1, deadline - time.monotonic())
            try:
                raw = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except TimeoutError as exc:
                raise OuraBleError(f"timed out waiting for tag 0x{expect_tag:02X}") from exc
            for packet in p.parse_packets(raw):
                if packet.tag != expect_tag:
                    if self.verbose:
                        print(
                            json.dumps(
                                {"unexpected": p.parse_response(packet)}, sort_keys=True
                            )
                        )
                    continue
                if extended_id is not None:
                    if not packet.payload or packet.payload[0] != extended_id:
                        continue
                return packet
        raise OuraBleError(f"timed out waiting for tag 0x{expect_tag:02X}")

    async def write(self, data: bytes) -> None:
        if not self._client or not self._io:
            raise OuraBleError("client is not connected")
        if self.verbose:
            print(json.dumps({"tx_hex": data.hex()}, sort_keys=True))
        await self._client.write_gatt_char(self._io.write, data, response=True)

    def _on_notify(self, _sender: BleakGATTCharacteristic, data: bytearray) -> None:
        raw = bytes(data)
        if self.verbose:
            print(json.dumps({"rx_hex": raw.hex()}, sort_keys=True))
        self._queue.put_nowait(raw)


def find_io_characteristics(client: BleakClient) -> IoCharacteristics:
    services = client.services
    all_chars: list[tuple[Any, BleakGATTCharacteristic]] = [
        (service, char) for service in services for char in service.characteristics
    ]

    write = first_char(
        all_chars, lambda _service, char: str(char.uuid).lower() == p.OURA_WRITE_UUID
    )
    notify = first_char(
        all_chars, lambda _service, char: str(char.uuid).lower() == p.OURA_NOTIFY_UUID
    )

    if write and notify:
        return IoCharacteristics(write=write, notify=notify)

    write = write or first_char(
        all_chars, lambda _service, char: getattr(char, "handle", None) == p.WRITE_HANDLE
    )
    notify = notify or first_char(
        all_chars, lambda _service, char: getattr(char, "handle", None) == p.NOTIFY_HANDLE
    )

    if write and notify:
        return IoCharacteristics(write=write, notify=notify)

    for service in services:
        if str(service.uuid).lower() != p.OURA_SERVICE_UUID:
            continue
        service_chars = [(service, char) for char in service.characteristics]
        write = write or first_char(
            service_chars,
            lambda _service, char: bool(
                {"write", "write-without-response"} & set(char.properties)
            ),
        )
        notify = notify or first_char(
            service_chars, lambda _service, char: "notify" in set(char.properties)
        )

    if not write or not notify:
        raise OuraBleError(
            "could not find Oura write/notify characteristics; run `inspect` and "
            "check for 98ed0002/98ed0003 or handles 0x0015/0x0012"
        )
    return IoCharacteristics(write=write, notify=notify)


def first_char(
    chars: list[tuple[Any, BleakGATTCharacteristic]], predicate: Any
) -> BleakGATTCharacteristic | None:
    for service, char in chars:
        if predicate(service, char):
            return char
    return None


async def probe_devices(
    timeout: float,
    *,
    connect_timeout: float = 6.0,
    limit: int = 12,
) -> list[dict[str, Any]]:
    devices = merge_device_advertisements(
        await scan_devices(timeout),
        await scan_devices(min(timeout, 20.0), only_oura=True),
    )
    candidates = [entry for entry in devices if should_probe_device(entry)]
    candidates = candidates[:limit]
    results: list[dict[str, Any]] = []
    for entry in candidates:
        row = entry.to_json()
        try:
            row["gatt"] = await inspect_device_with_timeout(entry, timeout=connect_timeout)
            service_uuids = {
                service["uuid"]
                for service in row["gatt"].get("services", [])
                if isinstance(service, dict)
            }
            row["has_oura_service"] = p.OURA_SERVICE_UUID in service_uuids
        except Exception as exc:
            row["gatt_error"] = f"{type(exc).__name__}: {exc}"
            row["has_oura_service"] = False
        results.append(row)
    return results


def merge_device_advertisements(
    *groups: list[DeviceAdvertisement],
) -> list[DeviceAdvertisement]:
    merged: dict[str, DeviceAdvertisement] = {}
    for group in groups:
        for entry in group:
            existing = merged.get(entry.device.address)
            if existing is None:
                merged[entry.device.address] = entry
                continue
            existing_rssi = existing.advertisement.rssi if existing.advertisement else -999
            entry_rssi = entry.advertisement.rssi if entry.advertisement else -999
            if entry_rssi > existing_rssi or (
                not is_oura_candidate(existing.device, existing.advertisement)
                and is_oura_candidate(entry.device, entry.advertisement)
            ):
                merged[entry.device.address] = entry
    return sorted(
        merged.values(),
        key=lambda entry: (
            not is_oura_candidate(entry.device, entry.advertisement),
            -(entry.advertisement.rssi if entry.advertisement else -999),
            entry.device.name or "",
        ),
    )


def should_probe_device(entry: DeviceAdvertisement) -> bool:
    row = entry.to_json()
    if row["is_oura_candidate"]:
        return True
    name = (row["name"] or "").strip()
    if name in {
        "Kitchen",
        "Living Room",
        "Living Room (2)",
        "Master Bedroom",
        "Bowflex M5",
        "PL70e-BT_FF60-LE",
    }:
        return False
    if row["rssi"] is not None and row["rssi"] < -85:
        return False
    return True


async def inspect_device_with_timeout(
    entry: DeviceAdvertisement, timeout: float
) -> dict[str, Any]:
    return await asyncio.wait_for(
        inspect_device(entry.device, timeout=timeout),
        timeout=timeout + 1.0,
    )
