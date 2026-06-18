"""Low-latency CoreBluetooth transport for Oura Ring 4 on macOS."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from CoreBluetooth import (  # type: ignore[import-not-found]
    CBUUID,
    CBCentralManager,
    CBCentralManagerScanOptionAllowDuplicatesKey,
    CBCharacteristicWriteWithResponse,
    CBManagerStatePoweredOn,
)
from Foundation import (  # type: ignore[import-not-found]
    NSUUID,
    NSData,
    NSDate,
    NSObject,
    NSRunLoop,
)
from objc import super  # type: ignore[import-not-found]

from . import protocol as p


class CoreBluetoothError(RuntimeError):
    """Raised when the native CoreBluetooth transport fails."""


@dataclass
class NativeResult:
    device: dict[str, Any]
    firmware: dict[str, Any] | None = None
    battery: dict[str, Any] | None = None
    events: list[dict[str, Any]] | None = None

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {"device": self.device}
        if self.firmware is not None:
            data["firmware"] = self.firmware
        if self.battery is not None:
            data["battery"] = self.battery
        if self.events is not None:
            data["events"] = self.events
        return data


class OuraCoreBluetoothDelegate(NSObject):
    def initWithVerbose_(self, verbose: bool) -> OuraCoreBluetoothDelegate:
        self = super().init()
        if self is None:
            return None
        self.verbose = verbose
        self.state = "init"
        self.error = None
        self.central = None
        self.peripheral = None
        self.address = None
        self.service_uuid = CBUUID.UUIDWithString_(p.OURA_SERVICE_UUID.upper())
        self.write_uuid = CBUUID.UUIDWithString_(p.OURA_WRITE_UUID.upper())
        self.notify_uuid = CBUUID.UUIDWithString_(p.OURA_NOTIFY_UUID.upper())
        self.connect_timeout = 8.0
        self.max_attempts = 3
        self.attempts = 0
        self.state_since = time.monotonic()
        self.write_char = None
        self.notify_char = None
        self.device = None
        self.responses = []
        self._pending_requests = []
        self.done = False
        return self

    def start(self) -> None:
        self.central = CBCentralManager.alloc().initWithDelegate_queue_(self, None)

    def centralManagerDidUpdateState_(self, central: CBCentralManager) -> None:
        if central.state() == CBManagerStatePoweredOn:
            if self.address and self.connectCachedPeripheral_(central):
                return
            self.transition_("scanning")
            self._start_scan()
            return
        self.state = f"central_state_{central.state()}"

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self,
        central: CBCentralManager,
        peripheral: Any,
        advertisement_data: Any,
        rssi: Any,
    ) -> None:
        if self.peripheral is not None:
            return
        if not advertisement_has_oura(advertisement_data):
            return
        self.attempts += 1
        self.peripheral = peripheral
        peripheral.setDelegate_(self)
        self.device = {
            "address": str(peripheral.identifier().UUIDString()),
            "name": str(peripheral.name()) if peripheral.name() else None,
            "rssi": int(rssi),
            "advertisement": pythonize_foundation(advertisement_data),
        }
        if self.verbose:
            print(
                json.dumps(
                    {
                        "native_event": "discovered",
                        "attempt": self.attempts,
                        "device": self.device,
                    }
                ),
                flush=True,
            )
        self.transition_("connecting")
        central.stopScan()
        central.connectPeripheral_options_(peripheral, None)

    def centralManager_didConnectPeripheral_(
        self, _central: CBCentralManager, peripheral: Any
    ) -> None:
        self.transition_("discovering_services")
        if self.verbose:
            print(json.dumps({"native_event": "connected"}), flush=True)
        peripheral.discoverServices_([self.service_uuid])

    def centralManager_didFailToConnectPeripheral_error_(
        self, _central: CBCentralManager, _peripheral: Any, error: Any
    ) -> None:
        self.retryOrFail_(f"failed to connect: {error}")

    def centralManager_didDisconnectPeripheral_error_(
        self, _central: CBCentralManager, _peripheral: Any, error: Any
    ) -> None:
        if self.done:
            return
        self.retryOrFail_(f"disconnected: {error}" if error else "disconnected")

    def peripheral_didDiscoverServices_(self, peripheral: Any, error: Any) -> None:
        if error:
            self.error = f"service discovery failed: {error}"
            self.done = True
            return
        services = list(peripheral.services() or [])
        if self.verbose:
            print(
                json.dumps(
                    {
                        "native_event": "services",
                        "uuids": [str(service.UUID().UUIDString()) for service in services],
                    }
                )
            )
        for service in services:
            if str(service.UUID().UUIDString()).lower() == p.OURA_SERVICE_UUID:
                self.transition_("discovering_characteristics")
                peripheral.discoverCharacteristics_forService_(
                    [self.write_uuid, self.notify_uuid], service
                )
                return
        self.error = "Oura service not discovered"
        self.done = True

    def peripheral_didDiscoverCharacteristicsForService_error_(
        self, peripheral: Any, service: Any, error: Any
    ) -> None:
        if error:
            self.error = f"characteristic discovery failed: {error}"
            self.done = True
            return
        chars = list(service.characteristics() or [])
        if self.verbose:
            print(
                json.dumps(
                    {
                        "native_event": "characteristics",
                        "chars": [
                            {
                                "uuid": str(char.UUID().UUIDString()),
                                "handle": int(char.handle()),
                                "properties": int(char.properties()),
                            }
                            for char in chars
                        ],
                    }
                )
            )
        for char in chars:
            uuid = str(char.UUID().UUIDString()).lower()
            if uuid == p.OURA_WRITE_UUID or int(char.handle()) == p.WRITE_HANDLE:
                self.write_char = char
            if uuid == p.OURA_NOTIFY_UUID or int(char.handle()) == p.NOTIFY_HANDLE:
                self.notify_char = char
        if not self.write_char or not self.notify_char:
            self.error = "Oura write/notify characteristics not discovered"
            self.done = True
            return
        self.transition_("subscribing")
        peripheral.setNotifyValue_forCharacteristic_(True, self.notify_char)

    def peripheral_didUpdateNotificationStateForCharacteristic_error_(
        self, peripheral: Any, _characteristic: Any, error: Any
    ) -> None:
        if error:
            self.error = f"notification setup failed: {error}"
            self.done = True
            return
        self.transition_("reading")
        self._pending_requests = [
            ("firmware", p.build_get_firmware_request(), p.TAG_FIRMWARE_RESPONSE),
            ("battery", p.build_get_battery_request(), p.TAG_BATTERY_RESPONSE),
        ]
        self.sendNextRequest_(peripheral)

    def peripheral_didWriteValueForCharacteristic_error_(
        self, _peripheral: Any, _characteristic: Any, error: Any
    ) -> None:
        if error:
            self.error = f"write failed: {error}"
            self.done = True

    def peripheral_didUpdateValueForCharacteristic_error_(
        self, peripheral: Any, characteristic: Any, error: Any
    ) -> None:
        if error:
            self.error = f"notification failed: {error}"
            self.done = True
            return
        raw = bytes(characteristic.value())
        if self.verbose:
            print(json.dumps({"rx_hex": raw.hex()}), flush=True)
        for packet in p.parse_packets(raw):
            self.responses.append(p.parse_response(packet))
            if self._pending_requests and packet.tag == self._pending_requests[0][2]:
                self._pending_requests.pop(0)
                self.sendNextRequest_(peripheral)
                return
        if not self._pending_requests:
            self.done = True

    def sendNextRequest_(self, peripheral: Any) -> None:
        if not self._pending_requests:
            self.done = True
            return
        _name, data, _expect = self._pending_requests[0]
        if self.verbose:
            print(json.dumps({"tx_hex": data.hex()}), flush=True)
        peripheral.writeValue_forCharacteristic_type_(
            NSData.dataWithBytes_length_(data, len(data)),
            self.write_char,
            CBCharacteristicWriteWithResponse,
        )

    def tick(self) -> None:
        if (
            self.state == "connecting"
            and time.monotonic() - self.state_since >= self.connect_timeout
        ):
            self.retryOrFail_(
                f"connect attempt timed out after {self.connect_timeout:.1f}s"
            )

    def transition_(self, state: str) -> None:
        self.state = state
        self.state_since = time.monotonic()

    def _start_scan(self) -> None:
        if not self.central:
            return
        self.central.scanForPeripheralsWithServices_options_(
            None,
            {CBCentralManagerScanOptionAllowDuplicatesKey: True},
        )

    def connectCachedPeripheral_(self, central: CBCentralManager) -> bool:
        uuid = NSUUID.alloc().initWithUUIDString_(self.address)
        peripherals = list(central.retrievePeripheralsWithIdentifiers_([uuid]) or [])
        if self.verbose:
            print(
                json.dumps(
                    {
                        "native_event": "cached_lookup",
                        "address": self.address,
                        "count": len(peripherals),
                    }
                ),
                flush=True,
            )
        if not peripherals:
            return False
        self.attempts += 1
        self.peripheral = peripherals[0]
        self.peripheral.setDelegate_(self)
        self.device = {
            "address": str(self.peripheral.identifier().UUIDString()),
            "name": str(self.peripheral.name()) if self.peripheral.name() else None,
            "rssi": None,
            "advertisement": None,
            "source": "cached",
        }
        self.transition_("connecting")
        central.connectPeripheral_options_(self.peripheral, None)
        return True

    def retryOrFail_(self, reason: str) -> None:
        if self.verbose:
            print(
                json.dumps(
                    {
                        "native_event": "retryable_connection_failure",
                        "attempt": self.attempts,
                        "reason": reason,
                    }
                ),
                flush=True,
            )
        if self.attempts >= self.max_attempts:
            self.error = reason
            self.done = True
            return
        if self.central and self.peripheral:
            self.central.cancelPeripheralConnection_(self.peripheral)
        self.peripheral = None
        self.write_char = None
        self.notify_char = None
        self.transition_("scanning")
        self._start_scan()


def native_read(
    timeout: float = 20.0,
    *,
    verbose: bool = False,
    connect_timeout: float = 8.0,
    attempts: int = 3,
    address: str | None = None,
) -> dict[str, Any]:
    delegate = OuraCoreBluetoothDelegate.alloc().initWithVerbose_(verbose)
    delegate.connect_timeout = connect_timeout
    delegate.max_attempts = attempts
    delegate.address = address
    delegate.start()
    run_loop_until(delegate, timeout)
    if delegate.error:
        raise CoreBluetoothError(delegate.error)
    if not delegate.done:
        raise CoreBluetoothError(f"timed out in state {delegate.state}")
    firmware = first_decoded_response(delegate.responses, p.TAG_FIRMWARE_RESPONSE)
    battery = first_decoded_response(delegate.responses, p.TAG_BATTERY_RESPONSE)
    return NativeResult(
        device=delegate.device or {},
        firmware=firmware,
        battery=battery,
        events=delegate.responses,
    ).to_json()


class OuraAdvertisementDelegate(NSObject):
    def init(self) -> OuraAdvertisementDelegate:
        self = super().init()
        if self is None:
            return None
        self.central = None
        self.service_uuid = CBUUID.UUIDWithString_(p.OURA_SERVICE_UUID.upper())
        self.rows = []
        return self

    def start(self) -> None:
        self.central = CBCentralManager.alloc().initWithDelegate_queue_(self, None)

    def centralManagerDidUpdateState_(self, central: CBCentralManager) -> None:
        if central.state() == CBManagerStatePoweredOn:
            central.scanForPeripheralsWithServices_options_(
                None,
                {CBCentralManagerScanOptionAllowDuplicatesKey: True},
            )

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self,
        _central: CBCentralManager,
        peripheral: Any,
        advertisement_data: Any,
        rssi: Any,
    ) -> None:
        if not advertisement_has_oura(advertisement_data):
            return
        row = {
            "address": str(peripheral.identifier().UUIDString()),
            "name": str(peripheral.name()) if peripheral.name() else None,
            "rssi": int(rssi),
            "advertisement": pythonize_foundation(advertisement_data),
        }
        self.rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)


def native_listen(timeout: float = 30.0) -> list[dict[str, Any]]:
    delegate = OuraAdvertisementDelegate.alloc().init()
    delegate.start()
    deadline = time.monotonic() + timeout
    run_loop = NSRunLoop.currentRunLoop()
    while time.monotonic() < deadline:
        run_loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.05))
    if delegate.central:
        delegate.central.stopScan()
    return list(delegate.rows)


def run_loop_until(delegate: OuraCoreBluetoothDelegate, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    run_loop = NSRunLoop.currentRunLoop()
    while time.monotonic() < deadline and not delegate.done and not delegate.error:
        delegate.tick()
        run_loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.05))
    if delegate.central and delegate.peripheral:
        delegate.central.cancelPeripheralConnection_(delegate.peripheral)


def first_decoded_response(
    responses: list[dict[str, Any]], tag: int
) -> dict[str, Any] | None:
    tag_hex = f"0x{tag:02X}"
    for response in responses:
        if response.get("tag") == tag_hex:
            return response
    return None


def pythonize_foundation(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "bytes") and hasattr(value, "length"):
        try:
            return bytes(value).hex()
        except (TypeError, ValueError):
            pass
    if hasattr(value, "allKeys"):
        return {
            str(key): pythonize_foundation(value.objectForKey_(key))
            for key in list(value.allKeys())
        }
    if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
        try:
            return [pythonize_foundation(item) for item in value]
        except TypeError:
            pass
    return str(value)


def advertisement_has_oura(advertisement_data: Any) -> bool:
    if not advertisement_data:
        return False
    payload: dict[str, Any] = {}
    for key in list(advertisement_data.allKeys()):
        payload[str(key)] = advertisement_data.objectForKey_(key)
    return advertisement_has_oura_payload(payload)


def advertisement_has_oura_payload(payload: dict[str, Any]) -> bool:
    for key_text, value in payload.items():
        if "ServiceUUID" in key_text and value:
            uuids = [
                str(uuid.UUIDString()).lower()
                if hasattr(uuid, "UUIDString")
                else str(uuid).lower()
                for uuid in value
            ]
            if p.OURA_SERVICE_UUID in uuids:
                return True
        if "ManufacturerData" in key_text and value:
            data = bytes(value)
            if data.startswith(b"\xb2\x02") or data.startswith(b"\x02\xb2"):
                return True
            observed_payloads = (
                "04601b01",
                "04611b01",
                "04621b01",
                "04661b01",
                "04671b01",
            )
            if any(data.startswith(bytes.fromhex(value)) for value in observed_payloads):
                return True
    return False
