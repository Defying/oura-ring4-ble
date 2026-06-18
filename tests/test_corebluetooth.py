from __future__ import annotations

import sys

import pytest

if sys.platform != "darwin":
    pytest.skip("CoreBluetooth tests require macOS", allow_module_level=True)

from Foundation import NSData

from oura_ring4_ble.corebluetooth import (
    advertisement_has_oura_payload,
    pythonize_foundation,
)


def test_matches_oura_manufacturer_company_id() -> None:
    assert advertisement_has_oura_payload(
        {"ManufacturerData": bytes.fromhex("b20204601b01")}
    )


def test_matches_observed_oura_payloads_without_company_id() -> None:
    for payload in ("04601b01", "04611b01", "04621b01", "04661b01", "04671b01"):
        assert advertisement_has_oura_payload({"ManufacturerData": bytes.fromhex(payload)})


def test_matches_oura_service_uuid() -> None:
    assert advertisement_has_oura_payload(
        {"ServiceUUIDs": ["98ed0001-a541-11e4-b6a0-0002a5d5c51b"]}
    )


def test_rejects_unrelated_apple_payload() -> None:
    assert not advertisement_has_oura_payload(
        {"ManufacturerData": bytes.fromhex("4c0013084a68797cc0c12800")}
    )


def test_pythonize_foundation_converts_nsdata_to_hex() -> None:
    raw = bytes.fromhex("b20204601b01")
    data = NSData.dataWithBytes_length_(raw, len(raw))

    assert pythonize_foundation(data) == "b20204601b01"
