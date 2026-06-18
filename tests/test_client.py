from __future__ import annotations

from types import SimpleNamespace

from oura_ring4_ble.client import (
    DeviceAdvertisement,
    is_oura_candidate,
    oura_connectable_hint,
    oura_manufacturer_payload,
    oura_state_hint,
)


def adv(**kwargs: object) -> SimpleNamespace:
    defaults = {
        "local_name": None,
        "rssi": None,
        "tx_power": None,
        "service_uuids": [],
        "manufacturer_data": {},
        "service_data": {},
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def device(**kwargs: object) -> SimpleNamespace:
    defaults = {"address": "AA:BB:CC:DD:EE:FF", "name": None}
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_oura_candidate_matches_observed_company_id() -> None:
    assert is_oura_candidate(device(), adv(manufacturer_data={0x02B2: b"\x04\x60"}))


def test_oura_candidate_matches_service_uuid() -> None:
    assert is_oura_candidate(
        device(),
        adv(service_uuids=["98ed0001-a541-11e4-b6a0-0002a5d5c51b"]),
    )


def test_device_advertisement_json_includes_raw_ble_fields() -> None:
    row = DeviceAdvertisement(
        device(address="11:22:33:44:55:66", name=None),
        adv(
            local_name="example",
            rssi=-42,
            tx_power=4,
            service_uuids=["0000180a-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={0x02B2: b"\x04\x60\x1b\x01"},
            service_data={"0000180a-0000-1000-8000-00805f9b34fb": b"\x01\x02"},
        ),
    ).to_json()

    assert row["name"] == "example"
    assert row["tx_power"] == 4
    assert row["manufacturer_data"] == {"0x02B2": "04601b01"}
    assert row["oura_manufacturer_payload"] == "04601b01"
    assert row["oura_state_hint"] == "observed_restricted_or_reset_prompt"
    assert row["oura_connectable_hint"] is False
    assert row["service_data"] == {
        "0000180a-0000-1000-8000-00805f9b34fb": "0102"
    }
    assert row["is_oura_candidate"] is True


def test_oura_advertisement_state_hints_are_inferred_from_manufacturer_payload() -> None:
    setup = adv(manufacturer_data={0x02B2: bytes.fromhex("04621b01")})
    reset = adv(manufacturer_data={0x02B2: bytes.fromhex("04671b01")})
    unknown = adv(manufacturer_data={0x02B2: bytes.fromhex("04651b01")})

    assert oura_manufacturer_payload(setup) == "04621b01"
    assert oura_state_hint(setup) == "observed_setup_ready_to_pair"
    assert oura_connectable_hint(setup) is False

    assert oura_manufacturer_payload(reset) == "04671b01"
    assert oura_state_hint(reset) == "observed_reset_connectable_hint"
    assert oura_connectable_hint(reset) is True

    assert oura_manufacturer_payload(unknown) == "04651b01"
    assert oura_state_hint(unknown) is None
    assert oura_connectable_hint(unknown) is True
