from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

from oura_ring4_ble import protocol as p


def load_provision_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-oura-provision-auth-key.py"
    spec = importlib.util.spec_from_file_location("pi_oura_provision_auth_key", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


provision = load_provision_module()


def test_build_state_record_keeps_raw_key_only_in_state() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    status = {
        "response_name": "set_auth_key_status",
        "status": 0,
        "status_name": "success",
    }

    record = provision.build_state_record(
        key,
        "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF",
        {
            "Address": "AA:BB:CC:DD:EE:FF",
            "AddressType": "random",
            "Name": "Oura Ring 4",
        },
        status,
    )

    assert record["auth_key_hex"] == key.hex()
    assert record["auth_key_sha256_16"] == provision.key_fingerprint(key)
    assert record["source"] == "local_uuid_random_apk_layout"
    assert record["set_auth_key_status"] == status


def test_write_state_file_uses_private_permissions(tmp_path: Path) -> None:
    path = tmp_path / "state" / "ring-auth-key.json"
    provision.write_state_file(path, {"auth_key_hex": "00" * 16})

    assert path.exists()
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_packet_matches_extended_id() -> None:
    nonce_packet = p.packet_from_hex("2f102c111122223333444455556666777788")
    auth_packet = p.packet_from_hex("2f022e00")

    assert provision.packet_matches(nonce_packet, p.TAG_EXTENDED, p.EXT_AUTH_NONCE_RESPONSE)
    assert not provision.packet_matches(
        nonce_packet,
        p.TAG_EXTENDED,
        p.EXT_AUTHENTICATE_RESPONSE,
    )
    assert provision.packet_matches(
        auth_packet,
        p.TAG_EXTENDED,
        p.EXT_AUTHENTICATE_RESPONSE,
    )


def test_set_auth_key_request_context_redacts_raw_key() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    packet = p.build_set_auth_key_request(key)
    context = provision.request_context("set_auth_key", packet)

    assert context["packet"] == "set_auth_key"
    assert context["tx_length"] == len(packet)
    assert context["tx_hex"] == "2410<redacted-auth-key>"
    assert key.hex() not in str(context)


def test_device_score_identifies_oura_candidates() -> None:
    props = {
        "Address": "AA:BB:CC:DD:EE:FF",
        "Name": "Oura Ring 4",
        "UUIDs": [p.OURA_SERVICE_UUID],
        "ManufacturerData": {p.OURA_COMPANY_ID: b"\x04\x62\x1b\x01"},
        "Connected": True,
        "Paired": True,
    }

    assert provision.device_score(props) >= 85
    assert provision.device_score(props, "aa:bb:cc:dd:ee:ff") >= 185
    assert provision.device_score({"Name": "Keyboard"}) == 0


def test_authenticated_read_result_summarizes_daytime_hr_without_raw_key() -> None:
    latest = {
        "ok": True,
        "packet": "feature_latest:daytime_hr",
        "tx_hex": "2f022402",
        "response": p.parse_response(
            p.packet_from_hex("2f102502000000000000000000000000007f")
        ),
    }
    feature_mode = p.parse_response(p.packet_from_hex("2f03230200"))
    feature_subscription = {
        "ok": True,
        "packet": "feature_subscription:daytime_hr:latest",
        "tx_hex": "2f03260202",
        "response": p.parse_response(p.packet_from_hex("2f03270200")),
    }
    result = {
        "device": {"address": "AA:BB:CC:DD:EE:FF", "name": "Oura Ring 4"},
        "authentication": {"auth_result": "success", "nonce_length": 15},
        "auth_key_sha256_16": "should-not-be-copied",
        "live_hr_probe": {
            "enabled_packets": [feature_mode, feature_subscription],
            "notification_count": 0,
            "latest_values": latest,
        },
        "meditation_hr_probe": None,
    }

    read_result = provision.build_authenticated_read_result(result)

    assert read_result["source"] == "authenticated_provision"
    assert read_result["authentication"]["auth_result"] == "success"
    assert read_result["daytime_hr"]["latest_values"]["response"]["decoded"] == {
        "daytime_hr_duration": 0,
        "daytime_hr_ibi_ms": 0,
        "daytime_hr_quality": 127,
        "daytime_hr_timestamp": 0,
        "extended_id": "0x25",
        "extended_name": "feature_latest_values_response",
        "feature_id": 2,
        "feature_name": "daytime_hr",
        "result": 0,
        "result_name": "success",
        "state": 0,
        "state_name": "idle",
        "status_duration": 0,
        "status_name": "off",
        "status_value": 0,
    }
    assert len(read_result["feature_set_results"]) == 2
    assert "should-not-be-copied" not in str(read_result)
