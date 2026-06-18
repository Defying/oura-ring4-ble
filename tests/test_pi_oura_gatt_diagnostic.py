from __future__ import annotations

import asyncio
import importlib.util
import signal
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


def load_gatt_diagnostic_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-oura-gatt-diagnostic.py"
    spec = importlib.util.spec_from_file_location("pi_oura_gatt_diagnostic", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gatt_diag = load_gatt_diagnostic_module()


def test_disconnect_like_error_matches_bluez_not_connected() -> None:
    assert gatt_diag.is_disconnect_like_error("org.bluez.Error.Failed: Not connected")
    assert gatt_diag.is_disconnect_like_error("Software caused connection abort")
    assert gatt_diag.disconnect_like_exception(EOFError())
    assert not gatt_diag.is_disconnect_like_error(
        "Operation failed with ATT error: 0x0e"
    )


def test_standard_gatt_reads_try_safe_gap_values_before_device_name() -> None:
    labels = [label for label, _uuid in gatt_diag.STANDARD_GATT_READS]

    assert labels[:4] == [
        "gap_peripheral_preferred_connection_parameters",
        "gap_central_address_resolution",
        "gap_resolvable_private_address_only",
        "gap_appearance",
    ]
    assert labels.index("gap_device_name") > labels.index("gap_appearance")


def test_decodes_standard_gap_values() -> None:
    assert gatt_diag.decode_standard_gatt_value(
        "gap_peripheral_preferred_connection_parameters",
        bytes.fromhex("1000200000004800"),
    ) == {
        "min_connection_interval_units": 16,
        "max_connection_interval_units": 32,
        "slave_latency": 0,
        "supervision_timeout_units": 72,
        "min_connection_interval_ms": 20.0,
        "max_connection_interval_ms": 40.0,
        "supervision_timeout_ms": 720,
    }
    assert (
        gatt_diag.decode_standard_gatt_value(
            "gap_central_address_resolution", b"\x01"
        )
        is True
    )
    assert gatt_diag.decode_standard_gatt_value(
        "gap_appearance", bytes.fromhex("4000")
    ) == {"appearance": 64}


def test_visible_bluez_device_addresses_parses_bluetoothctl(monkeypatch) -> None:
    def fake_command_output(command, *, timeout):
        assert command == ["bluetoothctl", "devices"]
        assert timeout == 6
        return {
            "stdout": "\n".join(
                [
                    "Device AA:BB:CC:DD:EE:FF Oura Ring 4",
                    "Device 11:22:33:44:55:66 Bowflex M5",
                    "Controller DC:A6:32:74:22:9A pi",
                ]
            )
        }

    monkeypatch.setattr(gatt_diag, "command_output", fake_command_output)

    assert gatt_diag.visible_bluez_device_addresses() == [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66",
    ]


def test_run_command_kills_process_group_on_timeout(monkeypatch) -> None:
    kills = []

    class FakeProcess:
        pid = 4242
        returncode = None

        def __init__(self):
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls <= 2:
                raise subprocess.TimeoutExpired(["sudo", "btmgmt"], timeout)
            self.returncode = -signal.SIGKILL
            return ("partial stdout", "partial stderr")

    def fake_popen(command, **kwargs):
        assert command == ["sudo", "-n", "btmgmt", "power", "off"]
        assert kwargs["start_new_session"] is True
        return FakeProcess()

    monkeypatch.setattr(gatt_diag.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        gatt_diag.os, "killpg", lambda pid, sig: kills.append((pid, sig))
    )

    result = gatt_diag.run_command(
        ["sudo", "-n", "btmgmt", "power", "off"], timeout=0.1
    )

    assert result.returncode == 127
    assert result.stdout == "partial stdout"
    assert "partial stderr" in result.stderr
    assert "timed out" in result.stderr
    assert kills == [(4242, signal.SIGTERM), (4242, signal.SIGKILL)]


def test_matrix_uuid_skip_filter_accepts_short_prefixes() -> None:
    chars = [
        SimpleNamespace(uuid="98ed0003-a541-11e4-b6a0-0002a5d5c51b"),
        SimpleNamespace(uuid="98ed0004-a541-11e4-b6a0-0002a5d5c51b"),
        SimpleNamespace(uuid="00060001-f8ce-11e4-abf4-0002a5d5c51b"),
    ]

    skip = gatt_diag.normalize_uuid_filters(
        ["98ed0003", "00060001-f8ce-11e4-abf4-0002a5d5c51b"]
    )

    assert skip == {
        "98ed0003",
        "00060001-f8ce-11e4-abf4-0002a5d5c51b",
    }
    assert [
        char.uuid for char in gatt_diag.filter_matrix_characteristics(chars, skip)
    ] == ["98ed0004-a541-11e4-b6a0-0002a5d5c51b"]


def test_target_state_filter_can_require_connectable_hint() -> None:
    presence = gatt_diag.DeviceAdvertisement(
        SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="Oura Ring 4"),
        SimpleNamespace(manufacturer_data={0x02B2: bytes.fromhex("04601b01")}),
    )
    connectable = gatt_diag.DeviceAdvertisement(
        SimpleNamespace(address="11:22:33:44:55:66", name="Oura Ring 4"),
        SimpleNamespace(manufacturer_data={0x02B2: bytes.fromhex("04671b01")}),
    )

    assert gatt_diag.target_state_filter_matches(
        presence,
        set(),
        connectable_hint_only=False,
    )
    assert not gatt_diag.target_state_filter_matches(
        presence,
        set(),
        connectable_hint_only=True,
    )
    assert gatt_diag.target_state_filter_matches(
        connectable,
        {"04671b01"},
        connectable_hint_only=True,
    )


def test_packet_probes_include_open_feature_queries() -> None:
    probes = {probe.name: probe for probe in gatt_diag.PACKET_PROBES}

    assert probes["capabilities:0x00"].data.hex() == "2f020100"
    assert probes["feature_status:daytime_hr"].data.hex() == "2f022002"
    assert probes["feature_status:resting_hr"].data.hex() == "2f022008"
    assert probes["feature_latest:daytime_hr"].data.hex() == "2f022402"
    assert probes["feature_latest:resting_hr"].data.hex() == "2f022408"
    assert probes["feature_latest:daytime_hr"].expected_extended_names == frozenset(
        {"feature_latest_values_response"}
    )


def test_scanner_kwargs_passive_uses_oura_manufacturer_pattern() -> None:
    kwargs = gatt_diag.scanner_kwargs(SimpleNamespace(passive_scan=True))

    assert kwargs["scanning_mode"] == "passive"
    assert kwargs["bluez"]["or_patterns"] == [
        (
            0,
            gatt_diag.AdvertisementDataType(0xFF),
            gatt_diag.p.OURA_COMPANY_ID.to_bytes(2, "little"),
        )
    ]
    assert gatt_diag.scanner_kwargs(SimpleNamespace(passive_scan=False)) == {
        "scanning_mode": "active"
    }


def test_matching_expected_packets_filters_extended_response_name() -> None:
    row = {
        "packets": [
            {
                "tag": "0x2F",
                "decoded": {"extended_name": "capabilities_response"},
            },
            {
                "tag": "0x2F",
                "decoded": {"extended_name": "feature_status_response"},
            },
            {
                "tag": "0x2F",
                "decoded": {"extended_name": "auth_status_response"},
            },
        ]
    }

    assert (
        gatt_diag.matching_expected_packets(
            row,
            frozenset({gatt_diag.p.TAG_EXTENDED}),
            frozenset({"feature_status_response"}),
        )
        == 2
    )
    assert (
        gatt_diag.matching_expected_packets(
            row,
            frozenset({gatt_diag.p.TAG_EXTENDED}),
            frozenset({"auth_nonce_response"}),
        )
        == 1
    )


def test_apply_packet_read_rows_promotes_feature_and_auth_gated_results() -> None:
    result = {}
    rows = [
        {
            "raw_hex": "2f03210201",
            "packets": [
                {
                    "tag": "0x2F",
                    "decoded": {
                        "extended_name": "feature_status_response",
                        "feature_name": "daytime_hr",
                    },
                }
            ],
        },
        {
            "raw_hex": "2f03250246",
            "packets": [
                {
                    "tag": "0x2F",
                    "decoded": {
                        "extended_name": "feature_latest_values_response",
                        "feature_name": "daytime_hr",
                        "latest_values": [{"value": 70}],
                    },
                }
            ],
        },
        {
            "raw_hex": "2f022f01",
            "packets": [
                {
                    "tag": "0x2F",
                    "decoded": {
                        "extended_name": "auth_status_response",
                        "auth_result_name": "authentication_error",
                    },
                }
            ],
        },
    ]

    gatt_diag.apply_packet_read_rows(
        result,
        "feature_latest:daytime_hr",
        bytes.fromhex("2f022402"),
        rows,
    )

    assert result["feature_status"]["feature_latest:daytime_hr"]["feature_name"] == (
        "daytime_hr"
    )
    assert result["feature_latest"]["feature_latest:daytime_hr"]["feature_name"] == (
        "daytime_hr"
    )
    assert result["daytime_hr_latest"]["latest_values"] == [{"value": 70}]
    assert result["auth_gated"] == ["feature_latest:daytime_hr"]
    assert result["probes"][0]["raw_responses"] == [
        "2f03210201",
        "2f03250246",
        "2f022f01",
    ]


def test_try_oura_read_can_skip_standard_gatt_reads(monkeypatch) -> None:
    events = []
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="ring")

    class FakeBleakClient:
        services = []

        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    async def fail_if_called(_client):
        raise AssertionError("standard GATT reads should be skipped")

    async def fake_packet_read_with_client(
        _client, _device, _response_timeout, _emit, *, pair, stage_ref
    ):
        assert pair is False
        stage_ref["stage"] = "fake_packet_read"
        return False

    monkeypatch.setattr(gatt_diag, "BleakClient", FakeBleakClient)
    monkeypatch.setattr(gatt_diag, "read_standard_gatt", fail_if_called)
    monkeypatch.setattr(
        gatt_diag, "try_oura_packet_read_with_client", fake_packet_read_with_client
    )

    success = asyncio.run(
        gatt_diag.try_oura_read(
            device,
            0.1,
            lambda event, payload: events.append((event, payload)),
            matrix_probe=False,
            matrix_response_timeout=0.1,
            matrix_read_timeout=0.1,
            matrix_pre_read=False,
            matrix_post_read=False,
            pair=False,
            matrix_skip_uuid=set(),
            skip_standard_reads=True,
        )
    )

    assert success is False
    assert events[0][0] == "gatt_services"
    assert events[0][1]["standard_gatt_reads"] == []
    assert events[0][1]["standard_gatt_reads_skipped"] is True


def test_matrix_pre_read_stops_after_not_connected_error() -> None:
    events = []
    char = SimpleNamespace(
        uuid="98ed0003-a541-11e4-b6a0-0002a5d5c51b",
        handle=17,
        description="notify",
        properties=["read", "notify"],
    )

    class Client:
        async def read_gatt_char(self, _char):
            raise RuntimeError("org.bluez.Error.Failed: Not connected")

    connected = asyncio.run(
        gatt_diag.read_matrix_characteristics(
            Client(),
            [char],
            0.1,
            lambda event, payload: events.append((event, payload)),
            "matrix_char_read",
        )
    )

    assert connected is False
    assert events == [
        (
            "matrix_char_read_error",
            {
                "characteristic": {
                    "description": "notify",
                    "handle": 17,
                    "properties": ["notify", "read"],
                    "uuid": "98ed0003-a541-11e4-b6a0-0002a5d5c51b",
                },
                "error": "org.bluez.Error.Failed: Not connected",
                "error_type": "RuntimeError",
            },
        )
    ]
