from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


def load_catalog_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-zeroauth-event-catalog.py"
    spec = importlib.util.spec_from_file_location("pi_zeroauth_event_catalog", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


catalog_module = load_catalog_module()


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows),
        encoding="utf-8",
    )


def test_catalogs_unique_debug_events_across_read_results(tmp_path: Path) -> None:
    first_log = tmp_path / "first.jsonl"
    second_log = tmp_path / "second.jsonl"
    battery_event = {
        "event_tag": "0x61",
        "event_name": "debug_data",
        "device_boot_timestamp": 100,
        "payload_length": 5,
        "payload_hex": "24648a0f00",
        "debug_data_code": 0x24,
        "debug_data_code_hex": "0x24",
        "debug_data_code_category": "battery",
        "debug_data_code_label": "battery_snapshot",
        "debug_category": "battery",
        "debug_data_tail_hex": "648a0f00",
        "debug_data_battery": {
            "battery_level_percent": 100,
            "voltage_mv": 3978,
            "status": 0,
            "status_hex": "0x00",
        },
    }
    write_jsonl(
        first_log,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x43",
                            "event_name": "debug_event",
                            "device_boot_timestamp": 99,
                            "payload_length": 13,
                            "payload_hex": "6368675f696e643b3130303b31",
                            "payload_text": "chg_ind;100;1",
                            "debug_key": "chg_ind",
                            "debug_values": ["100", "1"],
                            "debug_numeric_values": [100, 1],
                            "debug_category": "charger",
                            "debug_label": "charge_indicator",
                            "debug_fields": ["percent", "flag"],
                        },
                        battery_event,
                    ]
                },
            }
        ],
    )
    write_jsonl(
        second_log,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        battery_event,
                        {
                            "event_tag": "0x61",
                            "event_name": "debug_data",
                            "device_boot_timestamp": 101,
                            "payload_length": 9,
                            "payload_hex": "3d0000000101000000",
                            "debug_data_code": 0x3D,
                            "debug_data_code_hex": "0x3D",
                            "debug_data_code_category": "setup_binary",
                            "debug_data_code_label": "setup_binary_0x3d",
                            "debug_category": "setup_binary",
                            "debug_data_tail_hex": "0000000101000000",
                            "debug_data_tail_words": {
                                "byte_count": 8,
                                "u16_le": [0, 256, 1, 0],
                                "i16_le": [0, 256, 1, 0],
                                "u32_le": [16777216, 1],
                                "i32_le": [16777216, 1],
                            },
                        },
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([first_log, second_log])

    assert catalog["log_count"] == 2
    assert catalog["read_result_count"] == 2
    assert catalog["event_count"] == 4
    assert catalog["unique_event_count"] == 3
    assert catalog["duplicate_event_count"] == 1
    assert catalog["event_names"] == {"debug_data": 2, "debug_event": 1}
    assert catalog["debug_categories"] == {
        "battery": 1,
        "charger": 1,
        "setup_binary": 1,
    }
    assert catalog["debug_keys"] == {"chg_ind": 1}
    assert catalog["debug_data_codes"] == {"0x24": 1, "0x3D": 1}

    battery = catalog["debug_code_stats"]["0x24"]
    assert battery["category"] == "battery"
    assert battery["label"] == "battery_snapshot"
    assert battery["payload_length_min"] == 5
    assert battery["tail_byte_count_min"] == 4
    assert battery["latest_battery"] == {
        "battery_level_percent": 100,
        "voltage_mv": 3978,
        "status": 0,
        "status_hex": "0x00",
    }

    setup = catalog["debug_code_stats"]["0x3D"]
    assert setup["category"] == "setup_binary"
    assert setup["latest_tail_words"]["u16_le"] == [0, 256, 1, 0]
    assert setup["example"]["debug_data_tail_hex"] == "0000000101000000"


def test_text_output_surfaces_key_protocol_evidence(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x61",
                            "event_name": "debug_data",
                            "device_boot_timestamp": 200,
                            "payload_length": 14,
                            "payload_hex": "3680030101544553545f49445f31",
                            "debug_data_code_hex": "0x36",
                            "debug_data_code_category": "identity",
                            "debug_data_code_label": "identity_fragment",
                            "debug_category": "identity",
                            "debug_data_tail_hex": "80030101544553545f49445f31",
                            "debug_data_tail_words": {
                                "byte_count": 13,
                                "u16_le": [896, 257, 12338, 13874, 16944, 13618],
                            },
                            "printable_runs": ["TEST_ID_1"],
                        }
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([log_path])
    catalog_module.print_text(catalog)

    text = capsys.readouterr().out
    assert "logs=1 read_results=1 events=1 unique=1 duplicates=0" in text
    assert "debug_categories=identity:1" in text
    assert "debug_data_codes=0x36:1" in text
    assert "0x36: count=1 identity/identity_fragment boot=200" in text
    assert "words=bytes=13,u16_le=896/257/12338/13874/...(6 total)" in text
    assert "texts=TEST_ID_1:1" in text
    assert "text=TEST_ID_1" in text
    assert "example_payload=3680030101544553545f49445f31" in text


def test_text_output_surfaces_power_debug_candidate(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x61",
                            "event_name": "debug_data",
                            "device_boot_timestamp": 60382,
                            "payload_length": 14,
                            "payload_hex": "14f963840ffbffffff2d3c0000f3",
                            "debug_data_code_hex": "0x14",
                            "debug_data_code_category": "binary_debug",
                            "debug_data_code_label": "binary_debug_0x14",
                            "debug_category": "binary_debug",
                            "debug_data_tail_hex": "f963840ffbffffff2d3c0000f3",
                        }
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([log_path])
    catalog_module.print_text(catalog)

    code = catalog["debug_code_stats"]["0x14"]
    assert code["latest_power_sample_candidate"]["voltage_mv_candidate"] == 3972
    text = capsys.readouterr().out
    assert "debug_data_codes=0x14:1" in text
    assert "power_candidate=3972mV?/signed2=-5/signed3=-1/status=0xF3?" in text


def test_main_defaults_to_log_glob(tmp_path: Path, monkeypatch, capsys) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    write_jsonl(
        logs_dir / "pi-zeroauth-chase-product-test.jsonl",
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x61",
                            "event_name": "debug_data",
                            "device_boot_timestamp": 1,
                            "payload_length": 5,
                            "payload_hex": "24648a0f00",
                            "debug_data_code_hex": "0x24",
                            "debug_data_code_category": "battery",
                            "debug_data_code_label": "battery_snapshot",
                            "debug_category": "battery",
                            "debug_data_tail_hex": "648a0f00",
                            "debug_data_battery": {
                                "battery_level_percent": 100,
                                "voltage_mv": 3978,
                                "status_hex": "0x00",
                            },
                        }
                    ]
                },
            }
        ],
    )
    monkeypatch.chdir(tmp_path)

    rc = catalog_module.main([])

    assert rc == 0
    text = capsys.readouterr().out
    assert "logs=1 read_results=1 events=1 unique=1 duplicates=0" in text
    assert "battery=100%/3978mV/status=0x00" in text


def test_catalog_skips_interleaved_non_json_lines(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "capture.jsonl"
    log_path.write_text(
        "\n".join(
            [
                '{"event": "read_result", "payload": {"events": []}}',
                "< HCI Command: ogf 0x08, ocf 0x000c, plen 2",
                "  00 00",
            ]
        ),
        encoding="utf-8",
    )

    catalog = catalog_module.build_catalog([log_path])
    catalog_module.print_text(catalog)

    assert catalog["read_result_count"] == 1
    assert catalog["invalid_json_line_count"] == 2
    assert catalog["invalid_json_lines"][0]["line"] == 2
    assert "skipped_non_json_lines=2" in capsys.readouterr().out


def test_catalog_surfaces_unknown_debug_keys(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x43",
                            "event_name": "debug_event",
                            "device_boot_timestamp": 300,
                            "payload_length": 6,
                            "payload_hex": "58797a3b3830",
                            "payload_text": "Xyz;80",
                            "debug_key": "Xyz",
                            "debug_values": ["80"],
                            "debug_numeric_values": [80],
                        }
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([log_path])
    catalog_module.print_text(catalog)

    assert catalog["debug_keys"] == {"Xyz": 1}
    assert catalog["unknown_debug_keys"] == {"Xyz": 1}
    assert "unknown_debug_keys=Xyz:1" in capsys.readouterr().out


def test_catalog_redecodes_fuel_gauge_debug_keys(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x43",
                            "event_name": "debug_event",
                            "device_boot_timestamp": 97963,
                            "payload_length": 8,
                            "payload_hex": "46475666253b3739",
                            "payload_text": "FGVf%;79",
                            "debug_key": "FGVf%",
                            "debug_values": ["79"],
                            "debug_numeric_values": [79],
                        }
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([log_path], redecode_events=True)

    assert catalog["debug_keys"] == {"FGVf%": 1}
    assert catalog["debug_categories"] == {"fuel_gauge": 1}
    assert catalog["debug_labels"] == {"fuel_gauge_vf_percent_candidate": 1}
    assert catalog["unknown_debug_keys"] == {}


def test_catalog_can_redecode_stale_event_payloads(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "events": [
                        {
                            "event_tag": "0x43",
                            "event_name": "debug_event",
                            "device_boot_timestamp": 83243,
                            "payload_length": 10,
                            "payload_hex": "4448525f6d6f64653a33",
                            "payload_text": "DHR_mode:3",
                            "debug_key": "DHR_mode",
                            "debug_values": ["3"],
                            "debug_numeric_values": [3],
                        }
                    ]
                },
            }
        ],
    )

    catalog = catalog_module.build_catalog([log_path], redecode_events=True)

    assert catalog["debug_keys"] == {"DHR_mode": 1}
    assert catalog["debug_categories"] == {"daytime_hr": 1}
    assert catalog["debug_labels"] == {"daytime_hr_mode": 1}
    assert catalog["unknown_debug_keys"] == {}
