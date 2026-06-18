from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def load_summary_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-zeroauth-log-summary.py"
    spec = importlib.util.spec_from_file_location("pi_zeroauth_log_summary", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


summary_module = load_summary_module()


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows),
        encoding="utf-8",
    )


def test_summarizes_live_scan_state(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "scan.jsonl"
    note = (
        "no target is not proof of a parser/client failure; current physical "
        "state may not advertise"
    )
    write_jsonl(
        log_path,
        [
            {
                "elapsed_seconds": 30.0,
                "event": "raw_scan_heartbeat",
                "payload": {
                    "cycle": 3,
                    "scan_backend": "hci_le_scan",
                    "seconds_remaining": 270.0,
                    "no_target_classification": "no_oura_seen",
                    "manufacturer_counts": {"01016401": 4, "04661b01": 2},
                    "resolvable_counts": {"13052a32": 1},
                    "oura_candidate_counts": {},
                    "last_address": "AA:BB:CC:DD:EE:FF",
                    "last_address_type": "Resolvable",
                    "last_event_type": "Scan response - SCAN_RSP (0x04)",
                    "physical_state_note": note,
                },
            },
            {
                "elapsed_seconds": 300.0,
                "event": "raw_cycle_no_target",
                "payload": {
                    "cycle": 3,
                    "consecutive_no_targets": 3,
                    "no_target_classification": "no_oura_seen",
                    "manufacturer_counts": {"01016401": 8, "04661b01": 2},
                    "physical_state_note": note,
                },
            },
        ],
    )

    summary = summary_module.summarize_log(log_path)

    assert summary["scan"]["heartbeat_count"] == 1
    assert summary["scan"]["no_target_window_count"] == 1
    assert summary["scan"]["latest_status"]["event"] == "raw_cycle_no_target"
    assert summary["scan"]["latest_status"]["physical_state_note"] == note
    assert summary["scan"]["latest_status"]["manufacturer_counts"] == {
        "01016401": 8,
        "04661b01": 2,
    }

    summary_module.print_text([summary])
    text = capsys.readouterr().out
    assert "scan: heartbeats=1 no_target_windows=1" in text
    assert "latest_scan: event=raw_cycle_no_target; cycle=3" in text
    assert "latest_manufacturers: 01016401:8, 04661b01:2" in text
    assert f"physical_state_note: {note}" in text


def test_summarizes_connect_timeouts_and_cancels(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "connect.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "elapsed_seconds": 1.0,
                "event": "raw_scan_target",
                "payload": {
                    "cycle": 1,
                    "manufacturer_hex": "04601b01",
                    "raw_manufacturer_hex": "b20204601b01",
                    "rpa": "7E:11:22:33:44:55",
                },
            },
            {
                "elapsed_seconds": 1.2,
                "event": "raw_connect_start",
                "payload": {"cycle": 1, "rpa": "7E:11:22:33:44:55"},
            },
            {
                "elapsed_seconds": 11.2,
                "event": "raw_connect_timeout",
                "payload": {
                    "cycle": 1,
                    "rpa": "7E:11:22:33:44:55",
                    "timeout": 10.0,
                },
            },
            {
                "elapsed_seconds": 11.3,
                "event": "raw_connect_cancel",
                "payload": {
                    "cycle": 1,
                    "rpa": "7E:11:22:33:44:55",
                    "reason": "connect_timeout",
                    "command": {"returncode": 0},
                },
            },
        ],
    )

    summary = summary_module.summarize_log(log_path)

    assert summary["raw_target_count"] == 1
    assert summary["connection_attempt_count"] == 1
    assert summary["connection_success_count"] == 0
    assert summary["connection_timeout_count"] == 1
    assert summary["connect_cancel_count"] == 1
    assert summary["latest_connect_status"]["event"] == "raw_connect_cancel"
    assert summary["latest_connect_status"]["command_returncode"] == 0
    assert summary["scan"]["latest_status"]["raw_manufacturer_hex"] == "b20204601b01"

    summary_module.print_text([summary])
    text = capsys.readouterr().out
    assert "connects: attempts=1 ok=0 failures=0 timeouts=1 cancels=1" in text
    assert "latest_connect: event=raw_connect_cancel; cycle=1" in text
    assert "raw_manufacturer=b20204601b01" in text


def test_summarizes_aggregate_read_result(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "read_result.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "elapsed_seconds": 40.0,
                "event": "read_result",
                "payload": {
                    "firmware": {
                        "firmware_version": "2.11.0",
                        "api_version": "2.0.0",
                        "bluetooth_stack_version": "5.0.15",
                    },
                    "auth_nonce": {"nonce_hex": "112233"},
                    "battery": {
                        "battery_level_percent": 100,
                        "charging_progress": 100,
                        "charging_recommended": False,
                        "battery_status_hex": "0x00",
                        "voltage_mv": 3955,
                    },
                    "device_snapshot": {
                        "serial_number": "TEST_SERIAL_0000",
                        "hardware_id": "ORE_06",
                        "firmware_git": "29df664",
                        "setup_transition": "Sw to App",
                        "battery": {
                            "level_percent": 100,
                            "charging_progress": 100,
                            "charging_recommended": False,
                            "battery_status_hex": "0x00",
                            "voltage_mv": 3955,
                        },
                        "charger_debug": {
                            "chg_ind": {
                                "values": ["100", "1"],
                                "numeric_values": [100, 1],
                                "device_boot_timestamp": 6210,
                            }
                        },
                        "charger_state": {
                            "latest_boot_timestamp": 6210,
                            "indicator_percent": 100,
                            "indicator_flag": 1,
                            "source_keys": ["chg_ind"],
                        },
                        "setup_state": {
                            "latest_boot_timestamp": 6305,
                            "transition": "Sw to App",
                            "in_bed_flag": 0,
                            "info_state": 6,
                            "boot_context": 0x43,
                            "platform_flags": 0x07,
                            "eflo_flag": 0,
                            "ccm": 1,
                            "ccp_value": "1",
                            "ccp_status": "NA",
                            "ble_setup_state_a": 50,
                        },
                        "health_features": {
                            "daytime_hr": "automatic/off/idle/off",
                            "resting_hr": "automatic/off/idle/off",
                        },
                    },
                    "event_summary": {
                        "count": 41,
                        "unique_count": 37,
                        "duplicate_count": 4,
                        "first_boot_timestamp": 6307,
                        "last_boot_timestamp": 6597,
                        "next_start_timestamp": 6598,
                        "latest_events_done": {
                            "request_start_timestamp": 6307,
                            "request_start_hex": "0x000018a3",
                            "request_max_events": 41,
                            "events_received": 0,
                            "bytes_left": 0,
                            "sleep_analysis_progress": 0,
                            "unknown_u16": 65283,
                        },
                        "complete": True,
                        "debug_keys": {
                            "chg_hs": 4,
                            "chgv": 4,
                            "chg_ind": 3,
                            "chg_rp": 3,
                            "chg_bc": 2,
                        },
                        "debug_categories": {
                            "charger": 16,
                            "identity": 3,
                            "setup_state": 2,
                        },
                        "debug_data_codes": {
                            "0x04": 3,
                            "0x0F": 3,
                            "0x09": 2,
                        },
                        "health_events": {
                            "event_counts": {"ibi_and_amplitude_event": 1},
                            "ibi_record_count": 6,
                            "bpm_estimate_min": 500.0,
                            "bpm_estimate_max": 750.0,
                            "bpm_estimate_latest": 500.0,
                        },
                        "debug_value_stats": {
                            "chg_ind": {
                                "count": 3,
                                "latest_values": ["100", "1"],
                                "min_numeric_values": [100, 1],
                                "max_numeric_values": [100, 1],
                            },
                            "chgv": {
                                "count": 4,
                                "latest_values": ["6860", "5544"],
                                "min_numeric_values": [6860, 5026],
                                "max_numeric_values": [6902, 5950],
                            },
                        },
                    },
                    "product_info": {
                        "hardware_id": "ORE_06",
                        "serial_number": "TEST_SERIAL_0000",
                    },
                    "product_info_memory": {
                        "byte_count": 24,
                        "source_count": 2,
                        "segments": [
                            {
                                "start": "0x0000",
                                "end_exclusive": "0x0018",
                                "length": 24,
                                "hex": "7856341207000000544553545f53455249414c5f30303030",
                                "ascii_preview": "xV4.....TEST_SERIAL_0000",
                                "printable_runs": [
                                    {"offset": "0x0008", "text": "TEST_SERIAL_0000"}
                                ],
                            }
                        ],
                        "conflicts": [],
                    },
                    "feature_status": {
                        "feature_status:0x02": {
                            "feature_id": 2,
                            "feature_name": "daytime_hr",
                            "mode_name": "automatic",
                            "status_name": "off",
                            "state_name": "idle",
                            "subscription_mode_name": "off",
                        }
                    },
                    "feature_summary": {
                        "count": 2,
                        "modes": {"automatic": 2},
                        "statuses": {"off": 1, "searching": 1},
                        "states": {"idle": 1, "measuring": 1},
                        "subscriptions": {"off": 1, "state": 1},
                        "health_features": {
                            "daytime_hr": "automatic/off/idle/off",
                            "resting_hr": "automatic/searching/measuring/state",
                        },
                        "active_features": ["resting_hr"],
                    },
                    "feature_set_results": [
                        {
                            "packet": "feature_subscription:0x02:latest",
                            "extended_name": "set_feature_subscription_response",
                            "feature_id": 2,
                            "feature_name": "daytime_hr",
                            "result_name": "success",
                        }
                    ],
                    "auth_gated": ["battery", "feature_status:0x08"],
                    "unattributed_notifications": [
                        {
                            "extended_name": "auth_status_response",
                            "auth_result": "authentication_error",
                        }
                    ],
                },
            }
        ],
    )

    summary = summary_module.summarize_log(log_path)

    assert summary["read_result_count"] == 1
    assert summary["latest_read_result"]["firmware"]["firmware_version"] == "2.11.0"

    summary_module.print_text([summary])
    text = capsys.readouterr().out
    assert "streams=0 read_results=1" in text
    assert "latest_read_result: fw=2.11.0 api=2.0.0 ble=5.0.15" in text
    assert "battery=100% charge_progress=100% voltage=3955mV status=0x00" in text
    assert "device_snapshot: serial=TEST_SERIAL_0000 hw=ORE_06" in text
    assert "git=29df664 transition=Sw to App battery=100%" in text
    assert "charge_progress=100% voltage=3955mV" in text
    assert "charger=chg_ind:100,1" in text
    assert "charger_state=ind=100/1,ts=6210" in text
    assert (
        "setup_state=transition=Sw to App,in_bed=0,info=6,bc=67,pf=7,"
        "eflo=0,ccm=1,ble_state=50,ccp=1/NA,ts=6305"
    ) in text
    assert "health=daytime_hr:automatic/off/idle/off" in text
    assert (
        "event_summary: count=41 unique=37 duplicates=4 "
        "span=6307-6597 next=0x000019c6"
    ) in text
    assert "req=0x000018a3/41" in text
    assert "done=0/bytes_left=0 complete=true" in text
    assert "keys=chg_hs:4,chgv:4,chg_ind:3,chg_rp:3,chg_bc:2" in text
    assert "categories=charger:16,identity:3,setup_state:2" in text
    assert "codes=0x04:3,0x0F:3,0x09:2" in text
    assert "health_events=events=ibi_and_amplitude_event:1,ibi=6" in text
    assert "bpm=500.0-750.0,latest_bpm=500.0" in text
    assert (
        "values=chgv:n4 latest=6860,5544 range=6860-6902,5026-5950;"
        "chg_ind:n3 latest=100,1 range=100-100,1-1"
    ) in text
    assert (
        "feature_summary: count=2 modes=automatic:2 statuses=off:1,searching:1 "
        "states=idle:1,measuring:1 subs=off:1,state:1"
    ) in text
    assert "health=daytime_hr:automatic/off/idle/off" in text
    assert "active=resting_hr" in text
    assert "feature_status: daytime_hr=automatic/off/idle/off" in text
    assert "feature_subscription:0x02:latest:daytime_hr/success" in text
    assert "serial_number=TEST_SERIAL_0000" in text
    assert "product_info_memory: bytes=24 sources=2" in text
    assert "text=0x0008=TEST_SERIAL_0000" in text
    assert "auth_gated=battery,feature_status:0x08" in text
    assert "unattributed_notifications=1" in text


def test_summarizes_event_printable_payload() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "debug_event",
                "device_boot_timestamp": 7186,
                "payload_length": 13,
                "payload_text": "chg_ind;100;1",
                "debug_key": "chg_ind",
                "debug_values": ["100", "1"],
            }
        )
        == (
            "event=debug_event boot_ts=7186 payload_len=13 "
            "text=chg_ind;100;1 debug=chg_ind:100,1"
        )
    )


def test_summarizes_event_binary_debug_code() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "debug_data",
                "device_boot_timestamp": 6404,
                "payload_length": 9,
                "debug_data_code_hex": "0x3D",
            }
        )
        == "event=debug_data boot_ts=6404 payload_len=9 debug_code=0x3D"
    )


def test_summarizes_event_binary_debug_battery_snapshot() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "debug_data",
                "device_boot_timestamp": 13623,
                "payload_length": 5,
                "debug_data_code_hex": "0x24",
                "debug_data_battery": {
                    "battery_level_percent": 100,
                    "voltage_mv": 3962,
                    "status_hex": "0x00",
                },
            }
        )
        == (
            "event=debug_data boot_ts=13623 payload_len=5 "
            "debug_code=0x24 battery=100% voltage=3962mV status=0x00"
        )
    )


def test_summarizes_event_binary_debug_tail_words() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "debug_data",
                "device_boot_timestamp": 13613,
                "payload_length": 14,
                "debug_data_code_hex": "0x14",
                "debug_data_tail_words": {
                    "byte_count": 13,
                    "u16_le": [25593, 4000, 65523, 65535, 15405, 0],
                    "i16_le": [25593, 4000, -13, -1, 15405, 0],
                    "u32_le": [262169593, 4294967283, 15405],
                    "i32_le": [262169593, -13, 15405],
                },
            }
        )
        == (
            "event=debug_data boot_ts=13613 payload_len=14 debug_code=0x14 "
            "words=bytes=13,u16_le=25593/4000/65523/65535/...(6 total),"
            "i16_le=25593/4000/-13/-1/...(6 total),"
            "u32_le=262169593/4294967283/15405,"
            "i32_le=262169593/-13/15405"
        )
    )


def test_summarizes_event_power_debug_candidate() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "debug_data",
                "device_boot_timestamp": 60382,
                "payload_length": 14,
                "debug_data_code_hex": "0x14",
                "debug_data_tail_hex": "f963840ffbffffff2d3c0000f3",
            }
        )
        == (
            "event=debug_data boot_ts=60382 payload_len=14 debug_code=0x14 "
            "power_candidate=voltage=3972mV?,signed2=-5,signed3=-1,status=0xF3?"
        )
    )


def test_formats_debug_battery_snapshot() -> None:
    assert summary_module.format_battery_debug(
        {
            "battery_level_percent": 100,
            "voltage_mv": 3996,
            "status_hex": "0x02",
            "min_voltage_mv": 3962,
            "max_voltage_mv": 3996,
            "sample_count": 4,
            "device_boot_timestamp": 14884,
        }
    ) == "100%,voltage=3996mV,status=0x02,range=3962-3996mV,n=4,ts=14884"


def test_formats_power_debug_candidate_snapshot() -> None:
    assert summary_module.format_power_debug_candidate(
        {
            "voltage_mv_candidate": 3972,
            "signed2_i16": -5,
            "signed3_i16": -1,
            "status_hex_candidate": "0xF3",
            "min_voltage_mv_candidate": 3972,
            "max_voltage_mv_candidate": 4000,
            "sample_count": 2,
            "device_boot_timestamp": 60382,
        }
    ) == (
        "voltage=3972mV?,signed2=-5,signed3=-1,status=0xF3?,"
        "range=3972-4000mV?,n=2,ts=60382"
    )


def test_formats_charger_activity_summary() -> None:
    assert summary_module.format_charger_activity(
        {
            "event_count": 510,
            "span_seconds": 12553,
            "key_counts": {
                "chg_ind": 314,
                "chg_hs": 52,
                "chg_rp": 52,
                "chgv": 52,
                "chg_rc": 40,
            },
            "rp_state_counts": {"10": 47, "1": 3, "11": 2},
            "rc_state_counts": {"0": 30, "1": 10},
            "indicator_flag_counts": {"1": 314},
            "indicator_percent_latest": 100,
            "indicator_percent_min": 100,
            "indicator_percent_max": 100,
            "rp_raw_latest": 687,
            "rp_raw_min": 533,
            "rp_raw_max": 6146,
            "hs_raw_latest": 6090,
            "hs_raw_min": 5348,
            "hs_raw_max": 6090,
            "chgv_raw_a_latest": 6902,
            "chgv_raw_a_min": 6804,
            "chgv_raw_a_max": 6902,
            "chgv_raw_b_latest": 6076,
            "chgv_raw_b_min": 3892,
            "chgv_raw_b_max": 6076,
        }
    ) == (
        "events=510,span=12553s,keys=chg_ind:314,chg_hs:52,chg_rp:52,"
        "chgv:52,chg_rc:40,rp_states=10:47,1:3,11:2,rc_states=0:30,1:10,"
        "ind_flags=1:314,ind=100(100-100),rp_raw=687(533-6146),"
        "hs=6090(5348-6090),chgv_a=6902(6804-6902),"
        "chgv_b=6076(3892-6076)"
    )


def test_formats_extended_charger_state_fields() -> None:
    assert summary_module.format_charger_state(
        {
            "bc_state": 3,
            "brx_state": "l",
            "brx_raw": 49,
            "brx_flag": 1,
            "charger_status_hex": "0x0000081b",
            "charger_status_bits": [0, 1, 3, 4, 11],
            "rcell_hex": "0x0b54",
            "rcell_raw": 2900,
            "latest_boot_timestamp": 48271,
        }
    ) == (
        "bc=3,brx=l/49/1,chg_status=0x0000081b[0/1/3/4/11],"
        "rcell=0x0b54/2900,ts=48271"
    )


def test_formats_fuel_gauge_state_fields() -> None:
    assert summary_module.format_fuel_gauge_state(
        {
            "vf_percent_candidate": 79,
            "lcu_value_a_candidate": 81,
            "lcu_value_b_candidate": 79,
            "design_capacity_candidate": 43,
            "latest_boot_timestamp": 97964,
        }
    ) == "vf%?=79,lcu?=81/79,dcap?=43,ts=97964"


def test_formats_extra_setup_state_fields() -> None:
    assert summary_module.format_setup_state(
        {
            "bls_state": 3,
            "ccv_value": 64641036,
            "mfc_value": "500",
            "mfc_status": "4",
            "tef_code": "110b",
            "tef_status": "0000",
            "latest_boot_timestamp": 6324,
        }
    ) == "bls=3,ccv=64641036,mfc=500/4,tef=110b/0000,ts=6324"


def test_formats_extended_charger_activity_fields() -> None:
    assert summary_module.format_charger_activity(
        {
            "event_count": 4,
            "key_counts": {"ChgSt": 1, "brx": 1, "chg_bc": 1, "rcell": 1},
            "bc_state_counts": {"3": 1},
            "brx_state_counts": {"l": 1},
            "brx_flag_counts": {"1": 1},
            "charger_status_counts": {"0x0000081b": 1},
            "rcell_raw_latest": 2900,
            "rcell_raw_min": 2900,
            "rcell_raw_max": 2900,
            "brx_raw_latest": 49,
            "brx_raw_min": 49,
            "brx_raw_max": 49,
        }
    ) == (
        "events=4,keys=ChgSt:1,brx:1,chg_bc:1,rcell:1,bc_states=3:1,"
        "brx_states=l:1,brx_flags=1:1,chg_status=0x0000081b:1,"
        "rcell=2900(2900-2900),brx_raw=49(49-49)"
    )


def test_summarizes_ring_start_event_versions() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "event_name": "ring_start",
                "device_boot_timestamp": 6293,
                "payload_length": 14,
                "ring_start_marker_u32": 16,
                "ring_start_code_hex": "0x32",
                "firmware_version": "2.11.0",
                "bootloader_version": "1.0.1",
                "api_version": "2.0.0",
            }
        )
        == (
            "event=ring_start boot_ts=6293 payload_len=14 "
            "marker=16 code=0x32 fw=2.11.0 bootloader=1.0.1 api=2.0.0"
        )
    )


def test_summarizes_feature_set_response() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "extended_name": "set_feature_subscription_response",
                "feature_id": 2,
                "feature_name": "daytime_hr",
                "result_name": "success",
            }
        )
        == "feature_set feature_subscription_response daytime_hr=result:success"
    )


def test_summarizes_ring_mode_response() -> None:
    assert (
        summary_module.summarize_decoded(
            {
                "response_name": "set_ring_mode_status",
                "status": 0,
                "status_name": "ok",
            }
        )
        == "ring_mode status=ok raw=0"
    )


def test_format_limited_items_compacts_long_lists() -> None:
    assert (
        summary_module.format_limited_items(["a", "b", "c"], max_items=2)
        == "a, b, ... (3 total)"
    )
    assert (
        summary_module.format_limited_items(
            {"aa": 1, "bb": 2, "cc": 3}, separator="; ", max_items=2
        )
        == "aa; bb; ... (3 total)"
    )


def test_feature_summary_marks_truncated_active_features() -> None:
    text = summary_module.format_feature_summary(
        {
            "count": 9,
            "modes": {"off": 9},
            "statuses": {"off": 9},
            "states": {"idle": 9},
            "subscriptions": {"latest": 9},
            "active_features": [f"feature_{index}" for index in range(9)],
        }
    )

    assert "active=feature_0,feature_1,feature_2,feature_3" in text
    assert "feature_7,...(9 total)" in text
