from __future__ import annotations

import pytest

from oura_ring4_ble import protocol as p


def test_packet_round_trip() -> None:
    encoded = p.encode_packet(0x0C)
    assert encoded == bytes.fromhex("0c00")
    assert p.parse_packets(encoded) == [p.Packet(0x0C, b"")]


def test_builds_safe_read_requests() -> None:
    assert p.build_get_firmware_request() == bytes.fromhex("0800")
    assert p.build_get_battery_request() == bytes.fromhex("0c00")
    assert p.build_get_events_request(0, 4) == bytes.fromhex(
        "10090000000004ffffffff"
    )


def test_build_factory_reset_request() -> None:
    assert p.build_factory_reset_request() == bytes.fromhex("1a00")


def test_parse_factory_reset_status() -> None:
    decoded = p.parse_response(p.packet_from_hex("1b0100"))

    assert decoded["decoded"] == {
        "response_name": "factory_reset_status",
        "status": 0,
        "status_name": "ok",
    }


def test_parse_battery_response() -> None:
    packet = p.packet_from_hex("0D06 6400 00FF FFFF")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["battery_level_percent"] == 100
    assert decoded["decoded"]["charging_progress"] == 0
    assert decoded["decoded"]["charging_recommended"] is False
    assert decoded["decoded"]["battery_status_byte"] == 0xFF
    assert decoded["decoded"]["battery_status_hex"] == "0xFF"
    assert decoded["decoded"]["battery_voltage_raw"] == 0xFFFF
    assert "voltage_mv" not in decoded["decoded"]


def test_parse_observed_battery_voltage_response() -> None:
    packet = p.packet_from_hex("0D06 6464 0000 730F")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["battery_level_percent"] == 100
    assert decoded["decoded"]["charging_progress"] == 100
    assert decoded["decoded"]["charging_recommended"] is False
    assert decoded["decoded"]["unknown_hex"] == "00730f"
    assert decoded["decoded"]["battery_status_byte"] == 0
    assert decoded["decoded"]["battery_status_hex"] == "0x00"
    assert decoded["decoded"]["battery_voltage_raw"] == 3955
    assert decoded["decoded"]["voltage_mv"] == 3955


def test_parse_firmware_response() -> None:
    packet = p.packet_from_hex("0912 0112 0102 0002 0100 0305 0004 1111 2222 3333")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["api_version"] == "1.18.1"
    assert decoded["decoded"]["firmware_version"] == "2.0.2"
    assert decoded["decoded"]["bootloader_version"] == "1.0.3"
    assert decoded["decoded"]["bluetooth_stack_version"] == "5.0.4"
    assert decoded["decoded"]["mac_fragment_hex"] == "11:11:22:22:33:33"


def test_parse_auth_nonce_response() -> None:
    packet = p.packet_from_hex("2F10 2C11 1122 2233 3344 4455 5566 6677 7788")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["extended_name"] == "auth_nonce_response"
    assert decoded["decoded"]["nonce_length"] == 15


def test_parse_auth_status_response() -> None:
    packet = p.packet_from_hex("2F02 2F01")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["extended_name"] == "auth_status_response"
    assert decoded["decoded"]["auth_state"] == 1
    assert decoded["decoded"]["auth_result"] == "authentication_error"


def test_parse_capabilities_response() -> None:
    packet = p.packet_from_hex("2F02 0202")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["extended_name"] == "capabilities_response"
    assert decoded["decoded"]["page"] == 2
    assert decoded["decoded"]["payload_hex"] == "02"
    assert "capability_entries" not in decoded["decoded"]


def test_parse_observed_capability_entries() -> None:
    packet = p.packet_from_hex("2F12 020200050103020503030404050108020900")
    decoded = p.parse_response(packet)
    entries = decoded["decoded"]["capability_entries"]
    assert decoded["decoded"]["data_hex"] == "00050103020503030404050108020900"
    assert entries[0] == {
        "feature_id": 0,
        "feature_name": "background_dfu",
        "capability_value": 5,
        "capability_hex": "0x05",
        "capability_bits": [0, 2],
    }
    assert entries[-1]["feature_name"] == "app_auth"
    assert entries[-1]["capability_value"] == 0


def test_builds_zero_auth_extended_reads() -> None:
    assert p.build_get_capabilities_request() == bytes.fromhex("2f0201ff")
    assert p.build_get_capabilities_request(0x02) == bytes.fromhex("2f020102")
    assert p.build_get_feature_status_request(0x0C) == bytes.fromhex("2f02200c")
    assert p.build_get_feature_status_request(0x16) == bytes.fromhex("2f022016")
    assert p.build_get_feature_latest_values_request(0x02) == bytes.fromhex(
        "2f022402"
    )


def test_builds_product_info_reads() -> None:
    assert p.build_get_product_info_request("serial_number") == bytes.fromhex(
        "1803080010"
    )
    assert p.build_get_product_info_request("product_code") == bytes.fromhex(
        "1803280009"
    )


def test_parse_product_info_response() -> None:
    packet = p.packet_from_hex("1911 00544553545f53455249414c5f30303030")
    decoded = p.parse_response(packet, product_info_type="serial_number")
    assert decoded["decoded"]["info_type_name"] == "serial_number"
    assert decoded["decoded"]["status"] == 0
    assert decoded["decoded"]["status_name"] == "ok"
    assert decoded["decoded"]["value_text"] == "TEST_SERIAL_0000"


def test_parse_observed_product_info_hardware_response() -> None:
    packet = p.packet_from_hex("1911 00585858584f52455f3036000000000000")
    decoded = p.parse_response(packet, product_info_type="hardware_id_frodo")
    assert decoded["decoded"]["info_type_name"] == "hardware_id_frodo"
    assert decoded["decoded"]["value_text"] == "XXXXORE_06"


def test_parse_observed_product_info_old_serial_printable_tail() -> None:
    packet = p.packet_from_hex("1911 0007000000544553545f53455249414c5f")
    decoded = p.parse_response(packet, product_info_type="serial_number_old")
    assert decoded["decoded"]["info_type_name"] == "serial_number_old"
    assert decoded["decoded"]["value_hex"] == "07000000544553545f53455249414c5f"
    assert decoded["decoded"]["printable_runs"] == ["TEST_SERIAL_"]


def test_reconstruct_product_info_memory_prefers_supported_overlap() -> None:
    rows = [
        p.parse_response(
            p.packet_from_hex("1911 000b000000010000000100019902010499"),
            product_info_type=bytes.fromhex("2c0010"),
        )["decoded"],
        p.parse_response(
            p.packet_from_hex("1911 0001000000010001990201049978224217"),
            product_info_type=bytes.fromhex("340010"),
        )["decoded"],
        p.parse_response(
            p.packet_from_hex("1911 0001000199020104997822421700000001"),
            product_info_type=bytes.fromhex("340010"),
        )["decoded"],
        p.parse_response(
            p.packet_from_hex("1911 0002010499782242170000000100089800"),
            product_info_type=bytes.fromhex("380010"),
        )["decoded"],
    ]

    memory = p.reconstruct_product_info_memory(rows)

    assert memory["byte_count"] == 28
    assert memory["segments"][0]["start"] == "0x002C"
    assert memory["segments"][0]["end_exclusive"] == "0x0048"
    assert memory["segments"][0]["length"] == 28
    assert memory["segments"][0]["hex"] == (
        "0b000000010000000100019902010499"
        "782242170000000100089800"
    )
    assert memory["segments"][0]["printable_runs"] == []
    assert {
        conflict["offset"]: conflict["selected"]
        for conflict in memory["conflicts"]
    } == {
        "0x0036": "0x01",
        "0x0037": "0x99",
        "0x0038": "0x02",
        "0x0039": "0x01",
        "0x003A": "0x04",
        "0x003C": "0x78",
        "0x003D": "0x22",
        "0x003E": "0x42",
        "0x003F": "0x17",
        "0x0040": "0x00",
        "0x0041": "0x00",
        "0x0042": "0x00",
        "0x0043": "0x01",
    }


def test_parse_feature_status_response() -> None:
    packet = p.packet_from_hex("2F06 210C 0102 0302")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["extended_name"] == "feature_status_response"
    assert decoded["decoded"]["feature_name"] == "experimental"
    assert decoded["decoded"]["mode_name"] == "automatic"
    assert decoded["decoded"]["status_name"] == "searching"
    assert decoded["decoded"]["state_name"] == "postprocessing"
    assert decoded["decoded"]["subscription_mode_name"] == "latest"


def test_build_feature_set_requests() -> None:
    assert p.build_set_feature_mode_request(0x02, 0x03) == bytes.fromhex(
        "2f03220203"
    )
    assert p.build_set_feature_subscription_request(0x02, 0x02) == bytes.fromhex(
        "2f03260202"
    )
    assert p.FEATURE_MODES[0x03] == "connected_live"
    assert p.FEATURE_SUBSCRIPTION_MODES[0x04] == "feature_specific_data"


def test_build_and_parse_feature_parameters_requests() -> None:
    assert p.build_set_feature_parameters_request(0x02, b"\x01") == bytes.fromhex(
        "2f03290201"
    )
    assert p.build_set_daytime_hr_meditation_parameters_request(1) == bytes.fromhex(
        "2f03290201"
    )
    assert p.build_set_daytime_hr_meditation_parameters_request(0) == bytes.fromhex(
        "2f03290200"
    )

    decoded = p.parse_response(p.packet_from_hex("2f03 2a02 00"))
    assert decoded["decoded"]["extended_name"] == "set_feature_parameters_response"
    assert decoded["decoded"]["feature_name"] == "daytime_hr"
    assert decoded["decoded"]["result_name"] == "success"


def test_build_and_parse_realtime_measurements_requests() -> None:
    assert p.build_set_realtime_measurements_request(
        ["on_demand"],
        maximum_duration_minutes=1,
        delay=10,
    ) == bytes.fromhex("06070002000001000a")
    assert p.build_set_realtime_measurements_request(
        ["acm", "on_demand"],
        maximum_duration_minutes=2,
        delay=1,
    ) == bytes.fromhex("060720020000020001")
    assert p.build_disable_realtime_measurements_request() == bytes.fromhex(
        "060400000000"
    )

    decoded = p.parse_response(p.packet_from_hex("070100"))
    assert decoded["decoded"] == {
        "response_name": "realtime_measurements_status",
        "status": 0,
        "status_name": "success",
    }


def test_build_and_parse_ring_mode_request() -> None:
    assert p.build_set_ring_mode_request(0x01) == bytes.fromhex("310401000000")

    decoded = p.parse_response(p.packet_from_hex("320400000000"))
    assert decoded["decoded"] == {
        "response_name": "set_ring_mode_status",
        "status": 0,
        "status_name": "ok",
    }


def test_build_and_parse_set_auth_key() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert p.build_set_auth_key_request(key) == bytes.fromhex(
        "241000112233445566778899aabbccddeeff"
    )

    decoded = p.parse_response(p.packet_from_hex("250100"))
    assert decoded["decoded"] == {
        "response_name": "set_auth_key_status",
        "status": 0,
        "status_name": "success",
    }


def test_parse_set_auth_key_production_tests_missing_is_named() -> None:
    decoded = p.parse_response(p.packet_from_hex("250105"))
    assert decoded["decoded"] == {
        "response_name": "set_auth_key_status",
        "status": 5,
        "status_name": "production_tests_missing",
    }


def test_generate_auth_key_uses_16_bytes() -> None:
    assert len(p.generate_auth_key()) == 16


def test_parse_feature_set_subscription_response() -> None:
    decoded = p.parse_response(p.packet_from_hex("2F03 2702 00"))
    assert decoded["decoded"]["extended_name"] == "set_feature_subscription_response"
    assert decoded["decoded"]["feature_name"] == "daytime_hr"
    assert decoded["decoded"]["result_name"] == "success"


def test_parse_daytime_hr_latest_values_response() -> None:
    decoded = p.parse_response(
        p.packet_from_hex("2f10 2502 0001 0234 1220 0304 0302 011e 0007")
    )

    assert decoded["decoded"]["extended_name"] == "feature_latest_values_response"
    assert decoded["decoded"]["feature_name"] == "daytime_hr"
    assert decoded["decoded"]["result_name"] == "success"
    assert decoded["decoded"]["status_name"] == "on"
    assert decoded["decoded"]["state_name"] == "measuring"
    assert decoded["decoded"]["status_duration"] == 0x1234
    assert decoded["decoded"]["daytime_hr_ibi_ms"] == 800
    assert decoded["decoded"]["daytime_hr_timestamp"] == 0x01020304
    assert decoded["decoded"]["daytime_hr_duration"] == 30
    assert decoded["decoded"]["daytime_hr_quality"] == 7
    assert decoded["decoded"]["daytime_hr_bpm_estimate"] == 75.0


def test_auth_encrypts_nonce_with_pkcs7_padding() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("111122223333444455556666777788")
    encrypted = p.encrypt_nonce(key, nonce)
    assert len(encrypted) == 16
    request = p.parse_packets(p.build_authenticate_request(key, nonce))[0]
    assert request.tag == p.TAG_EXTENDED
    assert request.payload[0] == p.EXT_AUTHENTICATE
    assert request.payload[1:] == encrypted


def test_parse_event_packet() -> None:
    packet = p.packet_from_hex("6110 B0E8 A900 1A18 0025 0000 0000 0000 00F7")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["event_name"] == "debug_data"
    assert decoded["decoded"]["device_boot_timestamp"] == 11135152
    assert decoded["decoded"]["payload_hex"] == "1a18002500000000000000f7"
    assert decoded["decoded"]["payload_ascii"] == "...%........"
    assert decoded["decoded"]["debug_data_code"] == 0x1A
    assert decoded["decoded"]["debug_data_code_hex"] == "0x1A"
    assert decoded["decoded"]["debug_data_tail_hex"] == "18002500000000000000f7"


def test_parse_event_packet_printable_payload() -> None:
    packet = p.packet_from_hex("4311 121C0000 6368675f696e643b3130303b31")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["event_name"] == "debug_event"
    assert decoded["decoded"]["device_boot_timestamp"] == 7186
    assert decoded["decoded"]["payload_text"] == "chg_ind;100;1"
    assert decoded["decoded"]["printable_runs"] == ["chg_ind;100;1"]
    assert decoded["decoded"]["debug_text"] == "chg_ind;100;1"
    assert decoded["decoded"]["debug_key"] == "chg_ind"
    assert decoded["decoded"]["debug_values"] == ["100", "1"]
    assert decoded["decoded"]["debug_numeric_values"] == [100, 1]
    assert decoded["decoded"]["debug_category"] == "charger"
    assert decoded["decoded"]["debug_label"] == "charge_indicator"
    assert decoded["decoded"]["debug_fields"] == {"percent": "100", "flag": "1"}


def test_parse_debug_data_packet_printable_tail() -> None:
    packet = p.packet_from_hex("6112 61190000 046368675f72703b313b36383630")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["event_name"] == "debug_data"
    assert decoded["decoded"]["debug_data_code_hex"] == "0x04"
    assert decoded["decoded"]["debug_data_code_category"] == "charger"
    assert decoded["decoded"]["debug_data_code_label"] == "charger_report"
    assert decoded["decoded"]["payload_text"] == "chg_rp;1;6860"
    assert decoded["decoded"]["debug_key"] == "chg_rp"
    assert decoded["decoded"]["debug_values"] == ["1", "6860"]
    assert decoded["decoded"]["debug_numeric_values"] == [1, 6860]
    assert decoded["decoded"]["debug_category"] == "charger"
    assert decoded["decoded"]["debug_label"] == "charge_rp"
    assert decoded["decoded"]["debug_fields"] == {"state": "1", "raw": "6860"}


def test_parse_charger_brx_debug_data_tail() -> None:
    packet = p.packet_from_hex("610f 12820100 046272783b6c3b34393b31")
    decoded = p.parse_response(packet)

    assert decoded["decoded"]["event_name"] == "debug_data"
    assert decoded["decoded"]["debug_data_code_hex"] == "0x04"
    assert decoded["decoded"]["payload_text"] == "brx;l;49;1"
    assert decoded["decoded"]["debug_key"] == "brx"
    assert decoded["decoded"]["debug_values"] == ["l", "49", "1"]
    assert decoded["decoded"]["debug_numeric_values"] == [49, 1]
    assert decoded["decoded"]["debug_category"] == "charger"
    assert decoded["decoded"]["debug_label"] == "charger_brx"
    assert decoded["decoded"]["debug_fields"] == {
        "state": "l",
        "raw": "49",
        "flag": "1",
    }


def test_parse_charger_f4_debug_text() -> None:
    decoded = p.parse_response(
        p.packet_from_hex("4312 3c570400 436846343b303030303a30303561")
    )

    assert decoded["decoded"]["event_name"] == "debug_event"
    assert decoded["decoded"]["payload_text"] == "ChF4;0000:005a"
    assert decoded["decoded"]["debug_key"] == "ChF4"
    assert decoded["decoded"]["debug_values"] == ["0000:005a"]
    assert decoded["decoded"]["debug_category"] == "charger"
    assert decoded["decoded"]["debug_label"] == "charger_f4"
    assert decoded["decoded"]["debug_fields"] == {"value": "0000:005a"}


def test_parse_debug_data_packet_battery_snapshot() -> None:
    packet = p.packet_from_hex("6109 37350000 24647a0f00")
    decoded = p.parse_response(packet)

    assert decoded["decoded"]["event_name"] == "debug_data"
    assert decoded["decoded"]["device_boot_timestamp"] == 13623
    assert decoded["decoded"]["debug_data_code_hex"] == "0x24"
    assert decoded["decoded"]["debug_data_code_category"] == "battery"
    assert decoded["decoded"]["debug_data_code_label"] == "battery_snapshot"
    assert decoded["decoded"]["debug_data_battery"] == {
        "battery_level_percent": 100,
        "voltage_mv": 3962,
        "status": 0,
        "status_hex": "0x00",
    }


def test_parse_debug_data_packet_binary_tail_words() -> None:
    packet = p.packet_from_hex("6112 2d350000 14f963a00ff3ffffff2d3c0000f5")
    decoded = p.parse_response(packet)

    assert decoded["decoded"]["event_name"] == "debug_data"
    assert decoded["decoded"]["device_boot_timestamp"] == 13613
    assert decoded["decoded"]["debug_data_code_hex"] == "0x14"
    assert decoded["decoded"]["debug_data_code_category"] == "binary_debug"
    assert decoded["decoded"]["debug_data_tail_words"] == {
        "byte_count": 13,
        "u16_le": [25593, 4000, 65523, 65535, 15405, 0],
        "i16_le": [25593, 4000, -13, -1, 15405, 0],
        "u32_le": [262169593, 4294967283, 15405],
        "i32_le": [262169593, -13, 15405],
    }
    assert decoded["decoded"]["debug_data_power_sample_candidate"] == {
        "inferred": True,
        "source": "debug_data_code_0x14",
        "raw0_u16": 25593,
        "voltage_mv_candidate": 4000,
        "signed2_i16": -13,
        "signed3_i16": -1,
        "raw4_u16": 15405,
        "raw5_u16": 0,
        "status_byte_candidate": 245,
        "status_hex_candidate": "0xF5",
    }


def test_parse_new_binary_debug_codes() -> None:
    code_0f = p.parse_response(p.packet_from_hex("6109 0d250200 0f05000513"))
    assert code_0f["decoded"]["event_name"] == "debug_data"
    assert code_0f["decoded"]["debug_data_code_hex"] == "0x0F"
    assert code_0f["decoded"]["debug_data_code_category"] == "binary_debug"
    assert code_0f["decoded"]["debug_data_code_label"] == "binary_debug_0x0f"
    assert code_0f["decoded"]["debug_data_tail_words"] == {
        "byte_count": 4,
        "u16_le": [5, 4869],
        "i16_le": [5, 4869],
        "u32_le": [319094789],
        "i32_le": [319094789],
    }

    code_1f = p.parse_response(
        p.packet_from_hex("610e b2180000 1f270b00010000040301")
    )
    assert code_1f["decoded"]["debug_data_code_hex"] == "0x1F"
    assert code_1f["decoded"]["debug_data_code_category"] == "binary_debug"
    assert code_1f["decoded"]["debug_data_code_label"] == "binary_debug_0x1f"
    assert code_1f["decoded"]["debug_data_tail_words"] == {
        "byte_count": 9,
        "u16_le": [2855, 256, 0, 772],
        "i16_le": [2855, 256, 0, 772],
        "u32_le": [16780071, 50593792],
        "i32_le": [16780071, 50593792],
    }

    code_20 = p.parse_response(
        p.packet_from_hex("6110 e8570400 200a00000064641d0fb00f09")
    )
    assert code_20["decoded"]["debug_data_code_hex"] == "0x20"
    assert code_20["decoded"]["debug_data_code_category"] == "binary_debug"
    assert code_20["decoded"]["debug_data_code_label"] == "binary_debug_0x20"
    assert code_20["decoded"]["debug_data_tail_words"] == {
        "byte_count": 11,
        "u16_le": [10, 0, 25700, 3869, 4016],
        "i16_le": [10, 0, 25700, 3869, 4016],
        "u32_le": [10, 253584484],
        "i32_le": [10, 253584484],
    }

    code_27 = p.parse_response(
        p.packet_from_hex("6111 e9570400 27b00f900aa90a000000000000")
    )
    assert code_27["decoded"]["debug_data_code_hex"] == "0x27"
    assert code_27["decoded"]["debug_data_code_category"] == "binary_debug"
    assert code_27["decoded"]["debug_data_code_label"] == "binary_debug_0x27"
    assert code_27["decoded"]["debug_data_tail_words"] == {
        "byte_count": 12,
        "u16_le": [4016, 2704, 2729, 0, 0, 0],
        "i16_le": [4016, 2704, 2729, 0, 0, 0],
        "u32_le": [177213360, 2729, 0],
        "i32_le": [177213360, 2729, 0],
    }


def test_parse_ring_start_event_versions() -> None:
    packet = p.packet_from_hex("4112 95180000 1000000032020b00010001020000")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["event_name"] == "ring_start"
    assert decoded["decoded"]["device_boot_timestamp"] == 6293
    assert decoded["decoded"]["ring_start_marker_u32"] == 16
    assert decoded["decoded"]["ring_start_code_hex"] == "0x32"
    assert decoded["decoded"]["firmware_version"] == "2.11.0"
    assert decoded["decoded"]["bootloader_version"] == "1.0.1"
    assert decoded["decoded"]["api_version"] == "2.0.0"


def test_parse_debug_event_space_delimited_numeric_payload() -> None:
    packet = p.packet_from_hex("430B 9D180000 62632030783433")
    decoded = p.parse_response(packet)
    assert decoded["decoded"]["payload_text"] == "bc 0x43"
    assert decoded["decoded"]["debug_key"] == "bc"
    assert decoded["decoded"]["debug_values"] == ["0x43"]
    assert decoded["decoded"]["debug_numeric_values"] == [0x43]
    assert decoded["decoded"]["debug_category"] == "setup_state"
    assert decoded["decoded"]["debug_label"] == "boot_context"
    assert decoded["decoded"]["debug_fields"] == {"value": "0x43"}


def test_parse_daytime_hr_debug_mode_and_messages() -> None:
    mode = p.parse_response(
        p.packet_from_hex("430e 34400100 4448525f6d6f64653a33")
    )
    assert mode["decoded"]["payload_text"] == "DHR_mode:3"
    assert mode["decoded"]["debug_key"] == "DHR_mode"
    assert mode["decoded"]["debug_values"] == ["3"]
    assert mode["decoded"]["debug_numeric_values"] == [3]
    assert mode["decoded"]["debug_category"] == "daytime_hr"
    assert mode["decoded"]["debug_label"] == "daytime_hr_mode"
    assert mode["decoded"]["debug_fields"] == {"mode": "3"}

    subscribed = p.parse_response(
        p.packet_from_hex("4310 35450100 444852206461746120737562")
    )
    assert subscribed["decoded"]["payload_text"] == "DHR data sub"
    assert subscribed["decoded"]["debug_message"] == "DHR data sub"
    assert subscribed["decoded"]["debug_category"] == "daytime_hr"
    assert subscribed["decoded"]["debug_label"] == "daytime_hr_data_subscription"
    assert subscribed["decoded"]["debug_feature"] == "daytime_hr"
    assert subscribed["decoded"]["debug_action"] == "subscribe"

    unsubscribed = p.parse_response(
        p.packet_from_hex("430d 14470100 44485220756e737562")
    )
    assert unsubscribed["decoded"]["payload_text"] == "DHR unsub"
    assert unsubscribed["decoded"]["debug_action"] == "unsubscribe"


def test_parse_inferred_fuel_gauge_debug_keys() -> None:
    vf_percent = p.parse_response(
        p.packet_from_hex("430c ab7e0100 46475666253b3739")
    )
    assert vf_percent["decoded"]["payload_text"] == "FGVf%;79"
    assert vf_percent["decoded"]["debug_key"] == "FGVf%"
    assert vf_percent["decoded"]["debug_numeric_values"] == [79]
    assert vf_percent["decoded"]["debug_category"] == "fuel_gauge"
    assert vf_percent["decoded"]["debug_label"] == "fuel_gauge_vf_percent_candidate"
    assert vf_percent["decoded"]["debug_fields"] == {"percent": "79"}

    lcu = p.parse_response(
        p.packet_from_hex("4311 ac7e0100 46476c63753b2038313b203739")
    )
    assert lcu["decoded"]["payload_text"] == "FGlcu; 81; 79"
    assert lcu["decoded"]["debug_key"] == "FGlcu"
    assert lcu["decoded"]["debug_numeric_values"] == [81, 79]
    assert lcu["decoded"]["debug_category"] == "fuel_gauge"
    assert lcu["decoded"]["debug_label"] == "fuel_gauge_lcu_candidate"
    assert lcu["decoded"]["debug_fields"] == {"value_a": " 81", "value_b": " 79"}


def test_parse_boot_setup_debug_keys() -> None:
    ccv = p.parse_response(
        p.packet_from_hex("4310 a2180000 4363563b3634363431303336")
    )
    assert ccv["decoded"]["payload_text"] == "CcV;64641036"
    assert ccv["decoded"]["debug_key"] == "CcV"
    assert ccv["decoded"]["debug_category"] == "setup_state"
    assert ccv["decoded"]["debug_label"] == "ccv"
    assert ccv["decoded"]["debug_fields"] == {"value": "64641036"}

    fgdcap = p.parse_response(
        p.packet_from_hex("430d a4180000 4647646361703b3433")
    )
    assert fgdcap["decoded"]["payload_text"] == "FGdcap;43"
    assert fgdcap["decoded"]["debug_key"] == "FGdcap"
    assert fgdcap["decoded"]["debug_category"] == "fuel_gauge"
    assert fgdcap["decoded"]["debug_label"] == "fuel_gauge_design_capacity_candidate"
    assert fgdcap["decoded"]["debug_fields"] == {"capacity": "43"}

    tef = p.parse_response(
        p.packet_from_hex("4311 a5180000 7465663b313130623b30303030")
    )
    assert tef["decoded"]["payload_text"] == "tef;110b;0000"
    assert tef["decoded"]["debug_key"] == "tef"
    assert tef["decoded"]["debug_numeric_values"] == [0]
    assert tef["decoded"]["debug_category"] == "setup_state"
    assert tef["decoded"]["debug_label"] == "tef"
    assert tef["decoded"]["debug_fields"] == {"code": "110b", "status": "0000"}

    bm = p.parse_response(
        p.packet_from_hex("430c a7180000 424d5662493b3530")
    )
    assert bm["decoded"]["payload_text"] == "BMVbI;50"
    assert bm["decoded"]["debug_key"] == "BMVbI"
    assert bm["decoded"]["debug_category"] == "battery"
    assert bm["decoded"]["debug_label"] == "battery_mvbi_candidate"

    mfc = p.parse_response(
        p.packet_from_hex("430d a9180000 4d46433b3530303b34")
    )
    assert mfc["decoded"]["payload_text"] == "MFC;500;4"
    assert mfc["decoded"]["debug_key"] == "MFC"
    assert mfc["decoded"]["debug_category"] == "setup_state"
    assert mfc["decoded"]["debug_label"] == "mfc"

    bls = p.parse_response(p.packet_from_hex("4309 ad180000 424c533b33"))
    assert bls["decoded"]["payload_text"] == "BLS;3"
    assert bls["decoded"]["debug_key"] == "BLS"
    assert bls["decoded"]["debug_category"] == "setup_state"
    assert bls["decoded"]["debug_label"] == "bls"


def test_parse_time_sync_event_payload() -> None:
    decoded = p.parse_response(
        p.packet_from_hex("420d 00010000 00f1536500000000 f6")
    )["decoded"]

    assert decoded["event_name"] == "time_sync"
    assert decoded["device_boot_timestamp"] == 256
    assert decoded["ring_timestamp_ticks"] == 256
    assert decoded["ring_timestamp_ms"] == 25600
    assert decoded["epoch_seconds"] == 1_700_000_000
    assert decoded["utc_ms"] == 1_700_000_000_000
    assert decoded["timezone_30min"] == -10
    assert decoded["timezone_seconds"] == -18_000


def test_parse_structured_temperature_and_wear_events() -> None:
    temps = p.parse_response(
        p.packet_from_hex("460a 10000000 100e470e0f0e")
    )["decoded"]
    wear = p.parse_response(p.packet_from_hex("5307 20000000 024f4b"))["decoded"]

    assert temps["event_name"] == "temp_event"
    assert temps["temperature_c_samples"] == [36.0, 36.55, 35.99]
    assert wear["event_name"] == "wear_event"
    assert wear["wear"] == 2
    assert wear["wear_hex"] == "0x02"
    assert wear["wear_debug"] == "OK"


def test_parse_structured_cardio_and_spo2_events() -> None:
    ppg = p.parse_response(p.packet_from_hex("4a06 01000000 0080"))["decoded"]
    spo2 = p.parse_response(p.packet_from_hex("6f08 02000000 a16263ff"))["decoded"]
    stable = p.parse_response(p.packet_from_hex("7b06 03000000 264d"))["decoded"]

    assert ppg["event_name"] == "ppg_amplitude"
    assert ppg["ppg_amplitude_raw"] == 32768
    assert ppg["ppg_amplitude_ratio"] == pytest.approx(0.500008)
    assert spo2["event_name"] == "spo2_event"
    assert spo2["spo2_base"] == 1280
    assert spo2["spo2_status"] == 1
    assert spo2["spo2_samples"] == [98, 99]
    assert spo2["spo2_terminated"] is True
    assert stable["event_name"] == "spo2_stable_event"
    assert stable["spo2_stable_raw"] == 9805


def test_parse_ibi_and_amplitude_event_payload() -> None:
    decoded = p.parse_response(
        p.packet_from_hex("6012 01000000 0f0e0d0c0b0a12100e0c0a080000")
    )["decoded"]

    assert decoded["event_name"] == "ibi_and_amplitude_event"
    assert decoded["ibi_amplitude_shift"] == 1
    assert decoded["ibi_amplitude_records"] == [
        {"ibi_ms": 80, "amplitude": 8, "bpm_estimate": 750.0},
        {"ibi_ms": 88, "amplitude": 10, "bpm_estimate": 681.8},
        {"ibi_ms": 96, "amplitude": 12, "bpm_estimate": 625.0},
        {"ibi_ms": 104, "amplitude": 14, "bpm_estimate": 576.9},
        {"ibi_ms": 112, "amplitude": 16, "bpm_estimate": 535.7},
        {"ibi_ms": 120, "amplitude": 18, "bpm_estimate": 500.0},
    ]


def test_parse_green_ibi_and_spo2_ibi_events() -> None:
    green = p.parse_response(
        p.packet_from_hex("7112 03000000 0f0e0d0c0b0012100e0c0a000000")
    )["decoded"]
    spo2_ibi = p.parse_response(
        p.packet_from_hex("6e11 02000000 210e0d0c0b0a05060708090a0b")
    )["decoded"]

    assert green["event_name"] == "green_ibi_and_amplitude_event"
    assert green["green_ibi_amplitude_shift"] == 1
    assert green["green_ibi_amplitude_records"] == [
        {"ibi_ms": 0, "amplitude": 18},
        {"ibi_ms": 88, "amplitude": 18, "bpm_estimate": 681.8},
        {"ibi_ms": 96, "amplitude": 16, "bpm_estimate": 625.0},
        {"ibi_ms": 104, "amplitude": 14, "bpm_estimate": 576.9},
        {"ibi_ms": 112, "amplitude": 12, "bpm_estimate": 535.7},
        {"ibi_ms": 120, "amplitude": 10, "bpm_estimate": 500.0},
    ]
    assert spo2_ibi["event_name"] == "spo2_ibi_and_amplitude_event"
    assert spo2_ibi["spo2_ibi_flag"] == 0
    assert spo2_ibi["spo2_ibi_mode"] == 1
    assert spo2_ibi["spo2_ibi_shift"] == 2
    assert spo2_ibi["spo2_ibi_records"] == [
        {"ibi_ms": 80, "bpm_estimate": 750.0},
        {"ibi_ms": 88, "bpm_estimate": 681.8},
        {"ibi_ms": 96, "bpm_estimate": 625.0},
        {"ibi_ms": 104, "bpm_estimate": 576.9},
        {"ibi_ms": 112, "bpm_estimate": 535.7},
    ]
    assert spo2_ibi["spo2_ibi_amplitudes"] == [40, 24, 28, 32, 36, 40, 44]


def test_parse_green_ibi_quality_event_payload() -> None:
    decoded = p.parse_response(p.packet_from_hex("8008 05000000 0a2b1460"))[
        "decoded"
    ]

    assert decoded["event_name"] == "green_ibi_quality_event"
    assert decoded["green_ibi_quality_samples"] == [
        {"ibi_delta": 83, "quality_a": 1, "quality_b": 1},
        {"ibi_delta": 160, "quality_a": 0, "quality_b": 3},
    ]


def test_parse_measurement_quality_i24_samples() -> None:
    decoded = p.parse_response(
        p.packet_from_hex("6d11 04000000 00010000ffffff000080ffff7f")
    )["decoded"]

    assert decoded["event_name"] == "meas_quality_event"
    assert decoded["measurement_quality_type"] == 0
    assert decoded["measurement_quality_samples"] == [1, -1, -8388608, 8388607]


def test_rejects_truncated_packet() -> None:
    with pytest.raises(p.ProtocolError):
        p.parse_packets(bytes.fromhex("0d06 64"))
