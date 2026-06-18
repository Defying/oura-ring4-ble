from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from oura_ring4_ble import protocol as p


def install_dbus_stubs() -> None:
    dbus = ModuleType("dbus")
    dbus.Array = list
    dbus.Dictionary = dict
    dbus.Byte = int
    dbus.String = str
    dbus.UInt32 = int
    dbus.SystemBus = object
    dbus.Interface = lambda obj, _interface=None: obj
    dbus_service = ModuleType("dbus.service")

    class ServiceObject:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

    def method(*_args: object, **_kwargs: object):
        def decorator(func: object) -> object:
            return func

        return decorator

    dbus_service.Object = ServiceObject
    dbus_service.method = method
    dbus.service = dbus_service

    dbus_mainloop = ModuleType("dbus.mainloop")
    dbus_glib = ModuleType("dbus.mainloop.glib")
    dbus_glib.DBusGMainLoop = lambda set_as_default=False: None

    gi = ModuleType("gi")
    gi_repository = ModuleType("gi.repository")
    gi_repository.GLib = SimpleNamespace()

    sys.modules.setdefault("dbus", dbus)
    sys.modules.setdefault("dbus.service", dbus_service)
    sys.modules.setdefault("dbus.mainloop", dbus_mainloop)
    sys.modules.setdefault("dbus.mainloop.glib", dbus_glib)
    sys.modules.setdefault("gi", gi)
    sys.modules.setdefault("gi.repository", gi_repository)


def load_stream_module() -> ModuleType:
    install_dbus_stubs()
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-bluez-zeroauth-stream.py"
    spec = importlib.util.spec_from_file_location("pi_bluez_zeroauth_stream", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


stream = load_stream_module()


def decoded_packet(raw_hex: str, product_info_type: str | None = None) -> dict[str, object]:
    packet = p.packet_from_hex(raw_hex)
    return p.parse_response(packet, product_info_type=product_info_type)


def test_parse_probe_names_accepts_focused_capability_probe() -> None:
    assert stream.parse_probe_names(
        "firmware,capabilities:0x02,product_info_hex:000010,"
        "product_info_hex_stable,product_info_hex_range:0x40:0x50:0x10,"
        "events:0:4,events_range:6306:6700:194:24,"
        "events_walk:0x1bf4:3:64,feature_status:0x16,"
        "feature_mode:0x02:connected_live,"
        "feature_subscription:0x02:latest,daytime_hr_latest,"
        "live_hr_probe,ring_mode:fast_heart_rate,ring_mode_normal,"
        "setup_snapshot,factory_reset"
    ) == [
        "firmware",
        "capabilities:0x02",
        "product_info_hex:000010",
        "product_info_hex_stable",
        "product_info_hex_range:0x40:0x50:0x10",
        "events:0:4",
        "events_range:6306:6700:194:24",
        "events_walk:0x1bf4:3:64",
        "feature_status:0x16",
        "feature_mode:0x02:connected_live",
        "feature_subscription:0x02:latest",
        "daytime_hr_latest",
        "live_hr_probe",
        "ring_mode:fast_heart_rate",
        "ring_mode_normal",
        "setup_snapshot",
        "factory_reset",
    ]


def test_build_probe_packets_supports_extra_read_only_probes() -> None:
    assert stream.build_probe_packets("feature_status:0x16") == [
        ("feature_status:0x16", bytes.fromhex("2f022016"))
    ]
    assert stream.build_probe_packets("feature_mode:0x02:connected_live") == [
        ("feature_mode:0x02:connected_live", bytes.fromhex("2f03220203"))
    ]
    assert stream.build_probe_packets("feature_mode:0x02:requested_subscription") == [
        ("feature_mode:0x02:connected_live", bytes.fromhex("2f03220203"))
    ]
    assert stream.build_probe_packets("feature_subscription:0x02:latest") == [
        ("feature_subscription:0x02:latest", bytes.fromhex("2f03260202"))
    ]
    assert stream.build_probe_packets("daytime_hr_latest") == [
        ("feature_status:0x02", bytes.fromhex("2f022002")),
        ("feature_mode:0x02:connected_live", bytes.fromhex("2f03220203")),
        ("feature_subscription:0x02:latest", bytes.fromhex("2f03260202")),
        ("feature_status:0x02", bytes.fromhex("2f022002")),
    ]
    assert stream.build_probe_packets("live_hr_probe") == [
        ("battery", bytes.fromhex("0c00")),
        ("feature_status:0x02", bytes.fromhex("2f022002")),
        ("feature_status:0x08", bytes.fromhex("2f022008")),
        ("ring_mode:fast_heart_rate", bytes.fromhex("310401000000")),
        ("feature_status:0x02", bytes.fromhex("2f022002")),
        ("feature_mode:0x02:connected_live", bytes.fromhex("2f03220203")),
        ("feature_subscription:0x02:latest", bytes.fromhex("2f03260202")),
        ("feature_status:0x02", bytes.fromhex("2f022002")),
        ("feature_status:0x08", bytes.fromhex("2f022008")),
        ("feature_mode:0x08:connected_live", bytes.fromhex("2f03220803")),
        ("feature_subscription:0x08:latest", bytes.fromhex("2f03260802")),
        ("feature_status:0x08", bytes.fromhex("2f022008")),
        ("feature_status:0x02", bytes.fromhex("2f022002")),
        ("feature_status:0x08", bytes.fromhex("2f022008")),
    ]
    assert stream.build_probe_packets("ring_mode:fast_heart_rate") == [
        ("ring_mode:fast_heart_rate", bytes.fromhex("310401000000"))
    ]
    assert stream.build_probe_packets("ring_mode_normal") == [
        ("ring_mode:normal", bytes.fromhex("310400000000"))
    ]
    assert stream.build_probe_packets("product_info_hex:000010") == [
        ("product_info_hex:000010", bytes.fromhex("1803000010"))
    ]
    assert stream.build_probe_packets("product_info_hex_range:0x40:0x50:0x10") == [
        ("product_info_hex:400010", bytes.fromhex("1803400010")),
        ("product_info_hex:440010", bytes.fromhex("1803440010")),
        ("product_info_hex:480010", bytes.fromhex("1803480010")),
        ("product_info_hex:4c0010", bytes.fromhex("18034c0010")),
    ]
    assert stream.build_probe_packets("events:0:4") == [
        ("events:0x00000000:4", bytes.fromhex("10090000000004ffffffff"))
    ]
    assert stream.build_probe_packets("events_range:6306:6700:194:24") == [
        ("events:0x000018a2:24", bytes.fromhex("1009a218000018ffffffff")),
        ("events:0x00001964:24", bytes.fromhex("10096419000018ffffffff")),
        ("events:0x00001a26:24", bytes.fromhex("1009261a000018ffffffff")),
    ]
    assert stream.build_probe_packets("factory_reset") == [
        ("factory_reset", bytes.fromhex("1a00"))
    ]
    assert stream.parse_events_walk_probe("events_walk:0x1bf4:3:64") == (
        0x1BF4,
        3,
        64,
    )
    setup_packets = stream.build_probe_packets("setup_snapshot")
    assert ("firmware", bytes.fromhex("0800")) in setup_packets
    assert ("battery", bytes.fromhex("0c00")) in setup_packets
    assert ("auth_nonce", bytes.fromhex("2f012b")) in setup_packets
    assert ("feature_status:0x02", bytes.fromhex("2f022002")) in setup_packets
    assert ("product_info:serial_number", bytes.fromhex("1803080010")) in setup_packets
    assert (
        "events:0x00000000:24",
        bytes.fromhex("10090000000018ffffffff"),
    ) in setup_packets
    assert all(not name.startswith("feature_mode:") for name, _packet in setup_packets)
    assert all(
        not name.startswith("feature_subscription:")
        for name, _packet in setup_packets
    )
    assert all(not name.startswith("ring_mode:") for name, _packet in setup_packets)
    assert all(name != "factory_reset" for name, _packet in setup_packets)


def test_build_probe_packets_supports_scan_groups() -> None:
    product_info_packets = stream.build_probe_packets("product_info_hex_scan")
    stable_product_info_packets = stream.build_probe_packets("product_info_hex_stable")
    feature_status_packets = stream.build_probe_packets("feature_status_observed")
    capability_tail_packets = stream.build_probe_packets("capabilities_tail")

    assert ("product_info_hex:000010", bytes.fromhex("1803000010")) in product_info_packets
    assert ("product_info_hex:280010", bytes.fromhex("1803280010")) in product_info_packets
    assert all(name != "product_info_hex:080010" for name, _packet in product_info_packets)
    assert stable_product_info_packets == [
        ("product_info_hex:000010", bytes.fromhex("1803000010")),
        ("product_info_hex:0c0010", bytes.fromhex("18030c0010")),
        ("product_info_hex:100010", bytes.fromhex("1803100010")),
        ("product_info_hex:1c0010", bytes.fromhex("18031c0010")),
        ("product_info_hex:200010", bytes.fromhex("1803200010")),
        ("product_info_hex:240010", bytes.fromhex("1803240010")),
    ]
    assert ("feature_status:0x16", bytes.fromhex("2f022016")) in feature_status_packets
    assert ("feature_status:0x02", bytes.fromhex("2f022002")) in feature_status_packets
    assert capability_tail_packets[0] == ("capabilities:0x02", bytes.fromhex("2f020102"))
    assert capability_tail_packets[-1] == ("capabilities:0x0f", bytes.fromhex("2f02010f"))


def test_build_setup_state_promotes_observed_setup_debug_rows() -> None:
    setup_state = stream.build_setup_state(
        {
            "in_bed": {
                "category": "setup_state",
                "numeric_values": [0],
                "device_boot_timestamp": 6299,
            },
            "i_info": {
                "category": "setup_state",
                "numeric_values": [6],
                "device_boot_timestamp": 6300,
            },
            "bc": {
                "category": "setup_state",
                "numeric_values": [0x43],
                "device_boot_timestamp": 6301,
            },
            "pf": {
                "category": "setup_state",
                "numeric_values": [0x07],
                "device_boot_timestamp": 6302,
            },
            "EFLO": {
                "category": "setup_state",
                "numeric_values": [0],
                "device_boot_timestamp": 6303,
            },
            "CcM": {
                "category": "setup_state",
                "numeric_values": [1],
                "device_boot_timestamp": 6304,
            },
            "CcP": {
                "category": "setup_state",
                "values": ["1", "NA"],
                "numeric_values": [1],
                "device_boot_timestamp": 6305,
            },
            "blestda": {
                "category": "ble_setup",
                "numeric_values": [50],
                "device_boot_timestamp": 6260,
            },
            "BLS": {
                "category": "setup_state",
                "numeric_values": [3],
                "device_boot_timestamp": 6317,
            },
            "CcV": {
                "category": "setup_state",
                "numeric_values": [64641036],
                "device_boot_timestamp": 6306,
            },
            "MFC": {
                "category": "setup_state",
                "values": ["500", "4"],
                "device_boot_timestamp": 6313,
            },
            "tef": {
                "category": "setup_state",
                "values": ["110b", "0000"],
                "device_boot_timestamp": 6309,
            },
            "git": {
                "category": "identity",
                "values": ["29df664"],
                "device_boot_timestamp": 6294,
            },
        },
        transition="Sw to App",
    )

    assert setup_state == {
        "latest_boot_timestamp": 6317,
        "transition": "Sw to App",
        "in_bed_flag": 0,
        "info_state": 6,
        "boot_context": 0x43,
        "platform_flags": 0x07,
        "eflo_flag": 0,
        "bls_state": 3,
        "ccm": 1,
        "ccv_value": 64641036,
        "ble_setup_state_a": 50,
        "ccp_value": "1",
        "ccp_status": "NA",
        "mfc_value": "500",
        "mfc_status": "4",
        "tef_code": "110b",
        "tef_status": "0000",
        "source_keys": [
            "BLS",
            "CcM",
            "CcP",
            "CcV",
            "EFLO",
            "MFC",
            "bc",
            "blestda",
            "i_info",
            "in_bed",
            "pf",
            "tef",
        ],
    }


def test_build_health_debug_state_from_daytime_hr_rows() -> None:
    assert stream.build_health_debug_state(
        {
            "DHR_mode": {
                "category": "daytime_hr",
                "numeric_values": [3],
                "device_boot_timestamp": 83243,
            }
        }
    ) == {
        "latest_boot_timestamp": 83243,
        "daytime_hr_mode": 3,
        "source_keys": ["DHR_mode"],
    }


def test_build_read_result_promotes_debug_battery_snapshot() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    events = stream.get_probe_result(
        probe_results, "events:0x00003537:2", "10093735000002ffffffff"
    )
    events["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00003537:2", "tx_hex": "10093735000002ffffffff"},
        "61093735000024647a0f00",
        {"packets": [decoded_packet("61093735000024647a0f00")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00003537:2", "tx_hex": "10093735000002ffffffff"},
        "61094435000024647a0f02",
        {"packets": [decoded_packet("61094435000024647a0f02")]},
    )

    result = stream.build_read_result(
        probe_results,
        notification_count=3,
        subscribed_count=1,
    )

    assert result["device_snapshot"]["battery_debug"] == {
        "battery_level_percent": 100,
        "voltage_mv": 3962,
        "status": 2,
        "status_hex": "0x02",
        "device_boot_timestamp": 13636,
        "min_voltage_mv": 3962,
        "max_voltage_mv": 3962,
        "min_battery_level_percent": 100,
        "max_battery_level_percent": 100,
        "sample_count": 2,
    }
    assert result["event_summary"]["debug_data_codes"] == {"0x24": 2}
    assert result["event_summary"]["debug_categories"] == {"battery": 2}


def test_build_read_result_promotes_power_debug_candidate_snapshot() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    events = stream.get_probe_result(
        probe_results, "events:0x0000ebde:2", "1009deeb000002ffffffff"
    )
    events["tx_count"] += 1
    for raw_hex in (
        "6112deeb000014f963840ffbffffff2d3c0000f3",
        "61122d35000014f963a00ff3ffffff2d3c0000f5",
    ):
        stream.record_probe_response(
            probe_results,
            {"packet": "events:0x0000ebde:2", "tx_hex": "1009deeb000002ffffffff"},
            raw_hex,
            {"packets": [decoded_packet(raw_hex)]},
        )

    result = stream.build_read_result(
        probe_results,
        notification_count=2,
        subscribed_count=1,
    )

    assert result["device_snapshot"]["power_debug_candidate"] == {
        "source": "debug_data_code_0x14",
        "inferred": True,
        "raw0_u16": 25593,
        "voltage_mv_candidate": 3972,
        "signed2_i16": -5,
        "signed3_i16": -1,
        "raw4_u16": 15405,
        "raw5_u16": 0,
        "status_byte_candidate": 243,
        "status_hex_candidate": "0xF3",
        "device_boot_timestamp": 60382,
        "min_voltage_mv_candidate": 3972,
        "max_voltage_mv_candidate": 4000,
        "min_signed2_i16": -13,
        "max_signed2_i16": -5,
        "sample_count": 2,
    }
    assert result["event_summary"]["debug_data_codes"] == {"0x14": 2}
    assert result["event_summary"]["debug_categories"] == {"binary_debug": 2}


def test_build_read_result_promotes_new_charger_state_keys() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    events = stream.get_probe_result(
        probe_results, "events:0x0000bb10:3", "100910bb000003ffffffff"
    )
    events["tx_count"] += 1
    for raw_hex in (
        "430e0cbc00007263656c6c3b30623534",
        "4312fdbb000043686753743b3030303030383162",
        "430c8fbc00006368675f62633b33",
        "610f90bc0000046272783b6c3b34393b31",
    ):
        stream.record_probe_response(
            probe_results,
            {"packet": "events:0x0000bb10:3", "tx_hex": "100910bb000003ffffffff"},
            raw_hex,
            {"packets": [decoded_packet(raw_hex)]},
        )

    result = stream.build_read_result(
        probe_results,
        notification_count=4,
        subscribed_count=1,
    )

    assert result["device_snapshot"]["charger_debug"]["ChgSt"]["values"] == [
        "0000081b"
    ]
    assert result["device_snapshot"]["charger_debug"]["rcell"]["values"] == ["0b54"]
    assert result["device_snapshot"]["charger_debug"]["chg_bc"]["values"] == ["3"]
    assert result["device_snapshot"]["charger_debug"]["brx"]["values"] == [
        "l",
        "49",
        "1",
    ]
    assert result["device_snapshot"]["charger_state"] == {
        "latest_boot_timestamp": 48272,
        "bc_state": 3,
        "brx_state": "l",
        "brx_raw": 49,
        "brx_flag": 1,
        "charger_status_hex": "0x0000081b",
        "charger_status_value": 2075,
        "charger_status_bits": [0, 1, 3, 4, 11],
        "rcell_hex": "0x0b54",
        "rcell_raw": 2900,
        "source_keys": ["ChgSt", "brx", "chg_bc", "rcell"],
    }
    assert result["event_summary"]["charger_activity"] == {
        "event_count": 4,
        "key_counts": {"ChgSt": 1, "brx": 1, "chg_bc": 1, "rcell": 1},
        "first_boot_timestamp": 48125,
        "last_boot_timestamp": 48272,
        "span_seconds": 147,
        "brx_state_counts": {"l": 1},
        "brx_raw_latest": 49,
        "brx_raw_min": 49,
        "brx_raw_max": 49,
        "brx_flag_counts": {"1": 1},
        "charger_status_counts": {"0x0000081b": 1},
        "bc_state_counts": {"3": 1},
        "rcell_raw_latest": 2900,
        "rcell_raw_min": 2900,
        "rcell_raw_max": 2900,
    }


def test_build_read_result_promotes_fuel_gauge_debug_state() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    events = stream.get_probe_result(
        probe_results, "events:0x00017eab:2", "1009ab7e010002ffffffff"
    )
    events["tx_count"] += 1
    for raw_hex in (
        "430cab7e010046475666253b3739",
        "4311ac7e010046476c63753b2038313b203739",
        "430da41800004647646361703b3433",
    ):
        stream.record_probe_response(
            probe_results,
            {"packet": "events:0x00017eab:2", "tx_hex": "1009ab7e010002ffffffff"},
            raw_hex,
            {"packets": [decoded_packet(raw_hex)]},
        )

    result = stream.build_read_result(
        probe_results,
        notification_count=2,
        subscribed_count=1,
    )

    assert result["device_snapshot"]["fuel_gauge_debug"]["FGVf%"]["fields"] == {
        "percent": "79"
    }
    assert result["device_snapshot"]["fuel_gauge_debug"]["FGlcu"]["fields"] == {
        "value_a": " 81",
        "value_b": " 79",
    }
    assert result["device_snapshot"]["fuel_gauge_debug"]["FGdcap"]["fields"] == {
        "capacity": "43"
    }
    assert result["device_snapshot"]["fuel_gauge_state"] == {
        "latest_boot_timestamp": 97964,
        "vf_percent_candidate": 79,
        "lcu_value_a_candidate": 81,
        "lcu_value_b_candidate": 79,
        "design_capacity_candidate": 43,
        "source_keys": ["FGVf%", "FGdcap", "FGlcu"],
    }
    assert result["event_summary"]["debug_categories"] == {"fuel_gauge": 3}
    assert result["event_summary"]["debug_labels"] == {
        "fuel_gauge_design_capacity_candidate": 1,
        "fuel_gauge_lcu_candidate": 1,
        "fuel_gauge_vf_percent_candidate": 1,
    }


def test_find_device_strict_address_rejects_stale_oura_candidate() -> None:
    objects = {
        "/org/bluez/hci0/dev_76_02_35_A5_F7_1D": {
            stream.DEVICE: {
                "Address": "76:11:22:33:44:55",
                "Name": "Oura TEST_SERIAL_0000",
                "UUIDs": [p.OURA_SERVICE_UUID],
                "Connected": False,
                "ServicesResolved": False,
            }
        }
    }

    try:
        stream.find_device(
            objects,
            "7A:11:22:33:44:55",
            "",
            strict_address=True,
        )
    except RuntimeError as exc:
        assert "no exact BlueZ Device1 object" in str(exc)
        assert "76:11:22:33:44:55" in str(exc)
    else:
        raise AssertionError("strict address should reject non-matching Oura objects")


def test_find_device_non_strict_can_fall_back_to_oura_candidate() -> None:
    objects = {
        "/org/bluez/hci0/dev_76_02_35_A5_F7_1D": {
            stream.DEVICE: {
                "Address": "76:11:22:33:44:55",
                "Name": "Oura TEST_SERIAL_0000",
                "UUIDs": [p.OURA_SERVICE_UUID],
                "Connected": False,
            }
        }
    }

    path, props = stream.find_device(
        objects,
        "7A:11:22:33:44:55",
        "",
        strict_address=False,
    )

    assert path == "/org/bluez/hci0/dev_76_02_35_A5_F7_1D"
    assert props["Address"] == "76:11:22:33:44:55"


def test_build_read_result_aggregates_zeroauth_probe_data() -> None:
    probe_results: dict[str, dict[str, object]] = {}

    firmware = stream.get_probe_result(probe_results, "firmware", "0800")
    firmware["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "firmware", "tx_hex": "0800"},
        "0912020000020b0001000105000f3147b1f838a0",
        {
            "packets": [
                decoded_packet("0912020000020b0001000105000f3147b1f838a0")
            ]
        },
    )

    product_info = stream.get_probe_result(
        probe_results, "product_info:serial_number", "1803080010"
    )
    product_info["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "product_info:serial_number", "tx_hex": "1803080010"},
        "191100544553545f53455249414c5f30303030",
        {
            "packets": [
                decoded_packet(
                    "191100544553545f53455249414c5f30303030",
                    product_info_type="serial_number",
                )
            ]
        },
    )

    battery = stream.get_probe_result(probe_results, "battery", "0c00")
    battery["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "battery", "tx_hex": "0c00"},
        "2f022f01",
        {"packets": [decoded_packet("2f022f01")]},
    )

    product_info_unknown = stream.get_probe_result(
        probe_results, "product_info_hex:000010", "1803000010"
    )
    product_info_unknown["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "product_info_hex:000010", "tx_hex": "1803000010"},
        "19050001020304",
        {
            "packets": [
                decoded_packet(
                    "19050001020304",
                    product_info_type=bytes.fromhex("000010"),
                )
            ]
        },
    )

    events = stream.get_probe_result(
        probe_results, "events:0x00000000:1", "10090000000001ffffffff"
    )
    events["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00000000:1", "tx_hex": "10090000000001ffffffff"},
        "6110b0e8a9001a18002500000000000000f7",
        {"packets": [decoded_packet("6110b0e8a9001a18002500000000000000f7")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00000000:1", "tx_hex": "10090000000001ffffffff"},
        "4112951800001000000032020b00010001020000",
        {"packets": [decoded_packet("4112951800001000000032020b00010001020000")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00000000:1", "tx_hex": "10090000000001ffffffff"},
        "4112951800001000000032020b00010001020000",
        {"packets": [decoded_packet("4112951800001000000032020b00010001020000")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00000000:1", "tx_hex": "10090000000001ffffffff"},
        "430f961800006769743b32396466363634",
        {"packets": [decoded_packet("430f961800006769743b32396466363634")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00000000:1", "tx_hex": "10090000000001ffffffff"},
        "1106010000000000",
        {"packets": [decoded_packet("1106010000000000")]},
    )
    stream.record_probe_response(
        probe_results,
        {},
        "2f022f01",
        {"packets": [decoded_packet("2f022f01")]},
    )
    stream.record_probe_response(
        probe_results,
        {},
        "430e371800006368675f72633b313b31",
        {"packets": [decoded_packet("430e371800006368675f72633b313b31")]},
    )
    stream.record_probe_response(
        probe_results,
        {},
        "1106010000000000",
        {"packets": [decoded_packet("1106010000000000")]},
    )
    feature_status = stream.get_probe_result(
        probe_results, "feature_status:0x02", "2f022002"
    )
    feature_status["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "feature_status:0x02", "tx_hex": "2f022002"},
        "2f06210201000000",
        {"packets": [decoded_packet("2f06210201000000")]},
    )
    resting_hr_status = stream.get_probe_result(
        probe_results, "feature_status:0x08", "2f022008"
    )
    resting_hr_status["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "feature_status:0x08", "tx_hex": "2f022008"},
        "2f06210801020201",
        {"packets": [decoded_packet("2f06210801020201")]},
    )
    feature_subscription = stream.get_probe_result(
        probe_results, "feature_subscription:0x02:latest", "2f03260202"
    )
    feature_subscription["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "feature_subscription:0x02:latest", "tx_hex": "2f03260202"},
        "2f03270200",
        {"packets": [decoded_packet("2f03270200")]},
    )
    ring_mode = stream.get_probe_result(
        probe_results, "ring_mode:normal", "310400000000"
    )
    ring_mode["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "ring_mode:normal", "tx_hex": "310400000000"},
        "32020000",
        {"packets": [decoded_packet("32020000")]},
    )

    result = stream.build_read_result(
        probe_results,
        notification_count=7,
        subscribed_count=5,
    )

    assert result["notification_count"] == 7
    assert result["subscribed_count"] == 5
    assert result["firmware"]["firmware_version"] == "2.11.0"
    assert result["firmware"]["bluetooth_stack_version"] == "5.0.15"
    assert result["product_info"]["serial_number"] == "TEST_SERIAL_0000"
    assert result["product_info"]["product_info:000010"] == "01020304"
    assert result["product_info_memory"]["byte_count"] == 20
    assert result["product_info_memory"]["segments"][0]["start"] == "0x0000"
    assert result["product_info_memory"]["segments"][1]["start"] == "0x0008"
    assert [row["event_name"] for row in result["events"]] == [
        "debug_data",
        "ring_start",
        "ring_start",
        "debug_event",
        "debug_event",
    ]
    assert result["events"][1]["firmware_version"] == "2.11.0"
    assert result["event_summary"]["count"] == 5
    assert result["event_summary"]["unique_count"] == 4
    assert result["event_summary"]["duplicate_count"] == 1
    assert result["event_summary"]["first_boot_timestamp"] == 6199
    assert result["event_summary"]["last_boot_timestamp"] == 11135152
    assert result["event_summary"]["next_start_timestamp"] == 11135153
    assert result["event_summary"]["event_names"] == {
        "debug_data": 1,
        "debug_event": 2,
        "ring_start": 1,
    }
    assert result["event_summary"]["debug_keys"] == {"chg_rc": 1, "git": 1}
    assert result["event_summary"]["debug_categories"] == {
        "charger": 1,
        "identity": 1,
    }
    assert result["event_summary"]["debug_labels"] == {
        "charge_rc": 1,
        "firmware_git": 1,
    }
    assert result["event_summary"]["debug_data_codes"] == {"0x1A": 1}
    assert result["event_summary"]["debug_value_stats"]["chg_rc"] == {
        "count": 1,
        "latest_values": ["1", "1"],
        "latest_boot_timestamp": 6199,
        "latest_numeric_values": [1, 1],
        "min_numeric_values": [1, 1],
        "max_numeric_values": [1, 1],
    }
    assert result["event_summary"]["debug_value_stats"]["git"] == {
        "count": 1,
        "latest_values": ["29df664"],
        "latest_boot_timestamp": 6294,
    }
    assert result["event_summary"]["complete"] is False
    assert result["device_snapshot"]["serial_number"] == "TEST_SERIAL_0000"
    assert result["device_snapshot"]["firmware_version"] == "2.11.0"
    assert result["device_snapshot"]["firmware_git"] == "29df664"
    assert result["device_snapshot"]["ring_start"]["ring_start_code_hex"] == "0x32"
    assert result["device_snapshot"]["charger_debug"]["chg_rc"]["category"] == "charger"
    assert result["device_snapshot"]["charger_debug"]["chg_rc"]["label"] == "charge_rc"
    assert result["device_snapshot"]["charger_debug"]["chg_rc"]["fields"] == {
        "state": "1",
        "flag": "1",
    }
    assert result["device_snapshot"]["charger_state"] == {
        "latest_boot_timestamp": 6199,
        "rc_state": 1,
        "rc_flag": 1,
        "source_keys": ["chg_rc"],
    }
    assert (
        result["device_snapshot"]["health_features"]["daytime_hr"]
        == "automatic/off/idle/off"
    )
    assert result["events_done"] == [
        {
            "request_start_timestamp": 0,
            "request_start_hex": "0x00000000",
            "request_max_events": 1,
            "events_received": 1,
            "sleep_analysis_progress": 0,
            "bytes_left": 0,
        },
        {
            "events_received": 1,
            "sleep_analysis_progress": 0,
            "bytes_left": 0,
        },
    ]
    assert result["feature_status"]["feature_status:0x02"]["feature_name"] == "daytime_hr"
    assert result["feature_status"]["feature_status:0x02"]["mode_name"] == "automatic"
    assert result["feature_summary"]["count"] == 2
    assert result["feature_summary"]["modes"] == {"automatic": 2}
    assert result["feature_summary"]["statuses"] == {"off": 1, "searching": 1}
    assert result["feature_summary"]["states"] == {"idle": 1, "measuring": 1}
    assert result["feature_summary"]["subscriptions"] == {"off": 1, "state": 1}
    assert result["feature_summary"]["health_features"] == {
        "daytime_hr": "automatic/off/idle/off",
        "resting_hr": "automatic/searching/measuring/state",
    }
    assert result["feature_summary"]["active_features"] == ["resting_hr"]
    assert result["feature_set_results"][0]["packet"] == "feature_subscription:0x02:latest"
    assert result["feature_set_results"][0]["result_name"] == "success"
    assert result["ring_mode_results"] == [
        {
            "packet": "ring_mode:normal",
            "response_name": "set_ring_mode_status",
            "status": 0,
            "status_name": "ok",
        }
    ]
    assert result["battery"] is None
    assert (
        result["unattributed_notifications"][0]["extended_name"]
        == "auth_status_response"
    )
    assert result["auth_gated"] == ["battery"]
    assert {row["packet"]: row["classification"] for row in result["probes"]} == {
        "battery": "auth_gated",
        "events:0x00000000:1": "open_response",
        "feature_subscription:0x02:latest": "open_response",
        "feature_status:0x02": "open_response",
        "feature_status:0x08": "open_response",
        "firmware": "open_response",
        "product_info_hex:000010": "open_response",
        "product_info:serial_number": "open_response",
        "ring_mode:normal": "open_response",
        "unattributed_notification": "unattributed_auth_status",
    }


def test_event_probe_progress_tracks_next_cursor_and_completion() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    events = stream.get_probe_result(
        probe_results, "events:0x00001a23:64", "1009231a000040ffffffff"
    )
    events["tx_count"] += 1
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00001a23:64", "tx_hex": "1009231a000040ffffffff"},
        "43112d1a00006368675f696e643b3130303b31",
        {"packets": [decoded_packet("43112d1a00006368675f696e643b3130303b31")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00001a23:64", "tx_hex": "1009231a000040ffffffff"},
        "61123f1a0000046368675f72703b313b36383436",
        {"packets": [decoded_packet("61123f1a0000046368675f72703b313b36383436")]},
    )
    stream.record_probe_response(
        probe_results,
        {"packet": "events:0x00001a23:64", "tx_hex": "1009231a000040ffffffff"},
        "11084000f04803000300",
        {"packets": [decoded_packet("11084000f04803000300")]},
    )

    progress = stream.event_probe_progress(events)

    assert progress["event_count"] == 2
    assert progress["first_boot_timestamp"] == 6701
    assert progress["last_boot_timestamp"] == 6719
    assert progress["next_start_timestamp"] == 6720
    assert progress["next_start_hex"] == "0x00001a40"
    assert progress["events_received"] == 64
    assert progress["bytes_left"] == 215280
    assert progress["complete"] is False


def test_event_summary_builds_charger_activity() -> None:
    events = [
        decoded_packet("4311264800006368675f696e643b3130303b31")["decoded"],
        decoded_packet("6112284a0000046368675f72703b313b36313436")["decoded"],
        decoded_packet("61123e5f000014fc63980ffaffffff2d3c0000f4")["decoded"],
        decoded_packet("430e205400006368675f72633b313b31")["decoded"],
        decoded_packet("43120c540000636867763b363833323b34383836")["decoded"],
        decoded_packet("430f0d5400006368675f68733b35353732")["decoded"],
        decoded_packet("61121f540000046368675f72703b31303b363133")["decoded"],
        decoded_packet("430e0c7400006368675f72633b303b31")["decoded"],
    ]

    summary = stream.build_event_summary({"events": events})

    assert summary["charger_activity"] == {
        "event_count": 7,
        "key_counts": {
            "chg_hs": 1,
            "chg_ind": 1,
            "chg_rc": 2,
            "chg_rp": 2,
            "chgv": 1,
        },
        "first_boot_timestamp": 18470,
        "last_boot_timestamp": 29708,
        "span_seconds": 11238,
        "indicator_percent_latest": 100,
        "indicator_percent_min": 100,
        "indicator_percent_max": 100,
        "indicator_flag_counts": {"1": 1},
        "rp_state_counts": {"1": 1, "10": 1},
        "rp_raw_latest": 613,
        "rp_raw_min": 613,
        "rp_raw_max": 6146,
        "rc_state_counts": {"0": 1, "1": 1},
        "rc_flag_counts": {"1": 2},
        "chgv_raw_a_latest": 6832,
        "chgv_raw_a_min": 6832,
        "chgv_raw_a_max": 6832,
        "chgv_raw_b_latest": 4886,
        "chgv_raw_b_min": 4886,
        "chgv_raw_b_max": 4886,
        "hs_raw_latest": 5572,
        "hs_raw_min": 5572,
        "hs_raw_max": 5572,
    }


def test_event_summary_builds_health_events() -> None:
    events = [
        decoded_packet("6012 01000000 0f0e0d0c0b0a12100e0c0a080000")["decoded"],
        decoded_packet("6f08 02000000 a16263ff")["decoded"],
        decoded_packet("460a 10000000 100e470e0f0e")["decoded"],
        decoded_packet("8008 05000000 0a2b1460")["decoded"],
    ]

    summary = stream.build_event_summary({"events": events})

    assert summary["health_events"] == {
        "event_counts": {
            "green_ibi_quality_event": 1,
            "ibi_and_amplitude_event": 1,
            "spo2_event": 1,
            "temp_event": 1,
        },
        "ibi_record_count": 6,
        "ibi_ms_min": 80,
        "ibi_ms_max": 120,
        "ibi_ms_latest": 120,
        "bpm_estimate_min": 500.0,
        "bpm_estimate_max": 750.0,
        "bpm_estimate_latest": 500.0,
        "green_ibi_quality_sample_count": 2,
        "spo2_sample_count": 2,
        "spo2_value_min": 98,
        "spo2_value_max": 99,
        "spo2_value_latest": 99,
        "temperature_sample_count": 3,
        "temperature_c_min": 35.99,
        "temperature_c_max": 36.55,
        "temperature_c_latest": 35.99,
    }


def test_build_read_result_promotes_unattributed_factory_reset_ack() -> None:
    probe_results: dict[str, dict[str, object]] = {}
    stream.record_probe_response(
        probe_results,
        {},
        "1b0100",
        {"packets": [decoded_packet("1b0100")]},
    )

    result = stream.build_read_result(
        probe_results,
        notification_count=1,
        subscribed_count=1,
    )

    assert result["factory_reset"] == {
        "response_name": "factory_reset_status",
        "status": 0,
        "status_name": "ok",
    }


def test_stops_probe_run_after_disconnect_like_write_error(monkeypatch) -> None:
    class FailingWrite:
        def WriteValue(self, _value: object, _options: object) -> None:
            raise RuntimeError("org.bluez.Error.Failed: Not connected")

    class Bus:
        def get_object(self, _service: str, _path: str) -> FailingWrite:
            return FailingWrite()

    events: list[str] = []
    probe_results: dict[str, dict[str, object]] = {}
    active_probe: dict[str, str] = {}
    monkeypatch.setattr(stream.dbus, "Array", lambda values, signature=None: list(values))
    monkeypatch.setattr(
        stream.dbus,
        "Dictionary",
        lambda values, signature=None: dict(values),
    )

    stream.run_probes(
        bus=Bus(),
        objects={
            "/dev/service/char0015": {
                stream.CHAR: {"UUID": p.OURA_WRITE_UUID}
            }
        },
        device_path="/dev",
        probes=["firmware", "auth_nonce"],
        delay_seconds=0.0,
        response_timeout_seconds=0.0,
        active_probe=active_probe,
        probe_results=probe_results,
        emit=lambda event, _payload: events.append(event),
    )

    assert events == ["zeroauth_probe_tx", "zeroauth_probe_error", "zeroauth_probe_stop"]
    assert set(probe_results) == {"firmware|0800"}
