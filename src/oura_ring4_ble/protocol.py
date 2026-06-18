"""Packet framing and decoders for the observed Oura Ring 4 BLE protocol."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

OURA_SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
OURA_WRITE_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
OURA_NOTIFY_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"
OURA_COMPANY_ID = 0x02B2

WRITE_HANDLE = 0x0015
NOTIFY_HANDLE = 0x0012

TAG_GET_FIRMWARE = 0x08
TAG_FIRMWARE_RESPONSE = 0x09
TAG_SET_REALTIME_MEASUREMENTS = 0x06
TAG_REALTIME_MEASUREMENTS_STATUS = 0x07
TAG_GET_BATTERY = 0x0C
TAG_BATTERY_RESPONSE = 0x0D
TAG_GET_EVENTS = 0x10
TAG_EVENTS_DONE = 0x11
TAG_SYNC_TIME = 0x12
TAG_SYNC_TIME_RESPONSE = 0x13
TAG_GET_PRODUCT_INFO = 0x18
TAG_PRODUCT_INFO_RESPONSE = 0x19
TAG_FACTORY_RESET = 0x1A
TAG_FACTORY_RESET_STATUS = 0x1B
TAG_SET_AUTH_KEY = 0x24
TAG_SET_AUTH_KEY_STATUS = 0x25
TAG_EXTENDED = 0x2F
TAG_SET_RING_MODE = 0x31
TAG_SET_RING_MODE_STATUS = 0x32

EXT_GET_AUTH_NONCE = 0x2B
EXT_AUTH_NONCE_RESPONSE = 0x2C
EXT_AUTHENTICATE = 0x2D
EXT_AUTHENTICATE_RESPONSE = 0x2E
EXT_GET_CAPABILITIES = 0x01
EXT_CAPABILITIES_RESPONSE = 0x02
EXT_GET_FEATURE_STATUS = 0x20
EXT_FEATURE_STATUS_RESPONSE = 0x21
EXT_SET_FEATURE_MODE = 0x22
EXT_SET_FEATURE_MODE_RESPONSE = 0x23
EXT_GET_FEATURE_LATEST_VALUES = 0x24
EXT_FEATURE_LATEST_VALUES_RESPONSE = 0x25
EXT_SET_FEATURE_SUBSCRIPTION = 0x26
EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE = 0x27
EXT_SET_FEATURE_PARAMETERS = 0x29
EXT_SET_FEATURE_PARAMETERS_RESPONSE = 0x2A
EXT_AUTH_STATUS_RESPONSE = 0x2F

AUTH_RESULTS = {
    0x00: "success",
    0x01: "authentication_error",
    0x02: "in_factory_reset",
    0x03: "not_original_onboarded_device",
}

FEATURE_IDS = {
    0x00: "background_dfu",
    0x01: "research_data",
    0x02: "daytime_hr",
    0x03: "exercise_hr",
    0x04: "spo2",
    0x05: "bundling",
    0x06: "encrypted_api",
    0x07: "tap_to_tag",
    0x08: "resting_hr",
    0x09: "app_auth",
    0x0A: "ble_mode",
    0x0B: "real_steps",
    0x0C: "experimental",
    0x0D: "cva_ppg_sampler",
    0x0E: "charging_control",
    0x0F: "ambient_light",
    0x10: "special_feature",
    0x11: "raw_data_sampler",
    0x12: "atlas",
    0x16: "long_events",
}

FEATURE_MODES = {
    0x00: "off",
    0x01: "automatic",
    0x02: "requested",
    0x03: "connected_live",
}

FEATURE_STATUS_VALUES = {
    0x00: "off",
    0x01: "on",
    0x02: "searching",
    0x03: "no_reliable_ppg_signal",
    0x04: "cold_fingers",
    0x05: "too_much_movement",
    0x06: "identifying_signal",
}

FEATURE_STATES = {
    0x00: "idle",
    0x01: "scanning",
    0x02: "measuring",
    0x03: "postprocessing",
}

FEATURE_SUBSCRIPTION_MODES = {
    0x00: "off",
    0x01: "state",
    0x02: "latest",
    0x04: "feature_specific_data",
}

REALTIME_MEASUREMENT_TYPES = {
    "acm": 0x20,
    "on_demand": 0x200,
}

REALTIME_MEASUREMENT_RESPONSE_TAGS = {
    0x05: "on_demand",
    0x33: "acm",
}

SET_AUTH_KEY_RESULTS = {
    0x00: "success",
    0x05: "production_tests_missing",
}

FEATURE_SET_RESULTS = {
    0x00: "success",
    0x01: "not_supported",
    0x02: "not_available",
    0x03: "not_in_finger",
    0x04: "message_too_short",
    0x05: "low_battery",
}

RING_MODES = {
    0x00: "normal",
    0x01: "fast_heart_rate",
    0x02: "deep_sleep",
}

PRODUCT_INFO_TYPES = {
    bytes.fromhex("140010"): "hardware_id_frodo",
    bytes.fromhex("180010"): "hardware_id",
    bytes.fromhex("280009"): "product_code",
    bytes.fromhex("340004"): "product_code_frodo",
    bytes.fromhex("040010"): "serial_number_old",
    bytes.fromhex("080010"): "serial_number",
}

EVENT_TAGS = {
    0x41: "ring_start",
    0x42: "time_sync",
    0x43: "debug_event",
    0x44: "ibi_event",
    0x45: "state_change",
    0x46: "temp_event",
    0x47: "motion_event",
    0x48: "sleep_period_information",
    0x49: "sleep_summary_1",
    0x4A: "ppg_amplitude",
    0x4B: "sleep_phase_information",
    0x4C: "sleep_summary_2",
    0x4D: "ring_sleep_feature_information",
    0x4E: "sleep_phase_details",
    0x4F: "sleep_summary_3",
    0x50: "activity_information",
    0x51: "activity_summary_1",
    0x52: "activity_summary_2",
    0x53: "wear_event",
    0x54: "recovery_summary",
    0x55: "sleep_heart_rate",
    0x56: "alert_event",
    0x57: "ring_sleep_feature_information_2",
    0x58: "sleep_summary_4",
    0x59: "eda_event",
    0x5A: "sleep_phase_data",
    0x5B: "ble_connection",
    0x5C: "user_information",
    0x5D: "hrv_event",
    0x5E: "self_test_event",
    0x5F: "raw_acm_event",
    0x60: "ibi_and_amplitude_event",
    0x61: "debug_data",
    0x62: "on_demand_meas",
    0x63: "ppg_peak_event",
    0x64: "raw_ppg_event",
    0x65: "on_demand_session",
    0x66: "on_demand_motion",
    0x67: "raw_ppg_summary",
    0x68: "raw_ppg_data",
    0x69: "temp_period",
    0x6A: "sleep_period_information_2",
    0x6B: "motion_period",
    0x6C: "feature_session",
    0x6D: "meas_quality_event",
    0x6E: "spo2_ibi_and_amplitude_event",
    0x6F: "spo2_event",
    0x70: "spo2_smoothed_event",
    0x71: "green_ibi_and_amplitude_event",
    0x72: "sleep_acm_period",
    0x73: "ehr_trace_event",
    0x74: "ehr_acm_intensity_event",
    0x75: "sleep_temp_event",
    0x76: "bedtime_period",
    0x77: "spo2_dc_event",
    0x79: "self_test_data_event",
    0x7A: "tag_event",
    0x7B: "spo2_stable_event",
    0x7C: "spo2_combo_event",
    0x7E: "real_step_event_feature_1",
    0x7F: "real_step_event_feature_2",
    0x80: "green_ibi_quality_event",
    0x81: "cva_raw_ppg_data",
    0x82: "scan_start",
    0x83: "scan_end",
}

DEBUG_KEY_METADATA = {
    "SNL": {
        "category": "identity",
        "label": "serial_number_low",
        "fields": ("value",),
    },
    "SNH": {
        "category": "identity",
        "label": "serial_number_high",
        "fields": ("value",),
    },
    "HWID": {
        "category": "identity",
        "label": "hardware_id",
        "fields": ("value",),
    },
    "git": {
        "category": "identity",
        "label": "firmware_git",
        "fields": ("sha",),
    },
    "chg_ind": {
        "category": "charger",
        "label": "charge_indicator",
        "fields": ("percent", "flag"),
    },
    "chg_rp": {
        "category": "charger",
        "label": "charge_rp",
        "fields": ("state", "raw"),
    },
    "chg_rc": {
        "category": "charger",
        "label": "charge_rc",
        "fields": ("state", "flag"),
    },
    "chg_hs": {
        "category": "charger",
        "label": "charge_hs",
        "fields": ("raw",),
    },
    "chgv": {
        "category": "charger",
        "label": "charge_voltage_pair",
        "fields": ("raw_a", "raw_b"),
    },
    "batt": {
        "category": "battery",
        "label": "battery_percent_debug",
        "fields": ("percent",),
    },
    "BMVbI": {
        "category": "battery",
        "label": "battery_mvbi_candidate",
        "fields": ("value",),
    },
    "ChgSt": {
        "category": "charger",
        "label": "charger_status_bits",
        "fields": ("hex",),
    },
    "ChF4": {
        "category": "charger",
        "label": "charger_f4",
        "fields": ("value",),
    },
    "rcell": {
        "category": "charger",
        "label": "charger_cell",
        "fields": ("hex",),
    },
    "chg_bc": {
        "category": "charger",
        "label": "charger_bc",
        "fields": ("state",),
    },
    "brx": {
        "category": "charger",
        "label": "charger_brx",
        "fields": ("state", "raw", "flag"),
    },
    "FGVf%": {
        "category": "fuel_gauge",
        "label": "fuel_gauge_vf_percent_candidate",
        "fields": ("percent",),
    },
    "FGlcu": {
        "category": "fuel_gauge",
        "label": "fuel_gauge_lcu_candidate",
        "fields": ("value_a", "value_b"),
    },
    "in_bed": {
        "category": "setup_state",
        "label": "in_bed",
        "fields": ("flag",),
    },
    "i_info": {
        "category": "setup_state",
        "label": "info_state",
        "fields": ("value",),
    },
    "bc": {
        "category": "setup_state",
        "label": "boot_context",
        "fields": ("value",),
    },
    "pf": {
        "category": "setup_state",
        "label": "platform_flags",
        "fields": ("value",),
    },
    "EFLO": {
        "category": "setup_state",
        "label": "eflo",
        "fields": ("flag",),
    },
    "BLS": {
        "category": "setup_state",
        "label": "bls",
        "fields": ("state",),
    },
    "CcM": {
        "category": "setup_state",
        "label": "ccm",
        "fields": ("value",),
    },
    "CcP": {
        "category": "setup_state",
        "label": "ccp",
        "fields": ("value", "status"),
    },
    "CcV": {
        "category": "setup_state",
        "label": "ccv",
        "fields": ("value",),
    },
    "MFC": {
        "category": "setup_state",
        "label": "mfc",
        "fields": ("value", "status"),
    },
    "tef": {
        "category": "setup_state",
        "label": "tef",
        "fields": ("code", "status"),
    },
    "FGdcap": {
        "category": "fuel_gauge",
        "label": "fuel_gauge_design_capacity_candidate",
        "fields": ("capacity",),
    },
    "blestda": {
        "category": "ble_setup",
        "label": "ble_setup_state_a",
        "fields": ("state",),
    },
    "bleseck": {
        "category": "ble_setup",
        "label": "ble_security_state",
        "fields": ("state",),
    },
    "blep256": {
        "category": "ble_setup",
        "label": "ble_p256_state",
        "fields": ("state",),
    },
    "DHR_mode": {
        "category": "daytime_hr",
        "label": "daytime_hr_mode",
        "fields": ("mode",),
    },
}

DEBUG_MESSAGE_METADATA = {
    "DHR data sub": {
        "category": "daytime_hr",
        "label": "daytime_hr_data_subscription",
        "feature": "daytime_hr",
        "action": "subscribe",
    },
    "DHR unsub": {
        "category": "daytime_hr",
        "label": "daytime_hr_data_subscription",
        "feature": "daytime_hr",
        "action": "unsubscribe",
    },
}

DEBUG_DATA_CODE_METADATA = {
    0x04: {"category": "charger", "label": "charger_report"},
    0x09: {"category": "binary_debug", "label": "binary_debug_0x09"},
    0x0A: {"category": "binary_debug", "label": "binary_debug_0x0a"},
    0x0C: {"category": "binary_debug", "label": "binary_debug_0x0c"},
    0x0D: {"category": "binary_debug", "label": "binary_debug_0x0d"},
    0x0F: {"category": "binary_debug", "label": "binary_debug_0x0f"},
    0x14: {"category": "binary_debug", "label": "binary_debug_0x14"},
    0x18: {"category": "setup_binary", "label": "setup_binary_0x18"},
    0x19: {"category": "setup_binary", "label": "setup_binary_0x19"},
    0x1E: {"category": "binary_debug", "label": "binary_debug_0x1e"},
    0x1F: {"category": "binary_debug", "label": "binary_debug_0x1f"},
    0x20: {"category": "binary_debug", "label": "binary_debug_0x20"},
    0x21: {"category": "binary_debug", "label": "binary_debug_0x21"},
    0x24: {"category": "battery", "label": "battery_snapshot"},
    0x27: {"category": "binary_debug", "label": "binary_debug_0x27"},
    0x28: {"category": "binary_debug", "label": "binary_debug_0x28"},
    0x29: {"category": "binary_debug", "label": "binary_debug_0x29"},
    0x36: {"category": "identity", "label": "identity_fragment"},
    0x39: {"category": "setup_binary", "label": "setup_binary_0x39"},
    0x3C: {"category": "setup_binary", "label": "setup_binary_0x3c"},
    0x3D: {"category": "setup_binary", "label": "setup_binary_0x3d"},
}


class ProtocolError(ValueError):
    """Raised when an Oura BLE payload cannot be parsed."""


@dataclass(frozen=True)
class Packet:
    tag: int
    payload: bytes

    @property
    def raw(self) -> bytes:
        return encode_packet(self.tag, self.payload)

    @property
    def tag_hex(self) -> str:
        return f"0x{self.tag:02X}"

    def to_json(self) -> dict[str, Any]:
        return {
            "tag": self.tag_hex,
            "payload_length": len(self.payload),
            "payload_hex": self.payload.hex(),
            "raw_hex": self.raw.hex(),
        }


def encode_packet(tag: int, payload: bytes = b"") -> bytes:
    if not 0 <= tag <= 0xFF:
        raise ProtocolError(f"packet tag out of range: {tag!r}")
    if len(payload) > 0xFF:
        raise ProtocolError(f"payload too long for one packet: {len(payload)}")
    return bytes([tag, len(payload)]) + payload


def parse_packets(data: bytes) -> list[Packet]:
    packets: list[Packet] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ProtocolError(f"truncated packet header at offset {offset}")
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        end = offset + length
        if end > len(data):
            raise ProtocolError(
                f"truncated packet payload for tag 0x{tag:02X}: "
                f"wanted {length}, have {len(data) - offset}"
            )
        packets.append(Packet(tag, data[offset:end]))
        offset = end
    return packets


def packet_from_hex(value: str) -> Packet:
    packets = parse_packets(bytes_from_user(value))
    if len(packets) != 1:
        raise ProtocolError(f"expected one packet, found {len(packets)}")
    return packets[0]


def bytes_from_user(value: str) -> bytes:
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(compact) % 2:
        raise ProtocolError("hex input has an odd number of nibbles")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ProtocolError(f"invalid hex input: {value!r}") from exc


def parse_key(value: str) -> bytes:
    """Parse a 16-byte auth key from hex, base64, or a raw 16-character string."""

    stripped = value.strip()
    compact_hex = re.sub(r"[^0-9a-fA-F]", "", stripped)
    if len(compact_hex) == 32:
        return bytes.fromhex(compact_hex)

    try:
        decoded = base64.b64decode(stripped, validate=True)
    except binascii.Error:
        decoded = b""
    if len(decoded) == 16:
        return decoded

    raw = stripped.encode("utf-8")
    if len(raw) == 16:
        return raw

    raise ProtocolError("auth key must decode to exactly 16 bytes")


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def generate_auth_key() -> bytes:
    """Generate the 16-byte ring auth key using the app's UUID byte layout."""

    value = uuid.uuid4()
    msb = (value.int >> 64) & 0xFFFFFFFFFFFFFFFF
    lsb = value.int & 0xFFFFFFFFFFFFFFFF
    return struct.pack("<QQ", msb, lsb)


def semver(data: bytes) -> str:
    if len(data) != 3:
        raise ProtocolError(f"semver needs 3 bytes, got {len(data)}")
    return f"{data[0]}.{data[1]}.{data[2]}"


def parse_response(
    packet: Packet, *, product_info_type: str | bytes | None = None
) -> dict[str, Any]:
    base = packet.to_json()
    if packet.tag == TAG_FIRMWARE_RESPONSE:
        base["decoded"] = parse_firmware_response(packet.payload)
    elif packet.tag == TAG_BATTERY_RESPONSE:
        base["decoded"] = parse_battery_response(packet.payload)
    elif packet.tag == TAG_SYNC_TIME_RESPONSE:
        base["decoded"] = parse_sync_time_response(packet.payload)
    elif packet.tag == TAG_PRODUCT_INFO_RESPONSE:
        base["decoded"] = parse_product_info_response(
            packet.payload, product_info_type=product_info_type
        )
    elif packet.tag == TAG_FACTORY_RESET_STATUS:
        base["decoded"] = parse_factory_reset_status(packet.payload)
    elif packet.tag == TAG_REALTIME_MEASUREMENTS_STATUS:
        base["decoded"] = parse_realtime_measurements_status(packet.payload)
    elif packet.tag == TAG_SET_AUTH_KEY_STATUS:
        base["decoded"] = parse_set_auth_key_status(packet.payload)
    elif packet.tag == TAG_SET_RING_MODE_STATUS:
        base["decoded"] = parse_set_ring_mode_status(packet.payload)
    elif packet.tag == TAG_EXTENDED:
        base["decoded"] = parse_extended_response(packet.payload)
    elif packet.tag == TAG_EVENTS_DONE:
        base["decoded"] = parse_events_done_response(packet.payload)
    elif packet.tag >= 0x41:
        base["decoded"] = parse_event_packet(packet)
    return base


def parse_firmware_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 12:
        raise ProtocolError(f"firmware payload too short: {len(payload)}")
    decoded = {
        "api_version": semver(payload[0:3]),
        "firmware_version": semver(payload[3:6]),
        "bootloader_version": semver(payload[6:9]),
        "bluetooth_stack_version": semver(payload[9:12]),
    }
    if len(payload) >= 18:
        decoded["mac_fragment_hex"] = payload[12:18].hex(":")
    if len(payload) > 18:
        decoded["extra_hex"] = payload[18:].hex()
    return decoded


def parse_battery_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 3:
        raise ProtocolError(f"battery payload too short: {len(payload)}")
    decoded: dict[str, Any] = {
        "battery_level_percent": payload[0],
        "charging_progress": payload[1],
        "charging_recommended": bool(payload[2]),
    }
    if len(payload) > 3:
        extra = payload[3:]
        decoded["unknown_hex"] = extra.hex()
        decoded["battery_status_byte"] = extra[0]
        decoded["battery_status_hex"] = f"0x{extra[0]:02X}"
        if len(extra) >= 3:
            voltage_mv = struct.unpack_from("<H", extra, 1)[0]
            decoded["battery_voltage_raw"] = voltage_mv
            if voltage_mv != 0xFFFF:
                decoded["voltage_mv"] = voltage_mv
    return decoded


def parse_sync_time_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 5:
        raise ProtocolError(f"sync-time response too short: {len(payload)}")
    return {
        "device_boot_seconds": struct.unpack_from("<I", payload, 0)[0],
        "status": payload[4],
        "extra_hex": payload[5:].hex() if len(payload) > 5 else "",
    }


def parse_product_info_response(
    payload: bytes, *, product_info_type: str | bytes | None = None
) -> dict[str, Any]:
    decoded: dict[str, Any] = {"payload_hex": payload.hex()}
    if product_info_type is not None:
        type_bytes = product_info_type_bytes(product_info_type)
        decoded["request_type_hex"] = type_bytes.hex()
        decoded["info_type_name"] = PRODUCT_INFO_TYPES.get(type_bytes, "unknown")
    if payload:
        status = payload[0]
        value = payload[1:]
        decoded["status"] = status
        decoded["status_name"] = "ok" if status == 0 else "unknown"
        decoded["value_hex"] = value.hex()
        text = decode_c_string(value)
        if text is not None:
            decoded["value_text"] = text
        printable_runs = decode_printable_runs(value)
        if printable_runs:
            decoded["printable_runs"] = printable_runs
    else:
        decoded["status_name"] = "empty"
    return decoded


def parse_factory_reset_status(payload: bytes) -> dict[str, Any]:
    if len(payload) != 1:
        raise ProtocolError(f"factory reset status payload length: {len(payload)}")
    status = payload[0]
    return {
        "response_name": "factory_reset_status",
        "status": status,
        "status_name": "ok" if status == 0 else "unknown",
    }


def parse_set_ring_mode_status(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        raise ProtocolError(f"ring mode status payload too short: {len(payload)}")
    status_length = 4 if len(payload) >= 4 else 2
    if status_length == 4:
        status = struct.unpack_from("<I", payload, 0)[0] & 0x00FFFFFF
    else:
        status = struct.unpack_from("<H", payload, 0)[0]
    decoded = {
        "response_name": "set_ring_mode_status",
        "status": status,
        "status_name": "ok" if status == 0 else "error",
    }
    if len(payload) > status_length:
        decoded["extra_hex"] = payload[status_length:].hex()
    return decoded


def parse_set_auth_key_status(payload: bytes) -> dict[str, Any]:
    if not payload:
        raise ProtocolError("set auth key status payload too short: 0")
    status = payload[0]
    decoded = {
        "response_name": "set_auth_key_status",
        "status": status,
        "status_name": SET_AUTH_KEY_RESULTS.get(status, "error"),
    }
    if len(payload) > 1:
        decoded["extra_hex"] = payload[1:].hex()
    return decoded


def parse_realtime_measurements_status(payload: bytes) -> dict[str, Any]:
    if not payload:
        raise ProtocolError("realtime measurements status payload too short: 0")
    status = payload[0]
    decoded = {
        "response_name": "realtime_measurements_status",
        "status": status,
        "status_name": "success" if status == 0 else "error",
    }
    if len(payload) > 1:
        decoded["extra_hex"] = payload[1:].hex()
    return decoded


def parse_product_info_request_type(info_type: str | bytes) -> dict[str, int | str]:
    type_bytes = product_info_type_bytes(info_type)
    return {
        "request_type_hex": type_bytes.hex(),
        "offset": int.from_bytes(type_bytes[:2], "little"),
        "length": type_bytes[2],
    }


def product_info_type_bytes(info_type: str | bytes) -> bytes:
    if isinstance(info_type, str):
        normalized = info_type.strip().lower()
        by_name = {name: value for value, name in PRODUCT_INFO_TYPES.items()}
        try:
            return by_name[normalized]
        except KeyError as exc:
            raise ProtocolError(f"unknown product info type: {info_type}") from exc
    type_bytes = bytes(info_type)
    if len(type_bytes) != 3:
        raise ProtocolError("product info type must be exactly 3 bytes")
    return type_bytes


def decode_c_string(value: bytes) -> str | None:
    value = value.rstrip(b"\x00")
    if not value:
        return ""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        return None
    return text


def decode_printable_runs(value: bytes, min_length: int = 4) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    for byte in value:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                runs.append(current.decode("ascii"))
            current.clear()
    if len(current) >= min_length:
        runs.append(current.decode("ascii"))
    return runs


def reconstruct_product_info_memory(
    decoded_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    cells: dict[int, dict[int, int]] = {}
    source_count = 0
    for row in decoded_rows:
        request_type_hex = row.get("request_type_hex")
        value_hex = row.get("value_hex")
        if not isinstance(request_type_hex, str) or not isinstance(value_hex, str):
            continue
        if row.get("status") not in (0, None):
            continue
        try:
            request = parse_product_info_request_type(bytes.fromhex(request_type_hex))
            value = bytes.fromhex(value_hex)
        except (ProtocolError, ValueError):
            continue
        offset = int(request["offset"])
        requested_length = int(request["length"])
        if requested_length:
            value = value[:requested_length]
        if not value:
            continue
        source_count += 1
        for index, byte in enumerate(value):
            counts = cells.setdefault(offset + index, {})
            counts[byte] = counts.get(byte, 0) + 1

    if not cells:
        return {"byte_count": 0, "source_count": 0, "segments": [], "conflicts": []}

    chosen = {
        offset: sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        for offset, counts in cells.items()
    }
    segments = []
    sorted_offsets = sorted(chosen)
    start = sorted_offsets[0]
    previous = start
    data = bytearray([chosen[start]])
    for offset in sorted_offsets[1:]:
        if offset == previous + 1:
            data.append(chosen[offset])
        else:
            segments.append(product_info_memory_segment(start, bytes(data)))
            start = offset
            data = bytearray([chosen[offset]])
        previous = offset
    segments.append(product_info_memory_segment(start, bytes(data)))

    conflicts = []
    for offset, counts in sorted(cells.items()):
        if len(counts) <= 1:
            continue
        conflicts.append(
            {
                "offset": f"0x{offset:04X}",
                "selected": f"0x{chosen[offset]:02X}",
                "values": {
                    f"0x{byte:02X}": count
                    for byte, count in sorted(counts.items())
                },
            }
        )

    return {
        "byte_count": len(chosen),
        "source_count": source_count,
        "segments": segments,
        "conflicts": conflicts,
    }


def product_info_memory_segment(start: int, data: bytes) -> dict[str, Any]:
    return {
        "start": f"0x{start:04X}",
        "end_exclusive": f"0x{start + len(data):04X}",
        "length": len(data),
        "hex": data.hex(),
        "ascii_preview": ascii_preview(data),
        "printable_runs": printable_runs_with_offsets(data, start),
    }


def ascii_preview(value: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value)


def printable_runs_with_offsets(
    value: bytes,
    base_offset: int,
    min_length: int = 4,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    current = bytearray()
    current_start = base_offset
    for index, byte in enumerate(value):
        if 32 <= byte <= 126:
            if not current:
                current_start = base_offset + index
            current.append(byte)
        else:
            if len(current) >= min_length:
                runs.append(
                    {
                        "offset": f"0x{current_start:04X}",
                        "text": current.decode("ascii"),
                    }
                )
            current.clear()
    if len(current) >= min_length:
        runs.append(
            {
                "offset": f"0x{current_start:04X}",
                "text": current.decode("ascii"),
            }
        )
    return runs


def parse_events_done_response(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    if payload:
        decoded["events_received"] = payload[0]
    if len(payload) >= 2:
        decoded["sleep_analysis_progress"] = payload[1]
    if len(payload) >= 6:
        decoded["bytes_left"] = struct.unpack_from("<I", payload, 2)[0]
    if len(payload) >= 8:
        decoded["unknown_u16"] = struct.unpack_from("<H", payload, 6)[0]
    if len(payload) > 8:
        decoded["extra_hex"] = payload[8:].hex()
    return decoded


def parse_extended_response(payload: bytes) -> dict[str, Any]:
    if not payload:
        raise ProtocolError("empty extended response")
    request_id = payload[0]
    rest = payload[1:]
    decoded: dict[str, Any] = {
        "extended_id": f"0x{request_id:02X}",
        "extended_name": extended_name(request_id),
    }
    if request_id == EXT_AUTH_NONCE_RESPONSE:
        decoded["nonce_hex"] = rest.hex()
        decoded["nonce_length"] = len(rest)
    elif request_id == EXT_CAPABILITIES_RESPONSE:
        decoded.update(parse_capabilities_response(rest))
    elif request_id in {EXT_AUTHENTICATE_RESPONSE, EXT_AUTH_STATUS_RESPONSE}:
        if not rest:
            raise ProtocolError("authenticate response missing state byte")
        decoded["auth_state"] = rest[0]
        decoded["auth_result"] = AUTH_RESULTS.get(rest[0], "unknown")
        if len(rest) > 1:
            decoded["extra_hex"] = rest[1:].hex()
    elif request_id == EXT_FEATURE_STATUS_RESPONSE:
        decoded.update(parse_feature_status_response(rest))
    elif request_id == EXT_SET_FEATURE_MODE_RESPONSE:
        decoded.update(parse_feature_set_response(rest))
    elif request_id == EXT_FEATURE_LATEST_VALUES_RESPONSE:
        decoded.update(parse_feature_latest_values_response(rest))
    elif request_id == EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE:
        decoded.update(parse_feature_set_response(rest))
    elif request_id == EXT_SET_FEATURE_PARAMETERS_RESPONSE:
        decoded.update(parse_feature_set_response(rest))
    else:
        decoded["payload_hex"] = rest.hex()
    return decoded


def extended_name(request_id: int) -> str:
    return {
        EXT_GET_CAPABILITIES: "get_capabilities",
        EXT_CAPABILITIES_RESPONSE: "capabilities_response",
        EXT_GET_FEATURE_STATUS: "get_feature_status",
        EXT_FEATURE_STATUS_RESPONSE: "feature_status_response",
        EXT_SET_FEATURE_MODE: "set_feature_mode",
        EXT_SET_FEATURE_MODE_RESPONSE: "set_feature_mode_response",
        EXT_GET_FEATURE_LATEST_VALUES: "get_feature_latest_values",
        EXT_FEATURE_LATEST_VALUES_RESPONSE: "feature_latest_values_response",
        EXT_SET_FEATURE_SUBSCRIPTION: "set_feature_subscription",
        EXT_SET_FEATURE_SUBSCRIPTION_RESPONSE: "set_feature_subscription_response",
        EXT_SET_FEATURE_PARAMETERS: "set_feature_parameters",
        EXT_SET_FEATURE_PARAMETERS_RESPONSE: "set_feature_parameters_response",
        EXT_GET_AUTH_NONCE: "get_auth_nonce",
        EXT_AUTH_NONCE_RESPONSE: "auth_nonce_response",
        EXT_AUTHENTICATE: "authenticate",
        EXT_AUTHENTICATE_RESPONSE: "authenticate_response",
        EXT_AUTH_STATUS_RESPONSE: "auth_status_response",
    }.get(request_id, "unknown")


def parse_capabilities_response(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {"payload_hex": payload.hex()}
    if payload:
        decoded["page"] = payload[0]
        decoded["page_hex"] = f"0x{payload[0]:02X}"
    if len(payload) > 1:
        data = payload[1:]
        decoded["data_hex"] = data.hex()
        decoded.update(parse_capability_entries(data))
    return decoded


def parse_capability_entries(payload: bytes) -> dict[str, Any]:
    entries = []
    pair_length = len(payload) - (len(payload) % 2)
    for offset in range(0, pair_length, 2):
        feature_id = payload[offset]
        value = payload[offset + 1]
        entries.append(
            {
                "feature_id": feature_id,
                "feature_name": FEATURE_IDS.get(feature_id, "unknown"),
                "capability_value": value,
                "capability_hex": f"0x{value:02X}",
                "capability_bits": [
                    bit for bit in range(8) if value & (1 << bit)
                ],
            }
        )
    decoded: dict[str, Any] = {"capability_entries": entries}
    if len(payload) % 2:
        decoded["capability_remainder_hex"] = payload[-1:].hex()
    return decoded


def parse_feature_status_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 5:
        raise ProtocolError(f"feature status payload too short: {len(payload)}")
    feature_id, mode, status_value, state, subscription_mode = payload[:5]
    decoded: dict[str, Any] = {
        "feature_id": feature_id,
        "feature_name": FEATURE_IDS.get(feature_id, "unknown"),
        "mode": mode,
        "mode_name": FEATURE_MODES.get(mode, "unknown"),
        "status_value": status_value,
        "status_name": FEATURE_STATUS_VALUES.get(status_value, "unknown"),
        "state": state,
        "state_name": FEATURE_STATES.get(state, "unknown"),
        "subscription_mode": subscription_mode,
        "subscription_mode_name": FEATURE_SUBSCRIPTION_MODES.get(
            subscription_mode, "unknown"
        ),
    }
    if len(payload) > 5:
        decoded["extra_hex"] = payload[5:].hex()
    return decoded


def parse_feature_set_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        raise ProtocolError(f"feature set response payload too short: {len(payload)}")
    feature_id, result = payload[:2]
    decoded: dict[str, Any] = {
        "feature_id": feature_id,
        "feature_name": FEATURE_IDS.get(feature_id, "unknown"),
        "result": result,
        "result_name": FEATURE_SET_RESULTS.get(result, "unknown"),
    }
    if len(payload) > 2:
        decoded["extra_hex"] = payload[2:].hex()
    return decoded


def parse_feature_latest_values_response(payload: bytes) -> dict[str, Any]:
    if len(payload) < 6:
        raise ProtocolError(
            f"feature latest-values payload too short: {len(payload)}"
        )
    feature_id, result, status_value, state = payload[:4]
    status_duration = struct.unpack_from("<H", payload, 4)[0]
    decoded: dict[str, Any] = {
        "feature_id": feature_id,
        "feature_name": FEATURE_IDS.get(feature_id, "unknown"),
        "result": result,
        "result_name": FEATURE_SET_RESULTS.get(result, "unknown"),
        "status_value": status_value,
        "status_name": FEATURE_STATUS_VALUES.get(status_value, "unknown"),
        "state": state,
        "state_name": FEATURE_STATES.get(state, "unknown"),
        "status_duration": status_duration,
    }
    if feature_id == 0x02 and len(payload) >= 15:
        ibi_ms = struct.unpack_from("<h", payload, 6)[0]
        timestamp = struct.unpack_from("<i", payload, 8)[0]
        measurement_duration = struct.unpack_from("<h", payload, 12)[0]
        quality = payload[14]
        decoded.update(
            {
                "daytime_hr_ibi_ms": ibi_ms,
                "daytime_hr_timestamp": timestamp,
                "daytime_hr_duration": measurement_duration,
                "daytime_hr_quality": quality,
            }
        )
        if ibi_ms > 0:
            decoded["daytime_hr_bpm_estimate"] = round(60000 / ibi_ms, 1)
    if len(payload) > 15:
        decoded["extra_hex"] = payload[15:].hex()
    elif feature_id != 0x02 and len(payload) > 6:
        decoded["extra_hex"] = payload[6:].hex()
    return decoded


def build_get_firmware_request() -> bytes:
    return encode_packet(TAG_GET_FIRMWARE)


def build_get_battery_request() -> bytes:
    return encode_packet(TAG_GET_BATTERY)


def build_get_product_info_request(info_type: str | bytes) -> bytes:
    return encode_packet(TAG_GET_PRODUCT_INFO, product_info_type_bytes(info_type))


def build_get_auth_nonce_request() -> bytes:
    return encode_packet(TAG_EXTENDED, bytes([EXT_GET_AUTH_NONCE]))


def build_get_capabilities_request(page: int = 0xFF) -> bytes:
    if not 0 <= page <= 0xFF:
        raise ProtocolError("capabilities page must fit uint8")
    return encode_packet(TAG_EXTENDED, bytes([EXT_GET_CAPABILITIES, page]))


def build_get_feature_status_request(feature_id: int) -> bytes:
    if not 0 <= feature_id <= 0xFF:
        raise ProtocolError("feature id must fit uint8")
    return encode_packet(TAG_EXTENDED, bytes([EXT_GET_FEATURE_STATUS, feature_id]))


def build_get_feature_latest_values_request(feature_id: int) -> bytes:
    if not 0 <= feature_id <= 0xFF:
        raise ProtocolError("feature id must fit uint8")
    return encode_packet(
        TAG_EXTENDED,
        bytes([EXT_GET_FEATURE_LATEST_VALUES, feature_id]),
    )


def build_set_feature_mode_request(feature_id: int, mode: int) -> bytes:
    if not 0 <= feature_id <= 0xFF:
        raise ProtocolError("feature id must fit uint8")
    if not 0 <= mode <= 0xFF:
        raise ProtocolError("feature mode must fit uint8")
    return encode_packet(TAG_EXTENDED, bytes([EXT_SET_FEATURE_MODE, feature_id, mode]))


def build_set_feature_subscription_request(
    feature_id: int,
    subscription_mode: int,
) -> bytes:
    if not 0 <= feature_id <= 0xFF:
        raise ProtocolError("feature id must fit uint8")
    if not 0 <= subscription_mode <= 0xFF:
        raise ProtocolError("feature subscription mode must fit uint8")
    return encode_packet(
        TAG_EXTENDED,
        bytes([EXT_SET_FEATURE_SUBSCRIPTION, feature_id, subscription_mode]),
    )


def build_set_feature_parameters_request(feature_id: int, feature_config: bytes) -> bytes:
    if not 0 <= feature_id <= 0xFF:
        raise ProtocolError("feature id must fit uint8")
    config = bytes(feature_config)
    if len(config) > 0xFD:
        raise ProtocolError("feature parameter config is too long")
    return encode_packet(
        TAG_EXTENDED,
        bytes([EXT_SET_FEATURE_PARAMETERS, feature_id]) + config,
    )


def build_set_daytime_hr_meditation_parameters_request(
    duration_minutes: int,
) -> bytes:
    if not 0 <= duration_minutes <= 0xFF:
        raise ProtocolError("meditation duration minutes must fit uint8")
    return build_set_feature_parameters_request(0x02, bytes([duration_minutes]))


def realtime_measurement_bitmask(measurements: Iterable[str | int]) -> int:
    bitmask = 0
    for measurement in measurements:
        if isinstance(measurement, str):
            normalized = measurement.strip().lower().replace("-", "_")
            try:
                bitmask |= REALTIME_MEASUREMENT_TYPES[normalized]
            except KeyError as exc:
                raise ProtocolError(
                    f"unknown realtime measurement type: {measurement}"
                ) from exc
        else:
            value = int(measurement)
            if not 0 <= value <= 0xFFFFFFFF:
                raise ProtocolError("realtime measurement bit must fit uint32")
            bitmask |= value
    return bitmask


def build_set_realtime_measurements_request(
    measurements: Iterable[str | int],
    *,
    maximum_duration_minutes: int,
    delay: int,
) -> bytes:
    if not 0 <= maximum_duration_minutes <= 0xFFFF:
        raise ProtocolError("maximum duration minutes must fit uint16")
    if not 0 <= delay <= 0xFF:
        raise ProtocolError("realtime measurement delay must fit uint8")
    payload = struct.pack(
        "<IHB",
        realtime_measurement_bitmask(measurements),
        maximum_duration_minutes,
        delay,
    )
    return encode_packet(TAG_SET_REALTIME_MEASUREMENTS, payload)


def build_disable_realtime_measurements_request() -> bytes:
    return encode_packet(TAG_SET_REALTIME_MEASUREMENTS, b"\x00\x00\x00\x00")


def build_set_auth_key_request(key: bytes) -> bytes:
    if len(key) != 16:
        raise ProtocolError("auth key must be exactly 16 bytes")
    return encode_packet(TAG_SET_AUTH_KEY, key)


def build_factory_reset_request() -> bytes:
    return encode_packet(TAG_FACTORY_RESET)


def build_set_ring_mode_request(mode: int) -> bytes:
    if not 0 <= mode <= 0xFFFFFFFF:
        raise ProtocolError("ring mode must fit uint32")
    return encode_packet(TAG_SET_RING_MODE, struct.pack("<I", mode))


def build_authenticate_request(key: bytes, nonce: bytes) -> bytes:
    encrypted = encrypt_nonce(key, nonce)
    return encode_packet(TAG_EXTENDED, bytes([EXT_AUTHENTICATE]) + encrypted)


def build_get_events_request(start_timestamp: int = 0, max_events: int = 0xFF) -> bytes:
    if not 0 <= start_timestamp <= 0xFFFFFFFF:
        raise ProtocolError("start timestamp must fit uint32")
    if not 1 <= max_events <= 0xFF:
        raise ProtocolError("max events must be between 1 and 255")
    payload = struct.pack("<IBi", start_timestamp, max_events, -1)
    return encode_packet(TAG_GET_EVENTS, payload)


def build_sync_time_request(unix_seconds: int, timezone_half_hours: int) -> bytes:
    if not 0 <= timezone_half_hours <= 0xFF:
        raise ProtocolError("timezone offset half-hours must fit uint8")
    payload = struct.pack("<QB", unix_seconds, timezone_half_hours)
    return encode_packet(TAG_SYNC_TIME, payload)


def encrypt_nonce(key: bytes, nonce: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        from Cryptodome.Cipher import AES

    if len(key) != 16:
        raise ProtocolError("auth key must be exactly 16 bytes")
    if not nonce:
        raise ProtocolError("nonce must not be empty")
    pad_len = 16 - (len(nonce) % 16)
    padded = nonce + bytes([pad_len]) * pad_len
    return AES.new(key, AES.MODE_ECB).encrypt(padded)


def parse_event_packet(packet: Packet) -> dict[str, Any]:
    if packet.tag < 0x41:
        raise ProtocolError(f"not an event packet: 0x{packet.tag:02X}")
    if len(packet.payload) < 4:
        raise ProtocolError(f"event payload too short: {len(packet.payload)}")
    timestamp = struct.unpack_from("<I", packet.payload, 0)[0]
    signed_timestamp = struct.unpack_from("<i", packet.payload, 0)[0]
    payload = packet.payload[4:]
    decoded: dict[str, Any] = {
        "event_tag": packet.tag_hex,
        "event_name": EVENT_TAGS.get(packet.tag, "unknown"),
        "event_payload_length": len(packet.payload),
        "device_boot_timestamp": timestamp,
        "ring_timestamp_ticks": signed_timestamp,
        "ring_timestamp_ms": signed_timestamp * 100,
        "payload_length": len(payload),
        "payload_hex": payload.hex(),
    }
    if payload:
        decoded["payload_ascii"] = ascii_preview(payload)
        printable_runs = decode_printable_runs(payload)
        if printable_runs:
            decoded["printable_runs"] = printable_runs
            if len(printable_runs) == 1:
                decoded["payload_text"] = printable_runs[0]
        if packet.tag == 0x41:
            decoded.update(parse_ring_start_event_payload(payload))
        decoded.update(parse_known_event_payload(packet.tag, payload))
        decoded.update(parse_debug_event_payload(packet.tag, payload, decoded))
    return decoded


def parse_known_event_payload(event_tag: int, payload: bytes) -> dict[str, Any]:
    if event_tag == 0x42:
        return parse_time_sync_event_payload(payload)
    if event_tag in {0x45, 0x53}:
        field = "state" if event_tag == 0x45 else "wear"
        return parse_status_byte_event_payload(payload, field)
    if event_tag == 0x46:
        return parse_temp_event_payload(payload)
    if event_tag == 0x47:
        return parse_motion_event_payload(payload)
    if event_tag == 0x4A:
        return parse_ppg_amplitude_event_payload(payload)
    if event_tag == 0x56:
        return {"alert_type": payload[0], "alert_type_hex": f"0x{payload[0]:02X}"}
    if event_tag == 0x5D:
        return parse_hrv_event_payload(payload)
    if event_tag == 0x60:
        return parse_ibi_and_amplitude_event_payload(payload)
    if event_tag == 0x69:
        return parse_temp_period_event_payload(payload)
    if event_tag == 0x6D:
        return parse_meas_quality_event_payload(payload)
    if event_tag == 0x6E:
        return parse_spo2_ibi_and_amplitude_event_payload(payload)
    if event_tag == 0x6F:
        return parse_spo2_event_payload(payload)
    if event_tag == 0x71:
        return parse_green_ibi_and_amp_event_payload(payload)
    if event_tag == 0x75:
        return parse_sleep_temp_event_payload(payload)
    if event_tag == 0x7B:
        return parse_spo2_stable_event_payload(payload)
    if event_tag == 0x80:
        return parse_green_ibi_quality_event_payload(payload)
    return {}


def parse_time_sync_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 9:
        return {}
    epoch_seconds = struct.unpack_from("<q", payload, 0)[0]
    timezone_half_hours = struct.unpack_from("b", payload, 8)[0]
    return {
        "epoch_seconds": epoch_seconds,
        "utc_ms": epoch_seconds * 1000,
        "timezone_30min": timezone_half_hours,
        "timezone_seconds": timezone_half_hours * 1800,
    }


def parse_status_byte_event_payload(payload: bytes, field: str) -> dict[str, Any]:
    if not payload:
        return {}
    decoded: dict[str, Any] = {
        field: payload[0],
        f"{field}_hex": f"0x{payload[0]:02X}",
    }
    if len(payload) > 1:
        text = decode_c_string(payload[1:])
        if text:
            decoded[f"{field}_debug"] = text
        else:
            decoded[f"{field}_debug_hex"] = payload[1:].hex()
    return decoded


def parse_temp_event_payload(payload: bytes) -> dict[str, Any]:
    samples = parse_celsius_i16_samples(payload)
    decoded: dict[str, Any] = {"temperature_c_samples": samples}
    if len(payload) % 2:
        decoded["temperature_remainder_hex"] = payload[-1:].hex()
    return decoded


def parse_temp_period_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        return {}
    raw = struct.unpack_from("<h", payload, 0)[0]
    return {
        "temperature_raw": raw,
        "temperature_c": round(raw / 100, 2),
    }


def parse_sleep_temp_event_payload(payload: bytes) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for index, raw in enumerate(parse_u16_le_words(payload)):
        samples.append(
            {
                "seconds_before_event": index * 30,
                "temperature_raw": raw,
                "temperature_c": round(raw / 100, 2),
            }
        )
    decoded: dict[str, Any] = {
        "sample_spacing_seconds": 30,
        "sleep_temperature_samples": samples,
    }
    if len(payload) % 2:
        decoded["sleep_temperature_remainder_hex"] = payload[-1:].hex()
    return decoded


def parse_ppg_amplitude_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        return {}
    raw = struct.unpack_from("<H", payload, 0)[0]
    return {
        "ppg_amplitude_raw": raw,
        "ppg_amplitude_ratio": round(raw / 0xFFFF, 6),
    }


def parse_motion_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 4:
        return {}
    packed = payload[0]
    axes = [struct.unpack_from("b", payload, offset)[0] * 8 for offset in range(1, 4)]
    decoded: dict[str, Any] = {
        "motion_field_a": (packed >> 5) & 0x07,
        "motion_field_b": packed & 0x1F,
        "motion_axes_scaled": axes,
    }
    if len(payload) > 4:
        decoded["motion_extra_hex"] = payload[4:].hex()
    return decoded


def parse_hrv_event_payload(payload: bytes) -> dict[str, Any]:
    samples: list[dict[str, int]] = []
    for offset in range(0, len(payload) - 1, 2):
        samples.append(
            {
                "minutes_before_event": (offset // 2) * 5,
                "raw_a": payload[offset],
                "raw_b": payload[offset + 1],
            }
        )
    decoded: dict[str, Any] = {
        "sample_spacing_minutes": 5,
        "hrv_raw_samples": samples,
    }
    if len(payload) % 2:
        decoded["hrv_remainder_hex"] = payload[-1:].hex()
    return decoded


def parse_ibi_and_amplitude_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) != 14:
        return {"ibi_amplitude_error": "expected_body_length_14"}
    shift_nibble = payload[13] & 0x0F
    shift = 0 if shift_nibble == 7 else shift_nibble + 1
    ibis = [
        (payload[11] & 1) | (payload[5] << 3) | ((payload[13] >> 3) & 6),
        (payload[10] & 1) | (payload[4] << 3) | ((payload[13] >> 5) & 6),
        (payload[3] << 3) | (payload[9] & 1) | ((payload[12] & 3) << 1),
        (payload[8] & 1) | (payload[2] << 3) | ((payload[12] >> 1) & 6),
        (payload[7] & 1) | (payload[1] << 3) | ((payload[12] >> 3) & 6),
        (payload[6] & 1) | (payload[0] << 3) | ((payload[12] >> 5) & 6),
    ]
    amplitudes = [
        (payload[11] >> 1) << shift,
        (payload[10] >> 1) << shift,
        (payload[9] >> 1) << shift,
        (payload[8] >> 1) << shift,
        (payload[7] >> 1) << shift,
        (payload[6] >> 1) << shift,
    ]
    return {
        "ibi_amplitude_shift": shift,
        "ibi_amplitude_records": ibi_amplitude_records(ibis, amplitudes),
    }


def parse_green_ibi_and_amp_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) != 14:
        return {"green_ibi_amplitude_error": "expected_body_length_14"}
    if payload[13] & 0x08:
        return {"green_ibi_amplitude_error": "unexpected_reserved_bit"}
    shift_bits = payload[13] & 0x07
    shift = 0 if shift_bits == 7 else shift_bits + 1
    ibis = [
        (payload[10] & 1) | (payload[4] << 3) | ((payload[13] >> 5) & 6),
        (payload[9] & 1) | (payload[3] << 3) | ((payload[12] & 3) << 1),
        (payload[8] & 1) | (payload[2] << 3) | ((payload[12] >> 1) & 6),
        (payload[7] & 1) | (payload[1] << 3) | ((payload[12] >> 3) & 6),
        (payload[6] & 1) | (payload[0] << 3) | ((payload[12] >> 5) & 6),
    ]
    amplitudes = [
        (payload[6] >> 1) << shift,
        (payload[7] >> 1) << shift,
        (payload[8] >> 1) << shift,
        (payload[9] >> 1) << shift,
        (payload[10] >> 1) << shift,
    ]
    records = [{"ibi_ms": 0, "amplitude": amplitudes[0]}]
    records.extend(ibi_amplitude_records(ibis, amplitudes))
    return {
        "green_ibi_amplitude_shift": shift,
        "green_ibi_amplitude_records": records,
    }


def parse_spo2_ibi_and_amplitude_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) != 13:
        return {"spo2_ibi_amplitude_error": "expected_body_length_13"}
    head = payload[0]
    ibis = [payload[offset] * 8 for offset in (5, 4, 3, 2, 1)]
    shift = (head >> 4) & 0x07
    amplitudes = [payload[6] << 3]
    amplitudes.extend(value << shift for value in payload[7:13])
    return {
        "spo2_ibi_flag": (head >> 7) & 0x01,
        "spo2_ibi_mode": head & 0x0F,
        "spo2_ibi_shift": shift,
        "spo2_ibi_records": ibi_records(ibis),
        "spo2_ibi_amplitudes": amplitudes,
    }


def parse_green_ibi_quality_event_payload(payload: bytes) -> dict[str, Any]:
    samples: list[dict[str, int]] = []
    for offset in range(0, len(payload) - 1, 2):
        first = payload[offset]
        second = payload[offset + 1]
        samples.append(
            {
                "ibi_delta": (first << 3) | (second & 0x07),
                "quality_a": (second >> 3) & 0x03,
                "quality_b": second >> 5,
            }
        )
    decoded: dict[str, Any] = {"green_ibi_quality_samples": samples}
    if len(payload) % 2:
        decoded["green_ibi_quality_remainder_hex"] = payload[-1:].hex()
    return decoded


def parse_meas_quality_event_payload(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {}
    quality_type = payload[0]
    data = payload[1:]
    if quality_type == 0:
        default_count = 4
    elif quality_type == 1:
        default_count = 3
    else:
        default_count = len(data) // 3
    sample_count = min(default_count, len(data) // 3)
    samples = [
        decode_i24_le(data[offset : offset + 3])
        for offset in range(0, sample_count * 3, 3)
    ]
    decoded: dict[str, Any] = {
        "measurement_quality_type": quality_type,
        "measurement_quality_samples": samples,
    }
    remainder = data[sample_count * 3 :]
    if quality_type == 1 and remainder:
        decoded["measurement_quality_flag"] = remainder[0]
        if len(remainder) > 1:
            decoded["measurement_quality_remainder_hex"] = remainder[1:].hex()
    elif remainder:
        decoded["measurement_quality_remainder_hex"] = remainder.hex()
    return decoded


def parse_spo2_event_payload(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {}
    head = payload[0]
    raw_samples = list(payload[1:])
    terminated = 0xFF in raw_samples
    samples = raw_samples[: raw_samples.index(0xFF)] if terminated else raw_samples
    return {
        "spo2_base": ((head >> 4) & 0x0F) << 7,
        "spo2_status": head & 0x0F,
        "spo2_status_hex": f"0x{head & 0x0F:01X}",
        "spo2_samples": samples,
        "spo2_terminated": terminated,
    }


def parse_spo2_stable_event_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        return {}
    return {"spo2_stable_raw": struct.unpack_from(">H", payload, 0)[0]}


def parse_celsius_i16_samples(payload: bytes) -> list[float]:
    return [
        round(struct.unpack_from("<h", payload, offset)[0] / 100, 2)
        for offset in range(0, len(payload) - 1, 2)
    ]


def parse_u16_le_words(payload: bytes) -> list[int]:
    return [
        struct.unpack_from("<H", payload, offset)[0]
        for offset in range(0, len(payload) - 1, 2)
    ]


def decode_i24_le(value: bytes) -> int:
    if len(value) != 3:
        raise ProtocolError(f"i24 value needs 3 bytes, got {len(value)}")
    raw = value[0] | (value[1] << 8) | (value[2] << 16)
    if raw & 0x800000:
        raw -= 0x1000000
    return raw


def ibi_amplitude_records(
    ibis: list[int], amplitudes: list[int]
) -> list[dict[str, int | float]]:
    return [
        {
            "ibi_ms": ibi,
            "amplitude": amplitudes[index],
            "bpm_estimate": round(60000 / ibi, 1) if ibi > 0 else 0.0,
        }
        for index, ibi in enumerate(ibis)
    ]


def ibi_records(ibis: list[int]) -> list[dict[str, int | float]]:
    return [
        {
            "ibi_ms": ibi,
            "bpm_estimate": round(60000 / ibi, 1) if ibi > 0 else 0.0,
        }
        for ibi in ibis
    ]


def parse_ring_start_event_payload(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    if len(payload) >= 4:
        decoded["ring_start_marker_u32"] = struct.unpack_from("<I", payload, 0)[0]
    if len(payload) >= 5:
        decoded["ring_start_code"] = payload[4]
        decoded["ring_start_code_hex"] = f"0x{payload[4]:02X}"
    if len(payload) >= 8:
        decoded["firmware_version"] = semver(payload[5:8])
    if len(payload) >= 11:
        decoded["bootloader_version"] = semver(payload[8:11])
    if len(payload) >= 14:
        decoded["api_version"] = semver(payload[11:14])
    if len(payload) > 14:
        decoded["ring_start_extra_hex"] = payload[14:].hex()
    return decoded


def parse_debug_event_payload(
    event_tag: int, payload: bytes, decoded: dict[str, Any]
) -> dict[str, Any]:
    if EVENT_TAGS.get(event_tag) not in {"debug_event", "debug_data"}:
        return {}
    result: dict[str, Any] = {}
    if event_tag == 0x61 and payload:
        result["debug_data_code"] = payload[0]
        result["debug_data_code_hex"] = f"0x{payload[0]:02X}"
        code_meta = DEBUG_DATA_CODE_METADATA.get(payload[0])
        if code_meta:
            result["debug_data_code_category"] = code_meta["category"]
            result["debug_data_code_label"] = code_meta["label"]
            result["debug_category"] = code_meta["category"]
        if len(payload) > 1:
            result["debug_data_tail_hex"] = payload[1:].hex()
        result.update(parse_debug_data_code_payload(payload[0], payload[1:]))
    text = decoded.get("payload_text")
    if not isinstance(text, str) or not text:
        return result
    parsed = parse_debug_text(text)
    if not parsed:
        parsed = parse_debug_message(text)
    if parsed:
        result["debug_text"] = text
        result.update(parsed)
    return result


def parse_debug_text(text: str) -> dict[str, Any]:
    if ";" in text:
        parts = text.split(";")
        values = parts[1:]
        result: dict[str, Any] = {
            "debug_key": parts[0],
            "debug_values": values,
        }
    elif "=" in text:
        key, value = text.split("=", 1)
        result = {
            "debug_key": key,
            "debug_values": [value],
        }
    elif ":" in text:
        key, value = text.split(":", 1)
        result = {
            "debug_key": key,
            "debug_values": [value],
        }
    elif " " in text:
        parts = text.split()
        if len(parts) != 2 or not is_debug_numeric_token(parts[1]):
            return {}
        result = {
            "debug_key": parts[0],
            "debug_values": [parts[1]],
        }
    else:
        return {}
    numeric_values: list[int] = []
    for value in result["debug_values"]:
        try:
            numeric_values.append(int(value, 0))
        except ValueError:
            continue
    if numeric_values:
        result["debug_numeric_values"] = numeric_values
    annotate_debug_text_result(result)
    return result


def parse_debug_message(text: str) -> dict[str, Any]:
    meta = DEBUG_MESSAGE_METADATA.get(text)
    if not meta:
        return {}
    result: dict[str, Any] = {
        "debug_message": text,
        "debug_category": meta["category"],
        "debug_label": meta["label"],
    }
    for key in ("feature", "action"):
        if key in meta:
            result[f"debug_{key}"] = meta[key]
    return result


def parse_debug_data_code_payload(code: int, tail: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    code_meta = DEBUG_DATA_CODE_METADATA.get(code)
    if code_meta and code_meta["category"] in {
        "binary_debug",
        "identity",
        "setup_binary",
    }:
        words = parse_debug_data_tail_words(tail)
        if words:
            result["debug_data_tail_words"] = words
    if code == 0x24 and len(tail) >= 4:
        voltage_mv = struct.unpack_from("<H", tail, 1)[0]
        result["debug_data_battery"] = {
            "battery_level_percent": tail[0],
            "voltage_mv": voltage_mv,
            "status": tail[3],
            "status_hex": f"0x{tail[3]:02X}",
        }
        if len(tail) > 4:
            result["debug_data_battery"]["extra_hex"] = tail[4:].hex()
    if code == 0x14:
        power_sample = parse_debug_data_power_sample_candidate(tail)
        if power_sample:
            result["debug_data_power_sample_candidate"] = power_sample
    return result


def parse_debug_data_power_sample_candidate(tail: bytes) -> dict[str, Any]:
    """Parse observed 0x14 debug-data rows without assigning official names."""
    if len(tail) < 12:
        return {}
    result: dict[str, Any] = {
        "inferred": True,
        "source": "debug_data_code_0x14",
        "raw0_u16": struct.unpack_from("<H", tail, 0)[0],
        "voltage_mv_candidate": struct.unpack_from("<H", tail, 2)[0],
        "signed2_i16": struct.unpack_from("<h", tail, 4)[0],
        "signed3_i16": struct.unpack_from("<h", tail, 6)[0],
        "raw4_u16": struct.unpack_from("<H", tail, 8)[0],
        "raw5_u16": struct.unpack_from("<H", tail, 10)[0],
    }
    if len(tail) > 12:
        result["status_byte_candidate"] = tail[12]
        result["status_hex_candidate"] = f"0x{tail[12]:02X}"
    if len(tail) > 13:
        result["extra_hex"] = tail[13:].hex()
    return result


def parse_debug_data_tail_words(tail: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"byte_count": len(tail)}
    if len(tail) >= 2:
        result["u16_le"] = [
            struct.unpack_from("<H", tail, offset)[0]
            for offset in range(0, len(tail) - 1, 2)
        ]
        result["i16_le"] = [
            struct.unpack_from("<h", tail, offset)[0]
            for offset in range(0, len(tail) - 1, 2)
        ]
    if len(tail) >= 4:
        result["u32_le"] = [
            struct.unpack_from("<I", tail, offset)[0]
            for offset in range(0, len(tail) - 3, 4)
        ]
        result["i32_le"] = [
            struct.unpack_from("<i", tail, offset)[0]
            for offset in range(0, len(tail) - 3, 4)
        ]
    return result


def annotate_debug_text_result(result: dict[str, Any]) -> None:
    key = result.get("debug_key")
    if not isinstance(key, str):
        return
    meta = DEBUG_KEY_METADATA.get(key)
    if not meta:
        return
    result["debug_category"] = meta["category"]
    result["debug_label"] = meta["label"]
    fields = meta.get("fields")
    values = result.get("debug_values")
    if not isinstance(fields, tuple) or not isinstance(values, list):
        return
    result["debug_fields"] = {
        field: str(value)
        for field, value in zip(fields, values, strict=False)
    }


def is_debug_numeric_token(value: str) -> bool:
    try:
        int(value, 0)
    except ValueError:
        return False
    return True
