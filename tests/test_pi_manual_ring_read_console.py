from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def load_console_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/pi-manual-ring-read-console.py"
    spec = importlib.util.spec_from_file_location("pi_manual_ring_read_console", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


console = load_console_module()


def test_scan_heartbeat_is_compact() -> None:
    line = json.dumps(
        {
            "event": "raw_scan_heartbeat",
            "elapsed_seconds": 12.4,
            "payload": {
                "cycle": 2,
                "manufacturer_sample_count": 31,
                "manufacturer_counts": {"1006": 30, "04671b01": 1},
                "oura_candidate_counts": {},
                "unique_address_count": 8,
                "resolvable_address_count": 3,
                "scan_backend": "hci_le_scan",
                "seconds_remaining": 88.2,
                "manufacturer_rssi": {
                    "04671b01": {"samples": 2, "min": -60, "max": -42, "last": -42}
                },
                "manufacturer_addresses": {
                    "04671b01": {
                        "samples": 2,
                        "latest_address": "C1:22:33:44:55:66",
                        "latest_address_type": "Resolvable",
                        "max_rssi": -42,
                        "max_rssi_resolvable_address": "C1:22:33:44:55:66",
                        "max_rssi_address_type": "Resolvable",
                        "max_rssi_event_type": "Connectable undirected - ADV_IND (0x00)",
                    }
                },
                "address_rssi": {
                    "AA:BB:CC:DD:EE:FF": {
                        "samples": 7,
                        "max": -41,
                    }
                },
            },
        }
    )

    text = console.format_line(line)
    verbose_text = console.format_line(line, verbose=True)

    assert "[cycle 2 12.4s] scan" in text
    assert "samples=31" in text
    assert "addrs=8" in text
    assert "oura=0" in text
    assert "left=88s" in text
    assert "near_mfg" not in text
    assert "near_addr" not in text
    assert "address_rssi" not in text
    assert "AA:BB:CC:DD:EE:FF" not in text
    assert "near_mfg=04671b01:-42dBm/2" in verbose_text
    assert "near_addr=04671b01:-42dBm/C1:22:33:44:55:66/Resolvable/ADV_IND" in verbose_text


def test_read_result_uses_existing_summary() -> None:
    text = console.format_line(
        json.dumps(
            {
                "event": "read_result",
                "raw_cycle": 1,
                "payload": {
                    "firmware": {
                        "firmware_version": "2.11.0",
                        "api_version": "2.0.0",
                        "bluetooth_stack_version": "5.0.15",
                    },
                    "battery": {
                        "battery_level_percent": 86,
                        "charging_progress": 100,
                    },
                    "auth_nonce": {"nonce_hex": "00112233445566778899aabbccddee"},
                    "event_summary": {
                        "health_events": {
                            "event_counts": {"ibi_and_amplitude_event": 1},
                            "ibi_record_count": 6,
                            "bpm_estimate_min": 500.0,
                            "bpm_estimate_max": 750.0,
                        }
                    },
                },
            }
        )
    )

    assert text.startswith("[cycle 1] READ RESULT:")
    assert "fw=2.11.0 api=2.0.0 ble=5.0.15" in text
    assert "battery=86% charge=100%" in text
    assert "auth_nonce=15B" in text
    assert "health_events=events=ibi_and_amplitude_event:1" in text


def test_non_json_noise_is_suppressed_but_errors_pass_through() -> None:
    assert console.format_line("< HCI Command: LE Set Scan Enable") == ""
    assert console.format_line("random btmon chatter") == ""
    assert console.format_line("Traceback (most recent call last):") == (
        "Traceback (most recent call last):"
    )
    assert console.format_line("zeroauth_error: failed") == "zeroauth_error: failed"


def test_target_and_probe_events_are_human_readable() -> None:
    target = console.format_line(
        json.dumps(
            {
                "event": "raw_scan_target",
                "payload": {
                    "cycle": 4,
                    "rpa": "C1:22:33:44:55:66",
                    "target_signal": "manufacturer",
                    "manufacturer_hex": "04671b01",
                    "address_type": "Resolvable",
                    "scan_backend": "hci_le_scan",
                },
            }
        )
    )
    probe_line = json.dumps(
        {
            "event": "zeroauth_probe_tx",
            "raw_cycle": 4,
            "payload": {"packet": "battery"},
        }
    )
    probe = console.format_line(probe_line)
    verbose_probe = console.format_line(
        probe_line,
        verbose=True,
    )

    assert target == (
        "[cycle 4] TARGET: rpa=C1:22:33:44:55:66 signal=manufacturer "
        "mfg=04671b01 type=Resolvable backend=hci_le_scan"
    )
    assert probe == ""
    assert verbose_probe == "[cycle 4] probe tx: battery"
