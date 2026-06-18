#!/usr/bin/env python3
"""Summarize zero-auth Pi capture logs into probe-response evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from oura_ring4_ble import protocol as p


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize pi-bluez-zeroauth-stream JSONL captures."
    )
    parser.add_argument("logs", nargs="+", help="JSONL log paths")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    summaries = [summarize_log(Path(path)) for path in args.logs]
    if args.json:
        print(json.dumps(summaries, indent=2, sort_keys=True))
    else:
        print_text(summaries)
    return 0


def summarize_log(path: Path) -> dict[str, Any]:
    rows = read_jsonl(path)
    probes: dict[str, dict[str, Any]] = {}
    current_probe: dict[str, str] = {}
    raw_targets: list[dict[str, Any]] = []
    raw_oura_candidates: list[dict[str, Any]] = []
    scan_heartbeats: list[dict[str, Any]] = []
    no_target_windows: list[dict[str, Any]] = []
    physical_hints: list[dict[str, Any]] = []
    connect_attempts: list[dict[str, Any]] = []
    connections: list[dict[str, Any]] = []
    connect_failures: list[dict[str, Any]] = []
    connect_timeouts: list[dict[str, Any]] = []
    connect_cancels: list[dict[str, Any]] = []
    stream_runs = 0
    read_results: list[dict[str, Any]] = []
    latest_scan_status: dict[str, Any] | None = None
    latest_connect_status: dict[str, Any] | None = None

    for row in rows:
        event = row.get("event")
        payload = row.get("payload", {})
        raw_cycle = row.get("raw_cycle")
        if event == "raw_scan_target":
            raw_targets.append(payload)
            latest_scan_status = compact_scan_status(row, payload)
        elif event == "raw_scan_oura_candidate":
            raw_oura_candidates.append(payload)
            latest_scan_status = compact_scan_status(row, payload)
        elif event == "raw_scan_heartbeat":
            status = compact_scan_status(row, payload)
            scan_heartbeats.append(status)
            latest_scan_status = status
        elif event == "raw_cycle_no_target":
            status = compact_scan_status(row, payload)
            no_target_windows.append(status)
            latest_scan_status = status
        elif event == "raw_physical_toggle_hint":
            physical_hints.append(compact_scan_status(row, payload))
        elif event == "raw_connect_start":
            status = compact_connect_status(row, payload)
            connect_attempts.append(status)
            latest_connect_status = status
        elif event == "raw_connect_done":
            status = compact_connect_status(row, payload)
            if payload.get("returncode") == 0:
                connections.append(status)
            else:
                connect_failures.append(status)
            latest_connect_status = status
        elif event == "raw_connect_timeout":
            status = compact_connect_status(row, payload)
            connect_timeouts.append(status)
            latest_connect_status = status
        elif event == "raw_connect_cancel":
            status = compact_connect_status(row, payload)
            connect_cancels.append(status)
            latest_connect_status = status
        elif event == "zeroauth_stream_done":
            stream_runs += 1
        elif event == "read_result":
            read_results.append(payload)
        elif event == "zeroauth_probe_tx":
            current_probe = {
                "packet": str(payload.get("packet", "")),
                "tx_hex": str(payload.get("tx_hex", "")),
            }
            probe = get_probe(probes, current_probe, raw_cycle)
            probe["tx_count"] += 1
        elif event == "zeroauth_notify":
            probe_context = payload.get("probe_context") or current_probe
            probe = get_probe(probes, probe_context, raw_cycle)
            raw_hex = str(payload.get("raw_hex", ""))
            decoded_packets = decode_packets(raw_hex, str(probe_context.get("packet", "")))
            probe["notifications"].append(
                {
                    "raw_hex": raw_hex,
                    "decoded": decoded_packets,
                }
            )
            probe["raw_responses"][raw_hex] += 1
        elif event == "zeroauth_probe_error":
            probe_context = {
                "packet": str(payload.get("packet", "")),
                "tx_hex": str(payload.get("tx_hex", "")),
            }
            probe = get_probe(probes, probe_context, raw_cycle)
            probe["errors"].append(
                {
                    "error_type": payload.get("error_type"),
                    "error": payload.get("error"),
                }
            )

    summarized_probes = []
    for probe in sorted(probes.values(), key=lambda item: item["packet"]):
        raw_responses = dict(sorted(probe.pop("raw_responses").items()))
        probe["raw_responses"] = raw_responses
        probe["classification"] = classify_probe(probe)
        probe["details"] = summarize_probe_details(probe)
        summarized_probes.append(probe)

    return {
        "log": str(path),
        "raw_target_count": len(raw_targets),
        "connection_attempt_count": len(connect_attempts),
        "connection_success_count": len(connections),
        "connection_failure_count": len(connect_failures),
        "connection_timeout_count": len(connect_timeouts),
        "connect_cancel_count": len(connect_cancels),
        "zeroauth_stream_count": stream_runs,
        "read_result_count": len(read_results),
        "latest_read_result": read_results[-1] if read_results else None,
        "latest_connect_status": latest_connect_status,
        "raw_targets": raw_targets,
        "scan": {
            "heartbeat_count": len(scan_heartbeats),
            "no_target_window_count": len(no_target_windows),
            "oura_candidate_count": len(raw_oura_candidates),
            "physical_hint_count": len(physical_hints),
            "latest_status": latest_scan_status,
            "latest_no_target": no_target_windows[-1] if no_target_windows else None,
            "latest_oura_candidate": (
                raw_oura_candidates[-1] if raw_oura_candidates else None
            ),
            "latest_physical_hint": physical_hints[-1] if physical_hints else None,
        },
        "probes": summarized_probes,
    }


def get_probe(
    probes: dict[str, dict[str, Any]], context: dict[str, Any], raw_cycle: int | None
) -> dict[str, Any]:
    packet = str(context.get("packet", "unknown") or "unknown")
    tx_hex = str(context.get("tx_hex", "") or "")
    key = f"{packet}|{tx_hex}"
    if key not in probes:
        probes[key] = {
            "packet": packet,
            "tx_hex": tx_hex,
            "cycles": [],
            "tx_count": 0,
            "notifications": [],
            "raw_responses": defaultdict(int),
            "errors": [],
        }
    if raw_cycle is not None and raw_cycle not in probes[key]["cycles"]:
        probes[key]["cycles"].append(raw_cycle)
    return probes[key]


def classify_probe(probe: dict[str, Any]) -> str:
    decoded_rows = [
        decoded
        for notification in probe["notifications"]
        for decoded in notification.get("decoded", [])
    ]
    if any(
        decoded.get("extended_name") == "auth_status_response"
        for decoded in decoded_rows
    ):
        return "auth_gated"
    if probe["notifications"]:
        return "open_response"
    if any("Not connected" in str(error.get("error", "")) for error in probe["errors"]):
        return "not_connected"
    if probe["errors"]:
        return "write_error"
    return "no_response"


def decode_packets(raw_hex: str, packet_name: str) -> list[dict[str, Any]]:
    try:
        product_info_type: str | bytes | None = None
        if packet_name.startswith("product_info_hex:"):
            product_info_type = bytes.fromhex(packet_name.split(":", 1)[1])
        elif packet_name.startswith("product_info:"):
            product_info_type = packet_name.split(":", 1)[1]
        return [
            p.parse_response(packet, product_info_type=product_info_type)["decoded"]
            for packet in p.parse_packets(bytes.fromhex(raw_hex))
        ]
    except Exception:
        return []


def summarize_probe_details(probe: dict[str, Any]) -> list[str]:
    details: list[str] = []
    for notification in probe["notifications"]:
        for decoded in notification.get("decoded", []):
            detail = summarize_decoded(decoded)
            if detail and detail not in details:
                details.append(detail)
    return details


def compact_scan_status(row: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "cycle",
        "no_target_classification",
        "scan_backend",
        "seconds_remaining",
        "last_address",
        "last_address_type",
        "last_address_kind",
        "last_event_type",
        "manufacturer_hex",
        "raw_manufacturer_hex",
        "rpa",
        "rpa_source",
        "reason",
        "physical_state_note",
        "note",
    ]
    status = {
        "event": row.get("event"),
        "elapsed_seconds": row.get("elapsed_seconds"),
    }
    for field in fields:
        if field in payload:
            status[field] = payload.get(field)
    for field in ["manufacturer_counts", "resolvable_counts", "oura_candidate_counts"]:
        counts = payload.get(field)
        if isinstance(counts, dict):
            status[field] = sort_counts(counts)
    return status


def sort_counts(counts: dict[str, Any]) -> dict[str, int]:
    int_counts = {str(key): int(value) for key, value in counts.items()}
    return dict(
        sorted(int_counts.items(), key=lambda item: (-item[1], item[0]))
    )


def compact_connect_status(row: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    status = {
        "event": row.get("event"),
        "elapsed_seconds": row.get("elapsed_seconds"),
    }
    for field in ["cycle", "rpa", "returncode", "stdout", "stderr", "timeout", "reason"]:
        if field in payload:
            status[field] = payload.get(field)
    command = payload.get("command")
    if isinstance(command, dict):
        status["command_returncode"] = command.get("returncode")
        status["command_timeout"] = command.get("timeout", False)
    return status


def summarize_decoded(decoded: dict[str, Any]) -> str:
    if "event_name" in decoded:
        text = (
            "event={event_name} boot_ts={device_boot_timestamp} "
            "payload_len={payload_length}"
        ).format(**decoded)
        if decoded.get("event_name") == "ring_start":
            details = []
            marker = decoded.get("ring_start_marker_u32")
            if marker is not None:
                details.append(f"marker={marker}")
            code = decoded.get("ring_start_code_hex")
            if code:
                details.append(f"code={code}")
            firmware = decoded.get("firmware_version")
            if firmware:
                details.append(f"fw={firmware}")
            bootloader = decoded.get("bootloader_version")
            if bootloader:
                details.append(f"bootloader={bootloader}")
            api = decoded.get("api_version")
            if api:
                details.append(f"api={api}")
            if details:
                return f"{text} {' '.join(details)}"
        payload_text = decoded.get("payload_text")
        if payload_text:
            debug_key = decoded.get("debug_key")
            debug_values = decoded.get("debug_values")
            if debug_key and isinstance(debug_values, list):
                return (
                    f"{text} text={payload_text} "
                    f"debug={debug_key}:{','.join(str(value) for value in debug_values)}"
                )
            return f"{text} text={payload_text}"
        printable_runs = decoded.get("printable_runs") or []
        if printable_runs:
            runs = "|".join(str(run) for run in printable_runs[:3])
            return f"{text} runs={runs}"
        debug_code = decoded.get("debug_data_code_hex")
        if debug_code:
            battery = decoded.get("debug_data_battery")
            if isinstance(battery, dict):
                return (
                    f"{text} debug_code={debug_code} "
                    f"battery={battery.get('battery_level_percent')}% "
                    f"voltage={battery.get('voltage_mv')}mV "
                    f"status={battery.get('status_hex')}"
                )
            power_sample = power_sample_candidate_from_decoded(decoded)
            if isinstance(power_sample, dict):
                return (
                    f"{text} debug_code={debug_code} "
                    f"power_candidate={format_power_debug_candidate(power_sample)}"
                )
            words = decoded.get("debug_data_tail_words")
            if isinstance(words, dict):
                return (
                    f"{text} debug_code={debug_code} "
                    f"words={format_debug_tail_words(words)}"
                )
            return f"{text} debug_code={debug_code}"
        return text
    if "firmware_version" in decoded:
        return (
            "fw={firmware_version} api={api_version} ble={bluetooth_stack_version}"
        ).format(**decoded)
    if "events_received" in decoded:
        return "events_done count={events_received} bytes_left={bytes_left}".format(
            events_received=decoded.get("events_received", ""),
            bytes_left=decoded.get("bytes_left", ""),
        )
    if decoded.get("extended_name") == "auth_nonce_response":
        return f"nonce={decoded.get('nonce_hex', '')}"
    if decoded.get("extended_name") == "capabilities_response":
        entries = decoded.get("capability_entries") or []
        if entries:
            entry_text = ", ".join(
                "{feature}=0x{value:02x}".format(
                    feature=entry.get("feature_name")
                    if entry.get("feature_name") != "unknown"
                    else f"feature_0x{entry.get('feature_id', 0):02x}",
                    value=int(entry.get("capability_value", 0)),
                )
                for entry in entries
            )
            return "capabilities page={page_hex} entries={entries}: {entry_text}".format(
                page_hex=decoded["page_hex"],
                entries=len(entries),
                entry_text=entry_text,
            )
        return "capabilities page={page_hex} payload={payload_hex}".format(**decoded)
    if decoded.get("extended_name") == "feature_status_response":
        return (
            "feature_status {feature}=mode:{mode} status:{status} "
            "state:{state} sub:{subscription}"
        ).format(
            feature=feature_status_label(decoded),
            mode=decoded.get("mode_name", ""),
            status=decoded.get("status_name", ""),
            state=decoded.get("state_name", ""),
            subscription=decoded.get("subscription_mode_name", ""),
        )
    if decoded.get("extended_name") in {
        "set_feature_mode_response",
        "set_feature_subscription_response",
    }:
        return "feature_set {kind} {feature}=result:{result}".format(
            kind=decoded.get("extended_name", "").removeprefix("set_"),
            feature=feature_status_label(decoded),
            result=decoded.get("result_name", ""),
        )
    if decoded.get("extended_name") == "auth_status_response":
        return "auth={auth_result}".format(**decoded)
    if decoded.get("response_name") == "set_ring_mode_status":
        return "ring_mode status={status_name} raw={status}".format(**decoded)
    if "info_type_name" in decoded:
        value = decoded.get("value_text")
        if value is None and decoded.get("printable_runs"):
            value = "/".join(decoded["printable_runs"])
        if value is None:
            value = decoded.get("value_hex", "")
        info_type_name = decoded["info_type_name"]
        if info_type_name == "unknown":
            info_type_name = f"product_info:{decoded.get('request_type_hex', 'unknown')}"
        return f"{info_type_name}={value}"
    return ""


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def print_text(summaries: list[dict[str, Any]]) -> None:
    for summary in summaries:
        print(f"log: {summary['log']}")
        print(
            "  targets={raw_target_count} connections={connection_success_count} "
            "streams={zeroauth_stream_count} read_results={read_result_count}".format(
                **summary
            )
        )
        print_connect_text(summary)
        print_scan_text(summary["scan"])
        print_read_result_text(summary.get("latest_read_result"))
        for probe in summary["probes"]:
            detail_text = format_limited_items(
                probe["details"], separator="; ", max_items=24
            )
            print(
                "  {packet} ({tx_hex}) -> {classification}; "
                "responses={responses}; errors={errors}{details}".format(
                    packet=probe["packet"],
                    tx_hex=probe["tx_hex"],
                    classification=probe["classification"],
                    responses=format_limited_items(probe["raw_responses"]),
                    errors=len(probe["errors"]),
                    details=f"; {detail_text}" if detail_text else "",
                )
            )


def print_read_result_text(result: dict[str, Any] | None) -> None:
    if not result:
        return
    parts = []
    firmware = result.get("firmware")
    if isinstance(firmware, dict):
        parts.append(
            "fw={firmware_version} api={api_version} ble={bluetooth_stack_version}".format(
                **firmware
            )
        )
    auth_nonce = result.get("auth_nonce")
    if isinstance(auth_nonce, dict):
        parts.append(f"nonce={auth_nonce.get('nonce_hex', '')}")
    battery = result.get("battery")
    if isinstance(battery, dict):
        parts.append(format_battery(battery))
    device_snapshot = result.get("device_snapshot")
    if isinstance(device_snapshot, dict) and device_snapshot:
        parts.append(format_device_snapshot(device_snapshot))
    event_summary = result.get("event_summary")
    if isinstance(event_summary, dict) and event_summary:
        parts.append(format_event_summary(event_summary))
    feature_summary = result.get("feature_summary")
    if isinstance(feature_summary, dict) and feature_summary:
        parts.append(format_feature_summary(feature_summary))
    feature_status = result.get("feature_status")
    if isinstance(feature_status, dict) and feature_status:
        compact = ", ".join(
            format_feature_status_row(row)
            for _key, row in sorted(feature_status.items())
            if isinstance(row, dict)
        )
        if compact:
            parts.append(f"feature_status: {compact}")
    feature_set_results = result.get("feature_set_results")
    if isinstance(feature_set_results, list) and feature_set_results:
        compact = ", ".join(
            format_feature_set_result(row)
            for row in feature_set_results
            if isinstance(row, dict)
        )
        if compact:
            parts.append(f"feature_set: {compact}")
    ring_mode_results = result.get("ring_mode_results")
    if isinstance(ring_mode_results, list) and ring_mode_results:
        compact = ", ".join(
            format_ring_mode_result(row)
            for row in ring_mode_results
            if isinstance(row, dict)
        )
        if compact:
            parts.append(f"ring_mode: {compact}")
    product_info = result.get("product_info")
    if isinstance(product_info, dict) and product_info:
        compact = ", ".join(
            f"{key}={value}" for key, value in sorted(product_info.items())
        )
        parts.append(f"product_info: {compact}")
    memory = result.get("product_info_memory")
    if isinstance(memory, dict) and memory.get("byte_count"):
        parts.append(format_product_info_memory(memory))
    events = result.get("events")
    if isinstance(events, list) and events:
        parts.append(f"events={len(events)}")
    events_done = result.get("events_done")
    if isinstance(events_done, list) and events_done:
        latest = events_done[-1]
        parts.append(
            "events_done count={count} bytes_left={bytes_left}".format(
                count=latest.get("events_received", ""),
                bytes_left=latest.get("bytes_left", ""),
            )
        )
    auth_gated = result.get("auth_gated")
    if isinstance(auth_gated, list) and auth_gated:
        parts.append("auth_gated=" + ",".join(str(item) for item in auth_gated))
    unattributed = result.get("unattributed_notifications")
    if isinstance(unattributed, list) and unattributed:
        parts.append(f"unattributed_notifications={len(unattributed)}")
    if parts:
        print(f"  latest_read_result: {'; '.join(parts)}")


def format_limited_items(
    values: Any,
    *,
    separator: str = ", ",
    max_items: int = 10,
) -> str:
    if isinstance(values, dict):
        items = [str(key) for key in values]
    else:
        items = [str(value) for value in values or []]
    if not items:
        return "-"
    if len(items) <= max_items:
        return separator.join(items)
    visible = separator.join(items[:max_items])
    return f"{visible}{separator}... ({len(items)} total)"


def feature_status_label(decoded: dict[str, Any]) -> str:
    feature_name = decoded.get("feature_name")
    feature_id = decoded.get("feature_id")
    if feature_name and feature_name != "unknown":
        return str(feature_name)
    if isinstance(feature_id, int):
        return f"feature_0x{feature_id:02x}"
    return "feature_unknown"


def format_feature_status_row(decoded: dict[str, Any]) -> str:
    return "{feature}={mode}/{status}/{state}/{subscription}".format(
        feature=feature_status_label(decoded),
        mode=decoded.get("mode_name", ""),
        status=decoded.get("status_name", ""),
        state=decoded.get("state_name", ""),
        subscription=decoded.get("subscription_mode_name", ""),
    )


def format_feature_summary(summary: dict[str, Any]) -> str:
    pieces = [f"count={summary.get('count')}"]
    for key, label in (
        ("modes", "modes"),
        ("statuses", "statuses"),
        ("states", "states"),
        ("subscriptions", "subs"),
    ):
        counts = summary.get(key)
        if isinstance(counts, dict) and counts:
            pieces.append(f"{label}={compact_count_map(counts)}")
    health = summary.get("health_features")
    if isinstance(health, dict) and health:
        pieces.append(
            "health="
            + ",".join(f"{key}:{value}" for key, value in sorted(health.items()))
        )
    active = summary.get("active_features")
    if isinstance(active, list) and active:
        pieces.append("active=" + compact_list(active))
    return "feature_summary: " + " ".join(pieces)


def format_feature_set_result(decoded: dict[str, Any]) -> str:
    return "{packet}:{feature}/{result}".format(
        packet=decoded.get("packet", ""),
        feature=feature_status_label(decoded),
        result=decoded.get("result_name", ""),
    )


def format_battery(battery: dict[str, Any]) -> str:
    pieces = [f"battery={battery.get('battery_level_percent')}%"]
    progress = battery.get("charging_progress")
    if progress is not None:
        pieces.append(f"charge_progress={progress}%")
    voltage = battery.get("voltage_mv")
    if voltage is not None:
        pieces.append(f"voltage={voltage}mV")
    status_hex = battery.get("battery_status_hex")
    if status_hex is not None:
        pieces.append(f"status={status_hex}")
    return " ".join(pieces)


def format_ring_mode_result(decoded: dict[str, Any]) -> str:
    return "{packet}/{status}".format(
        packet=decoded.get("packet", "ring_mode"),
        status=decoded.get("status_name", "unknown"),
    )


def format_device_snapshot(snapshot: dict[str, Any]) -> str:
    pieces = []
    for key, label in (
        ("serial_number", "serial"),
        ("hardware_id", "hw"),
        ("firmware_git", "git"),
        ("setup_transition", "transition"),
    ):
        value = snapshot.get(key)
        if value:
            pieces.append(f"{label}={value}")
    battery = snapshot.get("battery")
    if isinstance(battery, dict):
        level = battery.get("level_percent")
        progress = battery.get("charging_progress")
        voltage = battery.get("voltage_mv")
        if level is not None:
            pieces.append(f"battery={level}%")
        if progress is not None:
            pieces.append(f"charge_progress={progress}%")
        if voltage is not None:
            pieces.append(f"voltage={voltage}mV")
    battery_debug = snapshot.get("battery_debug")
    if isinstance(battery_debug, dict) and battery_debug:
        pieces.append("battery_debug=" + format_battery_debug(battery_debug))
    power_debug = snapshot.get("power_debug_candidate")
    if isinstance(power_debug, dict) and power_debug:
        pieces.append("power_candidate=" + format_power_debug_candidate(power_debug))
    charger = snapshot.get("charger_debug")
    if isinstance(charger, dict):
        compact = []
        for key, row in sorted(charger.items()):
            if isinstance(row, dict) and isinstance(row.get("values"), list):
                compact.append(f"{key}:{','.join(str(value) for value in row['values'])}")
        if compact:
            pieces.append("charger=" + "|".join(compact[:6]))
    charger_state = snapshot.get("charger_state")
    if isinstance(charger_state, dict) and charger_state:
        pieces.append("charger_state=" + format_charger_state(charger_state))
    fuel_gauge_state = snapshot.get("fuel_gauge_state")
    if isinstance(fuel_gauge_state, dict) and fuel_gauge_state:
        pieces.append("fuel_gauge=" + format_fuel_gauge_state(fuel_gauge_state))
    setup_state = snapshot.get("setup_state")
    if isinstance(setup_state, dict) and setup_state:
        pieces.append("setup_state=" + format_setup_state(setup_state))
    health = snapshot.get("health_features")
    if isinstance(health, dict):
        compact = ",".join(
            f"{key}:{value}" for key, value in sorted(health.items())
        )
        if compact:
            pieces.append(f"health={compact}")
    if not pieces:
        return "device_snapshot"
    return "device_snapshot: " + " ".join(pieces)


def format_battery_debug(state: dict[str, Any]) -> str:
    pieces = []
    level = state.get("battery_level_percent")
    if level is not None:
        pieces.append(f"{level}%")
    voltage = state.get("voltage_mv")
    if voltage is not None:
        pieces.append(f"voltage={voltage}mV")
    status = state.get("status_hex")
    if status is not None:
        pieces.append(f"status={status}")
    min_voltage = state.get("min_voltage_mv")
    max_voltage = state.get("max_voltage_mv")
    if min_voltage is not None and max_voltage is not None:
        pieces.append(f"range={min_voltage}-{max_voltage}mV")
    sample_count = state.get("sample_count")
    if sample_count is not None:
        pieces.append(f"n={sample_count}")
    timestamp = state.get("device_boot_timestamp")
    if timestamp is not None:
        pieces.append(f"ts={timestamp}")
    return ",".join(str(piece) for piece in pieces) if pieces else "present"


def power_sample_candidate_from_decoded(decoded: dict[str, Any]) -> dict[str, Any] | None:
    sample = decoded.get("debug_data_power_sample_candidate")
    if isinstance(sample, dict):
        return sample
    if decoded.get("debug_data_code_hex") != "0x14":
        return None
    tail_hex = decoded.get("debug_data_tail_hex")
    if not isinstance(tail_hex, str):
        return None
    try:
        return p.parse_debug_data_power_sample_candidate(bytes.fromhex(tail_hex))
    except ValueError:
        return None


def format_power_debug_candidate(state: dict[str, Any]) -> str:
    pieces = []
    voltage = state.get("voltage_mv_candidate")
    if voltage is not None:
        pieces.append(f"voltage={voltage}mV?")
    signed2 = state.get("signed2_i16")
    if signed2 is not None:
        pieces.append(f"signed2={signed2}")
    signed3 = state.get("signed3_i16")
    if signed3 is not None:
        pieces.append(f"signed3={signed3}")
    status = state.get("status_hex_candidate")
    if status is not None:
        pieces.append(f"status={status}?")
    min_voltage = state.get("min_voltage_mv_candidate")
    max_voltage = state.get("max_voltage_mv_candidate")
    if min_voltage is not None and max_voltage is not None:
        pieces.append(f"range={min_voltage}-{max_voltage}mV?")
    sample_count = state.get("sample_count")
    if sample_count is not None:
        pieces.append(f"n={sample_count}")
    timestamp = state.get("device_boot_timestamp")
    if timestamp is not None:
        pieces.append(f"ts={timestamp}")
    return ",".join(str(piece) for piece in pieces) if pieces else "present"


def format_debug_tail_words(words: dict[str, Any], max_items: int = 4) -> str:
    pieces = []
    byte_count = words.get("byte_count")
    if byte_count is not None:
        pieces.append(f"bytes={byte_count}")
    for key in ("u16_le", "i16_le", "u32_le", "i32_le"):
        values = words.get(key)
        if isinstance(values, list) and values:
            pieces.append(f"{key}={compact_number_list(values, max_items=max_items)}")
    return ",".join(pieces) if pieces else "present"


def compact_number_list(values: list[Any], max_items: int = 4) -> str:
    items = [str(value) for value in values]
    if len(items) <= max_items:
        return "/".join(items)
    return "/".join(items[:max_items]) + f"/...({len(items)} total)"


def format_charger_state(state: dict[str, Any]) -> str:
    pieces = []
    if "indicator_percent" in state:
        indicator = str(state["indicator_percent"])
        if "indicator_flag" in state:
            indicator += f"/{state['indicator_flag']}"
        pieces.append(f"ind={indicator}")
    if "rp_state" in state:
        rp = str(state["rp_state"])
        if "rp_raw" in state:
            rp += f"/{state['rp_raw']}"
        pieces.append(f"rp={rp}")
    if "rc_state" in state:
        rc = str(state["rc_state"])
        if "rc_flag" in state:
            rc += f"/{state['rc_flag']}"
        pieces.append(f"rc={rc}")
    if "hs_raw" in state:
        pieces.append(f"hs={state['hs_raw']}")
    if "chgv_raw_a" in state:
        chgv = str(state["chgv_raw_a"])
        if "chgv_raw_b" in state:
            chgv += f"/{state['chgv_raw_b']}"
        pieces.append(f"chgv={chgv}")
    if "bc_state" in state:
        pieces.append(f"bc={state['bc_state']}")
    if "brx_state" in state:
        brx = str(state["brx_state"])
        if "brx_raw" in state:
            brx += f"/{state['brx_raw']}"
        if "brx_flag" in state:
            brx += f"/{state['brx_flag']}"
        pieces.append(f"brx={brx}")
    if "charger_status_hex" in state:
        status = str(state["charger_status_hex"])
        bits = state.get("charger_status_bits")
        if isinstance(bits, list) and bits:
            status += "[" + "/".join(str(bit) for bit in bits) + "]"
        pieces.append(f"chg_status={status}")
    if "rcell_hex" in state:
        rcell = str(state["rcell_hex"])
        if "rcell_raw" in state:
            rcell += f"/{state['rcell_raw']}"
        pieces.append(f"rcell={rcell}")
    if "latest_boot_timestamp" in state:
        pieces.append(f"ts={state['latest_boot_timestamp']}")
    return ",".join(pieces) if pieces else "present"


def format_fuel_gauge_state(state: dict[str, Any]) -> str:
    pieces = []
    if "vf_percent_candidate" in state:
        pieces.append(f"vf%?={state['vf_percent_candidate']}")
    if "lcu_value_a_candidate" in state:
        lcu = str(state["lcu_value_a_candidate"])
        if "lcu_value_b_candidate" in state:
            lcu += f"/{state['lcu_value_b_candidate']}"
        pieces.append(f"lcu?={lcu}")
    if "design_capacity_candidate" in state:
        pieces.append(f"dcap?={state['design_capacity_candidate']}")
    if "latest_boot_timestamp" in state:
        pieces.append(f"ts={state['latest_boot_timestamp']}")
    return ",".join(pieces) if pieces else "present"


def format_setup_state(state: dict[str, Any]) -> str:
    pieces = []
    for key, label in (
        ("transition", "transition"),
        ("in_bed_flag", "in_bed"),
        ("info_state", "info"),
        ("boot_context", "bc"),
        ("platform_flags", "pf"),
        ("eflo_flag", "eflo"),
        ("bls_state", "bls"),
        ("ccm", "ccm"),
        ("ccv_value", "ccv"),
        ("ble_setup_state_a", "ble_state"),
        ("ble_security_state", "ble_sec"),
        ("ble_p256_state", "ble_p256"),
    ):
        if key in state:
            pieces.append(f"{label}={state[key]}")
    if "ccp_value" in state:
        ccp = str(state["ccp_value"])
        if "ccp_status" in state:
            ccp += f"/{state['ccp_status']}"
        pieces.append(f"ccp={ccp}")
    if "mfc_value" in state:
        mfc = str(state["mfc_value"])
        if "mfc_status" in state:
            mfc += f"/{state['mfc_status']}"
        pieces.append(f"mfc={mfc}")
    if "tef_code" in state:
        tef = str(state["tef_code"])
        if "tef_status" in state:
            tef += f"/{state['tef_status']}"
        pieces.append(f"tef={tef}")
    if "latest_boot_timestamp" in state:
        pieces.append(f"ts={state['latest_boot_timestamp']}")
    return ",".join(pieces) if pieces else "present"


def format_event_summary(summary: dict[str, Any]) -> str:
    pieces = [f"count={summary.get('count')}"]
    unique_count = summary.get("unique_count")
    duplicate_count = summary.get("duplicate_count")
    if unique_count is not None:
        pieces.append(f"unique={unique_count}")
    if duplicate_count is not None:
        pieces.append(f"duplicates={duplicate_count}")
    first = summary.get("first_boot_timestamp")
    last = summary.get("last_boot_timestamp")
    if first is not None and last is not None:
        pieces.append(f"span={first}-{last}")
    next_start = summary.get("next_start_timestamp")
    if next_start is not None:
        pieces.append(f"next=0x{int(next_start):08x}")
    latest_done = summary.get("latest_events_done")
    if isinstance(latest_done, dict):
        request_start = latest_done.get("request_start_timestamp")
        if request_start is not None:
            pieces.append(
                "req=0x{start:08x}/{max_events}".format(
                    start=int(request_start),
                    max_events=latest_done.get("request_max_events", ""),
                )
            )
        pieces.append(
            "done={count}/bytes_left={bytes_left}".format(
                count=latest_done.get("events_received", ""),
                bytes_left=latest_done.get("bytes_left", ""),
            )
        )
    if summary.get("complete") is True:
        pieces.append("complete=true")
    debug_keys = summary.get("debug_keys")
    if isinstance(debug_keys, dict) and debug_keys:
        pieces.append("keys=" + compact_count_map(debug_keys))
    debug_categories = summary.get("debug_categories")
    if isinstance(debug_categories, dict) and debug_categories:
        pieces.append("categories=" + compact_count_map(debug_categories))
    debug_codes = summary.get("debug_data_codes")
    if isinstance(debug_codes, dict) and debug_codes:
        pieces.append("codes=" + compact_count_map(debug_codes))
    charger_activity = summary.get("charger_activity")
    if isinstance(charger_activity, dict) and charger_activity:
        pieces.append("charger_activity=" + format_charger_activity(charger_activity))
    health_events = summary.get("health_events")
    if isinstance(health_events, dict) and health_events:
        pieces.append("health_events=" + format_health_events(health_events))
    debug_value_stats = summary.get("debug_value_stats")
    if isinstance(debug_value_stats, dict) and debug_value_stats:
        pieces.append("values=" + format_debug_value_stats(debug_value_stats))
    return "event_summary: " + " ".join(pieces)


def format_health_events(summary: dict[str, Any]) -> str:
    pieces: list[str] = []
    event_counts = summary.get("event_counts")
    if isinstance(event_counts, dict) and event_counts:
        pieces.append("events=" + compact_count_map(event_counts, max_items=5))
    ibi_count = summary.get("ibi_record_count")
    if isinstance(ibi_count, int) and not isinstance(ibi_count, bool):
        pieces.append(f"ibi={ibi_count}")
    bpm_min = summary.get("bpm_estimate_min")
    bpm_max = summary.get("bpm_estimate_max")
    bpm_latest = summary.get("bpm_estimate_latest")
    if bpm_min is not None and bpm_max is not None:
        pieces.append(f"bpm={bpm_min}-{bpm_max}")
    if bpm_latest is not None:
        pieces.append(f"latest_bpm={bpm_latest}")
    spo2_count = summary.get("spo2_sample_count")
    if isinstance(spo2_count, int) and not isinstance(spo2_count, bool):
        pieces.append(
            "spo2_raw={count}:{minimum}-{maximum}".format(
                count=spo2_count,
                minimum=summary.get("spo2_value_min"),
                maximum=summary.get("spo2_value_max"),
            )
        )
    temp_count = summary.get("temperature_sample_count")
    if isinstance(temp_count, int) and not isinstance(temp_count, bool):
        pieces.append(
            "temp_c={count}:{minimum}-{maximum}".format(
                count=temp_count,
                minimum=summary.get("temperature_c_min"),
                maximum=summary.get("temperature_c_max"),
            )
        )
    quality_count = summary.get("green_ibi_quality_sample_count")
    if isinstance(quality_count, int) and not isinstance(quality_count, bool):
        pieces.append(f"green_quality={quality_count}")
    ppg_count = summary.get("ppg_amplitude_count")
    if isinstance(ppg_count, int) and not isinstance(ppg_count, bool):
        pieces.append(f"ppg_amp={ppg_count}")
    return ",".join(pieces)


def format_charger_activity(activity: dict[str, Any]) -> str:
    pieces = []
    event_count = activity.get("event_count")
    if event_count is not None:
        pieces.append(f"events={event_count}")
    span = activity.get("span_seconds")
    if span is not None:
        pieces.append(f"span={span}s")
    key_counts = activity.get("key_counts")
    if isinstance(key_counts, dict) and key_counts:
        pieces.append("keys=" + compact_count_map(key_counts, max_items=5))
    for key, label in (
        ("rp_state_counts", "rp_states"),
        ("rc_state_counts", "rc_states"),
        ("bc_state_counts", "bc_states"),
        ("brx_state_counts", "brx_states"),
        ("brx_flag_counts", "brx_flags"),
        ("indicator_flag_counts", "ind_flags"),
        ("charger_status_counts", "chg_status"),
    ):
        counts = activity.get(key)
        if isinstance(counts, dict) and counts:
            pieces.append(f"{label}=" + compact_count_map(counts, max_items=5))
    for prefix, label in (
        ("indicator_percent", "ind"),
        ("rp_raw", "rp_raw"),
        ("hs_raw", "hs"),
        ("chgv_raw_a", "chgv_a"),
        ("chgv_raw_b", "chgv_b"),
        ("rcell_raw", "rcell"),
        ("brx_raw", "brx_raw"),
    ):
        text = format_numeric_range(activity, prefix)
        if text:
            pieces.append(f"{label}={text}")
    return ",".join(pieces) if pieces else "present"


def format_numeric_range(activity: dict[str, Any], prefix: str) -> str:
    latest = activity.get(f"{prefix}_latest")
    low = activity.get(f"{prefix}_min")
    high = activity.get(f"{prefix}_max")
    if latest is None:
        return ""
    if low is not None and high is not None:
        return f"{latest}({low}-{high})"
    return str(latest)


def format_debug_value_stats(values: dict[str, Any], max_items: int = 6) -> str:
    items = []
    for key, row in sorted(
        values.items(),
        key=lambda item: (-int(item[1].get("count", 0)), item[0])
        if isinstance(item[1], dict)
        else (0, item[0]),
    ):
        if not isinstance(row, dict):
            continue
        piece = f"{key}:n{row.get('count')}"
        latest = row.get("latest_values")
        if isinstance(latest, list) and latest:
            piece += " latest=" + ",".join(str(value) for value in latest)
        min_values = row.get("min_numeric_values")
        max_values = row.get("max_numeric_values")
        if isinstance(min_values, list) and isinstance(max_values, list):
            ranges = []
            for low, high in zip(min_values, max_values, strict=False):
                ranges.append(f"{low}-{high}")
            if ranges:
                piece += " range=" + ",".join(ranges)
        items.append(piece)
    if len(items) <= max_items:
        return ";".join(items)
    return ";".join(items[:max_items]) + f";...({len(items)} total)"


def compact_count_map(values: dict[str, Any], max_items: int = 8) -> str:
    items = [
        f"{key}:{value}"
        for key, value in sorted(values.items(), key=lambda item: (-int(item[1]), item[0]))
    ]
    if len(items) <= max_items:
        return ",".join(items)
    return ",".join(items[:max_items]) + f",...({len(items)} total)"


def compact_list(values: list[Any], max_items: int = 8) -> str:
    items = [str(value) for value in values]
    if len(items) <= max_items:
        return ",".join(items)
    return ",".join(items[:max_items]) + f",...({len(items)} total)"


def format_product_info_memory(memory: dict[str, Any]) -> str:
    segments = [
        "{start}-{end} ({length}B)".format(
            start=segment.get("start"),
            end=segment.get("end_exclusive"),
            length=segment.get("length"),
        )
        for segment in memory.get("segments", [])
        if isinstance(segment, dict)
    ]
    text_runs = []
    for segment in memory.get("segments", []):
        if not isinstance(segment, dict):
            continue
        for run in segment.get("printable_runs", []):
            if isinstance(run, dict):
                text_runs.append(f"{run.get('offset')}={run.get('text')}")
    pieces = [
        f"bytes={memory.get('byte_count')}",
        f"sources={memory.get('source_count')}",
    ]
    if segments:
        pieces.append("ranges=" + ",".join(segments))
    if text_runs:
        pieces.append("text=" + ",".join(text_runs))
    conflicts = memory.get("conflicts")
    if isinstance(conflicts, list) and conflicts:
        pieces.append(f"conflicts={len(conflicts)}")
    return "product_info_memory: " + " ".join(pieces)


def print_connect_text(summary: dict[str, Any]) -> None:
    print(
        "  connects: attempts={connection_attempt_count} ok={connection_success_count} "
        "failures={connection_failure_count} timeouts={connection_timeout_count} "
        "cancels={connect_cancel_count}".format(**summary)
    )
    latest = summary.get("latest_connect_status") or {}
    if not latest:
        return
    parts = [
        f"event={latest.get('event')}",
        f"cycle={latest.get('cycle')}",
    ]
    if latest.get("rpa"):
        parts.append(f"rpa={latest['rpa']}")
    if latest.get("returncode") is not None:
        parts.append(f"returncode={latest['returncode']}")
    if latest.get("timeout") is not None:
        parts.append(f"timeout={latest['timeout']}")
    if latest.get("reason"):
        parts.append(f"reason={latest['reason']}")
    if latest.get("stderr"):
        parts.append(f"stderr={latest['stderr']}")
    if latest.get("command_returncode") is not None:
        parts.append(f"cancel_returncode={latest['command_returncode']}")
    print(f"  latest_connect: {'; '.join(parts)}")


def print_scan_text(scan: dict[str, Any]) -> None:
    latest = scan.get("latest_status") or {}
    print(
        "  scan: heartbeats={heartbeat_count} "
        "no_target_windows={no_target_window_count} "
        "oura_candidates={oura_candidate_count} "
        "physical_hints={physical_hint_count}".format(**scan)
    )
    if not latest:
        return
    parts = [
        f"event={latest.get('event')}",
        f"cycle={latest.get('cycle')}",
    ]
    if latest.get("no_target_classification"):
        parts.append(f"class={latest['no_target_classification']}")
    if latest.get("scan_backend"):
        parts.append(f"backend={latest['scan_backend']}")
    if latest.get("seconds_remaining") is not None:
        parts.append(f"remaining={latest['seconds_remaining']}s")
    if latest.get("last_address"):
        parts.append(
            "last={address} {address_type} {event_type}".format(
                address=latest["last_address"],
                address_type=latest.get("last_address_type", ""),
                event_type=latest.get("last_event_type", ""),
            ).strip()
        )
    if latest.get("manufacturer_hex"):
        parts.append(f"manufacturer={latest['manufacturer_hex']}")
    if latest.get("raw_manufacturer_hex"):
        parts.append(f"raw_manufacturer={latest['raw_manufacturer_hex']}")
    if latest.get("rpa"):
        parts.append(f"rpa={latest['rpa']}")
    print(f"  latest_scan: {'; '.join(parts)}")
    if latest.get("manufacturer_counts"):
        print(f"  latest_manufacturers: {format_counts(latest['manufacturer_counts'])}")
    if latest.get("resolvable_counts"):
        print(f"  latest_resolvable: {format_counts(latest['resolvable_counts'])}")
    if latest.get("oura_candidate_counts"):
        print(f"  latest_oura_candidates: {format_counts(latest['oura_candidate_counts'])}")
    note = latest.get("physical_state_note") or latest.get("note")
    if note:
        print(f"  physical_state_note: {note}")


def format_counts(counts: dict[str, int], limit: int = 8) -> str:
    if not counts:
        return "-"
    rows = list(counts.items())
    text = ", ".join(f"{key}:{value}" for key, value in rows[:limit])
    if len(rows) > limit:
        text += f", +{len(rows) - limit} more"
    return text


if __name__ == "__main__":
    sys.exit(main())
