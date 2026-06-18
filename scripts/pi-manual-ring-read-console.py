#!/usr/bin/env python3
"""Compact console formatter for the foreground Linux Oura reader.

The manual reader keeps the original JSONL stream in its log. This formatter is
only for the terminal copy, where full raw scan payloads are too noisy to use.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from typing import Any


NOISY_TEXT_PREFIXES = (
    "< HCI Command",
    "> HCI Event",
    "@ MGMT",
    "HCI Event:",
    "LE Meta Event:",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print concise live status from pi-manual-ring-read JSONL."
    )
    parser.add_argument(
        "--show-noisy-text",
        action="store_true",
        help="also print non-JSON btmon/hcitool chatter",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print probe/subscribe/notify chatter in addition to milestones",
    )
    args = parser.parse_args(argv)
    for line in sys.stdin:
        formatted = format_line(
            line,
            show_noisy_text=args.show_noisy_text,
            verbose=args.verbose,
        )
        if formatted:
            print(formatted, flush=True)
    return 0


def format_line(
    line: str,
    *,
    show_noisy_text: bool = False,
    verbose: bool = False,
) -> str:
    text = line.strip()
    if not text:
        return ""
    try:
        row = json.loads(text)
    except json.JSONDecodeError:
        return format_text_line(text, show_noisy_text=show_noisy_text)
    if not isinstance(row, dict):
        return ""
    return format_row(row, verbose=verbose)


def format_text_line(text: str, *, show_noisy_text: bool = False) -> str:
    lowered = text.lower()
    if (
        "traceback" in lowered
        or "error" in lowered
        or "exception" in lowered
        or text.startswith("manual reader")
        or text.startswith("summary:")
        or text.startswith("stop:")
    ):
        return text
    if show_noisy_text:
        return text
    if text.startswith(NOISY_TEXT_PREFIXES):
        return ""
    return ""


def format_row(row: dict[str, Any], *, verbose: bool = False) -> str:
    event = str(row.get("event") or row.get("native_event") or "")
    payload = row.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    cycle = row.get("raw_cycle") or payload.get("cycle")
    elapsed = row.get("elapsed_seconds")
    prefix = format_prefix(cycle=cycle, elapsed=elapsed)

    if event == "pi_manual_reader_launcher":
        text = (
            f"reader: log={payload.get('logfile')} "
            f"backend={payload.get('scan_backend')}"
        )
        if verbose:
            text += f" probes={payload.get('stream_probes')}"
        return text
    if event == "raw_loop_start":
        text = (
            "watching: "
            f"backend={payload.get('scan_backend')} "
            f"scan={payload.get('scan_seconds')}s"
        )
        if verbose:
            text += f" probes={payload.get('after_connect') or payload.get('stream_probes')}"
        return text
    if event == "raw_cycle_start":
        return f"{prefix}scan start"
    if event in {"raw_scan_heartbeat", "raw_cycle_no_target", "raw_cycle_scan_inactive", "raw_scan_inactive"}:
        return format_scan_status(event, payload, prefix=prefix, verbose=verbose)
    if event == "raw_scan_oura_candidate":
        return format_oura_candidate(payload, prefix=prefix)
    if event == "raw_scan_target":
        return format_scan_target(payload, prefix=prefix)
    if event == "raw_scan_backend_switch":
        return (
            f"{prefix}scan backend: "
            f"{payload.get('scan_backend') or payload.get('backend')} "
            f"reason={payload.get('reason')}"
        )
    if event == "raw_hci_scan_enable":
        codes = extract_hci_status_codes(payload)
        suffix = f" status={','.join(codes)}" if codes else ""
        return f"{prefix}hci scan enable: reason={payload.get('reason')}{suffix}"
    if event == "raw_bluetooth_recovery":
        return f"{prefix}bluetooth recovery: reason={payload.get('reason')}"
    if event in {"raw_connections", "raw_scan_find_start", "raw_scan_disable"}:
        return f"{prefix}{event.replace('raw_', '').replace('_', ' ')}" if verbose else ""
    if event == "raw_after_connect_start":
        return f"{prefix}connected; running {payload.get('mode') or 'post-connect probe'}"
    if event == "raw_after_connect_skipped":
        return f"{prefix}post-connect probe skipped"
    if event.startswith("raw_connect") or event.startswith("raw_hcitool") or event.startswith("raw_le_create"):
        return format_connect_event(event, payload, prefix=prefix)
    if event in {
        "raw_stream_agent_start",
        "raw_stream_agent_ready",
        "raw_stream_agent_stop",
        "agent_ready",
        "zeroauth_agent_registered",
    }:
        return f"{prefix}{event.replace('_', ' ')}" if verbose else ""
    if event == "zeroauth_device":
        return f"{prefix}zeroauth device: {payload.get('path')}" if verbose else ""
    if event in {"zeroauth_connect_start", "zeroauth_pair_start", "zeroauth_pair_done"}:
        return format_zeroauth_state(event, payload, prefix=prefix)
    if event == "zeroauth_subscribe_plan":
        chars = payload.get("characteristics")
        count = len(chars) if isinstance(chars, list) else 0
        return (
            f"{prefix}subscribe plan: connected={payload.get('bluez_connected')} "
            f"resolved={payload.get('services_resolved')} chars={count}"
        ) if verbose else ""
    if event == "zeroauth_subscribed":
        return (
            f"{prefix}subscribed: {payload.get('uuid')} handle={payload.get('handle')}"
            if verbose
            else ""
        )
    if event == "zeroauth_probe_tx":
        return f"{prefix}probe tx: {payload.get('packet')}" if verbose else ""
    if event == "zeroauth_notify":
        return format_notify(payload, prefix=prefix) if verbose else ""
    if event in {"zeroauth_probe_error", "zeroauth_probe_stop", "zeroauth_error"}:
        return format_error_event(event, payload, prefix=prefix)
    if event == "zeroauth_events_walk_page":
        return format_events_walk(payload, prefix=prefix) if verbose else ""
    if event == "zeroauth_events_walk_stop":
        return (
            f"{prefix}events walk stop: {payload.get('walk')} "
            f"page={payload.get('page_index')} reason={payload.get('reason')}"
        )
    if event == "read_result":
        return format_read_result(payload, prefix=prefix)
    if event in {"zeroauth_stream_done", "raw_zeroauth_stream_done"}:
        return format_stream_done(event, payload, prefix=prefix)
    if event == "raw_zeroauth_stream_unusable":
        return (
            f"{prefix}stream unusable: read_results={payload.get('read_results')} "
            f"errors={payload.get('probe_errors')} reason={payload.get('reason')}"
        )
    if event in {"raw_loop_success", "raw_loop_done"}:
        return format_loop_done(event, payload, prefix=prefix)
    if event.endswith("_error") or event in {"raw_dbus_stderr", "raw_zeroauth_stderr"}:
        return format_error_event(event, payload, prefix=prefix)
    return ""


def format_prefix(*, cycle: Any, elapsed: Any) -> str:
    pieces: list[str] = []
    if cycle is not None:
        pieces.append(f"cycle {cycle}")
    if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
        pieces.append(f"{elapsed:.1f}s")
    return f"[{' '.join(pieces)}] " if pieces else ""


def format_scan_status(
    event: str,
    payload: dict[str, Any],
    *,
    prefix: str,
    verbose: bool = False,
) -> str:
    raw_oura = payload.get("oura_candidate_counts")
    oura_count = sum_numeric(raw_oura.values()) if isinstance(raw_oura, dict) else 0
    parts = [
        "scan" if event == "raw_scan_heartbeat" else "no target",
        f"samples={intish(payload.get('manufacturer_sample_count'), 0)}",
        f"addrs={intish(payload.get('unique_address_count'), 0)}",
        f"resolvable={intish(payload.get('resolvable_address_count'), 0)}",
        f"oura={oura_count}",
    ]
    classification = payload.get("no_target_classification")
    if classification:
        parts.append(f"class={classification}")
    backend = payload.get("scan_backend")
    if backend:
        parts.append(f"backend={backend}")
    remaining = payload.get("seconds_remaining")
    if isinstance(remaining, (int, float)) and not isinstance(remaining, bool):
        parts.append(f"left={remaining:.0f}s")
    if verbose:
        near_mfg = format_near_manufacturers(payload.get("manufacturer_rssi"), limit=2)
        if near_mfg:
            parts.append(f"near_mfg={near_mfg}")
        near_addr = format_near_manufacturer_addresses(
            payload.get("manufacturer_rssi"),
            payload.get("manufacturer_addresses"),
            limit=1,
        )
        if near_addr:
            parts.append(f"near_addr={near_addr}")
    hint = raw_scan_operator_hint(payload)
    if event != "raw_scan_heartbeat" and hint:
        parts.append(f"hint={hint}")
    return prefix + " ".join(parts)


def format_oura_candidate(payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"reason={payload.get('reason')}",
        f"addr={payload.get('address')}",
        f"type={payload.get('address_type')}",
        f"mfg={payload.get('manufacturer_hex')}",
        f"name={payload.get('name')}",
    ]
    return prefix + "OURA candidate: " + compact_parts(details)


def format_scan_target(payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"rpa={payload.get('rpa')}",
        f"signal={payload.get('target_signal')}",
        f"mfg={payload.get('manufacturer_hex') or payload.get('raw_manufacturer_hex')}",
        f"type={payload.get('address_type')}",
        f"backend={payload.get('scan_backend')}",
    ]
    return prefix + "TARGET: " + compact_parts(details)


def format_connect_event(event: str, payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"rpa={payload.get('rpa') or payload.get('address')}",
        f"backend={payload.get('backend') or payload.get('connect_backend')}",
        f"rc={payload.get('returncode')}",
        f"reason={payload.get('reason')}",
    ]
    return prefix + event.replace("_", " ") + ": " + compact_parts(details)


def format_zeroauth_state(event: str, payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"path={payload.get('path')}",
        f"paired={payload.get('paired')}",
        f"bonded={payload.get('bonded')}",
        f"connected={payload.get('connected')}",
    ]
    return prefix + event.replace("_", " ") + ": " + compact_parts(details)


def format_notify(payload: dict[str, Any], *, prefix: str) -> str:
    context = payload.get("probe_context")
    packet = context.get("packet") if isinstance(context, dict) else None
    decoded = payload.get("decoded")
    decoded_name = decoded.get("event_name") if isinstance(decoded, dict) else None
    details = [
        f"packet={packet}",
        f"uuid={payload.get('uuid')}",
        f"decoded={decoded_name or decoded.get('packet') if isinstance(decoded, dict) else None}",
        f"bytes={len(str(payload.get('raw_hex') or '')) // 2}",
    ]
    return prefix + "notify: " + compact_parts(details)


def format_events_walk(payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"walk={payload.get('walk')}",
        f"page={payload.get('page_index')}/{payload.get('page_count')}",
        f"events={payload.get('events_received')}",
        f"left={payload.get('bytes_left')}",
        f"complete={payload.get('complete')}",
        f"next={payload.get('next_start_hex')}",
    ]
    return prefix + "events: " + compact_parts(details)


def format_read_result(payload: dict[str, Any], *, prefix: str) -> str:
    parts = summarize_read_result(payload)
    if parts:
        return prefix + "READ RESULT: " + "; ".join(parts)
    keys = ",".join(sorted(str(key) for key in payload)[:12])
    return prefix + f"READ RESULT: no usable fields keys={keys or '-'}"


def format_stream_done(event: str, payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"rc={payload.get('returncode')}",
        f"read_results={payload.get('read_results')}",
        f"usable={payload.get('usable_read_results')}",
        f"notifications={payload.get('notification_count')}",
        f"subscribed={payload.get('subscribed_count')}",
    ]
    return prefix + event.replace("_", " ") + ": " + compact_parts(details)


def format_loop_done(event: str, payload: dict[str, Any], *, prefix: str) -> str:
    details = [
        f"success={payload.get('success')}",
        f"cycle={payload.get('cycle')}",
        f"cycles={payload.get('cycles')}",
        f"rpa={payload.get('rpa')}",
    ]
    return prefix + event.replace("_", " ") + ": " + compact_parts(details)


def format_error_event(event: str, payload: dict[str, Any], *, prefix: str) -> str:
    error = payload.get("error") or payload.get("stderr") or payload.get("line")
    details = [
        f"packet={payload.get('packet')}",
        f"type={payload.get('error_type')}",
        f"reason={payload.get('reason')}",
        f"error={shorten(error, 180)}",
    ]
    return prefix + event.replace("_", " ") + ": " + compact_parts(details)


def compact_parts(parts: Iterable[str]) -> str:
    return " ".join(part for part in parts if not part.endswith("=None") and not part.endswith("="))


def summarize_read_result(result: Any) -> list[str]:
    if not isinstance(result, dict):
        return []
    parts: list[str] = []
    firmware = result.get("firmware")
    if isinstance(firmware, dict):
        version = firmware.get("firmware_version")
        api = firmware.get("api_version")
        ble = firmware.get("bluetooth_stack_version")
        detail = f"fw={version}" if version else "fw=present"
        if api:
            detail += f" api={api}"
        if ble:
            detail += f" ble={ble}"
        parts.append(detail)
    battery = result.get("battery")
    if isinstance(battery, dict):
        parts.append(format_battery_summary(battery))
    auth_nonce = result.get("auth_nonce")
    if isinstance(auth_nonce, dict):
        nonce = auth_nonce.get("nonce_hex")
        parts.append(f"auth_nonce={len(str(nonce)) // 2}B" if nonce else "auth_nonce")
    for key in ("daytime_hr_latest", "resting_hr_latest"):
        summary = summarize_feature_latest_payload(key, result.get(key))
        if summary:
            parts.append(summary)
    feature_latest = result.get("feature_latest")
    if isinstance(feature_latest, dict):
        for key, payload in sorted(feature_latest.items()):
            summary = summarize_feature_latest_payload(str(key), payload)
            if summary and summary not in parts:
                parts.append(summary)
    feature_status = result.get("feature_status")
    if isinstance(feature_status, dict) and feature_status:
        active = [
            feature_status_name(row)
            for _key, row in sorted(feature_status.items())
            if isinstance(row, dict)
            and row.get("mode_name") not in {None, "", "off"}
        ]
        if active:
            parts.append("active_features=" + ",".join(active[:8]))
    events = result.get("events")
    if isinstance(events, list) and events:
        parts.append(f"events={len(events)}")
    event_summary = result.get("event_summary")
    if isinstance(event_summary, dict):
        health_summary = summarize_health_events(event_summary.get("health_events"))
        if health_summary:
            parts.append(health_summary)
        count = event_summary.get("count") or event_summary.get("event_count")
        if count is not None:
            parts.append(f"event_summary_count={count}")
    auth_gated = result.get("auth_gated")
    if isinstance(auth_gated, list) and auth_gated:
        visible = ",".join(str(item) for item in auth_gated[:8])
        suffix = f",...({len(auth_gated)} total)" if len(auth_gated) > 8 else ""
        parts.append(f"auth_gated={visible}{suffix}")
    return parts


def format_battery_summary(battery: dict[str, Any]) -> str:
    pieces = [f"battery={battery.get('battery_level_percent')}%"]
    progress = battery.get("charging_progress")
    if progress is not None:
        pieces.append(f"charge={progress}%")
    voltage = battery.get("voltage_mv")
    if voltage is not None:
        pieces.append(f"voltage={voltage}mV")
    status = battery.get("battery_status_hex")
    if status is not None:
        pieces.append(f"status={status}")
    return " ".join(pieces)


def summarize_feature_latest_payload(label: str, payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    feature = str(payload.get("feature_name") or label).replace("feature_latest:", "")
    bpm = payload.get("daytime_hr_bpm_estimate")
    if isinstance(bpm, (int, float)) and not isinstance(bpm, bool):
        return f"{feature}~{bpm}bpm"
    latest_values = payload.get("latest_values")
    if isinstance(latest_values, list) and latest_values:
        values = [
            row.get("value") if isinstance(row, dict) else row
            for row in latest_values[:5]
        ]
        values_text = ",".join(str(value) for value in values if value is not None)
        if values_text:
            suffix = "" if feature.endswith("_latest") else "_latest"
            return f"{feature}{suffix}={values_text}"
    state = payload.get("state_name")
    status = payload.get("status_name")
    if state or status:
        return f"{feature}={status or '?'}:{state or '?'}"
    return None


def feature_status_name(row: dict[str, Any]) -> str:
    feature = row.get("feature_name")
    if feature and feature != "unknown":
        return str(feature)
    feature_id = row.get("feature_id")
    if isinstance(feature_id, int) and not isinstance(feature_id, bool):
        return f"feature_0x{feature_id:02x}"
    return "feature_unknown"


def summarize_health_events(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return ""
    pieces: list[str] = []
    event_counts = value.get("event_counts")
    if isinstance(event_counts, dict) and event_counts:
        pieces.append("events=" + format_top_counts(event_counts, limit=5))
    ibi_count = value.get("ibi_record_count")
    if isinstance(ibi_count, int) and not isinstance(ibi_count, bool):
        pieces.append(f"ibi={ibi_count}")
    bpm_min = value.get("bpm_estimate_min")
    bpm_max = value.get("bpm_estimate_max")
    bpm_latest = value.get("bpm_estimate_latest")
    if bpm_min is not None and bpm_max is not None:
        pieces.append(f"bpm={bpm_min}-{bpm_max}")
    if bpm_latest is not None:
        pieces.append(f"latest_bpm={bpm_latest}")
    spo2_count = value.get("spo2_sample_count")
    if isinstance(spo2_count, int) and not isinstance(spo2_count, bool):
        pieces.append(
            f"spo2_raw={spo2_count}:{value.get('spo2_value_min')}-{value.get('spo2_value_max')}"
        )
    temp_count = value.get("temperature_sample_count")
    if isinstance(temp_count, int) and not isinstance(temp_count, bool):
        pieces.append(
            f"temp_c={temp_count}:{value.get('temperature_c_min')}-{value.get('temperature_c_max')}"
        )
    quality_count = value.get("green_ibi_quality_sample_count")
    if isinstance(quality_count, int) and not isinstance(quality_count, bool):
        pieces.append(f"green_quality={quality_count}")
    ppg_count = value.get("ppg_amplitude_count")
    if isinstance(ppg_count, int) and not isinstance(ppg_count, bool):
        pieces.append(f"ppg_amp={ppg_count}")
    return "health_events=" + " ".join(pieces) if pieces else ""


def raw_scan_operator_hint(raw_scan: dict[str, Any]) -> str | None:
    reason = raw_scan.get("reason")
    classification = raw_scan.get("no_target_classification")
    samples = numeric_value(raw_scan.get("manufacturer_sample_count"))
    addresses = numeric_value(raw_scan.get("unique_address_count"))
    if reason in {
        "silent_scan_no_manufacturer_samples",
        "btmgmt_find_did_not_enable_discovery",
        "hci_le_scan_enable_failed",
    }:
        return "scanner/controller issue; recover BlueZ or switch scan backend"
    if classification == "oura_seen_without_target_payload":
        return "ring presence seen, but not a connect/read target payload"
    if classification == "no_oura_seen":
        if samples > 0 or addresses > 0:
            return "BLE is visible, but no Oura state is visible; wake/toggle the ring"
        return "no Oura and no manufacturer samples yet; verify controller scanning"
    return None


def numeric_value(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def format_top_counts(counts: Any, *, limit: int = 3) -> str:
    items = top_count_items(counts, limit=limit)
    return ",".join(f"{key}:{value}" for key, value in items) if items else "-"


def top_count_items(counts: Any, *, limit: int = 5) -> list[tuple[str, int | float]]:
    if not isinstance(counts, dict):
        return []
    numeric_counts = [
        (str(key), value)
        for key, value in counts.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    return sorted(numeric_counts, key=lambda item: (-item[1], item[0]))[:limit]


def format_near_manufacturers(value: Any, *, limit: int = 5) -> str:
    if not isinstance(value, dict):
        return ""
    rows: list[tuple[str, int, int]] = []
    for manufacturer, summary in value.items():
        if not isinstance(summary, dict):
            continue
        max_rssi = summary.get("max")
        samples = summary.get("samples")
        if isinstance(max_rssi, bool) or isinstance(samples, bool):
            continue
        if isinstance(max_rssi, int) and isinstance(samples, int):
            rows.append((str(manufacturer), max_rssi, samples))
    rows.sort(key=lambda row: (-row[1], -row[2], row[0]))
    return ", ".join(
        f"{manufacturer}:{max_rssi}dBm/{samples}"
        for manufacturer, max_rssi, samples in rows[:limit]
    )


def format_near_manufacturer_addresses(
    rssi_value: Any, address_value: Any, *, limit: int = 3
) -> str:
    if not isinstance(rssi_value, dict) or not isinstance(address_value, dict):
        return ""
    rows: list[tuple[str, int, str, str, str, str]] = []
    for manufacturer, rssi_summary in rssi_value.items():
        if not isinstance(rssi_summary, dict):
            continue
        max_rssi = rssi_summary.get("max")
        if isinstance(max_rssi, bool) or not isinstance(max_rssi, int):
            continue
        address_summary = address_value.get(manufacturer)
        if not isinstance(address_summary, dict):
            continue
        address = (
            address_summary.get("max_rssi_resolvable_address")
            or address_summary.get("max_rssi_address")
            or address_summary.get("latest_resolvable_address")
            or address_summary.get("latest_address")
        )
        if not address:
            continue
        address_type = (
            address_summary.get("max_rssi_address_type")
            or address_summary.get("latest_address_type")
            or "?"
        )
        event_type = (
            address_summary.get("max_rssi_event_type")
            or address_summary.get("latest_event_type")
            or "?"
        )
        company = short_company_name(
            str(
                address_summary.get("max_rssi_company")
                or address_summary.get("latest_company")
                or ""
            )
        )
        rows.append(
            (
                str(manufacturer),
                max_rssi,
                str(address),
                str(address_type),
                short_ble_event_type(str(event_type)),
                company,
            )
        )
    rows.sort(key=lambda row: (-row[1], row[0], row[2]))
    return ", ".join(format_near_address_row(row) for row in rows[:limit])


def format_near_address_row(row: tuple[str, int, str, str, str, str]) -> str:
    manufacturer, max_rssi, address, address_type, event_type, company = row
    company_part = f"/{company}" if company else ""
    return (
        f"{manufacturer}:{max_rssi}dBm/{address}/{address_type}/"
        f"{event_type}{company_part}"
    )


def short_ble_event_type(event_type: str) -> str:
    if "ADV_IND" in event_type:
        return "ADV_IND"
    if "ADV_DIRECT_IND" in event_type:
        return "ADV_DIRECT"
    if "ADV_SCAN_IND" in event_type:
        return "ADV_SCAN"
    if "ADV_NONCONN_IND" in event_type:
        return "ADV_NONCONN"
    if "SCAN_RSP" in event_type:
        return "SCAN_RSP"
    return event_type


def short_company_name(company: str) -> str:
    if not company:
        return ""
    name = company.split(" (", 1)[0].strip()
    if len(name) <= 24:
        return name
    return name[:21].rstrip() + "..."


HCI_STATUS_NAMES = {
    "00": "success",
    "0C": "command_disallowed",
}


def extract_hci_status_codes(payload: dict[str, Any]) -> list[str]:
    return unique_hci_status_codes(extract_hci_status_sequence(payload))


def unique_hci_status_codes(codes: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for code in codes:
        if code in seen:
            continue
        seen.add(code)
        unique.append(code)
    return unique


def extract_hci_status_sequence(payload: dict[str, Any]) -> list[str]:
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return []
    codes: list[str] = []
    for command in commands:
        if not isinstance(command, dict):
            continue
        stdout = command.get("stdout")
        if not isinstance(stdout, str):
            continue
        tokens = [token.upper() for token in stdout.replace("\n", " ").split()]
        for index in range(len(tokens) - 3):
            code = tokens[index + 3]
            if (
                tokens[index] == "01"
                and tokens[index + 2] == "20"
                and len(code) == 2
                and all(char in "0123456789ABCDEF" for char in code)
            ):
                codes.append(code)
    return codes


def intish(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    return default


def sum_numeric(values: Iterable[Any]) -> int:
    total = 0
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def shorten(value: Any, limit: int) -> str:
    text = str(value or "").replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


if __name__ == "__main__":
    raise SystemExit(main())
