#!/usr/bin/env python3
"""Catalog decoded zero-auth event traffic from Pi JSONL captures."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from oura_ring4_ble import protocol as p

DEFAULT_LOG_GLOB = "logs/pi-zeroauth-chase-product-*.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate decoded zero-auth events from Pi JSONL captures."
    )
    parser.add_argument("logs", nargs="*", help="JSONL logs to inspect")
    parser.add_argument(
        "--log-glob",
        default=DEFAULT_LOG_GLOB,
        help="glob used when no explicit log paths are supplied",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--redecode-events",
        action="store_true",
        help="reparse stored event_tag/timestamp/payload_hex with the current decoder",
    )
    args = parser.parse_args(argv)

    try:
        log_paths = resolve_log_paths(args.logs, args.log_glob)
        catalog = build_catalog(log_paths, redecode_events=args.redecode_events)
    except (OSError, ValueError) as exc:
        print(f"pi-zeroauth-event-catalog: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(catalog, indent=2, sort_keys=True))
    else:
        print_text(catalog)
    return 0


def resolve_log_paths(logs: Iterable[str], log_glob: str) -> list[Path]:
    paths = [Path(path) for path in logs if path]
    if not paths:
        paths = sorted(Path.cwd().glob(log_glob))
    existing = [path for path in paths if path.exists()]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise ValueError(f"log path(s) not found: {', '.join(missing)}")
    if not existing:
        raise ValueError(f"no logs supplied and no logs matched {log_glob}")
    return existing


def build_catalog(
    paths: Iterable[Path], *, redecode_events: bool = False
) -> dict[str, Any]:
    log_paths = list(paths)
    seen_events: set[tuple[Any, Any, Any, Any]] = set()
    invalid_json_lines: list[dict[str, Any]] = []
    read_result_count = 0
    event_count = 0
    unique_event_count = 0
    duplicate_event_count = 0
    event_names: Counter[str] = Counter()
    debug_categories: Counter[str] = Counter()
    debug_labels: Counter[str] = Counter()
    debug_keys: Counter[str] = Counter()
    unknown_debug_keys: Counter[str] = Counter()
    debug_data_codes: Counter[str] = Counter()
    debug_key_stats: dict[str, dict[str, Any]] = {}
    debug_code_stats: dict[str, dict[str, Any]] = {}

    for path in log_paths:
        for _line_number, row in read_jsonl_rows(
            path, invalid_json_lines=invalid_json_lines
        ):
            if row.get("event") != "read_result":
                continue
            payload = row.get("payload")
            if not isinstance(payload, dict):
                continue
            read_result_count += 1
            events = payload.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                event_count += 1
                event = redecode_stored_event(event) if redecode_events else event
                event_key = unique_event_key(event)
                if event_key in seen_events:
                    duplicate_event_count += 1
                    continue
                seen_events.add(event_key)
                unique_event_count += 1
                record_event(
                    event,
                    event_names,
                    debug_categories,
                    debug_labels,
                    debug_keys,
                    unknown_debug_keys,
                    debug_data_codes,
                    debug_key_stats,
                    debug_code_stats,
                )

    return {
        "log_count": len(log_paths),
        "logs": [str(path) for path in log_paths],
        "read_result_count": read_result_count,
        "invalid_json_line_count": len(invalid_json_lines),
        "invalid_json_lines": invalid_json_lines[:20],
        "event_count": event_count,
        "unique_event_count": unique_event_count,
        "duplicate_event_count": duplicate_event_count,
        "event_names": sorted_counter(event_names),
        "debug_categories": sorted_counter(debug_categories),
        "debug_labels": sorted_counter(debug_labels),
        "debug_keys": sorted_counter(debug_keys),
        "unknown_debug_keys": sorted_counter(unknown_debug_keys),
        "debug_key_stats": dict(sorted(debug_key_stats.items())),
        "debug_data_codes": sorted_counter(debug_data_codes),
        "debug_code_stats": {
            key: finalize_code_stat(value)
            for key, value in sorted(debug_code_stats.items())
        },
    }


def read_jsonl_rows(
    path: Path, *, invalid_json_lines: list[dict[str, Any]] | None = None
) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                if invalid_json_lines is not None:
                    invalid_json_lines.append(
                        {
                            "log": str(path),
                            "line": line_number,
                            "error": str(exc),
                            "text": text[:120],
                        }
                    )
                    continue
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if isinstance(row, dict):
                yield line_number, row


def unique_event_key(event: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        event.get("event_tag"),
        event.get("event_name"),
        event.get("device_boot_timestamp"),
        event.get("payload_hex"),
    )


def redecode_stored_event(event: dict[str, Any]) -> dict[str, Any]:
    tag = event.get("event_tag")
    timestamp = event.get("device_boot_timestamp")
    payload_hex = event.get("payload_hex")
    if not isinstance(tag, str):
        return event
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return event
    if not isinstance(payload_hex, str):
        return event
    try:
        tag_int = int(tag, 16)
        payload = struct.pack("<I", timestamp) + bytes.fromhex(payload_hex)
        decoded = p.parse_response(p.Packet(tag_int, payload)).get("decoded")
    except (ValueError, p.ProtocolError, struct.error):
        return event
    return decoded if isinstance(decoded, dict) else event


def record_event(
    event: dict[str, Any],
    event_names: Counter[str],
    debug_categories: Counter[str],
    debug_labels: Counter[str],
    debug_keys: Counter[str],
    unknown_debug_keys: Counter[str],
    debug_data_codes: Counter[str],
    debug_key_stats: dict[str, dict[str, Any]],
    debug_code_stats: dict[str, dict[str, Any]],
) -> None:
    event_name = string_value(event.get("event_name"))
    if event_name:
        event_names[event_name] += 1

    debug_category = event_debug_category(event)
    if debug_category:
        debug_categories[debug_category] += 1
    debug_label = event_debug_label(event)
    if debug_label:
        debug_labels[debug_label] += 1

    debug_key = string_value(event.get("debug_key"))
    if debug_key:
        debug_keys[debug_key] += 1
        if not debug_category:
            unknown_debug_keys[debug_key] += 1
        record_debug_key_stat(debug_key_stats, debug_key, event)

    debug_code = normalized_debug_code(event.get("debug_data_code_hex"))
    if debug_code:
        debug_data_codes[debug_code] += 1
        record_debug_code_stat(debug_code_stats, debug_code, event)


def record_debug_key_stat(
    stats: dict[str, dict[str, Any]], key: str, event: dict[str, Any]
) -> None:
    stat = stats.setdefault(
        key,
        {
            "count": 0,
            "category": event.get("debug_category"),
            "label": event.get("debug_label"),
            "fields": event.get("debug_fields"),
            "first_boot_timestamp": None,
            "last_boot_timestamp": None,
            "latest_values": [],
            "latest_numeric_values": [],
        },
    )
    stat["count"] += 1
    update_boot_range(stat, event.get("device_boot_timestamp"))
    values = event.get("debug_values")
    if isinstance(values, list):
        stat["latest_values"] = [str(value) for value in values]
    numeric_values = event.get("debug_numeric_values")
    if isinstance(numeric_values, list):
        stat["latest_numeric_values"] = [
            value
            for value in numeric_values
            if isinstance(value, int) and not isinstance(value, bool)
        ]


def record_debug_code_stat(
    stats: dict[str, dict[str, Any]], code: str, event: dict[str, Any]
) -> None:
    stat = stats.setdefault(code, new_debug_code_stat(code, event))
    stat["count"] += 1
    update_boot_range(stat, event.get("device_boot_timestamp"))
    update_min_max(stat, "payload_length", event.get("payload_length"))
    tail_hex = string_value(event.get("debug_data_tail_hex"))
    if tail_hex:
        tail_byte_count = hex_byte_count(tail_hex)
        if tail_byte_count is not None:
            update_min_max(stat, "tail_byte_count", tail_byte_count)
    else:
        update_min_max(stat, "tail_byte_count", 0)
    if not stat.get("example"):
        stat["example"] = build_code_example(event)
    battery = event.get("debug_data_battery")
    if isinstance(battery, dict):
        stat["latest_battery"] = compact_battery(battery)
    power_sample = power_sample_candidate_from_event(event)
    if isinstance(power_sample, dict):
        stat["latest_power_sample_candidate"] = compact_power_sample(power_sample)
    tail_words = event.get("debug_data_tail_words")
    if isinstance(tail_words, dict):
        stat["latest_tail_words"] = tail_words
    printable_runs = event.get("printable_runs")
    if isinstance(printable_runs, list) and printable_runs:
        printable_run_counts = stat.get("printable_run_counts")
        if isinstance(printable_run_counts, Counter):
            for value in printable_runs:
                text = string_value(value)
                if text:
                    printable_run_counts[text] += 1
        stat["latest_printable_runs"] = printable_runs


def new_debug_code_stat(code: str, event: dict[str, Any]) -> dict[str, Any]:
    category = event_debug_category(event)
    label = event_debug_label(event)
    if not category or not label:
        code_int = int(code, 16)
        meta = p.DEBUG_DATA_CODE_METADATA.get(code_int, {})
        category = category or meta.get("category")
        label = label or meta.get("label")
    return {
        "count": 0,
        "category": category,
        "label": label,
        "first_boot_timestamp": None,
        "last_boot_timestamp": None,
        "payload_length_min": None,
        "payload_length_max": None,
        "tail_byte_count_min": None,
        "tail_byte_count_max": None,
        "printable_run_counts": Counter(),
        "example": None,
    }


def finalize_code_stat(stat: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in stat.items():
        if value is None:
            continue
        if isinstance(value, Counter):
            if value:
                result[key] = sorted_counter(value)
            continue
        result[key] = value
    return result


def build_code_example(event: dict[str, Any]) -> dict[str, Any]:
    example = {
        key: event[key]
        for key in (
            "event_name",
            "device_boot_timestamp",
            "payload_length",
            "payload_hex",
            "debug_data_tail_hex",
        )
        if key in event
    }
    battery = event.get("debug_data_battery")
    if isinstance(battery, dict):
        example["debug_data_battery"] = compact_battery(battery)
    power_sample = power_sample_candidate_from_event(event)
    if isinstance(power_sample, dict):
        example["debug_data_power_sample_candidate"] = compact_power_sample(power_sample)
    tail_words = event.get("debug_data_tail_words")
    if isinstance(tail_words, dict):
        example["debug_data_tail_words"] = tail_words
    printable_runs = event.get("printable_runs")
    if isinstance(printable_runs, list) and printable_runs:
        example["printable_runs"] = printable_runs
    return example


def compact_battery(battery: dict[str, Any]) -> dict[str, Any]:
    return {
        key: battery[key]
        for key in (
            "battery_level_percent",
            "voltage_mv",
            "status",
            "status_hex",
            "extra_hex",
        )
        if key in battery
    }


def compact_power_sample(sample: dict[str, Any]) -> dict[str, Any]:
    return {
        key: sample[key]
        for key in (
            "source",
            "inferred",
            "raw0_u16",
            "voltage_mv_candidate",
            "signed2_i16",
            "signed3_i16",
            "raw4_u16",
            "raw5_u16",
            "status_byte_candidate",
            "status_hex_candidate",
            "extra_hex",
        )
        if key in sample
    }


def power_sample_candidate_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    sample = event.get("debug_data_power_sample_candidate")
    if isinstance(sample, dict):
        return sample
    if normalized_debug_code(event.get("debug_data_code_hex")) != "0x14":
        return None
    tail_hex = string_value(event.get("debug_data_tail_hex"))
    if not tail_hex:
        return None
    try:
        return p.parse_debug_data_power_sample_candidate(bytes.fromhex(tail_hex))
    except ValueError:
        return None


def event_debug_category(event: dict[str, Any]) -> str:
    return string_value(
        event.get("debug_category") or event.get("debug_data_code_category")
    )


def event_debug_label(event: dict[str, Any]) -> str:
    return string_value(event.get("debug_label") or event.get("debug_data_code_label"))


def normalized_debug_code(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return f"0x{value:02X}"
    text = string_value(value)
    if not text:
        return ""
    try:
        return f"0x{int(text, 16):02X}"
    except ValueError:
        return text


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def update_boot_range(stat: dict[str, Any], value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        return
    first = stat.get("first_boot_timestamp")
    last = stat.get("last_boot_timestamp")
    if not isinstance(first, int) or value < first:
        stat["first_boot_timestamp"] = value
    if not isinstance(last, int) or value > last:
        stat["last_boot_timestamp"] = value


def update_min_max(stat: dict[str, Any], prefix: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        return
    min_key = f"{prefix}_min"
    max_key = f"{prefix}_max"
    current_min = stat.get(min_key)
    current_max = stat.get(max_key)
    if not isinstance(current_min, int) or value < current_min:
        stat[min_key] = value
    if not isinstance(current_max, int) or value > current_max:
        stat[max_key] = value


def hex_byte_count(value: str) -> int | None:
    try:
        return len(bytes.fromhex(value))
    except ValueError:
        return None


def sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return {
        key: count
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    }


def print_text(catalog: dict[str, Any]) -> None:
    print(
        "logs={logs} read_results={read_results} events={events} "
        "unique={unique} duplicates={duplicates}".format(
            logs=catalog["log_count"],
            read_results=catalog["read_result_count"],
            events=catalog["event_count"],
            unique=catalog["unique_event_count"],
            duplicates=catalog["duplicate_event_count"],
        )
    )
    skipped = catalog.get("invalid_json_line_count")
    if isinstance(skipped, int) and skipped:
        print(f"skipped_non_json_lines={skipped}")
    print_counts("event_names", catalog.get("event_names"))
    print_counts("debug_categories", catalog.get("debug_categories"))
    print_counts("debug_labels", catalog.get("debug_labels"))
    print_counts("debug_keys", catalog.get("debug_keys"))
    print_counts("unknown_debug_keys", catalog.get("unknown_debug_keys"))
    print_counts("debug_data_codes", catalog.get("debug_data_codes"))

    key_stats = catalog.get("debug_key_stats")
    if isinstance(key_stats, dict) and key_stats:
        print("debug_key_examples:")
        for key, stat in key_stats.items():
            print(f"  {key}: {format_debug_key_stat(stat)}")

    code_stats = catalog.get("debug_code_stats")
    if isinstance(code_stats, dict) and code_stats:
        print("debug_code_examples:")
        for code, stat in code_stats.items():
            print(f"  {code}: {format_debug_code_stat(stat)}")


def print_counts(label: str, counts: Any) -> None:
    if not isinstance(counts, dict) or not counts:
        return
    print(f"{label}={format_counts(counts)}")


def format_counts(counts: dict[str, int]) -> str:
    return ",".join(f"{key}:{value}" for key, value in counts.items())


def format_limited_counts(counts: dict[str, int], limit: int = 8) -> str:
    items = list(counts.items())
    parts = [f"{key}:{value}" for key, value in items[:limit]]
    if len(items) > limit:
        parts.append(f"...({len(items)} total)")
    return ",".join(parts)


def format_debug_key_stat(stat: dict[str, Any]) -> str:
    parts = [f"count={stat.get('count', 0)}"]
    category = string_value(stat.get("category"))
    label = string_value(stat.get("label"))
    if category or label:
        parts.append("/".join(part for part in (category, label) if part))
    boot_range = format_boot_range(stat)
    if boot_range:
        parts.append(f"boot={boot_range}")
    values = stat.get("latest_values")
    if isinstance(values, list) and values:
        parts.append("latest=" + "/".join(str(value) for value in values))
    numeric_values = stat.get("latest_numeric_values")
    if isinstance(numeric_values, list) and numeric_values:
        parts.append("latest_numeric=" + "/".join(str(value) for value in numeric_values))
    return " ".join(parts)


def format_debug_code_stat(stat: dict[str, Any]) -> str:
    parts = [f"count={stat.get('count', 0)}"]
    category = string_value(stat.get("category"))
    label = string_value(stat.get("label"))
    if category or label:
        parts.append("/".join(part for part in (category, label) if part))
    boot_range = format_boot_range(stat)
    if boot_range:
        parts.append(f"boot={boot_range}")
    parts.extend(
        [
            format_min_max(stat, "payload_len", "payload_length"),
            format_min_max(stat, "tail_bytes", "tail_byte_count"),
        ]
    )
    battery = stat.get("latest_battery")
    if isinstance(battery, dict):
        parts.append("battery=" + format_battery(battery))
    power_sample = stat.get("latest_power_sample_candidate")
    if isinstance(power_sample, dict):
        parts.append("power_candidate=" + format_power_sample(power_sample))
    tail_words = stat.get("latest_tail_words")
    if isinstance(tail_words, dict):
        words = format_tail_words(tail_words)
        if words:
            parts.append("words=" + words)
    printable_counts = stat.get("printable_run_counts")
    if isinstance(printable_counts, dict) and printable_counts:
        parts.append("texts=" + format_limited_counts(printable_counts))
    printable_runs = stat.get("latest_printable_runs")
    if isinstance(printable_runs, list) and printable_runs:
        parts.append("text=" + format_printable_runs(printable_runs))
    example = stat.get("example")
    if isinstance(example, dict):
        payload_hex = string_value(example.get("payload_hex"))
        tail_hex = string_value(example.get("debug_data_tail_hex"))
        if payload_hex:
            parts.append(f"example_payload={payload_hex}")
        if tail_hex:
            parts.append(f"tail={tail_hex}")
    return " ".join(part for part in parts if part)


def format_boot_range(stat: dict[str, Any]) -> str:
    first = stat.get("first_boot_timestamp")
    last = stat.get("last_boot_timestamp")
    if isinstance(first, int) and isinstance(last, int):
        return str(first) if first == last else f"{first}-{last}"
    return ""


def format_min_max(stat: dict[str, Any], label: str, prefix: str) -> str:
    low = stat.get(f"{prefix}_min")
    high = stat.get(f"{prefix}_max")
    if not isinstance(low, int) or not isinstance(high, int):
        return ""
    value = str(low) if low == high else f"{low}-{high}"
    return f"{label}={value}"


def format_battery(battery: dict[str, Any]) -> str:
    parts = []
    percent = battery.get("battery_level_percent")
    if isinstance(percent, int):
        parts.append(f"{percent}%")
    voltage = battery.get("voltage_mv")
    if isinstance(voltage, int):
        parts.append(f"{voltage}mV")
    status = battery.get("status_hex")
    if isinstance(status, str):
        parts.append(f"status={status}")
    extra_hex = battery.get("extra_hex")
    if isinstance(extra_hex, str) and extra_hex:
        parts.append(f"extra={extra_hex}")
    return "/".join(parts)


def format_power_sample(sample: dict[str, Any]) -> str:
    parts = []
    voltage = sample.get("voltage_mv_candidate")
    if isinstance(voltage, int):
        parts.append(f"{voltage}mV?")
    signed2 = sample.get("signed2_i16")
    if isinstance(signed2, int):
        parts.append(f"signed2={signed2}")
    signed3 = sample.get("signed3_i16")
    if isinstance(signed3, int):
        parts.append(f"signed3={signed3}")
    status = sample.get("status_hex_candidate")
    if isinstance(status, str):
        parts.append(f"status={status}?")
    return "/".join(parts)


def format_tail_words(words: dict[str, Any]) -> str:
    parts = []
    byte_count = words.get("byte_count")
    if isinstance(byte_count, int):
        parts.append(f"bytes={byte_count}")
    for key in ("u16_le", "i16_le", "u32_le", "i32_le"):
        values = words.get(key)
        if isinstance(values, list) and values:
            parts.append(f"{key}={format_limited_values(values)}")
    return ",".join(parts)


def format_limited_values(values: list[Any], limit: int = 4) -> str:
    shown = [str(value) for value in values[:limit]]
    if len(values) > limit:
        shown.append(f"...({len(values)} total)")
    return "/".join(shown)


def format_printable_runs(values: list[Any]) -> str:
    return "/".join(str(value) for value in values[:4])


if __name__ == "__main__":
    raise SystemExit(main())
