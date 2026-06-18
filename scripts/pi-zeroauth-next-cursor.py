#!/usr/bin/env python3
"""Find the next zero-auth event cursor from Pi JSONL captures."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DEFAULT_CURRENT_POINTER = Path("logs/current-pi-zeroauth-chase.log")
DEFAULT_LOG_GLOB = "pi-zeroauth-chase-product-*.jsonl"


@dataclass(frozen=True)
class CursorEvidence:
    log: str
    line: int
    event: str
    next_start_timestamp: int
    next_start_hex: str
    request_start_timestamp: int | None = None
    request_start_hex: str | None = None
    request_max_events: int | None = None
    events_received: int | None = None
    bytes_left: int | None = None
    complete: bool | None = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit the next events_walk cursor from zero-auth Pi logs."
    )
    parser.add_argument("logs", nargs="*", help="JSONL logs to inspect")
    parser.add_argument(
        "--current-pointer",
        default=str(DEFAULT_CURRENT_POINTER),
        help="pointer file used when no log paths are supplied",
    )
    parser.add_argument(
        "--log-glob",
        default=DEFAULT_LOG_GLOB,
        help=(
            "glob, relative to the current pointer directory, searched when no "
            "explicit log paths are supplied"
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit cursor metadata")
    parser.add_argument(
        "--probe",
        action="store_true",
        help="emit an events_walk:<cursor>:<pages>:<max-events> probe",
    )
    parser.add_argument("--pages", type=int, default=8, help="events_walk page count")
    parser.add_argument(
        "--max-events", type=int, default=64, help="events_walk max events per page"
    )
    args = parser.parse_args(argv)

    try:
        log_paths = resolve_log_paths(args.logs, Path(args.current_pointer), args.log_glob)
        cursor = latest_cursor(log_paths)
    except (OSError, ValueError) as exc:
        print(f"pi-zeroauth-next-cursor: {exc}", file=sys.stderr)
        return 1

    if cursor is None:
        print("pi-zeroauth-next-cursor: no event cursor found", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(asdict(cursor), indent=2, sort_keys=True))
    elif args.probe:
        print(f"events_walk:{cursor.next_start_hex}:{args.pages}:{args.max_events}")
    else:
        print(cursor.next_start_hex)
    return 0


def resolve_log_paths(
    logs: Iterable[str], current_pointer: Path, log_glob: str = DEFAULT_LOG_GLOB
) -> list[Path]:
    paths = [Path(path) for path in logs if path]
    if paths:
        return paths

    candidates: list[Path] = []
    if current_pointer.exists():
        pointed = current_pointer.read_text(encoding="utf-8").strip()
        if pointed:
            candidates.append(Path(pointed))

    candidates.extend(current_pointer.parent.glob(log_glob))
    paths = sort_unique_by_mtime(candidates)
    if paths:
        return paths

    raise ValueError(
        f"no logs supplied, no current pointer log, and no logs matched {log_glob}"
    )


def sort_unique_by_mtime(paths: Iterable[Path]) -> list[Path]:
    unique: dict[Path, None] = {}
    for path in paths:
        unique[path] = None
    return sorted(unique, key=lambda path: path.stat().st_mtime if path.exists() else 0.0)


def latest_cursor(paths: Iterable[Path]) -> CursorEvidence | None:
    latest: CursorEvidence | None = None
    for path in paths:
        latest_in_log = latest_cursor_in_log(path)
        if latest_in_log is not None:
            latest = latest_in_log
    return latest


def latest_cursor_in_log(path: Path) -> CursorEvidence | None:
    latest_read_result: CursorEvidence | None = None
    latest_page: CursorEvidence | None = None

    for line_number, row in read_jsonl_rows(path):
        event = str(row.get("event") or "")
        payload = row.get("payload")
        if not isinstance(payload, dict):
            continue

        if event == "read_result":
            cursor = cursor_from_read_result(path, line_number, payload)
            if cursor is not None:
                latest_read_result = cursor
        elif event == "zeroauth_events_walk_page":
            cursor = cursor_from_events_walk_page(path, line_number, payload)
            if cursor is not None:
                latest_page = cursor

    return latest_read_result or latest_page


def read_jsonl_rows(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    if not path.exists():
        raise ValueError(f"log does not exist: {path}")

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # Active tee logs can have a partial final line; older complete rows
                # are still valid cursor evidence.
                continue
            if isinstance(row, dict):
                yield line_number, row


def cursor_from_read_result(
    path: Path, line_number: int, payload: dict[str, Any]
) -> CursorEvidence | None:
    summary = payload.get("event_summary")
    if not isinstance(summary, dict):
        return None

    next_start = parse_int(summary.get("next_start_timestamp"))
    if next_start is None:
        return None

    latest_done = summary.get("latest_events_done")
    if not isinstance(latest_done, dict):
        latest_done = {}

    return CursorEvidence(
        log=str(path),
        line=line_number,
        event="read_result",
        next_start_timestamp=next_start,
        next_start_hex=format_cursor(next_start),
        request_start_timestamp=parse_int(latest_done.get("request_start_timestamp")),
        request_start_hex=parse_str(latest_done.get("request_start_hex")),
        request_max_events=parse_int(latest_done.get("request_max_events")),
        events_received=parse_int(latest_done.get("events_received")),
        bytes_left=parse_int(latest_done.get("bytes_left")),
        complete=parse_bool(summary.get("complete")),
    )


def cursor_from_events_walk_page(
    path: Path, line_number: int, payload: dict[str, Any]
) -> CursorEvidence | None:
    next_start = parse_int(payload.get("next_start_timestamp"))
    if next_start is None:
        return None

    return CursorEvidence(
        log=str(path),
        line=line_number,
        event="zeroauth_events_walk_page",
        next_start_timestamp=next_start,
        next_start_hex=format_cursor(next_start),
        request_start_timestamp=parse_int(payload.get("request_start_timestamp")),
        request_start_hex=parse_str(payload.get("request_start_hex")),
        request_max_events=parse_int(payload.get("request_max_events")),
        events_received=parse_int(payload.get("events_received")),
        bytes_left=parse_int(payload.get("bytes_left")),
        complete=parse_bool(payload.get("complete")),
    )


def parse_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def parse_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def format_cursor(value: int) -> str:
    return f"0x{value:08x}"


if __name__ == "__main__":
    raise SystemExit(main())
