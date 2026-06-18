from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


def load_cursor_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-zeroauth-next-cursor.py"
    spec = importlib.util.spec_from_file_location("pi_zeroauth_next_cursor", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cursor_module = load_cursor_module()


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows),
        encoding="utf-8",
    )


def test_latest_read_result_cursor_wins_over_page_cursor(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "zeroauth_events_walk_page",
                "payload": {
                    "next_start_timestamp": 0x7F17,
                    "request_start_timestamp": 0x7930,
                    "request_start_hex": "0x00007930",
                    "request_max_events": 64,
                    "events_received": 64,
                    "bytes_left": 552039,
                    "complete": False,
                },
            },
            {
                "event": "read_result",
                "payload": {
                    "event_summary": {
                        "next_start_timestamp": 0x8696,
                        "complete": False,
                        "latest_events_done": {
                            "request_start_timestamp": 0x7F17,
                            "request_start_hex": "0x00007f17",
                            "request_max_events": 64,
                            "events_received": 64,
                            "bytes_left": 550911,
                        },
                    }
                },
            },
        ],
    )

    cursor = cursor_module.latest_cursor([log_path])

    assert cursor is not None
    assert cursor.event == "read_result"
    assert cursor.next_start_timestamp == 0x8696
    assert cursor.next_start_hex == "0x00008696"
    assert cursor.request_start_timestamp == 0x7F17
    assert cursor.bytes_left == 550911


def test_falls_back_to_latest_events_walk_page(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    write_jsonl(
        log_path,
        [
            {
                "event": "zeroauth_events_walk_page",
                "payload": {
                    "next_start_timestamp": 0x1000,
                    "request_start_timestamp": 0x0F00,
                    "request_max_events": 32,
                    "events_received": 32,
                },
            },
            {
                "event": "zeroauth_events_walk_page",
                "payload": {
                    "next_start_timestamp": 0x1800,
                    "request_start_timestamp": 0x1000,
                    "request_max_events": 64,
                    "events_received": 64,
                    "bytes_left": 128,
                },
            },
        ],
    )

    cursor = cursor_module.latest_cursor([log_path])

    assert cursor is not None
    assert cursor.event == "zeroauth_events_walk_page"
    assert cursor.next_start_hex == "0x00001800"
    assert cursor.request_start_timestamp == 0x1000
    assert cursor.request_max_events == 64
    assert cursor.bytes_left == 128


def test_probe_output_from_current_pointer(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    log_path = tmp_path / "capture.jsonl"
    pointer_path = tmp_path / "current.log"
    pointer_path.write_text(str(log_path), encoding="utf-8")
    write_jsonl(
        log_path,
        [
            {
                "event": "read_result",
                "payload": {
                    "event_summary": {
                        "next_start_timestamp": "0x8696",
                        "latest_events_done": {},
                    }
                },
            },
        ],
    )
    monkeypatch.chdir(tmp_path)

    rc = cursor_module.main(
        ["--current-pointer", str(pointer_path), "--probe", "--pages", "3"]
    )

    assert rc == 0
    assert capsys.readouterr().out.strip() == "events_walk:0x00008696:3:64"


def test_current_pointer_without_cursor_falls_back_to_recent_event_log(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    event_log = logs_dir / "pi-zeroauth-chase-product-20260614-181645.jsonl"
    current_log = logs_dir / "pi-zeroauth-chase-product-20260614-181844.jsonl"
    pointer_path = logs_dir / "current-pi-zeroauth-chase.log"
    pointer_path.write_text(str(current_log), encoding="utf-8")
    write_jsonl(
        event_log,
        [
            {
                "event": "read_result",
                "payload": {
                    "event_summary": {
                        "next_start_timestamp": 0xADDB,
                        "latest_events_done": {"bytes_left": 554002},
                    }
                },
            },
        ],
    )
    write_jsonl(
        current_log,
        [
            {
                "event": "read_result",
                "payload": {
                    "battery": {"battery_level_percent": 100},
                    "event_summary": {},
                },
            },
        ],
    )
    monkeypatch.chdir(tmp_path)

    rc = cursor_module.main(["--current-pointer", str(pointer_path), "--probe"])

    assert rc == 0
    assert capsys.readouterr().out.strip() == "events_walk:0x0000addb:8:64"


def test_invalid_partial_jsonl_line_is_ignored(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "zeroauth_events_walk_page",
                "payload": {"next_start_timestamp": 123},
            }
        )
        + "\n"
        + '{"event": "read_result", ',
        encoding="utf-8",
    )

    cursor = cursor_module.latest_cursor([log_path])

    assert cursor is not None
    assert cursor.next_start_hex == "0x0000007b"
