#!/usr/bin/env python3
"""Persistent Pi/Linux watcher for repeated Oura Ring 4 BLE attempts."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Repeat the Pi GATT diagnostic so transient Oura advertising states "
            "can be captured without manual restarts."
        )
    )
    parser.add_argument("--cycle-scan-seconds", type=float, default=300.0)
    parser.add_argument("--connect-timeout", type=float, default=8.0)
    parser.add_argument("--connect-limit", type=int, default=1)
    parser.add_argument("--summary-limit", type=int, default=5)
    parser.add_argument("--matrix-response-timeout", type=float, default=1.5)
    parser.add_argument("--matrix-read-timeout", type=float, default=1.0)
    parser.add_argument("--matrix-pre-read", action="store_true")
    parser.add_argument("--matrix-post-read", action="store_true")
    parser.add_argument(
        "--packet-read-only",
        action="store_true",
        default=True,
        help=(
            "run the focused safe packet reader instead of the characteristic matrix"
        ),
    )
    parser.add_argument(
        "--no-packet-read-only",
        dest="packet_read_only",
        action="store_false",
        help="allow matrix or standard read probing instead of the focused packet reader",
    )
    parser.add_argument(
        "--connectable-hint-only",
        action="store_true",
        default=True,
        help="only connect when the Oura advertisement has the readiness hint",
    )
    parser.add_argument(
        "--allow-presence-connects",
        dest="connectable_hint_only",
        action="store_false",
        help="also try sparse Oura presence adverts that usually time out when worn",
    )
    parser.add_argument(
        "--skip-standard-reads",
        action="store_true",
        default=True,
        help="skip ordinary GAP/Device Information reads before Oura packet probes",
    )
    parser.add_argument(
        "--with-standard-reads",
        dest="skip_standard_reads",
        action="store_false",
        help="include ordinary GAP/Device Information reads before packet probes",
    )
    parser.add_argument(
        "--power-off-after",
        action="store_true",
        default=True,
        help="power off hci0 after each scan/read cycle",
    )
    parser.add_argument(
        "--no-power-off-after",
        dest="power_off_after",
        action="store_false",
        help="leave hci0 powered after each cycle",
    )
    parser.add_argument(
        "--passive-scan",
        action="store_true",
        default=True,
        help="use BlueZ passive advertisement monitoring when available",
    )
    parser.add_argument(
        "--active-scan",
        dest="passive_scan",
        action="store_false",
        help="use active scanning instead of passive advertisement monitoring",
    )
    parser.add_argument(
        "--pair",
        action="store_true",
        help="pass --pair to the diagnostic so BlueZ bonds before GATT work",
    )
    parser.add_argument(
        "--agent",
        action="store_true",
        help="launch the Pi BlueZ auto-confirm agent while the watcher runs",
    )
    parser.add_argument("--agent-capability", default="KeyboardDisplay")
    parser.add_argument("--agent-python", default="/usr/bin/python3")
    parser.add_argument("--scan-heartbeat-seconds", type=float, default=60.0)
    parser.add_argument("--delay-seconds", type=float, default=2.0)
    parser.add_argument(
        "--btmon",
        action="store_true",
        help="capture a per-cycle sudo btmon -t log while the diagnostic runs",
    )
    parser.add_argument("--btmon-dir", default="logs")
    parser.add_argument(
        "--cycles",
        type=int,
        default=0,
        help="number of diagnostic cycles to run; 0 means run until success",
    )
    parser.add_argument(
        "--require-manufacturer-hex",
        action="append",
        default=[],
        help="only connect on this Oura manufacturer payload; may be repeated",
    )
    parser.add_argument(
        "--no-matrix-only",
        action="store_true",
        help="use the standard read path instead of the characteristic matrix",
    )
    return run(parser.parse_args())


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    cycle = 0
    emit(
        "watch_start",
        {
            "cycle_scan_seconds": args.cycle_scan_seconds,
            "connect_timeout": args.connect_timeout,
            "require_manufacturer_hex": args.require_manufacturer_hex,
            "matrix_only": not args.no_matrix_only,
            "matrix_pre_read": args.matrix_pre_read,
            "matrix_post_read": args.matrix_post_read,
            "matrix_read_timeout": args.matrix_read_timeout,
            "packet_read_only": args.packet_read_only,
            "connectable_hint_only": args.connectable_hint_only,
            "skip_standard_reads": args.skip_standard_reads,
            "power_off_after": args.power_off_after,
            "passive_scan": args.passive_scan,
            "pair": args.pair,
            "agent": args.agent,
            "agent_capability": args.agent_capability,
            "btmon": args.btmon,
            "cycles": args.cycles,
        },
        started,
    )
    agent_process: subprocess.Popen[str] | None = None
    try:
        if args.agent:
            agent_process = start_agent(args, started)
        while args.cycles <= 0 or cycle < args.cycles:
            cycle += 1
            emit("watch_cycle_start", {"cycle": cycle}, started)
            code = run_cycle(args, cycle, started)
            emit("watch_cycle_done", {"cycle": cycle, "exit_code": code}, started)
            if code == 0:
                emit("watch_success", {"cycle": cycle}, started)
                return 0
            if args.cycles > 0 and cycle >= args.cycles:
                break
            time.sleep(max(0.0, args.delay_seconds))
        emit("watch_done", {"cycles": cycle, "success": False}, started)
        return 1
    finally:
        if agent_process:
            stop_process(agent_process)


def run_cycle(args: argparse.Namespace, cycle: int, started: float) -> int:
    diagnostic = Path(__file__).with_name("pi-oura-gatt-diagnostic.py")
    env = child_python_env()
    command = [
        sys.executable,
        str(diagnostic),
        "--scan-seconds",
        str(args.cycle_scan_seconds),
        "--connect-timeout",
        str(args.connect_timeout),
        "--connect-limit",
        str(args.connect_limit),
        "--summary-limit",
        str(args.summary_limit),
        "--connect-on-first-oura",
        "--scan-heartbeat-seconds",
        str(args.scan_heartbeat_seconds),
        "--matrix-response-timeout",
        str(args.matrix_response_timeout),
        "--matrix-read-timeout",
        str(args.matrix_read_timeout),
    ]
    for value in args.require_manufacturer_hex:
        command.extend(["--require-manufacturer-hex", value])
    if args.packet_read_only:
        command.append("--packet-read-only")
    elif not args.no_matrix_only:
        command.append("--matrix-only")
    if args.connectable_hint_only:
        command.append("--connectable-hint-only")
    if args.skip_standard_reads:
        command.append("--skip-standard-reads")
    if args.power_off_after:
        command.append("--power-off-after")
    if args.passive_scan:
        command.append("--passive-scan")
    if args.matrix_pre_read:
        command.append("--matrix-pre-read")
    if args.matrix_post_read:
        command.append("--matrix-post-read")
    if args.pair:
        command.append("--pair")

    btmon_process: subprocess.Popen[str] | None = None
    btmon_handle: Any | None = None
    btmon_path: Path | None = None
    if args.btmon:
        btmon_dir = Path(args.btmon_dir)
        btmon_dir.mkdir(parents=True, exist_ok=True)
        btmon_path = btmon_dir / (
            f"btmon-pi-oura-cycle-{cycle:04d}-"
            f"{time.strftime('%Y%m%d-%H%M%S')}.log"
        )
        btmon_handle = btmon_path.open("w", encoding="utf-8")
        btmon_process = subprocess.Popen(
            ["sudo", "-n", "btmon", "-t"],
            stdout=btmon_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        emit("watch_btmon_start", {"cycle": cycle, "path": str(btmon_path)}, started)

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    try:
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
        return_code = process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
        if btmon_process:
            btmon_process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                btmon_process.wait(timeout=3)
            if btmon_process.poll() is None:
                btmon_process.kill()
                btmon_process.wait()
            emit(
                "watch_btmon_stop",
                {
                    "cycle": cycle,
                    "path": str(btmon_path),
                    "exit_code": btmon_process.returncode,
                },
                started,
            )
        if btmon_handle:
            btmon_handle.close()
    if return_code < 0:
        emit(
            "watch_cycle_signal",
            {"cycle": cycle, "signal": -return_code},
            started,
        )
    return return_code


def start_agent(
    args: argparse.Namespace, started: float
) -> subprocess.Popen[str]:
    script = Path(__file__).with_name("pi-bluez-auto-agent.py")
    env = child_python_env()
    command = [
        args.agent_python,
        str(script),
        "--capability",
        args.agent_capability,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid,
        env=env,
    )
    emit(
        "watch_agent_start",
        {"pid": process.pid, "command": command},
        started,
    )
    if process.stdout is not None:
        thread = threading.Thread(
            target=forward_agent_output,
            args=(process,),
            daemon=True,
        )
        thread.start()
    time.sleep(1.0)
    if process.poll() is not None:
        emit(
            "watch_agent_exit",
            {"pid": process.pid, "exit_code": process.returncode},
            started,
        )
    return process


def forward_agent_output(process: subprocess.Popen[str]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=3)
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def child_python_env() -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_path
        if not existing_pythonpath
        else f"{src_path}{os.pathsep}{existing_pythonpath}"
    )
    return env


def emit(event: str, payload: dict[str, Any], started: float) -> None:
    print(
        json.dumps(
            {
                "event": event,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "payload": payload,
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
