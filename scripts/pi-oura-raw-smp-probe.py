#!/usr/bin/env python3
"""Probe Oura setup-state SMP pairing behavior with raw HCI packets."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HCI_ACLDATA_PKT = 0x02
PB_FIRST_NON_FLUSH = 0x02
CID_SMP = 0x0006

PAIRING_VARIANTS = {
    "connect_only": b"",
    "legacy_no_bond_no_keys": bytes.fromhex("01030000100000"),
    "sc_no_bond_no_keys": bytes.fromhex("01030008100000"),
    "bond_legacy_no_mitm_no_keys": bytes.fromhex("01030001100000"),
    "bond_legacy_no_mitm_keys": bytes.fromhex("01030001100101"),
    "bond_sc_no_mitm_no_keys": bytes.fromhex("01030009100000"),
    "bond_sc_no_mitm_keys": bytes.fromhex("01030009100507"),
    "bond_sc_no_mitm_ct2_linkkey": bytes.fromhex("01030029100d0f"),
    "display_only_bond_sc_mitm_ct2_keys": bytes.fromhex("0100002d100507"),
    "display_yesno_bond_sc_mitm_keys": bytes.fromhex("0101000d100507"),
    "keyboard_only_bond_sc_mitm_ct2_keys": bytes.fromhex("0102002d100507"),
    "no_input_output_bond_sc_mitm_ct2_keys": bytes.fromhex("0103002d100507"),
    "keyboard_display_bond_sc_mitm_keys": bytes.fromhex("0104000d100507"),
    "display_yesno_bond_sc_mitm_ct2_keys": bytes.fromhex("0101002d100507"),
    "keyboard_display_bond_sc_mitm_ct2_keys": bytes.fromhex("0104002d100507"),
    "display_yesno_bond_sc_mitm_ct2_linkkey": bytes.fromhex("0101002d100d0f"),
    "oob_bond_legacy_no_mitm_keys": bytes.fromhex("01030101100101"),
    "oob_bond_sc_mitm_keys": bytes.fromhex("0103010d100507"),
    "oob_display_yesno_bond_sc_mitm_ct2_keys": bytes.fromhex("0101012d100507"),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan for a setup-state Oura RPA, open a raw LE connection, inject "
            "selected SMP Pairing Request variants, and write btmon logs."
        )
    )
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--scan-seconds", type=float, default=10.0)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument(
        "--pre-smp-delay-seconds",
        type=float,
        default=0.0,
        help="delay after LE connection before sending the SMP request",
    )
    parser.add_argument("--listen-seconds", type=float, default=2.0)
    parser.add_argument("--hci-index", type=int, default=0)
    parser.add_argument(
        "--own-address-type",
        choices=("public", "random"),
        default="public",
        help="central address type for LE Create Connection",
    )
    parser.add_argument(
        "--random-address",
        default="",
        help="static random central address for --own-address-type=random",
    )
    parser.add_argument(
        "--manufacturer-hex",
        default="04671b01,04661b01,04651b01,04621b01,04611b01,04601b01",
        help="comma-separated setup-state manufacturer payloads to target",
    )
    parser.add_argument(
        "--variants",
        default="legacy_no_bond_no_keys,sc_no_bond_no_keys",
        help=f"comma-separated variants: {','.join(sorted(PAIRING_VARIANTS))}",
    )
    parser.add_argument(
        "--stop-bluetoothd",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="stop bluetooth.service during probes and restore it afterward",
    )
    args = parser.parse_args()
    return run(args)


def run(args: argparse.Namespace) -> int:
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    variants = parse_variants(args.variants)
    target_manufacturers = parse_hex_list(args.manufacturer_hex)
    emit(
        "raw_smp_probe_start",
        {
            "variants": [name for name, _payload in variants],
            "manufacturer_hex": sorted(target_manufacturers),
            "stop_bluetoothd": args.stop_bluetoothd,
            "own_address_type": args.own_address_type,
            "random_address": args.random_address,
            "pre_smp_delay_seconds": args.pre_smp_delay_seconds,
        },
    )
    if args.stop_bluetoothd:
        stop_bluetoothd()
    outcomes: list[dict[str, Any]] = []
    try:
        ensure_adapter_up()
        for name, payload in variants:
            outcomes.append(
                probe_variant(args, log_dir, target_manufacturers, name, payload)
            )
    finally:
        if args.stop_bluetoothd:
            restore_bluetoothd()
    summary = summarize_probe_outcomes(outcomes)
    emit("raw_smp_probe_done", summary)
    return 0 if summary["probed_count"] else 1


def probe_variant(
    args: argparse.Namespace,
    log_dir: Path,
    target_manufacturers: set[str],
    name: str,
    payload: bytes,
) -> dict[str, Any]:
    address = find_setup_address(args.scan_seconds, target_manufacturers)
    if not address:
        emit("raw_smp_no_target", {"variant": name})
        return {"variant": name, "outcome": "no_target"}
    disconnect(address)
    path = log_dir / f"btmon-raw-smp-{name}-{timestamp()}.log"
    emit("raw_smp_variant_start", {"variant": name, "address": address, "path": str(path)})
    with path.open("w", encoding="utf-8") as handle:
        btmon = subprocess.Popen(
            maybe_sudo(["btmon"]),
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        time.sleep(0.25)
        try:
            configure_own_address(args)
            hci_le_create_connection(
                address, args.connect_timeout, args.own_address_type
            )
            handle_id = parse_connection_handle(address, args.connect_timeout)
            if payload:
                time.sleep(max(0.0, args.pre_smp_delay_seconds))
                send_smp_pairing_request(args.hci_index, handle_id, payload)
            time.sleep(max(0.0, args.listen_seconds))
        finally:
            disconnect(address)
            stop_process(btmon)
    security_failure = summarize_setup_security_failure(path)
    pairing_response = summarize_pairing_response(path)
    remote_disconnect = summarize_remote_disconnect_after_pairing_request(path)
    any_disconnect = summarize_disconnect(path)
    if not payload:
        outcome = (
            "connect_only_remote_disconnect"
            if any_disconnect and any_disconnect.get("remote")
            else "connect_only_no_remote_disconnect"
        )
    elif security_failure:
        outcome = "pairing_rejected"
    elif pairing_response:
        outcome = "pairing_response_observed"
    elif remote_disconnect:
        outcome = "remote_disconnect_after_pairing_request"
    else:
        outcome = "no_pairing_response_observed"
    emit(
        "raw_smp_variant_done",
        {
            "variant": name,
            "address": address,
            "path": str(path),
            "payload_hex": payload.hex(),
            "outcome": outcome,
            "disconnect": any_disconnect or None,
            "pairing_response": pairing_response or None,
            "remote_disconnect": remote_disconnect or None,
            "setup_security_failure": security_failure or None,
        },
    )
    return {
        "variant": name,
        "outcome": outcome,
        "path": str(path),
        "reason_code": (
            security_failure.get("smp_pairing_failed_reason_code")
            if security_failure
            else remote_disconnect.get("reason_code")
            if remote_disconnect
            else any_disconnect.get("reason_code")
            if any_disconnect
            else None
        ),
    }


def summarize_probe_outcomes(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for row in outcomes:
        outcome = str(row.get("outcome", "unknown"))
        counts[outcome] = counts.get(outcome, 0) + 1
    return {
        "outcomes": outcomes,
        "outcome_counts": counts,
        "probed_count": len(outcomes) - counts.get("no_target", 0),
        "non_rejected_variants": [
            row.get("variant")
            for row in outcomes
            if row.get("outcome")
            in {
                "pairing_response_observed",
                "no_pairing_response_observed",
                "connect_only_no_remote_disconnect",
            }
        ],
    }


def summarize_pairing_response(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    return (
        {"classification": "pairing_response_observed"}
        if any("SMP: Pairing Response" in line for line in lines)
        else {}
    )


def summarize_remote_disconnect_after_pairing_request(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    saw_request = any("SMP: Pairing Request" in line for line in lines)
    if not saw_request:
        return {}
    summary = summarize_disconnect(path)
    if not summary or not summary.get("remote"):
        return {}
    return {**summary, "classification": "remote_disconnect_after_pairing_request"}


def summarize_disconnect(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    for index, line in enumerate(lines):
        if "Disconnect Complete" not in line:
            continue
        for reason_line in lines[index + 1 : index + 8]:
            match = re.search(r"\s*Reason:\s+(.+?)\s+\((0x[0-9a-fA-F]+)\)", reason_line)
            if not match:
                continue
            reason = match.group(1)
            reason_code = match.group(2).lower()
            return {
                "classification": "disconnect_complete",
                "reason": reason,
                "reason_code": reason_code,
                "remote": reason_code in {"0x13", "0x15"} or "Remote" in reason,
            }
    return {}


def find_setup_address(scan_seconds: float, target_manufacturers: set[str]) -> str:
    deadline = time.monotonic() + scan_seconds
    command = maybe_sudo(["btmgmt", "find"])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    last_address = ""
    try:
        assert process.stdout is not None
        while time.monotonic() < deadline:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            fields = line.split()
            if "dev_found:" in line and len(fields) >= 3:
                last_address = fields[2]
            manufacturer = manufacturer_from_btmgmt_line(line)
            if manufacturer and manufacturer in target_manufacturers:
                return last_address
            if "name Oura Ring 4" in line and last_address:
                return last_address
    finally:
        run_command(maybe_sudo(["btmgmt", "stop-find"]), timeout=2)
        stop_process(process)
    return ""


def manufacturer_from_btmgmt_line(line: str) -> str:
    match = re.search(r"Data\[\d+\]:\s+([0-9a-fA-F]+)", line)
    return match.group(1).lower() if match else ""


def hci_le_create_connection(
    address: str, timeout_seconds: float, own_address_type: str = "public"
) -> None:
    run_command(maybe_sudo(["hcitool", "cmd", "0x08", "0x000c", "00", "00"]), timeout=3)
    command = [
        "hcitool",
        "cmd",
        "0x08",
        "0x000d",
        "10",
        "00",
        "10",
        "00",
        "00",
        "01",
        *bdaddr_to_hci_bytes(address),
        "01" if own_address_type == "random" else "00",
        "0f",
        "00",
        "0f",
        "00",
        "00",
        "00",
        "80",
        "0c",
        "01",
        "00",
        "01",
        "00",
    ]
    result = run_command(maybe_sudo(command), timeout=max(3.0, timeout_seconds))
    emit(
        "raw_smp_connect_command",
        {
            "address": address,
            "command": command,
            "own_address_type": own_address_type,
            "result": result,
        },
    )


def configure_own_address(args: argparse.Namespace) -> None:
    if args.own_address_type != "random":
        return
    if not args.random_address:
        args.random_address = generate_static_random_address()
    command = [
        "hcitool",
        "cmd",
        "0x08",
        "0x0005",
        *bdaddr_to_hci_bytes(args.random_address),
    ]
    result = run_command(maybe_sudo(command), timeout=3)
    emit(
        "raw_smp_random_address_set",
        {"address": args.random_address, "command": command, "result": result},
    )


def generate_static_random_address() -> str:
    data = bytearray(secrets.token_bytes(6))
    data[0] = (data[0] | 0xC0) & 0xFF
    return ":".join(f"{value:02X}" for value in data)


def parse_connection_handle(address: str, timeout_seconds: float) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = run_command(maybe_sudo(["hcitool", "con"]), timeout=2)
        for line in result["stdout"].splitlines():
            if address.upper() not in line.upper() or "handle" not in line:
                continue
            match = re.search(r"handle\s+(\d+)", line)
            if match:
                return int(match.group(1))
        time.sleep(0.1)
    raise RuntimeError(f"no LE connection handle for {address}")


def send_smp_pairing_request(hci_index: int, handle: int, payload: bytes) -> None:
    handle_pb_bc = handle | (PB_FIRST_NON_FLUSH << 12)
    l2cap = struct.pack("<HH", len(payload), CID_SMP) + payload
    acl = bytes([HCI_ACLDATA_PKT]) + struct.pack("<HH", handle_pb_bc, len(l2cap)) + l2cap
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((hci_index,))
    try:
        sent = sock.send(acl)
    finally:
        sock.close()
    emit(
        "raw_smp_pairing_request_tx",
        {"handle": handle, "payload_hex": payload.hex(), "sent_bytes": sent},
    )


def disconnect(address: str) -> None:
    for handle in connection_handles(address):
        run_command(maybe_sudo(["hcitool", "ledc", str(handle), "0x16"]), timeout=3)
    run_command(maybe_sudo(["hcitool", "cmd", "0x08", "0x000c", "00", "00"]), timeout=3)
    time.sleep(0.25)


def connection_handles(address: str) -> list[int]:
    result = run_command(maybe_sudo(["hcitool", "con"]), timeout=2)
    handles: list[int] = []
    for line in result["stdout"].splitlines():
        if address.upper() not in line.upper() or "handle" not in line:
            continue
        match = re.search(r"handle\s+(\d+)", line)
        if match:
            handles.append(int(match.group(1)))
    return handles


def stop_bluetoothd() -> None:
    emit(
        "raw_smp_bluetoothd_stop",
        run_command(maybe_sudo(["systemctl", "stop", "bluetooth"]), timeout=10),
    )


def restore_bluetoothd() -> None:
    commands = [
        ["systemctl", "start", "bluetooth"],
        ["hciconfig", "hci0", "up"],
        ["btmgmt", "power", "on"],
        ["btmgmt", "bondable", "on"],
    ]
    results = [run_command(maybe_sudo(command), timeout=10) for command in commands]
    emit("raw_smp_bluetoothd_restore", {"commands": results})


def ensure_adapter_up() -> None:
    run_command(maybe_sudo(["hciconfig", "hci0", "up"]), timeout=5)
    run_command(maybe_sudo(["btmgmt", "power", "on"]), timeout=5)


def summarize_setup_security_failure(path: Path) -> dict[str, Any]:
    script = Path(__file__).with_name("pi-oura-raw-rpa-read-loop.py")
    spec = importlib.util.spec_from_file_location("pi_oura_raw_rpa_read_loop", script)
    if spec is None or spec.loader is None:
        return {}
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.summarize_setup_security_failure(path)


def parse_variants(value: str) -> list[tuple[str, bytes]]:
    variants: list[tuple[str, bytes]] = []
    for part in value.split(","):
        name = part.strip()
        if not name:
            continue
        try:
            variants.append((name, PAIRING_VARIANTS[name]))
        except KeyError as exc:
            raise SystemExit(f"unknown SMP variant: {name}") from exc
    return variants


def parse_hex_list(value: str) -> set[str]:
    return {
        re.sub(r"[^0-9a-fA-F]", "", part).lower()
        for part in value.split(",")
        if re.sub(r"[^0-9a-fA-F]", "", part)
    }


def bdaddr_to_hci_bytes(address: str) -> list[str]:
    parts = address.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid Bluetooth address: {address}")
    return [f"{int(part, 16):02x}" for part in reversed(parts)]


def maybe_sudo(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    return ["sudo", "-n", *command]


def run_command(command: list[str], timeout: float) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["timeout", str(timeout), *command],
            text=True,
            capture_output=True,
            timeout=timeout + 1,
        )
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"command": command, "returncode": 124, "stdout": "", "stderr": "timeout"}


def stop_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def emit(event: str, payload: Any) -> None:
    print(json.dumps({"event": event, "payload": payload}, sort_keys=True), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
