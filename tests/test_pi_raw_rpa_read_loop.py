from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


def load_raw_loop_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-oura-raw-rpa-read-loop.py"
    spec = importlib.util.spec_from_file_location("pi_oura_raw_rpa_read_loop", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


raw_loop = load_raw_loop_module()


def load_raw_smp_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-oura-raw-smp-probe.py"
    spec = importlib.util.spec_from_file_location("pi_oura_raw_smp_probe", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


raw_smp = load_raw_smp_module()


def test_raw_loop_tracks_all_observed_oura_manufacturer_states() -> None:
    observed = {"04601b01", "04611b01", "04621b01", "04651b01", "04661b01", "04671b01"}

    assert observed <= raw_loop.KNOWN_OURA_MANUFACTURERS
    for value in observed:
        assert raw_loop.is_oura_manufacturer(value, "")


def test_raw_smp_probe_exposes_likely_pairing_variants() -> None:
    names = {
        "legacy_no_bond_no_keys",
        "connect_only",
        "sc_no_bond_no_keys",
        "bond_sc_no_mitm_keys",
        "display_only_bond_sc_mitm_ct2_keys",
        "display_yesno_bond_sc_mitm_ct2_linkkey",
        "keyboard_only_bond_sc_mitm_ct2_keys",
        "keyboard_display_bond_sc_mitm_ct2_keys",
        "no_input_output_bond_sc_mitm_ct2_keys",
        "oob_bond_sc_mitm_keys",
        "oob_display_yesno_bond_sc_mitm_ct2_keys",
    }

    assert names <= set(raw_smp.PAIRING_VARIANTS)
    for name in names:
        if name == "connect_only":
            assert raw_smp.PAIRING_VARIANTS[name] == b""
        else:
            assert raw_smp.PAIRING_VARIANTS[name].startswith(b"\x01")
            assert len(raw_smp.PAIRING_VARIANTS[name]) == 7


def test_raw_smp_probe_summarizes_outcomes() -> None:
    summary = raw_smp.summarize_probe_outcomes(
        [
            {"variant": "a", "outcome": "pairing_rejected", "reason_code": "0x08"},
            {"variant": "b", "outcome": "no_target"},
            {"variant": "c", "outcome": "pairing_response_observed"},
            {"variant": "d", "outcome": "remote_disconnect_after_pairing_request"},
            {"variant": "e", "outcome": "connect_only_no_remote_disconnect"},
        ]
    )

    assert summary["outcome_counts"] == {
        "pairing_rejected": 1,
        "no_target": 1,
        "pairing_response_observed": 1,
        "remote_disconnect_after_pairing_request": 1,
        "connect_only_no_remote_disconnect": 1,
    }
    assert summary["probed_count"] == 4
    assert summary["non_rejected_variants"] == ["c", "e"]


def test_raw_loop_stop_signal_raises_keyboard_interrupt() -> None:
    try:
        raw_loop.handle_stop_signal(raw_loop.signal.SIGTERM, None)
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("expected KeyboardInterrupt")


def test_raw_smp_probe_detects_remote_disconnect_after_pairing_request(tmp_path) -> None:
    log = tmp_path / "btmon.log"
    log.write_text(
        "\n".join(
            [
                "      SMP: Pairing Request (0x01) len 6",
                "        Authentication requirement: Bonding, No MITM, SC, "
                "No Keypresses (0x09)",
                "> HCI Event: Disconnect Complete (0x05) plen 4",
                "        Status: Success (0x00)",
                "        Handle: 64",
                "        Reason: Remote Device Terminated due to Power Off (0x15)",
            ]
        )
    )

    assert raw_smp.summarize_remote_disconnect_after_pairing_request(log) == {
        "classification": "remote_disconnect_after_pairing_request",
        "remote": True,
        "reason": "Remote Device Terminated due to Power Off",
        "reason_code": "0x15",
    }


def test_raw_smp_probe_detects_disconnect_reason(tmp_path) -> None:
    log = tmp_path / "btmon.log"
    log.write_text(
        "\n".join(
            [
                "> HCI Event: Disconnect Complete (0x05) plen 4",
                "        Status: Success (0x00)",
                "        Handle: 64",
                "        Reason: Connection Terminated By Local Host (0x16)",
            ]
        )
    )

    assert raw_smp.summarize_disconnect(log) == {
        "classification": "disconnect_complete",
        "remote": False,
        "reason": "Connection Terminated By Local Host",
        "reason_code": "0x16",
    }


def test_raw_smp_disconnect_uses_connection_handle(monkeypatch) -> None:
    commands = []

    def fake_run_command(command, timeout):
        commands.append(command)
        if command == ["hcitool", "con"]:
            return {
                "stdout": (
                    "Connections:\n"
                    "\t< LE AA:BB:CC:DD:EE:FF handle 64 state 1 lm CENTRAL\n"
                )
            }
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(raw_smp, "maybe_sudo", lambda command: command)
    monkeypatch.setattr(raw_smp, "run_command", fake_run_command)
    monkeypatch.setattr(raw_smp.time, "sleep", lambda _seconds: None)

    raw_smp.disconnect("AA:BB:CC:DD:EE:FF")

    assert ["hcitool", "ledc", "64", "0x16"] in commands
    assert ["hcitool", "ledc", "AA:BB:CC:DD:EE:FF"] not in commands
    assert ["hcitool", "cmd", "0x08", "0x000c", "00", "00"] in commands


def test_recover_bluetooth_restores_bondable_adapter_state(monkeypatch) -> None:
    commands = []
    events = []

    def fake_run_command(command, *, timeout, stdout=None, stderr=None):
        commands.append(command)
        return {"command": command, "returncode": 0}

    monkeypatch.setattr(raw_loop, "run_command", fake_run_command)
    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )

    raw_loop.recover_bluetooth(
        SimpleNamespace(reset_sleep_seconds=0.0),
        cycle=3,
        started=0.0,
        reason="test",
    )

    assert ["sudo", "-n", "timeout", "2", "btmgmt", "stop-find"] in commands
    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^script -qfec sudo -n btmgmt find -l /dev/null$",
    ] in commands
    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^btmgmt find -l$",
    ] in commands
    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^btmgmt bondable on$",
    ] in commands
    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^hcitool cmd ",
    ] in commands
    assert ["sudo", "-n", "timeout", "4", "btmgmt", "power", "on"] in commands
    assert ["sudo", "-n", "timeout", "4", "btmgmt", "bondable", "on"] in commands
    assert events[-1][0] == "raw_bluetooth_recovery"
    assert events[-1][1]["cycle"] == 3


def test_stop_stale_btmgmt_find_logs_cleanup(monkeypatch) -> None:
    commands = []
    events = []

    def fake_run_command(command, *, timeout, stdout=None, stderr=None):
        commands.append(command)
        return {"command": command, "returncode": 0}

    monkeypatch.setattr(raw_loop, "run_command", fake_run_command)
    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )

    raw_loop.stop_stale_btmgmt_find(cycle=7, started=0.0, reason="test_cleanup")

    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^script -qfec sudo -n btmgmt find -l /dev/null$",
    ] in commands
    assert [
        "sudo",
        "-n",
        "timeout",
        "2",
        "pkill",
        "-f",
        "^btmgmt find -l$",
    ] in commands
    assert events[-1][0] == "raw_btmgmt_find_cleanup"
    assert events[-1][1]["cycle"] == 7
    assert events[-1][1]["reason"] == "test_cleanup"


def test_signal_process_prefers_owned_process_group(monkeypatch) -> None:
    calls = []
    process = SimpleNamespace(pid=1234, send_signal=lambda sig: calls.append(("send", sig)))

    monkeypatch.setattr(raw_loop.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(
        raw_loop.os,
        "killpg",
        lambda pid, sig: calls.append(("killpg", pid, sig)),
    )

    raw_loop.signal_process(process, raw_loop.signal.SIGTERM)

    assert calls == [("killpg", 1234, raw_loop.signal.SIGTERM)]


def test_signal_process_falls_back_to_direct_signal(monkeypatch) -> None:
    calls = []
    process = SimpleNamespace(pid=1234, send_signal=lambda sig: calls.append(("send", sig)))

    monkeypatch.setattr(raw_loop.os, "getpgid", lambda _pid: 9999)
    monkeypatch.setattr(
        raw_loop.os,
        "killpg",
        lambda pid, sig: calls.append(("killpg", pid, sig)),
    )

    raw_loop.signal_process(process, raw_loop.signal.SIGTERM)

    assert calls == [("send", raw_loop.signal.SIGTERM)]


def test_run_command_kills_process_group_on_timeout(monkeypatch) -> None:
    popen_kwargs = []
    signals = []

    class FakeProcess:
        pid = 4321
        returncode = None

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls <= 2:
                raise raw_loop.subprocess.TimeoutExpired(["cmd"], timeout)
            self.returncode = -9
            return "partial stdout\n", "partial stderr\n"

    def fake_popen(command, **kwargs):
        popen_kwargs.append((command, kwargs))
        return FakeProcess()

    monkeypatch.setattr(raw_loop.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        raw_loop,
        "signal_process",
        lambda process, sig: signals.append((process.pid, sig)),
    )

    row = raw_loop.run_command(["cmd"], timeout=0.1)

    assert popen_kwargs[0][1]["start_new_session"] is True
    assert signals == [
        (4321, raw_loop.signal.SIGTERM),
        (4321, raw_loop.signal.SIGKILL),
    ]
    assert row == {
        "command": ["cmd"],
        "timeout": True,
        "stdout": "partial stdout",
        "stderr": "partial stderr",
    }


def test_raw_smp_static_random_address_sets_static_bits() -> None:
    address = raw_smp.generate_static_random_address()
    parts = address.split(":")

    assert len(parts) == 6
    assert int(parts[0], 16) & 0xC0 == 0xC0
    assert raw_smp.bdaddr_to_hci_bytes(address) == [
        part.lower() for part in reversed(parts)
    ]


def test_raw_loop_normalizes_company_prefixed_oura_manufacturer_data() -> None:
    assert raw_loop.oura_manufacturer_payload("b20204611b01") == "04611b01"
    assert raw_loop.oura_manufacturer_payload("b20204651b01") == "04651b01"
    assert raw_loop.oura_manufacturer_payload("02b204661b01") == "04661b01"
    assert raw_loop.oura_manufacturer_payload("b20204671b01") == "04671b01"
    assert raw_loop.oura_manufacturer_payload("04621b019900") == "04621b01"
    assert raw_loop.oura_manufacturer_payload("4c0013084a68797c") is None
    assert raw_loop.is_oura_manufacturer("b20204611b01", "")


def test_raw_loop_btmon_command_can_override_timestamps() -> None:
    args = SimpleNamespace(btmon_timestamps=True)

    assert raw_loop.btmon_command(args) == [
        "script",
        "-qfec",
        "sudo -n btmon -t",
        "/dev/null",
    ]
    assert raw_loop.btmon_command(args, timestamps=False) == [
        "script",
        "-qfec",
        "sudo -n btmon",
        "/dev/null",
    ]


def test_raw_loop_btmgmt_find_uses_pty_wrapper() -> None:
    assert raw_loop.btmgmt_find_command() == [
        "script",
        "-qfec",
        "sudo -n btmgmt find -l",
        "/dev/null",
    ]


def test_raw_loop_silent_scan_timeout_requires_empty_samples() -> None:
    assert raw_loop.silent_scan_timed_out(60.0, {}, 0, 10.0, 70.0)
    assert not raw_loop.silent_scan_timed_out(0.0, {}, 0, 10.0, 1000.0)
    assert not raw_loop.silent_scan_timed_out(
        60.0, {"04671b01": 1}, 0, 10.0, 70.0
    )
    assert not raw_loop.silent_scan_timed_out(60.0, {}, 1, 10.0, 70.0)
    assert not raw_loop.silent_scan_timed_out(60.0, {}, 0, 10.0, 69.0)


def test_raw_loop_drains_btmgmt_find_dev_found_lines() -> None:
    class FakeStdout:
        def __init__(self) -> None:
            self.lines = [
                "hci0 type 6 discovering on\n",
                (
                    "hci0 dev_found: 5B:B1:28:08:EA:C6 type LE Random "
                    "rssi -83 flags 0x0004 \n"
                ),
                "",
            ]

        def fileno(self) -> int:
            return 0

        def readline(self) -> str:
            return self.lines.pop(0)

    class FakeFind:
        stdout = FakeStdout()

    class FakeHandle:
        def __init__(self) -> None:
            self.lines = []

        def write(self, line: str) -> None:
            self.lines.append(line)

        def flush(self) -> None:
            pass

    ready_count = {"value": 0}

    def fake_select(reads, writes, errors, timeout):
        ready_count["value"] += 1
        if ready_count["value"] <= 3:
            return reads, writes, errors
        return [], writes, errors

    seen_addresses = set()
    address_type_counts = {}
    address_kind_counts = {}
    event_type_counts = {}
    address_rssi = {}
    handle = FakeHandle()

    original_select = raw_loop.select.select
    raw_loop.select.select = fake_select
    try:
        latest = raw_loop.drain_btmgmt_find_output(
            FakeFind(),
            handle,
            seen_addresses,
            address_type_counts,
            address_kind_counts,
            event_type_counts,
            address_rssi,
        )
    finally:
        raw_loop.select.select = original_select

    assert latest == (
        "5B:B1:28:08:EA:C6",
        "LE Random",
        "btmgmt_find",
        "btmgmt_dev_found",
    )
    assert seen_addresses == {"5B:B1:28:08:EA:C6"}
    assert address_type_counts == {"LE Random": 1}
    assert address_kind_counts == {"btmgmt_find": 1}
    assert event_type_counts == {"btmgmt_dev_found": 1}
    assert address_rssi == {
        "5B:B1:28:08:EA:C6": {
            "samples": 1,
            "min": -83,
            "max": -83,
            "last": -83,
            "address_type": "LE Random",
            "address_kind": "btmgmt_find",
            "event_type": "btmgmt_dev_found",
        }
    }
    assert handle.lines[0] == "hci0 type 6 discovering on\n"


def test_raw_loop_silent_scan_fallback_only_for_auto_btmgmt_phase() -> None:
    assert raw_loop.should_try_hci_silent_fallback("auto", hci_scan_enabled=False)
    assert not raw_loop.should_try_hci_silent_fallback("auto", hci_scan_enabled=True)
    assert not raw_loop.should_try_hci_silent_fallback("btmgmt", hci_scan_enabled=False)
    assert not raw_loop.should_try_hci_silent_fallback("hci", hci_scan_enabled=False)


def test_raw_loop_restarts_find_after_btmon_timestamp_crash_before_samples() -> None:
    assert raw_loop.should_restart_find_after_btmon_timestamp_crash(
        find_running=True,
        manufacturer_counts={},
    )
    assert not raw_loop.should_restart_find_after_btmon_timestamp_crash(
        find_running=False,
        manufacturer_counts={},
    )
    assert not raw_loop.should_restart_find_after_btmon_timestamp_crash(
        find_running=True,
        manufacturer_counts={"04671b01": 1},
    )


def test_raw_loop_cleans_pty_btmon_control_sequences() -> None:
    assert (
        raw_loop.clean_btmon_line(
            "\x00        \x1b[0m\x1b[0m  Address type: Random (0x01)\x1b[0m\r\n"
        )
        == "          Address type: Random (0x01)\r\n"
    )
    assert raw_loop.MANUFACTURER_RE.search(
        raw_loop.clean_btmon_line("        \x1b[0m\x1b[0m  Data: 04671b01\x1b[0m")
    )


def test_raw_loop_candidate_target_uses_resolvable_oura_signal() -> None:
    assert raw_loop.candidate_target_rpa("C1:22:33:44:55:66", "Resolvable", None) == (
        "C1:22:33:44:55:66",
        "current_resolvable_address",
    )
    assert raw_loop.candidate_target_rpa(
        "12:22:33:44:55:66", "Non-Resolvable", "C1:22:33:44:55:66"
    ) == ("C1:22:33:44:55:66", "last_oura_resolvable_address")
    assert raw_loop.candidate_target_rpa(
        "12:22:33:44:55:66", "Non-Resolvable", None
    ) == (None, "")


def test_raw_loop_scan_heartbeat_includes_scan_shape(monkeypatch) -> None:
    events = []

    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )
    monkeypatch.setattr(raw_loop.time, "monotonic", lambda: 12.0)

    raw_loop.emit_scan_heartbeat(
        2,
        0.0,
        {"04601b01": 1},
        {"04601b01": 1},
        {"04601b01": 1},
        {"Resolvable": 1},
        {"Random (0x01)": 1},
        {"Scan response - SCAN_RSP (0x04)": 1},
        {"04601b01": {"samples": 1, "min": -52, "max": -52, "last": -52}},
        {
            "04601b01": {
                "samples": 1,
                "latest_address": "C1:22:33:44:55:66",
                "latest_address_type": "Resolvable",
            }
        },
        {
            "C1:22:33:44:55:66": {
                "samples": 1,
                "min": -52,
                "max": -52,
                "last": -52,
                "address_type": "Resolvable",
                "address_kind": "Random (0x01)",
                "event_type": "Scan response - SCAN_RSP (0x04)",
            }
        },
        {"C1:22:33:44:55:66"},
        {"C1:22:33:44:55:66"},
        "C1:22:33:44:55:66",
        "Resolvable",
        "Random (0x01)",
        "Scan response - SCAN_RSP (0x04)",
        "hci_le_scan",
        20.0,
    )

    assert events[0][0] == "raw_scan_heartbeat"
    assert events[0][1]["unique_address_count"] == 1
    assert events[0][1]["resolvable_address_count"] == 1
    assert events[0][1]["address_type_counts"] == {"Resolvable": 1}
    assert events[0][1]["address_kind_counts"] == {"Random (0x01)": 1}
    assert events[0][1]["event_type_counts"] == {
        "Scan response - SCAN_RSP (0x04)": 1
    }
    assert events[0][1]["manufacturer_rssi"] == {
        "04601b01": {"samples": 1, "min": -52, "max": -52, "last": -52}
    }
    assert events[0][1]["manufacturer_addresses"] == {
        "04601b01": {
            "samples": 1,
            "latest_address": "C1:22:33:44:55:66",
            "latest_address_type": "Resolvable",
        }
    }
    assert events[0][1]["address_rssi"] == {
        "C1:22:33:44:55:66": {
            "samples": 1,
            "min": -52,
            "max": -52,
            "last": -52,
            "address_type": "Resolvable",
            "address_kind": "Random (0x01)",
            "event_type": "Scan response - SCAN_RSP (0x04)",
        }
    }


def test_raw_loop_records_manufacturer_rssi_summary() -> None:
    summaries = {}

    raw_loop.record_manufacturer_rssi(summaries, "04601b01", -60)
    raw_loop.record_manufacturer_rssi(summaries, "04601b01", -44)
    raw_loop.record_manufacturer_rssi(summaries, "04601b01", -55)

    assert summaries == {
        "04601b01": {"samples": 3, "min": -60, "max": -44, "last": -55}
    }


def test_raw_loop_records_manufacturer_address_summary() -> None:
    summaries = {}

    raw_loop.record_manufacturer_address(
        summaries,
        "04601b01",
        address="C1:22:33:44:55:66",
        address_type="Resolvable",
        address_kind="Random (0x01)",
        event_type="Scan response - SCAN_RSP (0x04)",
        company="Acme Sensor Co. (65535)",
        name="",
        rssi=-60,
    )
    raw_loop.record_manufacturer_address(
        summaries,
        "04601b01",
        address="C2:22:33:44:55:66",
        address_type="Resolvable",
        address_kind="Random (0x01)",
        event_type="Connectable undirected - ADV_IND (0x00)",
        company="Acme Sensor Co. (65535)",
        name="",
        rssi=-44,
    )

    assert summaries["04601b01"]["samples"] == 2
    assert summaries["04601b01"]["latest_address"] == "C2:22:33:44:55:66"
    assert summaries["04601b01"]["latest_resolvable_address"] == "C2:22:33:44:55:66"
    assert summaries["04601b01"]["latest_company"] == "Acme Sensor Co. (65535)"
    assert summaries["04601b01"]["max_rssi"] == -44
    assert summaries["04601b01"]["max_rssi_resolvable_address"] == "C2:22:33:44:55:66"
    assert summaries["04601b01"]["max_rssi_company"] == "Acme Sensor Co. (65535)"


def test_raw_loop_scan_target_event_can_be_service_uuid_driven(monkeypatch) -> None:
    events = []

    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )

    raw_loop.emit_raw_scan_target(
        4,
        0.0,
        "C1:22:33:44:55:66",
        manufacturer_hex=None,
        raw_manufacturer_hex=None,
        address_type="Resolvable",
        address_kind="Random (0x01)",
        rpa_source="current_resolvable_address",
        company="",
        name="",
        scan_backend="hci_le_scan",
        target_signal="service_uuid",
    )

    assert events == [
        (
            "raw_scan_target",
            {
                "cycle": 4,
                "manufacturer_hex": None,
                "raw_manufacturer_hex": None,
                "rpa": "C1:22:33:44:55:66",
                "address_type": "Resolvable",
                "address_kind": "Random (0x01)",
                "rpa_source": "current_resolvable_address",
                "company": "",
                "name": "",
                "scan_backend": "hci_le_scan",
                "target_signal": "service_uuid",
            },
        )
    ]


def test_raw_loop_hci_scan_enable_accepts_pre_disable_disallowed(
    monkeypatch,
) -> None:
    rows = [
        {
            "returncode": 0,
            "stdout": "Status: Command Disallowed (0x0c)",
            "stderr": "",
        },
        {"returncode": 0, "stdout": "Status: Success (0x00)", "stderr": ""},
        {"returncode": 0, "stdout": "Status: Success (0x00)", "stderr": ""},
    ]
    events = []

    monkeypatch.setattr(raw_loop, "run_command", lambda *_args, **_kwargs: rows.pop(0))
    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )

    assert raw_loop.enable_hci_le_scan(
        SimpleNamespace(hci_command_timeout_seconds=3.0),
        cycle=1,
        started=0.0,
        reason="test",
    )
    assert events[-1][0] == "raw_hci_scan_enable"


def test_raw_loop_hci_scan_enable_rejects_enable_disallowed(monkeypatch) -> None:
    rows = [
        {
            "returncode": 0,
            "stdout": "Status: Command Disallowed (0x0c)",
            "stderr": "",
        },
        {
            "returncode": 0,
            "stdout": "Status: Command Disallowed (0x0c)",
            "stderr": "",
        },
        {
            "returncode": 0,
            "stdout": "Status: Command Disallowed (0x0c)",
            "stderr": "",
        },
    ]

    monkeypatch.setattr(raw_loop, "run_command", lambda *_args, **_kwargs: rows.pop(0))
    monkeypatch.setattr(raw_loop, "emit", lambda *_args, **_kwargs: None)

    assert not raw_loop.enable_hci_le_scan(
        SimpleNamespace(hci_command_timeout_seconds=3.0),
        cycle=1,
        started=0.0,
        reason="test",
    )


def test_raw_loop_hci_status_parses_hcitool_command_complete_hex() -> None:
    row = {
        "returncode": 0,
        "stdout": (
            "< HCI Command: ogf 0x08, ocf 0x000b, plen 7\n"
            "  01 10 00 10 00 00 00 \n"
            "> HCI Event: 0x0e plen 4\n"
            "  01 0B 20 0C"
        ),
        "stderr": "",
    }

    assert raw_loop.hci_status_code(row) == "0x0c"
    assert not raw_loop.hci_command_succeeded(row)


def test_raw_loop_parses_plain_btmon_address_and_data_lines() -> None:
    address_match = raw_loop.ADDRESS_RE.search(
        "        LE Address: 64:7B:62:CD:D9:0E (Resolvable)"
    )
    data_match = raw_loop.MANUFACTURER_RE.search("          Data: b20204671b01")

    assert address_match is not None
    assert address_match.group(1) == "64:7B:62:CD:D9:0E"
    assert address_match.group(2) == "Resolvable"
    assert data_match is not None
    assert data_match.group(1) == "b20204671b01"


def test_no_target_note_covers_worn_and_charger_states() -> None:
    note = raw_loop.NO_TARGET_PHYSICAL_NOTE

    assert "worn" in note
    assert "charger" in note
    assert "connected elsewhere" in note


def test_le_create_connection_command_uses_wide_scan_and_little_endian_address() -> None:
    args = SimpleNamespace(
        le_create_scan_interval=0x0010,
        le_create_scan_window=0x0010,
        hci_command_timeout_seconds=3.0,
    )

    command = raw_loop.build_le_create_connection_command("66:11:22:33:44:55", args)

    assert command[:8] == [
        "sudo",
        "-n",
        "timeout",
        "3.0",
        "hcitool",
        "cmd",
        "0x08",
        "0x000d",
    ]
    assert command[8:12] == ["10", "00", "10", "00"]
    assert command[12:15] == ["00", "01", "55"]
    assert command[15:20] == ["44", "33", "22", "11", "66"]


def test_le_create_connection_command_exposes_tunable_connection_params() -> None:
    args = SimpleNamespace(
        le_create_scan_interval=0x0010,
        le_create_scan_window=0x0010,
        le_create_own_address_type="random",
        le_create_conn_min_interval=0x0018,
        le_create_conn_max_interval=0x0028,
        le_create_conn_latency=0x0002,
        le_create_supervision_timeout=0x0258,
        le_create_min_ce_length=0x0000,
        le_create_max_ce_length=0x0004,
        hci_command_timeout_seconds=3.0,
    )

    command = raw_loop.build_le_create_connection_command("66:11:22:33:44:55", args)

    payload = command[8:]
    assert payload[12] == "01"
    assert payload[13:15] == ["18", "00"]
    assert payload[15:17] == ["28", "00"]
    assert payload[17:19] == ["02", "00"]
    assert payload[19:21] == ["58", "02"]
    assert payload[21:23] == ["00", "00"]
    assert payload[23:25] == ["04", "00"]


def test_raw_connect_tries_fallback_backend_before_declaring_failure(monkeypatch) -> None:
    events = []
    calls = []
    args = SimpleNamespace(
        connect_backend="hci-create",
        connect_fallback_backend="hcitool-lecc",
        connect_attempts=1,
        connect_retry_delay_seconds=0.0,
        connect_settle_seconds=0.0,
    )

    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )
    monkeypatch.setattr(raw_loop, "stop_discovery_before_connect", lambda *args: None)
    monkeypatch.setattr(raw_loop.time, "sleep", lambda seconds: None)

    def fake_hci_create(*args):
        calls.append("hci-create")
        return raw_loop.RawConnectResult(False)

    def fake_hcitool(*args):
        calls.append("hcitool-lecc")
        return raw_loop.RawConnectResult(True, "66:11:22:33:44:55")

    monkeypatch.setattr(raw_loop, "raw_connect_hci_create", fake_hci_create)
    monkeypatch.setattr(raw_loop, "raw_connect_hcitool_lecc", fake_hcitool)

    result = raw_loop.raw_connect("66:11:22:33:44:55", args, 7, 0.0)

    assert result.success is True
    assert result.stream_address == "66:11:22:33:44:55"
    assert calls == ["hci-create", "hcitool-lecc"]
    assert ("raw_connect_retry", {
        "cycle": 7,
        "rpa": "66:11:22:33:44:55",
        "failed_attempt": 1,
        "failed_backend": "hci-create",
        "next_attempt": 1,
        "next_backend": "hcitool-lecc",
        "sequence": 1,
        "total": 2,
        "delay_seconds": 0.0,
    }) in events


def test_bluetooth_address_parser_rejects_invalid_address() -> None:
    try:
        raw_loop.bdaddr_to_hci_bytes("66:37:B4")
    except ValueError as exc:
        assert "invalid Bluetooth address" in str(exc)
    else:
        raise AssertionError("invalid address should fail")


def test_zeroauth_stream_timeout_includes_service_resolution_window() -> None:
    args = SimpleNamespace(
        stream_services_timeout=25.0,
        read_timeout=50.0,
        stream_duration=35.0,
        stream_exit_after_probes=False,
    )

    assert raw_loop.zeroauth_stream_timeout(args) == 115.0

    args.stream_exit_after_probes = True
    assert raw_loop.zeroauth_stream_timeout(args) == 80.0


def test_zeroauth_stream_command_connects_by_default() -> None:
    args = SimpleNamespace(
        identity_address="AA:BB:CC:DD:EE:FF",
        stream_duration=10.0,
        stream_services_timeout=25.0,
        stream_probes="firmware",
        stream_probe_delay_seconds=1.25,
        response_timeout=2.0,
        stream_connect=True,
        stream_all_notify_chars=True,
        stream_exit_after_probes=True,
        stream_address_source="identity",
        stream_strict_address=False,
        require_rpa_stream_address=False,
        stream_auto_confirm_agent=False,
        stream_agent_capability="DisplayYesNo",
        stream_pair=False,
        stream_pair_timeout=45.0,
    )

    command = raw_loop.build_zeroauth_stream_command(args, Path("stream.py"))

    assert "--connect" in command
    assert "--all-notify-chars" in command
    assert "--exit-after-probes" in command
    assert command[command.index("--probe-response-timeout") + 1] == "2.0"


def test_zeroauth_stream_command_can_skip_connect() -> None:
    args = SimpleNamespace(
        identity_address="AA:BB:CC:DD:EE:FF",
        stream_duration=10.0,
        stream_services_timeout=25.0,
        stream_probes="firmware",
        stream_probe_delay_seconds=1.25,
        response_timeout=2.0,
        stream_connect=False,
        stream_all_notify_chars=False,
        stream_exit_after_probes=False,
        stream_address_source="identity",
        stream_strict_address=False,
        require_rpa_stream_address=False,
        stream_auto_confirm_agent=False,
        stream_agent_capability="DisplayYesNo",
        stream_pair=False,
        stream_pair_timeout=45.0,
    )

    command = raw_loop.build_zeroauth_stream_command(args, Path("stream.py"))

    assert "--connect" not in command
    assert "--all-notify-chars" not in command
    assert "--exit-after-probes" not in command


def test_zeroauth_stream_command_can_target_current_rpa_strictly() -> None:
    args = SimpleNamespace(
        identity_address="AA:BB:CC:DD:EE:FF",
        stream_duration=10.0,
        stream_services_timeout=25.0,
        stream_probes="firmware",
        stream_probe_delay_seconds=1.25,
        response_timeout=2.0,
        stream_connect=True,
        stream_all_notify_chars=False,
        stream_exit_after_probes=False,
        stream_address_source="rpa",
        stream_strict_address=True,
        require_rpa_stream_address=True,
        stream_auto_confirm_agent=True,
        stream_agent_capability="DisplayYesNo",
        stream_pair=False,
        stream_pair_timeout=45.0,
    )

    command = raw_loop.build_zeroauth_stream_command(
        args, Path("stream.py"), rpa="7A:11:22:33:44:55"
    )

    assert command[command.index("--address") + 1] == "7A:11:22:33:44:55"
    assert "--strict-address" in command
    assert "--auto-confirm-agent" not in command
    assert "--agent-capability" not in command


def test_zeroauth_stream_command_can_request_explicit_pairing() -> None:
    args = SimpleNamespace(
        identity_address="AA:BB:CC:DD:EE:FF",
        stream_duration=10.0,
        stream_services_timeout=25.0,
        stream_probes="firmware",
        stream_probe_delay_seconds=1.25,
        response_timeout=2.0,
        stream_connect=True,
        stream_all_notify_chars=False,
        stream_exit_after_probes=False,
        stream_address_source="rpa",
        stream_strict_address=True,
        require_rpa_stream_address=True,
        stream_auto_confirm_agent=True,
        stream_agent_capability="DisplayYesNo",
        stream_pair=True,
        stream_pair_timeout=30.0,
    )

    command = raw_loop.build_zeroauth_stream_command(
        args, Path("stream.py"), rpa="7A:11:22:33:44:55"
    )

    assert "--pair" in command
    assert command[command.index("--pair-timeout") + 1] == "30.0"


def test_zeroauth_stream_status_requires_usable_read_payload() -> None:
    status = raw_loop.ZeroAuthStreamStatus(0, 0, 0, 0)

    for row in [
        {"event": "zeroauth_probe_error", "payload": {"packet": "firmware"}},
        {
            "event": "read_result",
            "payload": {
                "firmware": None,
                "auth_nonce": None,
                "battery": None,
                "product_info": {},
                "capabilities": {},
                "product_info_memory": {"byte_count": 0},
            },
        },
    ]:
        status = raw_loop.update_zeroauth_stream_status(status, row)

    assert status.read_results == 1
    assert status.usable_read_results == 0
    assert status.probe_errors == 1

    status = raw_loop.update_zeroauth_stream_status(
        status,
        {
            "event": "read_result",
            "payload": {"firmware": {"firmware_version": "2.11.0"}},
        },
    )

    assert status.read_results == 2
    assert status.usable_read_results == 1


def test_zeroauth_stream_status_accepts_product_info_memory() -> None:
    assert raw_loop.is_usable_read_result(
        {
            "firmware": None,
            "product_info_memory": {"byte_count": 56},
        }
    )


def test_zeroauth_stream_status_accepts_factory_reset_ack() -> None:
    assert raw_loop.is_usable_read_result(
        {"factory_reset": {"response_name": "factory_reset_status", "status": 0}}
    )


def test_zeroauth_stream_status_accepts_feature_status_only() -> None:
    assert raw_loop.is_usable_read_result(
        {
            "feature_status": {
                "feature_status:0x02": {
                    "feature_name": "daytime_hr",
                    "mode_name": "automatic",
                }
            }
        }
    )


def test_zeroauth_stream_status_accepts_feature_set_result_only() -> None:
    assert raw_loop.is_usable_read_result(
        {
            "feature_set_results": [
                {
                    "packet": "feature_subscription:0x02:latest",
                    "result_name": "success",
                }
            ]
        }
    )


def test_zeroauth_stream_status_accepts_event_only_result() -> None:
    assert raw_loop.is_usable_read_result(
        {
            "events": [{"event_name": "debug_event"}],
            "events_done": [
                {
                    "request_start_timestamp": 6306,
                    "request_max_events": 64,
                    "events_received": 64,
                    "bytes_left": 210924,
                }
            ],
            "event_summary": {"count": 64},
        }
    )


def test_summarize_setup_security_failure_from_bluez_pairing_log(tmp_path) -> None:
    log = tmp_path / "btmon.log"
    log.write_text(
        "\n".join(
            [
                "      ATT: Error Response (0x01) len 4",
                "        Error: Insufficient Encryption (0x0f)",
                "< ACL Data TX: Handle 64 flags 0x00 dlen 11",
                "      SMP: Pairing Request (0x01) len 6",
                "        IO capability: NoInputNoOutput (0x03)",
                "        OOB data: Authentication data not present (0x00)",
                "        Authentication requirement: Bonding, No MITM, SC, "
                "No Keypresses, CT2 (0x29)",
                "        Max encryption key size: 16",
                "        Initiator key distribution: EncKey Sign LinkKey (0x0d)",
                "        Responder key distribution: EncKey IdKey Sign LinkKey (0x0f)",
                "> ACL Data RX: Handle 64 flags 0x02 dlen 6",
                "      SMP: Pairing Failed (0x05) len 1",
                "        Reason: Unspecified reason (0x08)",
            ]
        )
    )

    summary = raw_loop.summarize_setup_security_failure(log)

    assert summary["classification"] == "setup_pairing_rejected"
    assert summary["att_insufficient_encryption"] is True
    assert summary["smp_pairing_failed_reason_code"] == "0x08"
    assert (
        summary["smp_pairing_request"]["authentication_requirement"]
        == "Bonding, No MITM, SC, No Keypresses, CT2 (0x29)"
    )


def test_summarize_setup_security_failure_from_raw_no_bond_smp_log(tmp_path) -> None:
    log = tmp_path / "btmon.log"
    log.write_text(
        "\n".join(
            [
                "python3: < ACL Data TX: Handle 64 flags 0x02 dlen 11",
                "      SMP: Pairing Request (0x01) len 6",
                "        IO capability: NoInputNoOutput (0x03)",
                "        OOB data: Authentication data not present (0x00)",
                "        Authentication requirement: No bonding, No MITM, "
                "Legacy, No Keypresses (0x00)",
                "        Max encryption key size: 16",
                "        Initiator key distribution: <none> (0x00)",
                "        Responder key distribution: <none> (0x00)",
                "> ACL Data RX: Handle 64 flags 0x02 dlen 6",
                "      SMP: Pairing Failed (0x05) len 1",
                "        Reason: Unspecified reason (0x08)",
            ]
        )
    )

    summary = raw_loop.summarize_setup_security_failure(log)

    assert summary["classification"] == "setup_pairing_rejected"
    assert summary["att_insufficient_encryption"] is False
    assert summary["smp_pairing_request"]["initiator_key_distribution"] == (
        "<none> (0x00)"
    )


def test_finite_continue_after_success_exits_successfully(monkeypatch) -> None:
    events = []
    args = SimpleNamespace(
        manufacturer_hex="04671b01",
        identity_address="AA:BB:CC:DD:EE:FF",
        scan_seconds=1.0,
        scan_heartbeat_seconds=0.0,
        connect_timeout=1.0,
        connect_settle_seconds=0.0,
        connect_backend="hci-create",
        le_create_scan_interval=0x0010,
        le_create_scan_window=0x0010,
        read_timeout=1.0,
        stream_services_timeout=1.0,
        stream_duration=1.0,
        stream_exit_after_probes=True,
        stream_address_source="rpa",
        stream_strict_address=True,
        require_rpa_stream_address=True,
        fresh_bluez_cache=True,
        stream_auto_confirm_agent=False,
        stream_agent_capability="DisplayYesNo",
        stream_pair=False,
        cycles=1,
        reset_bluetooth_after_no_targets=0,
        reset_bluetooth_after_connect_failures=0,
        scan_backend="hci",
        emit_all_manufacturer_lines=False,
        scan_activation_grace_seconds=0.0,
        recover_if_scan_inactive=False,
        verify_btmgmt_discovering=True,
        hci_command_timeout_seconds=1.0,
        btmon_timestamps=True,
        no_disconnect_before_scan=False,
        delay_seconds=0.0,
        keep_connected_after_probe=False,
        continue_after_success=True,
    )

    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )
    monkeypatch.setattr(
        raw_loop,
        "disconnect_identity_connections",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(raw_loop, "remove_bluez_device", lambda *args: None)
    monkeypatch.setattr(
        raw_loop,
        "capture_rpa",
        lambda *args: raw_loop.ScanResult(
            rpa="68:11:22:33:44:55",
            manufacturer_counts={"04671b01": 1},
            resolvable_counts={"68d66e6e": 1},
            oura_candidate_counts={"04671b01": 1},
            scan_active=True,
        ),
    )
    monkeypatch.setattr(raw_loop, "start_phase_btmon", lambda *args: object())
    monkeypatch.setattr(raw_loop, "stop_phase_btmon", lambda *args: None)
    monkeypatch.setattr(
        raw_loop,
        "raw_connect",
        lambda *args: raw_loop.RawConnectResult(
            success=True, stream_address="68:11:22:33:44:55"
        ),
    )
    monkeypatch.setattr(raw_loop, "should_reject_stream_address", lambda *args: False)
    monkeypatch.setattr(raw_loop, "run_after_connect", lambda *args: 0)
    monkeypatch.setattr(raw_loop.time, "sleep", lambda seconds: None)

    assert raw_loop.run(args) == 0
    assert ("raw_loop_success", {
        "cycle": 1,
        "rpa": "68:11:22:33:44:55",
        "stream_address": "68:11:22:33:44:55",
    }) in events
    assert events[-1] == ("raw_loop_done", {"cycles": 1, "success": True})


def test_raw_loop_no_target_event_keeps_scan_backend_context(monkeypatch) -> None:
    events = []
    args = SimpleNamespace(
        manufacturer_hex="04671b01",
        identity_address="AA:BB:CC:DD:EE:FF",
        scan_seconds=1.0,
        scan_heartbeat_seconds=0.0,
        connect_timeout=1.0,
        connect_settle_seconds=0.0,
        connect_backend="hci-create",
        le_create_scan_interval=0x0010,
        le_create_scan_window=0x0010,
        read_timeout=1.0,
        stream_services_timeout=1.0,
        stream_duration=1.0,
        stream_exit_after_probes=True,
        stream_address_source="rpa",
        stream_strict_address=True,
        require_rpa_stream_address=True,
        fresh_bluez_cache=True,
        stream_auto_confirm_agent=False,
        stream_agent_capability="DisplayYesNo",
        stream_pair=False,
        cycles=1,
        reset_bluetooth_after_no_targets=0,
        reset_bluetooth_after_connect_failures=0,
        scan_backend="hci",
        emit_all_manufacturer_lines=False,
        scan_activation_grace_seconds=0.0,
        recover_if_scan_inactive=False,
        verify_btmgmt_discovering=True,
        hci_command_timeout_seconds=1.0,
        btmon_timestamps=True,
        no_disconnect_before_scan=False,
        delay_seconds=0.0,
        keep_connected_after_probe=False,
        continue_after_success=False,
        physical_toggle_hint_after_no_targets=0,
        reset_sleep_seconds=0.0,
    )

    monkeypatch.setattr(
        raw_loop,
        "emit",
        lambda event, payload, started: events.append((event, payload)),
    )
    monkeypatch.setattr(
        raw_loop,
        "disconnect_identity_connections",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(raw_loop, "remove_bluez_device", lambda *args: None)
    monkeypatch.setattr(
        raw_loop,
        "capture_rpa",
        lambda *args: raw_loop.ScanResult(
            rpa=None,
            manufacturer_counts={"1006": 8},
            resolvable_counts={"1006": 8},
            oura_candidate_counts={},
            scan_active=True,
            scan_backend="hci_le_scan",
            last_address="C1:22:33:44:55:66",
            last_address_type="Resolvable",
            last_address_kind="Random (0x01)",
            last_event_type="Scan response - SCAN_RSP (0x04)",
        ),
    )
    monkeypatch.setattr(raw_loop.time, "sleep", lambda seconds: None)

    assert raw_loop.run(args) == 1

    no_target = [payload for event, payload in events if event == "raw_cycle_no_target"]
    assert no_target == [
        {
            "cycle": 1,
            "consecutive_no_targets": 1,
            "manufacturer_counts": {"1006": 8},
            "resolvable_counts": {"1006": 8},
            "oura_candidate_counts": {},
            "address_type_counts": {},
            "address_kind_counts": {},
            "event_type_counts": {},
            "manufacturer_rssi": {},
            "manufacturer_addresses": {},
            "address_rssi": {},
            "unique_address_count": 0,
            "resolvable_address_count": 0,
            "scan_backend": "hci_le_scan",
            "last_address": "C1:22:33:44:55:66",
            "last_address_type": "Resolvable",
            "last_address_kind": "Random (0x01)",
            "last_event_type": "Scan response - SCAN_RSP (0x04)",
            "no_target_classification": "no_oura_seen",
            "physical_state_note": raw_loop.NO_TARGET_PHYSICAL_NOTE,
        }
    ]
    assert events[-1] == ("raw_loop_done", {"cycles": 1, "success": False})


def test_connected_stream_address_ignores_pending_state() -> None:
    pending = "Connections:\\n\\t< LE AA:BB:CC:DD:EE:FF handle 3840 state 5 lm CENTRAL"
    link_only = "Connections:\\n\\t< LE AA:BB:CC:DD:EE:FF handle 64 state 7 lm CENTRAL"
    connected = (
        "Connections:\\n\\t< LE AA:BB:CC:DD:EE:FF "
        "handle 64 state 1 lm CENTRAL AUTH ENCRYPT"
    )

    assert raw_loop.connected_stream_address(
        pending, "60:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"
    ) is None
    assert raw_loop.connected_stream_address(
        link_only, "60:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"
    ) is None
    assert (
        raw_loop.connected_stream_address(
            connected, "60:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"
        )
        == "AA:BB:CC:DD:EE:FF"
    )


def test_rejects_identity_handoff_when_rpa_stream_required() -> None:
    args = SimpleNamespace(
        require_rpa_stream_address=True,
        stream_address_source="rpa",
    )

    assert raw_loop.should_reject_stream_address(
        args, "60:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"
    )
    assert not raw_loop.should_reject_stream_address(
        args, "60:11:22:33:44:55", "60:11:22:33:44:55"
    )
