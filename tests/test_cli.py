from __future__ import annotations

import json

from oura_ring4_ble import cli


def test_pi_auth_read_parser_defaults_to_resilient_linux_flow() -> None:
    args = cli.build_parser().parse_args(["pi-auth-read"])

    assert args.command == "pi-auth-read"
    assert args.restart_bluetooth_first is True
    assert args.clear_stale is True
    assert args.agent_capability == "NoInputNoOutput"
    assert args.meditation_hr_probe is True


def test_pi_zeroauth_read_parser_defaults_to_probe_read_result() -> None:
    args = cli.build_parser().parse_args(["pi-zeroauth-read"])

    assert args.command == "pi-zeroauth-read"
    assert args.connect is True
    assert args.probes == "firmware,battery,auth_nonce,live_hr_probe"


def test_pi_gatt_probe_parser_exposes_matrix_skip_filters() -> None:
    args = cli.build_parser().parse_args(
        [
            "pi-gatt-probe",
            "--matrix-only",
            "--connect-on-first-oura",
            "--matrix-skip-uuid",
            "98ed0003",
            "--matrix-skip-uuid",
            "98ed0004",
            "--skip-standard-reads",
            "--no-device-summary",
        ]
    )

    assert args.command == "pi-gatt-probe"
    assert args.matrix_only is True
    assert args.connect_on_first_oura is True
    assert args.matrix_skip_uuid == ["98ed0003", "98ed0004"]
    assert args.restart_bluetooth_first is True
    assert args.clear_stale is True
    assert args.power_off_after is True
    assert args.passive_scan is True
    assert args.skip_standard_reads is True
    assert args.no_device_summary is True


def test_pi_rpa_read_parser_defaults_to_fresh_rpa_probe() -> None:
    args = cli.build_parser().parse_args(["pi-rpa-read"])

    assert args.command == "pi-rpa-read"
    assert args.fresh_bluez_cache is True
    assert args.stream_address_source == "rpa"
    assert args.require_rpa_stream_address is True
    assert args.stream_probes == "firmware,battery,auth_nonce,live_hr_probe"
    assert args.stream_pair is False
    assert args.stream_auto_confirm_agent is False
    assert args.stream_agent_capability == "DisplayYesNo"
    assert args.stream_connect is True
    assert args.btmon_timestamps is True
    assert args.verify_btmgmt_discovering is True
    assert args.silent_scan_timeout_seconds == 0.0
    assert args.scan_backend == "auto"
    assert args.connect_attempts == 1
    assert args.connect_fallback_backend == ""
    assert args.le_create_conn_min_interval == 0x000F
    assert args.le_create_conn_max_interval == 0x000F


def test_decode_events_command_outputs_structured_event(capsys) -> None:
    args = cli.build_parser().parse_args(["decode-events", "4606 10000000 100e"])

    assert cli.command_decode_events(args) == 0

    decoded = json.loads(capsys.readouterr().out)
    assert decoded[0]["decoded"]["event_name"] == "temp_event"
    assert decoded[0]["decoded"]["temperature_c_samples"] == [36.0]


def test_pi_rpa_read_parser_exposes_stream_pairing_options() -> None:
    args = cli.build_parser().parse_args(
        [
            "pi-rpa-read",
            "--stream-pair",
            "--stream-pair-timeout",
            "12",
            "--stream-auto-confirm-agent",
            "--stream-agent-capability",
            "NoInputNoOutput",
            "--no-stream-connect",
            "--stream-all-notify-chars",
            "--stream-strict-address",
        ]
    )

    assert args.stream_pair is True
    assert args.stream_pair_timeout == 12
    assert args.stream_auto_confirm_agent is True
    assert args.stream_agent_capability == "NoInputNoOutput"
    assert args.stream_connect is False
    assert args.stream_all_notify_chars is True
    assert args.stream_strict_address is True


def test_pi_rpa_read_parser_exposes_orange_btmon_toggles() -> None:
    args = cli.build_parser().parse_args(
        [
            "pi-rpa-read",
            "--no-btmon-timestamps",
            "--no-verify-btmgmt-discovering",
        ]
    )

    assert args.btmon_timestamps is False
    assert args.verify_btmgmt_discovering is False


def test_pi_rpa_read_command_forwards_stream_pairing_options(
    monkeypatch, tmp_path
) -> None:
    captured = {}

    def fake_run(
        command,
        log_path,
        pointer_path,
        *,
        raw_log,
        success_summary_key=None,
        require_zero_returncode_for_summary=True,
    ):
        captured["command"] = command
        captured["log_path"] = log_path
        captured["pointer_path"] = pointer_path
        captured["raw_log"] = raw_log
        captured["success_summary_key"] = success_summary_key
        captured["require_zero_returncode_for_summary"] = (
            require_zero_returncode_for_summary
        )
        return 0

    monkeypatch.setattr(cli, "run_pi_jsonl_command", fake_run)
    args = cli.build_parser().parse_args(
        [
            "pi-rpa-read",
            "--log-dir",
            str(tmp_path),
            "--stream-pair",
            "--stream-pair-timeout",
            "12",
            "--stream-auto-confirm-agent",
            "--stream-agent-capability",
            "NoInputNoOutput",
            "--no-stream-connect",
            "--no-btmon-timestamps",
            "--no-verify-btmgmt-discovering",
            "--silent-scan-timeout-seconds",
            "75",
            "--connect-attempts",
            "2",
            "--connect-fallback-backend",
            "hcitool-lecc",
            "--connect-retry-delay-seconds",
            "0.05",
            "--le-create-own-address-type",
            "random",
            "--le-create-conn-min-interval",
            "0x18",
            "--le-create-conn-max-interval",
            "0x28",
            "--le-create-supervision-timeout",
            "0x258",
            "--scan-backend",
            "hci",
            "--stream-all-notify-chars",
            "--stream-strict-address",
        ]
    )

    assert cli.command_pi_rpa_read(args) == 0

    command = captured["command"]
    assert "--stream-pair" in command
    assert command[command.index("--stream-pair-timeout") + 1] == "12.0"
    assert "--stream-auto-confirm-agent" in command
    assert command[command.index("--stream-agent-capability") + 1] == "NoInputNoOutput"
    assert "--no-stream-connect" in command
    assert "--no-btmon-timestamps" in command
    assert "--no-verify-btmgmt-discovering" in command
    assert command[command.index("--silent-scan-timeout-seconds") + 1] == "75.0"
    assert command[command.index("--connect-attempts") + 1] == "2"
    assert command[command.index("--connect-fallback-backend") + 1] == "hcitool-lecc"
    assert command[command.index("--connect-retry-delay-seconds") + 1] == "0.05"
    assert command[command.index("--le-create-own-address-type") + 1] == "random"
    assert command[command.index("--le-create-conn-min-interval") + 1] == "24"
    assert command[command.index("--le-create-conn-max-interval") + 1] == "40"
    assert command[command.index("--le-create-supervision-timeout") + 1] == "600"
    assert command[command.index("--scan-backend") + 1] == "hci"
    assert "--stream-all-notify-chars" in command
    assert "--stream-strict-address" in command
    assert captured["pointer_path"] == tmp_path / "current-pi-bluez-read-result.log"


def test_pi_gatt_probe_command_forwards_matrix_options(monkeypatch, tmp_path) -> None:
    captured = {}

    def fake_run(
        command,
        log_path,
        pointer_path,
        *,
        raw_log,
        success_summary_key=None,
        require_zero_returncode_for_summary=True,
    ):
        captured["command"] = command
        captured["log_path"] = log_path
        captured["pointer_path"] = pointer_path
        captured["raw_log"] = raw_log
        captured["success_summary_key"] = success_summary_key
        captured["require_zero_returncode_for_summary"] = (
            require_zero_returncode_for_summary
        )
        return 0

    monkeypatch.setattr(cli, "run_pi_jsonl_command", fake_run)
    args = cli.build_parser().parse_args(
        [
            "pi-gatt-probe",
            "--log-dir",
            str(tmp_path),
            "--scan-seconds",
            "12",
            "--connect-timeout",
            "4",
            "--matrix-only",
            "--connect-on-first-oura",
            "--matrix-skip-uuid",
            "98ed0003",
            "--matrix-skip-uuid",
            "98ed0004",
            "--skip-standard-reads",
            "--require-manufacturer-hex",
            "04621b01",
            "--connectable-hint-only",
            "--no-device-summary",
        ]
    )

    assert cli.command_pi_gatt_probe(args) == 0

    command = captured["command"]
    assert command[1].endswith("scripts/pi-oura-gatt-diagnostic.py")
    assert command[command.index("--scan-seconds") + 1] == "12.0"
    assert command[command.index("--connect-timeout") + 1] == "4.0"
    assert "--matrix-only" in command
    assert "--connect-on-first-oura" in command
    assert "--connectable-hint-only" in command
    assert "--power-off-after" in command
    assert "--passive-scan" in command
    assert "--restart-bluetooth-first" in command
    assert "--clear-stale" in command
    assert "--skip-standard-reads" in command
    assert "--no-device-summary" in command
    assert command.count("--matrix-skip-uuid") == 2
    assert command[command.index("--matrix-skip-uuid") + 1] == "98ed0003"
    assert command[command.index("--require-manufacturer-hex") + 1] == "04621b01"
    assert captured["pointer_path"] == tmp_path / "current-pi-gatt-probe.log"
    assert captured["success_summary_key"] == "diagnostic_summary"
    assert captured["require_zero_returncode_for_summary"] is False


def test_pi_gatt_probe_command_omits_unsupported_negative_scan_flags(
    monkeypatch, tmp_path
) -> None:
    captured = {}

    def fake_run(
        command,
        log_path,
        pointer_path,
        *,
        raw_log,
        success_summary_key=None,
        require_zero_returncode_for_summary=True,
    ):
        captured["command"] = command
        return 0

    monkeypatch.setattr(cli, "run_pi_jsonl_command", fake_run)
    args = cli.build_parser().parse_args(
        [
            "pi-gatt-probe",
            "--log-dir",
            str(tmp_path),
            "--active-scan",
            "--no-power-off-after",
        ]
    )

    assert cli.command_pi_gatt_probe(args) == 0

    command = captured["command"]
    assert "--no-power-off-after" not in command
    assert "--active-scan" not in command
    assert "--power-off-after" not in command
    assert "--passive-scan" not in command


def test_pi_watch_parser_defaults_to_low_power_wait() -> None:
    args = cli.build_parser().parse_args(["pi-watch"])

    assert args.command == "pi-watch"
    assert args.packet_read_only is True
    assert args.connectable_hint_only is True
    assert args.skip_standard_reads is True
    assert args.power_off_after is True
    assert args.passive_scan is True
    assert args.no_matrix_only is False
    matrix_args = cli.build_parser().parse_args(["pi-watch", "--matrix-only"])
    assert matrix_args.packet_read_only is False


def test_pi_watch_command_forwards_low_power_defaults(monkeypatch, tmp_path) -> None:
    captured = {}

    def fake_run(
        command,
        log_path,
        pointer_path,
        *,
        raw_log,
        success_summary_key=None,
        require_zero_returncode_for_summary=True,
    ):
        captured["command"] = command
        captured["log_path"] = log_path
        captured["pointer_path"] = pointer_path
        captured["raw_log"] = raw_log
        captured["success_summary_key"] = success_summary_key
        captured["require_zero_returncode_for_summary"] = (
            require_zero_returncode_for_summary
        )
        return 0

    monkeypatch.setattr(cli, "run_pi_jsonl_command", fake_run)
    args = cli.build_parser().parse_args(
        [
            "pi-watch",
            "--log-dir",
            str(tmp_path),
            "--cycle-scan-seconds",
            "12",
            "--cycles",
            "2",
            "--require-manufacturer-hex",
            "04671b01",
        ]
    )

    assert cli.command_pi_watch(args) == 0

    command = captured["command"]
    assert command[1].endswith("scripts/pi-oura-watch-loop.py")
    assert command[command.index("--cycle-scan-seconds") + 1] == "12.0"
    assert command[command.index("--cycles") + 1] == "2"
    assert command[command.index("--require-manufacturer-hex") + 1] == "04671b01"
    assert "--packet-read-only" in command
    assert "--connectable-hint-only" in command
    assert "--skip-standard-reads" in command
    assert "--power-off-after" in command
    assert "--passive-scan" in command
    assert captured["pointer_path"] == tmp_path / "current-pi-watch.log"
    assert captured["success_summary_key"] == "read_result_usable"


def test_pi_watch_summary_defaults_to_current_watch_pointers(tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "watch_cycle_start", "payload": {"cycle": 2}}),
                json.dumps(
                    {
                        "event": "scan_heartbeat",
                        "elapsed_seconds": 63.0,
                        "payload": {
                            "advertisement_events": 12,
                            "unique_devices": 3,
                            "oura_candidates": 0,
                            "top_devices": [
                                {
                                    "count": 4,
                                    "device": {
                                        "address": "AA:BB:CC:DD:EE:FF",
                                        "is_oura_candidate": False,
                                        "manufacturer_data": {"0x004C": "1006"},
                                        "rssi": -42,
                                    },
                                }
                            ],
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "diagnostic_summary",
                        "payload": {
                            "targets": 0,
                            "gatt_successes": 0,
                            "read_successes": 0,
                        },
                    }
                ),
            ]
        )
    )
    pointer = tmp_path / "current-pi-watch.log"
    pointer.write_text(f"{log_path}\n")

    paths = cli.resolve_watch_summary_paths([], [], log_dir=tmp_path)
    summary = cli.watch_log_summary(paths[0])

    assert paths == [log_path]
    assert summary["read_result_usable"] is False
    assert summary["last_elapsed_seconds"] == 63.0
    assert summary["latest_scan_status"] == {
        "advertisement_events": 12,
        "unique_devices": 3,
        "oura_candidates": 0,
    }
    assert summary["latest_diagnostic_summary"]["targets"] == 0
    assert summary["top_devices"] == [
        {
            "count": 4,
            "address": "AA:BB:CC:DD:EE:FF",
            "rssi": -42,
            "is_oura_candidate": False,
            "manufacturer_data": {"0x004C": "1006"},
        }
    ]


def test_pi_watch_summary_marks_feature_read_result_usable(tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    read_result = {
        "feature_latest": {
            "feature_latest:daytime_hr": {
                "extended_name": "feature_latest_values_response",
                "feature_name": "daytime_hr",
                "latest_values": [{"value": 72}],
            }
        },
        "daytime_hr_latest": {"latest_values": [{"value": 72}]},
    }
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "read_result", "payload": read_result}),
                json.dumps({"event": "watch_success", "payload": {"cycle": 1}}),
            ]
        )
    )

    summary = cli.watch_log_summary(log_path)

    assert summary["read_result"] == read_result
    assert summary["read_result_usable"] is True
    assert summary["read_result_summary"] == ["daytime_hr_latest=72"]
    assert summary["wake_stats"]["read_results"] == 1
    assert summary["latest_watch_success"] == {"cycle": 1}


def test_pi_watch_summary_prints_read_result_highlights(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    read_result = {
        "firmware": {
            "firmware_version": "2.11.0",
            "api_version": "2.0.0",
            "bluetooth_stack_version": "5.0.15",
        },
        "battery": {
            "battery_level_percent": 86,
            "charging_progress": 100,
            "voltage_mv": 3950,
            "battery_status_hex": "0x00",
        },
        "feature_latest": {
            "feature_latest:daytime_hr": {
                "feature_name": "daytime_hr",
                "daytime_hr_bpm_estimate": 71.4,
            }
        },
        "event_summary": {
            "count": 4,
            "health_events": {
                "event_counts": {"ibi_and_amplitude_event": 1},
                "ibi_record_count": 6,
                "bpm_estimate_min": 500.0,
                "bpm_estimate_max": 750.0,
                "bpm_estimate_latest": 500.0,
            },
        },
        "auth_gated": ["events"],
    }
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "raw_scan_oura_candidate", "payload": {}}),
                json.dumps({"event": "raw_scan_target", "payload": {}}),
                json.dumps({"event": "read_result", "payload": read_result}),
            ]
        )
    )

    cli.print_watch_summaries([cli.watch_log_summary(log_path)])

    text = capsys.readouterr().out
    assert "latest_read_result: fw=2.11.0 api=2.0.0 ble=5.0.15" in text
    assert "battery=86% charge=100% voltage=3950mV status=0x00" in text
    assert "health_events=events=ibi_and_amplitude_event:1 ibi=6" in text
    assert "bpm=500.0-750.0 latest_bpm=500.0" in text
    assert "daytime_hr~71.4bpm" in text
    assert "auth_gated=events" in text
    assert "wake: raw_oura=1 targets=1 read_results=1" in text


def test_pi_watch_summary_command_prints_json(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "scan_done",
                "payload": {
                    "advertisement_events": 5,
                    "unique_devices": 2,
                    "oura_candidates": 0,
                    "selected_target": None,
                },
            }
        )
    )
    args = cli.build_parser().parse_args(
        ["pi-watch-summary", "--json", str(log_path)]
    )

    assert cli.command_pi_watch_summary(args) == 0

    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["latest_scan_status"] == {
        "advertisement_events": 5,
        "unique_devices": 2,
        "oura_candidates": 0,
        "selected_target": None,
    }


def test_pi_watch_summary_follow_parser_defaults() -> None:
    args = cli.build_parser().parse_args(["pi-watch-summary", "--follow"])

    assert args.follow is True
    assert args.interval == 15.0
    assert args.max_refreshes == 0
    assert args.until_read_result is False


def test_pi_watch_summary_follow_prints_one_refresh(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_scan_heartbeat",
                "payload": {
                    "cycle": 1,
                    "manufacturer_sample_count": 8,
                    "manufacturer_counts": {"1006": 8},
                    "oura_candidate_counts": {},
                    "no_target_classification": "no_oura_seen",
                    "scan_backend": "hci_le_scan",
                },
            }
        )
    )
    args = cli.build_parser().parse_args(
        ["pi-watch-summary", "--follow", "--max-refreshes", "1", str(log_path)]
    )

    assert cli.command_pi_watch_summary(args) == 0

    text = capsys.readouterr().out
    assert "==" in text
    assert "wake: raw_oura=0 targets=0 read_results=0 heartbeats=1" in text
    assert "raw: samples=8 oura=0 class=no_oura_seen backend=hci_le_scan" in text


def test_pi_watch_summary_follow_until_read_result(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "read_result",
                "payload": {
                    "battery": {
                        "battery_level_percent": 70,
                        "charging_progress": 100,
                    }
                },
            }
        )
    )
    args = cli.build_parser().parse_args(
        [
            "pi-watch-summary",
            "--follow",
            "--max-refreshes",
            "1",
            "--until-read-result",
            str(log_path),
        ]
    )

    assert cli.command_pi_watch_summary(args) == 0

    assert "latest_read_result: battery=70% charge=100%" in capsys.readouterr().out


def test_pi_watch_summary_follow_until_read_result_times_out(tmp_path) -> None:
    log_path = tmp_path / "pi-watch.jsonl"
    log_path.write_text(json.dumps({"event": "raw_scan_heartbeat", "payload": {}}))
    args = cli.build_parser().parse_args(
        [
            "pi-watch-summary",
            "--follow",
            "--max-refreshes",
            "1",
            "--until-read-result",
            str(log_path),
        ]
    )

    assert cli.command_pi_watch_summary(args) == 2


def test_pi_watch_summary_includes_raw_rpa_scan_status(tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    raw_scan = {
        "cycle": 3,
        "manufacturer_sample_count": 41,
        "manufacturer_counts": {"1006451d09e6dc48": 40, "04671b01": 1},
        "resolvable_counts": {"04671b01": 1},
        "oura_candidate_counts": {"04671b01": 1},
        "no_target_classification": "oura_seen_without_target_payload",
        "last_address": "C1:22:33:44:55:66",
        "last_address_type": "Resolvable",
        "scan_backend": "hci_le_scan",
        "seconds_remaining": 12.5,
    }
    raw_target = {
        "cycle": 3,
        "manufacturer_hex": "04671b01",
        "raw_manufacturer_hex": "04671b01",
        "rpa": "C1:22:33:44:55:66",
        "scan_backend": "hci_le_scan",
    }
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "raw_scan_heartbeat", "payload": raw_scan}),
                json.dumps({"event": "raw_scan_target", "payload": raw_target}),
                json.dumps(
                    {
                        "event": "raw_loop_success",
                        "payload": {
                            "cycle": 3,
                            "rpa": "C1:22:33:44:55:66",
                        },
                    }
                ),
            ]
        )
    )

    summary = cli.watch_log_summary(log_path)

    assert summary["latest_raw_scan_status"] == {
        **raw_scan,
        "operator_hint": (
            "ring presence seen, but not a connect/read target payload; keep "
            "watching for a setup/reset/app wake state or broaden the target set"
        ),
    }
    assert summary["latest_raw_target"] == raw_target
    assert summary["latest_raw_loop_success"]["cycle"] == 3


def test_pi_watch_summary_prints_raw_rpa_status(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event": "raw_cycle_no_target",
                        "payload": {
                            "cycle": 2,
                            "manufacturer_sample_count": 8,
                            "manufacturer_counts": {"1006": 8},
                            "resolvable_counts": {},
                            "oura_candidate_counts": {},
                            "no_target_classification": "no_oura_seen",
                            "scan_backend": "btmgmt",
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_loop_done",
                        "payload": {"cycles": 2, "success": False},
                    }
                ),
            ]
        )
    )

    cli.print_watch_summaries([cli.watch_log_summary(log_path)])

    text = capsys.readouterr().out
    assert "raw: samples=8 oura=0 class=no_oura_seen backend=btmgmt" in text
    assert "raw_top_mfg: 1006:8" in text
    assert (
        "raw_hint: scanner is receiving BLE advertisements, but no Oura state is "
        "visible; trigger a ring wake/charger transition/app activity"
    ) in text
    assert "raw_loop: success_cycle=None done_cycles=2 done_success=False" in text


def test_pi_watch_summary_treats_address_only_scan_as_ble_activity(
    capsys, tmp_path
) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_cycle_no_target",
                "payload": {
                    "cycle": 1,
                    "manufacturer_counts": {},
                    "oura_candidate_counts": {},
                    "no_target_classification": "no_oura_seen",
                    "scan_backend": "btmgmt",
                    "unique_address_count": 3,
                    "resolvable_address_count": 0,
                    "event_type_counts": {"btmgmt_dev_found": 3},
                    "address_type_counts": {"LE Random": 3},
                    "address_rssi": {
                        "5B:B1:28:08:EA:C6": {
                            "samples": 3,
                            "min": -86,
                            "max": -83,
                            "last": -84,
                            "address_type": "LE Random",
                            "event_type": "btmgmt_dev_found",
                        }
                    },
                },
            }
        )
    )

    cli.print_watch_summaries([cli.watch_log_summary(log_path)])

    text = capsys.readouterr().out
    assert "raw: samples=0 oura=0 class=no_oura_seen backend=btmgmt" in text
    assert "raw_seen: unique=3 resolvable=0 events=btmgmt_dev_found:3" in text
    assert (
        "raw_near_dev: 5B:B1:28:08:EA:C6:-83dBm/LE Random/"
        "btmgmt_dev_found/3"
    ) in text
    assert (
        "raw_hint: scanner is receiving BLE advertisements, but no Oura state is "
        "visible; trigger a ring wake/charger transition/app activity"
    ) in text


def test_pi_watch_summary_prints_raw_scan_shape(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_scan_heartbeat",
                "payload": {
                    "cycle": 1,
                    "manufacturer_sample_count": 12,
                    "manufacturer_counts": {"1006": 12},
                    "oura_candidate_counts": {},
                    "no_target_classification": "no_oura_seen",
                    "scan_backend": "hci_le_scan",
                    "unique_address_count": 7,
                    "resolvable_address_count": 4,
                    "event_type_counts": {
                        "Scan response - SCAN_RSP (0x04)": 5,
                        "Non connectable undirected - ADV_NONCONN_IND (0x03)": 3,
                    },
                    "address_type_counts": {
                        "Resolvable": 4,
                        "Non-Resolvable": 3,
                    },
                    "manufacturer_rssi": {
                        "near": {"samples": 2, "min": -51, "max": -42, "last": -42},
                        "far": {"samples": 8, "min": -90, "max": -77, "last": -85},
                    },
                    "manufacturer_addresses": {
                        "near": {
                            "samples": 2,
                            "latest_address": "C1:22:33:44:55:66",
                            "latest_address_type": "Resolvable",
                            "max_rssi": -42,
                            "max_rssi_resolvable_address": "C1:22:33:44:55:66",
                            "max_rssi_address_type": "Resolvable",
                            "max_rssi_event_type": (
                                "Connectable undirected - ADV_IND (0x00)"
                            ),
                            "max_rssi_company": "Acme Sensor Co. (65535)",
                        },
                        "far": {
                            "samples": 8,
                            "latest_address": "AA:22:33:44:55:66",
                            "latest_address_type": "Static",
                            "max_rssi": -77,
                            "max_rssi_address": "AA:22:33:44:55:66",
                            "max_rssi_address_type": "Static",
                            "max_rssi_event_type": (
                                "Non connectable undirected - ADV_NONCONN_IND (0x03)"
                            ),
                            "max_rssi_company": "Apple, Inc. (76)",
                        },
                    },
                    "address_rssi": {
                        "C1:22:33:44:55:66": {
                            "samples": 2,
                            "min": -51,
                            "max": -42,
                            "last": -42,
                            "address_type": "Resolvable",
                            "event_type": "Connectable undirected - ADV_IND (0x00)",
                        },
                        "AA:22:33:44:55:66": {
                            "samples": 8,
                            "min": -90,
                            "max": -77,
                            "last": -85,
                            "address_type": "Static",
                            "event_type": (
                                "Non connectable undirected - ADV_NONCONN_IND (0x03)"
                            ),
                        },
                    },
                },
            }
        )
    )

    cli.print_watch_summaries([cli.watch_log_summary(log_path)])

    text = capsys.readouterr().out
    assert "raw_seen: unique=7 resolvable=4" in text
    assert "Scan response - SCAN_RSP (0x04):5" in text
    assert "address_types=Resolvable:4,Non-Resolvable:3" in text
    assert "raw_near_mfg: near:-42dBm/2, far:-77dBm/8" in text
    assert (
        "raw_near_addr: near:-42dBm/C1:22:33:44:55:66/Resolvable/ADV_IND/Acme Sensor Co., "
        "far:-77dBm/AA:22:33:44:55:66/Static/ADV_NONCONN/Apple"
    ) in text
    assert (
        "raw_near_dev: C1:22:33:44:55:66:-42dBm/Resolvable/ADV_IND/2, "
        "AA:22:33:44:55:66:-77dBm/Static/ADV_NONCONN/8"
    ) in text
    assert (
        "raw_probe_candidates: near:-42dBm/ADV_IND/C1:22:33:44:55:66/Acme Sensor Co."
    ) in text


def test_pi_watch_summary_probe_candidates_skip_common_non_oura_companies() -> None:
    candidates = cli.ranked_manual_probe_candidates(
        {
            "apple": {"samples": 5, "min": -60, "max": -30, "last": -30},
            "unknown": {"samples": 2, "min": -65, "max": -45, "last": -45},
        },
        {
            "apple": {
                "max_rssi_address": "C1:22:33:44:55:66",
                "max_rssi_address_type": "Resolvable",
                "max_rssi_event_type": "Connectable undirected - ADV_IND (0x00)",
                "max_rssi_company": "Apple, Inc. (76)",
            },
            "unknown": {
                "max_rssi_address": "C2:22:33:44:55:66",
                "max_rssi_address_type": "Resolvable",
                "max_rssi_event_type": "Connectable undirected - ADV_IND (0x00)",
                "max_rssi_company": "",
            },
        },
    )

    assert [candidate["manufacturer_hex"] for candidate in candidates] == ["unknown"]


def test_pi_watch_summary_tracks_controller_recovery_events(tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event": "raw_scan_backend_switch",
                        "payload": {
                            "scan_backend": "btmgmt",
                            "reason": "configured",
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_scan_inactive",
                        "payload": {
                            "cycle": 1,
                            "reason": "silent_scan_no_manufacturer_samples",
                            "scan_backend": "btmgmt",
                            "seconds_without_samples": 75.08,
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_hci_scan_enable",
                        "payload": {
                            "cycle": 1,
                            "reason": "silent_scan_no_manufacturer_samples",
                            "commands": [
                                {
                                    "stdout": (
                                        "< HCI Command: ogf 0x08, ocf 0x000c, plen 2\n"
                                        "  00 00 \n"
                                        "> HCI Event: 0x0e plen 4\n"
                                        "  01 0C 20 0C"
                                    )
                                }
                            ],
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_bluetooth_recovery",
                        "payload": {"cycle": 1, "reason": "scan_inactive"},
                    }
                ),
            ]
        )
    )

    summary = cli.watch_log_summary(log_path)

    assert summary["latest_raw_scan_status"] == {
        "cycle": 1,
        "reason": "silent_scan_no_manufacturer_samples",
        "scan_backend": "btmgmt",
        "operator_hint": (
            "scanner/controller issue: recover BlueZ or switch scan backend before "
            "treating this as a ring protocol result"
        ),
    }
    assert summary["controller_status"] == {
        "scan_inactive_events": 1,
        "hci_scan_enable_events": 1,
        "bluetooth_recovery_events": 1,
        "backend_switch_events": 1,
        "latest_inactive_reason": "silent_scan_no_manufacturer_samples",
        "latest_inactive_backend": "btmgmt",
        "latest_seconds_without_samples": 75.08,
        "latest_hci_reason": "silent_scan_no_manufacturer_samples",
        "latest_hci_status_codes": ["0x0C"],
        "latest_hci_status_names": ["command_disallowed"],
        "latest_hci_final_status_code": "0x0C",
        "latest_hci_final_status_name": "command_disallowed",
        "latest_recovery_reason": "scan_inactive",
        "latest_backend": "btmgmt",
        "latest_backend_reason": "configured",
    }


def test_pi_watch_summary_prints_controller_status(capsys, tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event": "raw_scan_inactive",
                        "payload": {
                            "reason": "silent_scan_no_manufacturer_samples",
                            "scan_backend": "btmgmt",
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_hci_scan_enable",
                        "payload": {
                            "commands": [
                                {
                                    "stdout": (
                                        "< HCI Command: ogf 0x08, ocf 0x000c, plen 2\n"
                                        "  00 00 \n"
                                        "> HCI Event: 0x0e plen 4\n"
                                        "  01 0C 20 0C"
                                    )
                                }
                            ]
                        },
                    }
                ),
                json.dumps(
                    {
                        "event": "raw_bluetooth_recovery",
                        "payload": {"reason": "scan_inactive"},
                    }
                ),
            ]
        )
    )

    cli.print_watch_summaries([cli.watch_log_summary(log_path)])

    text = capsys.readouterr().out
    assert "controller: inactive=1 hci_enable=1 recoveries=1 backend_switches=0" in text
    assert (
        "controller_detail: inactive=silent_scan_no_manufacturer_samples "
        "recovery=scan_inactive hci_final=command_disallowed"
    ) in text


def test_pi_watch_summary_counts_cycle_scan_inactive_events(tmp_path) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_cycle_scan_inactive",
                "payload": {
                    "reason": "hci_le_scan_enable_failed",
                    "scan_backend": "btmgmt",
                },
            }
        )
    )

    summary = cli.watch_log_summary(log_path)

    assert summary["controller_status"]["scan_inactive_events"] == 1
    assert (
        summary["controller_status"]["latest_inactive_reason"]
        == "hci_le_scan_enable_failed"
    )


def test_pi_watch_summary_prints_final_hci_status_for_mixed_scan_enable(
    capsys, tmp_path
) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_hci_scan_enable",
                "payload": {
                    "commands": [
                        {
                            "stdout": (
                                "< HCI Command: ogf 0x08, ocf 0x000c, plen 2\n"
                                "  00 00 \n"
                                "> HCI Event: 0x0e plen 4\n"
                                "  01 0C 20 0C"
                            )
                        },
                        {
                            "stdout": (
                                "< HCI Command: ogf 0x08, ocf 0x000c, plen 2\n"
                                "  01 00 \n"
                                "> HCI Event: 0x0e plen 4\n"
                                "  01 0C 20 00"
                            )
                        },
                    ]
                },
            }
        )
    )

    summary = cli.watch_log_summary(log_path)
    assert summary["controller_status"]["latest_hci_status_names"] == [
        "command_disallowed",
        "success",
    ]
    assert summary["controller_status"]["latest_hci_final_status_name"] == "success"

    cli.print_watch_summaries([summary])

    text = capsys.readouterr().out
    assert "controller_detail: hci_final=success" in text
    assert "hci_status=command_disallowed,success" not in text


def test_pi_watch_summary_computes_raw_sample_count_from_completed_cycle(
    tmp_path,
) -> None:
    log_path = tmp_path / "pi-rpa.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "event": "raw_cycle_no_target",
                "payload": {
                    "cycle": 1,
                    "manufacturer_counts": {"1006": 8, "04671b01": 2},
                    "resolvable_counts": {"04671b01": 2},
                    "oura_candidate_counts": {"04671b01": 2},
                    "no_target_classification": "oura_seen_without_target_payload",
                    "scan_backend": "hci_le_scan",
                    "last_address": "C1:22:33:44:55:66",
                    "last_address_type": "Resolvable",
                    "last_address_kind": "Random (0x01)",
                    "last_event_type": "Scan response - SCAN_RSP (0x04)",
                },
            }
        )
    )

    summary = cli.watch_log_summary(log_path)

    assert summary["latest_raw_scan_status"]["manufacturer_sample_count"] == 10
    assert summary["latest_raw_scan_status"]["scan_backend"] == "hci_le_scan"
    assert summary["latest_raw_scan_status"]["last_address"] == "C1:22:33:44:55:66"
    assert (
        summary["latest_raw_scan_status"]["last_event_type"]
        == "Scan response - SCAN_RSP (0x04)"
    )
    assert summary["latest_raw_scan_status"]["operator_hint"] == (
        "ring presence seen, but not a connect/read target payload; keep "
        "watching for a setup/reset/app wake state or broaden the target set"
    )


def test_pi_smp_probe_parser_defaults_to_setup_pairing_matrix() -> None:
    args = cli.build_parser().parse_args(["pi-smp-probe"])

    assert args.command == "pi-smp-probe"
    assert args.stop_bluetoothd is True
    assert args.own_address_type == "public"
    assert "display_yesno_bond_sc_mitm_ct2_keys" in args.variants
    assert "display_only_bond_sc_mitm_ct2_keys" in args.variants
    assert "keyboard_only_bond_sc_mitm_ct2_keys" in args.variants
    assert "no_input_output_bond_sc_mitm_ct2_keys" in args.variants


def test_pi_smp_probe_command_wraps_raw_probe(monkeypatch, tmp_path) -> None:
    captured = {}

    def fake_run(
        command, log_path, pointer_path, *, raw_log, success_summary_key=None
    ):
        captured["command"] = command
        captured["log_path"] = log_path
        captured["pointer_path"] = pointer_path
        captured["raw_log"] = raw_log
        captured["success_summary_key"] = success_summary_key
        return 0

    monkeypatch.setattr(cli, "run_pi_jsonl_command", fake_run)
    args = cli.build_parser().parse_args(
        [
            "pi-smp-probe",
            "--log-dir",
            str(tmp_path),
            "--scan-seconds",
            "12",
            "--connect-timeout",
            "4",
            "--listen-seconds",
            "1",
            "--manufacturer-hex",
            "04621b01",
            "--own-address-type",
            "random",
            "--random-address",
            "C1:22:33:44:55:66",
            "--variants",
            "connect_only",
            "--no-stop-bluetoothd",
        ]
    )

    assert cli.command_pi_smp_probe(args) == 0

    command = captured["command"]
    assert command[:3] == ["sudo", "-E", "/usr/bin/python3"]
    assert command[3].endswith("scripts/pi-oura-raw-smp-probe.py")
    assert command[command.index("--scan-seconds") + 1] == "12.0"
    assert command[command.index("--connect-timeout") + 1] == "4.0"
    assert command[command.index("--listen-seconds") + 1] == "1.0"
    assert command[command.index("--manufacturer-hex") + 1] == "04621b01"
    assert command[command.index("--own-address-type") + 1] == "random"
    assert command[command.index("--random-address") + 1] == "C1:22:33:44:55:66"
    assert command[command.index("--variants") + 1] == "connect_only"
    assert "--no-stop-bluetoothd" in command
    assert captured["pointer_path"] == tmp_path / "current-pi-raw-smp-probe.log"
    assert captured["success_summary_key"] == "raw_smp_probe_done"


def test_build_packet_parser_accepts_factory_reset_aliases() -> None:
    dashed = cli.build_parser().parse_args(["build-packet", "factory-reset"])
    underscored = cli.build_parser().parse_args(["build-packet", "factory_reset"])

    assert dashed.command == "build-packet"
    assert dashed.name == "factory-reset"
    assert underscored.name == "factory_reset"


def test_build_packet_factory_reset_prints_opcode(capsys) -> None:
    args = cli.build_parser().parse_args(["build-packet", "factory-reset"])

    assert cli.command_build_packet(args) == 0

    assert capsys.readouterr().out.splitlines()[0] == "1a00"


def test_latest_jsonl_summary_returns_read_result_and_errors(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    read_result = {"firmware": {"firmware_version": "2.11.0"}}
    error = {"error_type": "DBusException", "error": "Authentication Failed"}
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "provision_scan_start", "payload": {}}),
                json.dumps({"event": "read_result", "payload": read_result}),
                json.dumps({"event": "provision_error", "payload": error}),
                "",
            ]
        )
    )

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["event_counts"] == {
        "provision_scan_start": 1,
        "read_result": 1,
        "provision_error": 1,
    }
    assert summary["read_result"] == read_result
    assert summary["read_result_usable"] is True
    assert summary["provision_error"] == error


def test_latest_jsonl_summary_marks_empty_write_error_read_result_unusable(
    tmp_path,
) -> None:
    log_path = tmp_path / "probe.jsonl"
    read_result = {
        "firmware": None,
        "battery": None,
        "auth_nonce": None,
        "probes": [
            {
                "classification": "write_error",
                "errors": [{"error": "Not connected"}],
                "raw_responses": [],
            }
        ],
    }
    log_path.write_text(json.dumps({"event": "read_result", "payload": read_result}))

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["read_result"] == read_result
    assert summary["read_result_usable"] is False


def test_latest_jsonl_summary_marks_feature_latest_read_result_usable(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    read_result = {
        "feature_latest": {
            "feature_latest:daytime_hr": {
                "extended_name": "feature_latest_values_response",
                "feature_name": "daytime_hr",
                "latest_values": [{"value": 71}],
            }
        },
        "daytime_hr_latest": {"latest_values": [{"value": 71}]},
    }
    log_path.write_text(json.dumps({"event": "read_result", "payload": read_result}))

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["read_result"] == read_result
    assert summary["read_result_usable"] is True


def test_latest_jsonl_summary_marks_auth_gated_read_result_usable(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    read_result = {"auth_gated": ["battery", "feature_latest:daytime_hr"]}
    log_path.write_text(json.dumps({"event": "read_result", "payload": read_result}))

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["read_result"] == read_result
    assert summary["read_result_usable"] is True


def test_latest_jsonl_summary_includes_setup_security_failure(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    failure = {
        "classification": "setup_pairing_rejected",
        "att_insufficient_encryption": True,
        "smp_pairing_failed_reason": "Unspecified reason",
        "smp_pairing_failed_reason_code": "0x08",
    }
    read_result = {
        "probes": [
            {
                "packet": "firmware",
                "errors": [
                    {
                        "error": "org.bluez.Error.Failed: Not connected",
                        "error_type": "DBusException",
                    }
                ],
            }
        ]
    }
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "read_result", "payload": read_result}),
                json.dumps({"event": "raw_setup_security_failure", "payload": failure}),
                json.dumps({"event": "raw_loop_done", "payload": {"success": False}}),
            ]
        )
    )

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["raw_setup_security_failure"] == failure
    assert summary["read_failure"] == {
        "classification": "setup_pairing_rejected",
        "detail": "ring rejected SMP pairing before Oura packet reads could run",
        "att_insufficient_encryption": True,
        "smp_pairing_failed_reason": "Unspecified reason",
        "smp_pairing_failed_reason_code": "0x08",
        "first_probe_error": {
            "packet": "firmware",
            "error": "org.bluez.Error.Failed: Not connected",
            "error_type": "DBusException",
        },
    }


def test_latest_jsonl_summary_includes_raw_smp_probe_summary(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    smp_summary = {
        "non_rejected_variants": [],
        "outcome_counts": {"pairing_rejected": 3},
        "probed_count": 3,
    }
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "raw_smp_probe_start", "payload": {}}),
                json.dumps({"event": "raw_smp_probe_done", "payload": smp_summary}),
            ]
        )
    )

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["event_counts"] == {
        "raw_smp_probe_start": 1,
        "raw_smp_probe_done": 1,
    }
    assert summary["raw_smp_probe_done"] == smp_summary


def test_latest_jsonl_summary_includes_gatt_diagnostic_summary(tmp_path) -> None:
    log_path = tmp_path / "probe.jsonl"
    diagnostic = {"targets": 1, "read_successes": 0, "gatt_successes": 0}
    matrix = {"expected_response_hits": 0, "aborted": True}
    log_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "matrix_summary", "payload": matrix}),
                json.dumps({"event": "diagnostic_summary", "payload": diagnostic}),
            ]
        )
    )

    summary = cli.latest_jsonl_summary(log_path)

    assert summary["diagnostic_summary"] == diagnostic
    assert summary["matrix_summary"] == matrix
