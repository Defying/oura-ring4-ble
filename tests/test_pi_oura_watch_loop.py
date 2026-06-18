from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


def load_watch_loop_module() -> ModuleType:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "pi-oura-watch-loop.py"
    spec = importlib.util.spec_from_file_location("pi_oura_watch_loop", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


watch_loop = load_watch_loop_module()


def test_watch_cycle_forwards_low_power_diagnostic_flags(monkeypatch) -> None:
    captured = {}

    class FakeProcess:
        returncode = 1
        stdout = []

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(command, **_kwargs):
        captured["command"] = command
        captured["env"] = _kwargs.get("env")
        return FakeProcess()

    monkeypatch.setattr(watch_loop.subprocess, "Popen", fake_popen)
    args = SimpleNamespace(
        cycle_scan_seconds=12.0,
        connect_timeout=4.0,
        connect_limit=1,
        summary_limit=5,
        scan_heartbeat_seconds=3.0,
        matrix_response_timeout=1.5,
        matrix_read_timeout=1.0,
        require_manufacturer_hex=["04671b01"],
        packet_read_only=True,
        connectable_hint_only=True,
        skip_standard_reads=True,
        power_off_after=True,
        passive_scan=True,
        no_matrix_only=False,
        matrix_pre_read=False,
        matrix_post_read=False,
        pair=False,
        btmon=False,
    )

    assert watch_loop.run_cycle(args, 1, 0.0) == 1

    command = captured["command"]
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    assert captured["env"]["PYTHONPATH"].split(os.pathsep)[0] == src_path
    assert command[1].endswith("pi-oura-gatt-diagnostic.py")
    assert command[command.index("--scan-seconds") + 1] == "12.0"
    assert command[command.index("--require-manufacturer-hex") + 1] == "04671b01"
    assert "--packet-read-only" in command
    assert "--connectable-hint-only" in command
    assert "--skip-standard-reads" in command
    assert "--power-off-after" in command
    assert "--passive-scan" in command
