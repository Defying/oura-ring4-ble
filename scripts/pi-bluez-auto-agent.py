#!/usr/bin/env python3
"""BlueZ pairing agent for Pi-side Oura Ring 4 diagnostics.

The Oura Ring 4 setup path requires a BLE bond before protected GATT writes.
This agent auto-accepts BlueZ pairing prompts so unattended diagnostics can
reach the application-level protocol.
"""

from __future__ import annotations

import argparse
import json
import signal
import time
from typing import Any

AGENT_PATH = "/com/carve/oura/AutoAgent"


def main() -> int:
    parser = argparse.ArgumentParser(description="Register an auto-confirm BlueZ agent.")
    parser.add_argument("--adapter", default="/org/bluez/hci0")
    parser.add_argument(
        "--capability",
        default="KeyboardDisplay",
        choices=[
            "DisplayOnly",
            "DisplayYesNo",
            "KeyboardOnly",
            "NoInputNoOutput",
            "KeyboardDisplay",
        ],
    )
    args = parser.parse_args()

    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


def run(args: argparse.Namespace) -> int:
    import dbus
    import dbus.mainloop.glib
    import dbus.service
    from gi.repository import GLib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    loop = GLib.MainLoop()

    class AutoAgent(dbus.service.Object):
        @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
        def Release(self) -> None:
            emit("agent_release", {})
            loop.quit()

        @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="s")
        def RequestPinCode(self, device: str) -> str:
            emit("agent_request_pin_code", {"device": device})
            return "0000"

        @dbus.service.method("org.bluez.Agent1", in_signature="ouq", out_signature="")
        def DisplayPasskey(self, device: str, passkey: int, entered: int) -> None:
            emit(
                "agent_display_passkey",
                {"device": device, "passkey": int(passkey), "entered": int(entered)},
            )

        @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="u")
        def RequestPasskey(self, device: str) -> dbus.UInt32:
            emit("agent_request_passkey", {"device": device})
            return dbus.UInt32(0)

        @dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
        def RequestConfirmation(self, device: str, passkey: int) -> None:
            emit(
                "agent_request_confirmation",
                {"device": device, "passkey": int(passkey), "accepted": True},
            )

        @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="")
        def RequestAuthorization(self, device: str) -> None:
            emit("agent_request_authorization", {"device": device, "accepted": True})

        @dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="")
        def AuthorizeService(self, device: str, uuid: str) -> None:
            emit(
                "agent_authorize_service",
                {"device": device, "uuid": uuid, "accepted": True},
            )

        @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
        def Cancel(self) -> None:
            emit("agent_cancel", {})

    agent = AutoAgent(bus, AGENT_PATH)
    manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.AgentManager1",
    )
    adapter_props = dbus.Interface(
        bus.get_object("org.bluez", args.adapter),
        "org.freedesktop.DBus.Properties",
    )

    def shutdown(_signum: int, _frame: Any) -> None:
        loop.quit()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    adapter_props.Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(True))
    manager.RegisterAgent(AGENT_PATH, args.capability)
    manager.RequestDefaultAgent(AGENT_PATH)
    emit(
        "agent_ready",
        {
            "path": AGENT_PATH,
            "adapter": args.adapter,
            "capability": args.capability,
        },
    )
    try:
        loop.run()
    finally:
        with suppress_dbus_error():
            manager.UnregisterAgent(AGENT_PATH)
        with suppress_dbus_error():
            adapter_props.Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(False))
        agent.remove_from_connection()
        emit("agent_stopped", {})
    return 0


class suppress_dbus_error:
    def __enter__(self) -> None:
        return None

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> bool:
        return True


def emit(event: str, payload: dict[str, Any]) -> None:
    print(
        json.dumps(
            {
                "event": event,
                "elapsed_seconds": round(time.monotonic() - STARTED, 3),
                "payload": payload,
            },
            sort_keys=True,
        ),
        flush=True,
    )


STARTED = time.monotonic()


if __name__ == "__main__":
    raise SystemExit(main())
