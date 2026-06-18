"""macOS Bluetooth TCC repair for command-line BLE access."""

from __future__ import annotations

import platform
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


class PermissionFixError(RuntimeError):
    """Raised when macOS Bluetooth permission repair cannot be completed."""


@dataclass(frozen=True)
class TccIdentity:
    client: str
    client_type: int
    requirement: str
    source: str


@dataclass(frozen=True)
class PermissionFixResult:
    tcc_db: Path
    backup: Path | None
    identities: list[TccIdentity]
    dry_run: bool
    restarted_tccd: bool

    def to_json(self) -> dict[str, object]:
        return {
            "tcc_db": str(self.tcc_db),
            "backup": str(self.backup) if self.backup else None,
            "dry_run": self.dry_run,
            "restarted_tccd": self.restarted_tccd,
            "identities": [
                {
                    "client": identity.client,
                    "client_type": identity.client_type,
                    "requirement": identity.requirement,
                    "source": identity.source,
                }
                for identity in self.identities
            ],
        }


SERVICE_BLUETOOTH = "kTCCServiceBluetoothAlways"
AUTH_ALLOW = 2
AUTH_REASON_USER_SET = 2
AUTH_VERSION = 1


def fix_macos_bluetooth_permissions(
    *, dry_run: bool = False, restart_tccd: bool = True
) -> PermissionFixResult:
    if platform.system() != "Darwin":
        raise PermissionFixError("Bluetooth TCC repair only applies to macOS")

    tcc_db = user_tcc_db()
    if not tcc_db.exists():
        raise PermissionFixError(f"user TCC database does not exist: {tcc_db}")

    identities = bluetooth_tcc_identities()
    if not identities:
        raise PermissionFixError("no code-signed identities found to authorize")

    backup = None
    if not dry_run:
        backup = backup_tcc_db(tcc_db)
        insert_bluetooth_grants(tcc_db, identities)
        if restart_tccd:
            restart_user_tccd()

    return PermissionFixResult(
        tcc_db=tcc_db,
        backup=backup,
        identities=identities,
        dry_run=dry_run,
        restarted_tccd=bool(restart_tccd and not dry_run),
    )


def user_tcc_db() -> Path:
    return Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"


def bluetooth_tcc_identities() -> list[TccIdentity]:
    identities: list[TccIdentity] = []
    for source, executable in candidate_executables():
        if not executable.exists():
            continue
        requirement = designated_requirement(executable)
        identities.append(
            TccIdentity(
                client=str(executable),
                client_type=1,
                requirement=requirement,
                source=source,
            )
        )

    bundle = python_app_bundle_id()
    python_app = python_app_executable()
    if bundle and python_app and python_app.exists():
        identities.append(
            TccIdentity(
                client=bundle,
                client_type=0,
                requirement=designated_requirement(python_app),
                source="python-app-bundle",
            )
        )

    return dedupe_identities(identities)


def candidate_executables() -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []

    def add(source: str, value: str | None) -> None:
        if value:
            candidates.append((source, Path(value)))
            try:
                candidates.append((f"{source}-realpath", Path(value).resolve()))
            except OSError:
                pass

    add("sys-executable", sys.executable)
    add("base-executable", getattr(sys, "_base_executable", None))

    python_app = python_app_executable()
    if python_app:
        add("python-app-executable", str(python_app))

    python_name = Path(sys.executable).name
    for found in executable_paths_from_path(python_name):
        add("path-lookup", str(found))

    # Codex commands on this Mac arrive through SSH; TCC evaluates this
    # platform binary as the responsible process for CoreBluetooth requests.
    add("ssh-responsible-process", "/usr/libexec/sshd-keygen-wrapper")

    return candidates


def executable_paths_from_path(name: str) -> list[Path]:
    found: list[Path] = []
    current = shutil.which(name)
    if current:
        found.append(Path(current))

    if name == "python3":
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        versioned = shutil.which(version)
        if versioned:
            found.append(Path(versioned))
    return found


def python_app_executable() -> Path | None:
    real_executable = Path(sys.executable).resolve()
    parts = real_executable.parts
    try:
        versions_index = parts.index("Versions")
    except ValueError:
        return None
    if len(parts) <= versions_index + 1:
        return None
    version_root = Path(*parts[: versions_index + 2])
    app_executable = (
        version_root / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    )
    if app_executable.exists():
        return app_executable
    return None


def python_app_bundle_id() -> str | None:
    python_app = python_app_executable()
    if not python_app:
        return None
    plist = python_app.parents[1] / "Info.plist"
    if not plist.exists():
        return None
    proc = subprocess.run(  # nosec B603
        ["/usr/bin/defaults", "read", str(plist), "CFBundleIdentifier"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        return None
    bundle = proc.stdout.strip()
    return bundle or None


def dedupe_identities(identities: list[TccIdentity]) -> list[TccIdentity]:
    seen: set[tuple[str, int]] = set()
    deduped: list[TccIdentity] = []
    for identity in identities:
        key = (identity.client, identity.client_type)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(identity)
    return deduped


def designated_requirement(executable: Path) -> str:
    proc = subprocess.run(  # nosec B603
        ["/usr/bin/codesign", "-dr", "-", str(executable)],
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    output = "\n".join(part for part in [proc.stdout, proc.stderr] if part)
    match = re.search(r"(?:# )?designated => (.+)", output)
    if match:
        return match.group(1).strip()
    cdhash = cdhash_for_executable(executable)
    return f'cdhash H"{cdhash}"'


def cdhash_for_executable(executable: Path) -> str:
    proc = subprocess.run(  # nosec B603
        ["/usr/bin/codesign", "-dv", "--verbose=4", str(executable)],
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    output = "\n".join(part for part in [proc.stdout, proc.stderr] if part)
    match = re.search(r"CDHash=([0-9a-fA-F]+)", output)
    if not match:
        raise PermissionFixError(f"could not read CDHash for {executable}")
    return match.group(1)


def compile_requirement(requirement: str) -> bytes:
    with tempfile.NamedTemporaryFile() as tmp:
        proc = subprocess.run(  # nosec B603
            ["/usr/bin/csreq", "-r", f"={requirement}", "-b", tmp.name],
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            raise PermissionFixError(f"csreq failed for {requirement!r}: {stderr}")
        return Path(tmp.name).read_bytes()


def backup_tcc_db(tcc_db: Path) -> Path:
    backup = tcc_db.with_name(f"TCC.db.backup.{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(tcc_db, backup)
    return backup


def insert_bluetooth_grants(tcc_db: Path, identities: list[TccIdentity]) -> None:
    now = int(time.time())
    with sqlite3.connect(tcc_db) as conn:
        for identity in identities:
            conn.execute(
                """
                insert or replace into access (
                    service,
                    client,
                    client_type,
                    auth_value,
                    auth_reason,
                    auth_version,
                    csreq,
                    policy_id,
                    indirect_object_identifier_type,
                    indirect_object_identifier,
                    indirect_object_code_identity,
                    flags,
                    last_modified,
                    pid,
                    pid_version,
                    boot_uuid,
                    last_reminded
                )
                values (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'UNUSED', NULL, 0,
                        ?, NULL, NULL, 'UNUSED', 0)
                """,
                (
                    SERVICE_BLUETOOTH,
                    identity.client,
                    identity.client_type,
                    AUTH_ALLOW,
                    AUTH_REASON_USER_SET,
                    AUTH_VERSION,
                    compile_requirement(identity.requirement),
                    now,
                ),
            )
        conn.commit()


def restart_user_tccd() -> None:
    subprocess.run(  # nosec B603
        ["/usr/bin/killall", "tccd"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
