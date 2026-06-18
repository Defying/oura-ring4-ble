# oura-ring4-ble

Console probes and protocol notes for the observed Oura Ring 4 BLE interface.

This repository is research tooling, not a replacement for the Oura app. It is
intended for people who own the hardware they are testing and want a local,
scriptable BLE console for protocol exploration.

## What Is Included

- Python packet builders/parsers for the observed Ring 4 BLE framing.
- macOS/CoreBluetooth and Linux/BlueZ diagnostic readers.
- Linux/BlueZ scripts for scanning, pairing, GATT probing, and app-free
  local-key provisioning experiments.
- Rust CoreBluetooth monitors for long-running macOS advertisement/read
  attempts.
- Public-safe notes for protocol facts learned from live BLE captures and
  Android APK static analysis.

## What Is Not Included

- No APK, APKS/APKM, decompiled app source, app assets, or copyrighted binaries.
- No social-media provenance or third-party media/source material.
- No account, cloud, phone-backup, or device-storage key extraction.
- No checked-in auth keys, ring state files, BLE logs, or private device
  identifiers.

The code contains packet builders and Linux probes for provisioning,
authentication, and factory-reset research. Use destructive packets only with
hardware you own and are willing to reset.

## Protocol Docs

- [Protocol Notes](docs/protocol-notes.md)
- [APK Static-Analysis Findings](docs/apk-findings.md)

The APK findings document records interoperability facts such as packet tags,
feature IDs, request/response layouts, and state-machine behavior. It does not
include copied app code or decompiled source.

## Requirements

- Python 3.13
- [`uv`](https://docs.astral.sh/uv/)
- Linux BlueZ tools for Linux BLE work: `bluetoothctl`, `btmon`,
  `btmgmt`, `hcitool`
- Rust toolchain for the optional macOS CoreBluetooth monitors

Install Python dependencies:

```bash
uv sync --python 3.13
```

Run tests:

```bash
uv run pytest
cargo test
```

## Basic Python CLI

Scan nearby BLE advertisements:

```bash
uv run oura-ring4-ble scan --only-oura --timeout 20
uv run oura-ring4-ble scan --timeout 15
```

Inspect a discovered GATT target:

```bash
uv run oura-ring4-ble probe --timeout 20
uv run oura-ring4-ble inspect --address ADDRESS_FROM_SCAN
```

Read firmware and battery:

```bash
uv run oura-ring4-ble read --address ADDRESS_FROM_SCAN --timeout 60 --attempts 5
```

Authenticate with a locally held key and dump raw event packets:

```bash
export OURA_RING_AUTH_KEY='hex-or-base64-16-byte-key'
uv run oura-ring4-ble read --address ADDRESS_FROM_SCAN --events --sync-time
```

Decode sample packets offline:

```bash
uv run oura-ring4-ble decode '0D06 6400 00FF FFFF'
uv run oura-ring4-ble decode-events '460A 10000000 100E470E0F0E'
uv run oura-ring4-ble build-packet battery
uv run oura-ring4-ble build-packet factory-reset
```

## Linux / BlueZ Flow

Use the GATT diagnostic to stream advertisements, connect to likely Oura
candidates, and print `read_result` when packet responses arrive:

Several scripts still have `pi-` in their filename because the original test
client was a Raspberry Pi. They are Linux/BlueZ scripts and are not limited to
ARM64.

```bash
uv run oura-ring4-ble pi-gatt-probe \
  --scan-seconds 60 \
  --connect-timeout 12 \
  --connect-on-first-oura

PYTHONPATH=src /usr/bin/python3 scripts/pi-oura-gatt-diagnostic.py \
  --scan-seconds 60 \
  --connect-timeout 12 \
  --non-oura-connect-limit 1
```

`pi-gatt-probe` restarts bluetoothd, power-cycles hci0, and removes visible
BlueZ device objects before scanning by default. Use
`--no-restart-bluetooth-first --no-clear-stale` only when intentionally testing
cached BlueZ state.

When the ring rotates private addresses quickly, connect as soon as an Oura
advertisement is seen and run the characteristic matrix:

```bash
uv run oura-ring4-ble pi-gatt-probe \
  --scan-seconds 120 \
  --connect-timeout 8 \
  --connect-on-first-oura \
  --matrix-only \
  --matrix-skip-uuid 98ed0003

PYTHONPATH=src /usr/bin/python3 scripts/pi-oura-gatt-diagnostic.py \
  --scan-seconds 120 \
  --connect-timeout 8 \
  --connect-limit 1 \
  --connect-on-first-oura \
  --scan-heartbeat-seconds 60 \
  --matrix-only \
  --matrix-response-timeout 1.5
```

For setup-state rings that disconnect on ordinary Generic Access reads, skip
those reads and run a one-connection packet probe:

```bash
uv run oura-ring4-ble pi-gatt-probe \
  --scan-seconds 60 \
  --connect-timeout 10 \
  --connect-on-first-oura \
  --packet-read-only \
  --skip-standard-reads
```

When the ring is paired and worn, scans may only see sparse `04601b01`
presence advertisements that time out on GATT connect. Wait for the observed
connectable/readiness hint before attempting a packet read:

```bash
uv run oura-ring4-ble pi-gatt-probe \
  --scan-seconds 300 \
  --connect-timeout 10 \
  --connect-on-first-oura \
  --connectable-hint-only \
  --packet-read-only \
  --skip-standard-reads
```

For low-duty waiting while the ring is paired/worn, use the watch command. By
default it uses passive Oura advertisement monitoring, only connects on the
readiness hint, skips standard GATT reads, runs focused packet probes, and powers
off hci0 after every cycle:

```bash
uv run oura-ring4-ble pi-watch \
  --cycle-scan-seconds 300 \
  --cycles 0
```

Use `--active-scan` only when passive BlueZ monitoring is not available or when
you are intentionally comparing advertisement visibility.

Summarize one or more active watcher logs, or follow the current pointer until a
usable `read_result` appears:

```bash
uv run oura-ring4-ble pi-watch-summary
uv run oura-ring4-ble pi-watch-summary \
  --follow \
  --interval 10 \
  --until-read-result \
  --pointer logs/current-pi-bluez-read-result.log
```

When a paired or worn ring is quiet, `pi-watch-summary` also prints
`raw_near_mfg` and `raw_near_addr` for the strongest nearby manufacturer
payloads seen by the raw scanner. If the test area is isolated and one of those
payloads is plausibly the ring, rerun `pi-rpa-read --manufacturer-hex HEX` as a
manual target. Do not use this against unrelated nearby devices.

If BlueZ sees a bonded identity address but does not issue an HCI connection,
the lower-level raw-RPA loop can watch `btmon`, connect to the current
resolvable private address, and then run a safe probe:

```bash
PYTHONPATH=src /usr/bin/python3 scripts/pi-oura-raw-rpa-read-loop.py \
  --identity-address AA:BB:CC:DD:EE:FF \
  --scan-seconds 300 \
  --connect-timeout 12 \
  --read-timeout 20 \
  --response-timeout 2.5
```

For app-free local-key provisioning experiments on a reset/ready-to-pair ring:

```bash
uv run oura-ring4-ble pi-auth-read \
  --scan-seconds 30 \
  --response-timeout 6 \
  --live-hr-seconds 20 \
  --meditation-hr-probe \
  --meditation-duration-minutes 1 \
  --meditation-listen-seconds 60 \
  --state-path state/ring-auth-key.json
```

The state file contains the locally generated raw auth key and is ignored by
git. Do not publish it.

For a setup-state ring that is rotating resolvable private addresses, use the
raw-RPA reader. It prints a parsed JSON summary and exits non-zero when the
`read_result` is only an error shell with no firmware, battery, auth, feature,
or event payloads:

```bash
uv run oura-ring4-ble pi-rpa-read \
  --stream-probes firmware,battery,auth_nonce,live_hr_probe
```

For a hands-on session where a person is physically toggling or wearing the
ring, use the foreground manual reader. It prints a compact live terminal
summary while writing full raw JSONL to a timestamped log, updates
`logs/current-pi-manual-read.log` and
`logs/current-pi-bluez-read-result.log`, and can be stopped with Ctrl-C. It
does not send the factory-reset probe.

```bash
scripts/pi-manual-ring-read.sh

SCAN_SECONDS=60 scripts/pi-manual-ring-read.sh
EMIT_ALL_MANUFACTURER_LINES=1 scripts/pi-manual-ring-read.sh
CONSOLE_VERBOSE=1 scripts/pi-manual-ring-read.sh
CONSOLE_MODE=raw scripts/pi-manual-ring-read.sh
CONSOLE_MODE=quiet scripts/pi-manual-ring-read.sh
```

On hosts where `btmgmt find` starts but `bluetoothctl`/BlueZ discovery state is
stale or where `btmon` is the only reliable evidence source, skip the `btmgmt`
phase and enable raw LE scanning directly:

```bash
uv run oura-ring4-ble pi-rpa-read \
  --scan-backend hci \
  --stream-probes setup_snapshot,daytime_hr_latest,resting_hr_latest,live_hr_probe
```

If the scanner repeatedly sees connectable JouZen/Oura RPAs but raw HCI
connection attempts time out before any `read_result`, shorten each attempt and
try the alternate backend before restarting Bluetooth:

```bash
uv run oura-ring4-ble pi-rpa-read \
  --scan-backend hci \
  --connect-timeout 8 \
  --connect-fallback-backend hcitool-lecc \
  --le-create-conn-min-interval 0x18 \
  --le-create-conn-max-interval 0x28 \
  --le-create-supervision-timeout 0x258 \
  --stream-probes firmware,auth_nonce,product_info_all,battery
```

`scripts/pi-zeroauth-chase.sh` uses that faster fallback profile by default and
updates both `logs/current-pi-zeroauth-chase.log` and
`logs/current-pi-bluez-read-result.log` so `pi-watch-summary` follows the live
chase run.

To force an explicit BlueZ pairing attempt after the raw HCI connection, skip
BlueZ's extra `Device1.Connect()` call and register an auto-confirm agent:

```bash
uv run oura-ring4-ble pi-rpa-read \
  --stream-probes setup_snapshot,daytime_hr_latest,resting_hr_latest,live_hr_probe \
  --no-stream-connect \
  --stream-pair \
  --stream-auto-confirm-agent \
  --stream-agent-capability DisplayYesNo
```

For direct BlueZ reads against an existing Device1 object:

```bash
uv run oura-ring4-ble pi-zeroauth-read \
  --probes firmware,battery,auth_nonce,live_hr_probe
```

The lower-level BlueZ stream script can send the observed factory-reset request
as an explicit probe:

```bash
PYTHONPATH=src /usr/bin/python3 scripts/pi-bluez-zeroauth-stream.py \
  --probes factory_reset \
  --read-result-on-probes
```

For setup-state pairing diagnostics, the raw SMP probe can stop bluetoothd,
connect directly with HCI, inject selected SMP Pairing Requests, capture btmon,
and restore bluetoothd afterward:

```bash
uv run oura-ring4-ble pi-smp-probe \
  --variants display_yesno_bond_sc_mitm_ct2_keys,display_only_bond_sc_mitm_ct2_keys,keyboard_only_bond_sc_mitm_ct2_keys,no_input_output_bond_sc_mitm_ct2_keys

sudo -E /usr/bin/python3 scripts/pi-oura-raw-smp-probe.py \
  --stop-bluetoothd \
  --variants connect_only

sudo -E /usr/bin/python3 scripts/pi-oura-raw-smp-probe.py \
  --stop-bluetoothd \
  --variants legacy_no_bond_no_keys,sc_no_bond_no_keys

sudo -E /usr/bin/python3 scripts/pi-oura-raw-smp-probe.py \
  --stop-bluetoothd \
  --own-address-type random \
  --pre-smp-delay-seconds 0.5 \
  --variants bond_sc_no_mitm_keys,display_yesno_bond_sc_mitm_ct2_keys
```

## Rust Monitors And Linux Builds

Build and test:

```bash
cargo test
cargo build --bin oura-ring4-keepalive
cargo build --bin oura-ring4-native-read
```

On Linux, build natively for the current machine:

```bash
cargo build --release --bin oura-ring4-keepalive
target/release/oura-ring4-keepalive --help
```

Run the macOS keepalive monitor in the foreground:

```bash
target/debug/oura-ring4-keepalive \
  --heartbeat 30 \
  --connect-timeout 30 \
  --property-timeout 3 \
  --scan-refresh 90 \
  --read-cooldown 30
```

Run the native macOS reader:

```bash
target/debug/oura-ring4-native-read \
  --scan-only \
  --timeout 90 \
  --connect-timeout 30 \
  --connect-options \
  --scan-heartbeat 10 \
  --verbose
```

Build a Linux keepalive binary in Docker. Use `--platform` for explicit cross-
architecture builds, or pass `--host` and the script will detect the remote
Linux architecture with `uname -m` before building:

```bash
scripts/build-linux-keepalive.sh --platform linux/amd64 --no-deploy
scripts/build-linux-keepalive.sh --platform linux/arm64 --no-deploy
scripts/build-linux-keepalive.sh --host user@linux-amd64-host
scripts/build-linux-keepalive.sh --host user@linux-arm64-host
```

`scripts/build-pi-keepalive.sh` remains as a compatibility wrapper for
`--platform linux/arm64`.

## Public-Release Hygiene

Before publishing logs or captures from your own hardware, check for:

- Raw auth keys or `state/ring-auth-key.json`
- Device identity addresses and resolvable private addresses
- Personal hostnames, usernames, local paths, and IP addresses
- APKs, decompiled APK output, or app assets
- Social-media provenance or third-party media/source material

This repository’s `.gitignore` excludes common local captures, build outputs,
state files, APK artifacts, and logs.
