# Protocol Notes

These notes describe the public, implementation-oriented protocol map used by
this repository. They combine live BLE observations from personally owned
hardware, public protocol references, and static-analysis facts summarized in
[APK Static-Analysis Findings](apk-findings.md).

No APKs, decompiled app source, auth keys, logs, third-party media, or private
device identifiers are included in this repository.

## Transport

Observed Ring 4 BLE transport:

```text
Company identifier: 0x02B2
Service UUID:       98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write UUID:         98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notify/read UUID:   98ed0003-a541-11e4-b6a0-0002a5d5c51b
```

Packet frame:

```text
uint8 tag
uint8 payload_length
bytes payload
```

Numeric payload fields observed so far are little-endian.

## Safe Read Requests

| Name | Request | Response | Notes |
| --- | --- | --- | --- |
| Firmware | `08 00` | `09` | API, firmware, bootloader, BLE stack, MAC fragment |
| Battery | `0c 00` | `0d` | Percent, charging progress, voltage/status fields |
| Auth nonce | `2f 01 2b` | `2f 10 2c ...` | 15-byte nonce |
| Events | `10 09 <u32 start> <u8 max> ff ff ff ff` | event packets then `11` | Raw event walk |
| Factory reset | `1a 00` | `1b 01 <status>` | Destructive; use only on owned hardware |

## Auth And Provisioning

Auth is a challenge-response flow:

```text
2f 01 2b                      request nonce
2f 10 2c <15-byte nonce>      nonce response
2f 11 2d <encrypted nonce>    authenticate
2f .. 2e <status>             auth response
```

The encrypted nonce is AES-128 ECB with PKCS#7-compatible padding over the
15-byte nonce. The key is a local 16-byte ring auth key.

Fresh local-key provisioning uses:

```text
24 10 <16-byte key>           set auth key
25 01 <status>                set-auth-key status
```

Known statuses:

```text
00 success
05 production_tests_missing
```

The provisioning script writes state to `state/ring-auth-key.json` by default.
That file is ignored by git and must not be published.

Live setup-state observations:

- The ready-to-pair/setup advertisement currently uses Oura manufacturer data
  `04 62 1b 01` with the Ring 4 vendor service UUID.
- During one phone-app restricted-mode/factory-reset attempt, a passive
  scan-only Linux watcher saw an initial `04 60 1b 01` advertisement, then a
  burst of `04 67 1b 01` advertisements with the Ring 4 vendor service UUID.
  Heartbeat counters recorded 16 `04 60 1b 01` advertisement events and 51
  `04 67 1b 01` events in that window. Treat these labels as state hints:
  they are useful for scanner targeting, but the bit meanings are not decoded.
- In a 180-second paired-and-worn passive scan, the same environment saw 6,221
  total advertisements and only two Oura advertisements. Both were
  `04 60 1b 01` with the Ring 4 vendor service UUID, and no `04 67 1b 01`
  burst appeared. In practice, worn/paired state is much quieter than
  setup/reset state and should not be treated as proof that scanning is broken.
- In a later 300-second paired-and-worn targeted scan, the ring again only
  emitted two `04 60 1b 01` advertisements. A GATT attempt against that payload
  timed out at the connect stage. A second 300-second scan that waited for
  `04 65 1b 01`, `04 66 1b 01`, or `04 67 1b 01` saw no matching connectable
  state. Use the connectable-hint filter when the goal is a read attempt rather
  than passive presence detection.
- Setup-state service discovery exposed the standard Generic Access
  characteristics for Device Name, Appearance, Peripheral Preferred Connection
  Parameters, Central Address Resolution, and Resolvable Private Address Only.
  It also exposed Oura vendor characteristics `98ed0002` through `98ed0006`
  plus `00060001-f8ce-11e4-abf4-0002a5d5c51b`.
- On the current setup-state ring, reads of both standard Generic Access
  characteristics and the Oura notify/read characteristic returned ATT
  `Unlikely Error (0x0e)` and then disconnected. Treat service discovery as the
  only unauthenticated GATT proof available before the ring accepts pairing.
- Matrix probes that skipped earlier disconnect triggers showed the same ATT
  `Unlikely Error (0x0e)` protection on `98ed0004`, `98ed0005`, `98ed0006`,
  and `00060001-f8ce-11e4-abf4-0002a5d5c51b` notifications. A write-only
  probe against `98ed0002` dropped before any packet response. So far, no Oura
  vendor characteristic has produced unauthenticated setup-state packet data.
- A one-connection packet probe that skipped standard GAP reads reached
  `start_notify` on `98ed0003`, then the setup-state ring returned ATT
  `Unlikely Error (0x0e)`. Standard GAP reads are therefore not the only
  trigger; the primary Oura notify channel itself is protected in setup state.
- Linux can discover the setup-state GATT services at low ATT security, but the
  Oura notify characteristic can reject subscription with ATT `0x0e` and the
  write path can immediately become `Not connected` unless the link is accepted
  by the ring.
- Direct writes against setup-state GATT can return ATT
  `Insufficient Encryption (0x0f)`. BlueZ then initiates SMP pairing; the
  setup-state test ring replied `Pairing Failed` reason `0x08` and disconnected.
- BlueZ `Device1.Pair()` sends SMP pairing requests with bonding enabled. On
  the current setup-state test ring, the ring rejected both SC/no-MITM and
  legacy/no-MITM bonding requests with SMP `Pairing Failed` reason `0x08`
  before any passkey/confirmation agent callback.
- Disabling BR/EDR removed CTKD/link-key distribution from the SMP request
  (`EncKey Sign` / `EncKey IdKey Sign` instead of LinkKey-bearing
  distributions), but the setup-state ring still rejected bonding with SMP
  reason `0x08`.
- Enabling controller privacy changed the central own address type to random,
  but the ring disconnected during feature exchange before SMP pairing began.
- With bluetoothd stopped and raw HCI ACL injection, the setup-state test ring
  also rejected no-bond SMP Pairing Requests with reason `0x08` for both legacy
  pairing (`authreq 0x00`, no key distribution) and Secure Connections
  (`authreq 0x08`, no key distribution). This suggests the rejection is not
  only a BlueZ bonding/CTKD shape problem.
- Additional raw SMP probes against the setup-state test ring rejected legacy
  bonding, SC bonding, MITM, CT2, LinkKey-bearing, and OOB-present request
  variants with the same `0x08` reason when the central used its public address.
- A connect-only raw HCI control with the central public address stayed up until
  local disconnect (`0x16`), which confirms the raw link can be held without
  BlueZ GATT involvement.
- The same connect-only control with a generated static-random central address
  remote-disconnected with HCI reason `0x15` (`Remote Device Terminated due to
  Power Off`) before any SMP packet was sent. Random central address behavior is
  therefore not evidence of pairing progress by itself.
- Adding a 0.5s delay before sending a public-address SMP Pairing Request did
  not change the rejection behavior; the setup-state test ring still returned
  SMP `Pairing Failed` reason `0x08`.
- A raw-HCI RPA connection followed by explicit BlueZ `Device1.Pair()` with a
  `DisplayYesNo` auto-confirm agent did reach an SMP Pairing Request with
  DisplayYesNo, MITM, SC, and CT2 (`authreq 0x2d`), but the setup-state ring
  still rejected it with reason `0x08`. This rules out the previous
  NoInputNoOutput default agent as the sole blocker.
- Raw HCI injection of CT2/MITM/bonding pairing requests with DisplayOnly,
  KeyboardOnly, and NoInputNoOutput IO capabilities also produced SMP
  `Pairing Failed` reason `0x08`. Together with the DisplayYesNo and
  KeyboardDisplay cases above, this makes the setup-state rejection look
  independent of the central IO-capability branch for public-address connects.

## Feature Controls

Feature IDs, feature modes, subscription modes, feature parameters, Daytime HR,
realtime measurements, and ring mode packets are documented in
[APK Static-Analysis Findings](apk-findings.md) and implemented in
`src/oura_ring4_ble/protocol.py`.

Most relevant Daytime HR packet sequence:

```text
2f 03 22 02 03                daytime_hr connected_live
2f 03 26 02 02                daytime_hr latest subscription
2f 02 24 02                   get daytime_hr latest values
```

Meditation/on-demand measurement probes:

```text
2f 03 29 02 01                daytime_hr meditation duration = 1 minute
2f 03 22 02 02                daytime_hr requested mode
06 07 00 02 00 00 01 00 0a    legacy on-demand realtime, 1 minute, delay 10
06 04 00 00 00 00             disable realtime measurement
```

## Event Decoding

The event parser names many event/debug tags, keeps raw payload hex for fields
that are not yet confirmed, and decodes a conservative set of stable binary
payload layouts:

- `0x42` time sync: epoch seconds and timezone offset.
- `0x45` / `0x53` state and wear status bytes.
- `0x46`, `0x69`, `0x75` temperature samples and periods.
- `0x4a` PPG amplitude.
- `0x5d` HRV byte-pair samples.
- `0x60`, `0x6e`, `0x71` IBI/amplitude event records with derived BPM
  estimates.
- `0x6d` measurement-quality 24-bit signed samples.
- `0x6f` / `0x7b` SpO2 sample and stable-value fields.
- `0x80` green IBI quality samples.

Known HR-adjacent event names include:

```text
62 on_demand_meas
65 on_demand_session
6c feature_session
71 green_ibi_and_amplitude_event
73 ehr_trace_event
74 ehr_acm_intensity_event
80 green_ibi_quality_event
```

Open work:

- Capture and verify live HR-bearing notifications while worn.
- Confirm which packets transition the ring into the live measurement session
  across firmware versions.
- Decode on-demand measurement payload tag `0x05`.
- Decode more event payload fields without overfitting to one user's logs.

## Implementation Pointers

- `src/oura_ring4_ble/protocol.py`: packet builders/parsers.
- `scripts/pi-oura-provision-auth-key.py`: Linux BlueZ pairing/provisioning and
  live-HR probe flow.
- `scripts/pi-bluez-zeroauth-stream.py`: broad BlueZ stream/probe runner.
- `scripts/pi-oura-raw-rpa-read-loop.py`: connect to current RPAs and hand off
  to the stream reader.
- `scripts/pi-oura-raw-smp-probe.py`: stop bluetoothd, inject raw SMP pairing
  variants, capture btmon, and restore bluetoothd.
- `scripts/pi-zeroauth-event-catalog.py`: offline event cataloging from local
  JSONL logs.
- `tests/test_protocol.py`: protocol packet examples and parser coverage.
