# APK Static-Analysis Findings

These notes summarize protocol facts inferred from static analysis of an Oura
Android APK plus live BLE behavior. They intentionally do not include APK files,
decompiled source, app assets, third-party media, or copied proprietary code.

The goal is to record interoperability facts that are useful for implementing a
local BLE console against personally owned hardware.

## Method

Useful Android classes identified during static analysis:

```text
com/ouraring/ourakit/internal/Constants
com/ouraring/ourakit/operations/GetAuthNonce
com/ouraring/ourakit/operations/Authenticate
com/ouraring/ourakit/operations/AuthResponse
com/ouraring/ourakit/operations/SetAuthKey
com/ouraring/ourakit/operations/SetFeatureMode
com/ouraring/ourakit/operations/SetFeatureSubscription
com/ouraring/ourakit/operations/SetFeatureParameters
com/ouraring/ourakit/operations/GetFeatureLatestValues
com/ouraring/ourakit/operations/SetRealtimeMeasurements
com/ouraring/ourakit/operations/SetRingMode
com/ouraring/ourakit/domain/FeatureMode
com/ouraring/ourakit/domain/SubscriptionMode
com/ouraring/ourakit/domain/RealTimeMeasurementType
com/ouraring/oura/data/device/ring/f2
com/ouraring/oura/data/device/ring/o1
com/ouraring/oura/data/device/ring/c2
com/ouraring/ringeventparser/data/RingEventType
com/ouraring/ringeventparser/data/RawEventTypes
```

Only facts needed to build packet encoders/decoders are recorded here.

## BLE Constants

```text
Company identifier: 0x02B2
Service UUID:       98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write UUID:         98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notify/read UUID:   98ed0003-a541-11e4-b6a0-0002a5d5c51b
CCCD UUID:          00002902-0000-1000-8000-00805f9b34fb
```

Packet framing:

```text
tag: uint8
payload_length: uint8
payload: bytes[payload_length]
```

Numeric fields observed so far are little-endian.

## Authentication And Local-Key Provisioning

The APK has a fresh-ring path that generates a local 16-byte key, writes it to
the ring, stores it locally, and then authenticates with a nonce challenge.

Get auth nonce:

```text
request:  2f 01 2b
response: 2f 10 2c <15-byte nonce>
```

Authenticate:

```text
request:  2f 11 2d <16-byte encrypted nonce>
response: 2f ?? 2e <status>
```

Encryption:

```text
AES/ECB/PKCS5Padding
key: 16-byte local auth key
plaintext: 15-byte nonce
ciphertext: 16 bytes
```

Auth response status:

```text
00 success
01 authentication_error
02 in_factory_reset
03 not_original_onboarded_device
```

Set auth key:

```text
request:  24 10 <16-byte key>
response: 25 01 <status>
```

SetAuthKey status:

```text
00 success
05 production_tests_missing
```

The app treats both `00` and `05` as operation completion, but this repo logs
`05` distinctly because it is not the normal success code.

Production key generation observed in the APK:

```text
UUID.randomUUID()
16-byte little-endian buffer:
  putLong(uuid.mostSignificantBits)
  putLong(uuid.leastSignificantBits)
```

The equivalent helper is `protocol.generate_auth_key()`.

## Feature Capability IDs

```text
00 background_dfu
01 research_data
02 daytime_hr
03 exercise_hr
04 spo2
05 bundling
06 encrypted_api
07 tap_to_tag
08 resting_hr
09 app_auth
0a ble_mode
0b real_steps
0c experimental
0d cva_ppg_sampler
0e charging_control
0f ambient_light
10 special_feature
11 raw_data_sampler
12 atlas
16 long_events
```

## Feature Modes And Subscriptions

Feature mode values:

```text
00 off
01 automatic
02 requested
03 connected_live
```

Subscription mode values:

```text
00 off
01 state
02 latest
04 feature_specific_data
```

Set feature mode:

```text
request:  2f 03 22 <feature_id> <mode>
response: 2f 03 23 <feature_id> <result>
```

Set feature subscription:

```text
request:  2f 03 26 <feature_id> <subscription_mode>
response: 2f 03 27 <feature_id> <result>
```

Feature request results:

```text
00 success
01 not_supported
02 not_available
03 not_in_finger
04 message_too_short
05 low_battery
```

## Feature Parameters

Feature-parameter writes are extended `0x2f` operations:

```text
request:  2f <len> 29 <feature_id> <feature_config>
response: 2f 03 2a <feature_id> <result>
```

Daytime-HR meditation parameters:

```text
feature_id: 02
config: one byte duration in minutes, clamped to 0..255
start 1 minute: 2f 03 29 02 01
stop/reset:      2f 03 29 02 00
success:         2f 03 2a 02 00
```

Observed app-level meditation control shape:

```text
startMeditationMeasurement(minutes):
  set Daytime HR feature parameters to minutes
  setFeatureMode(daytime_hr, requested)

stopMeditationMeasurement():
  setFeatureMode(daytime_hr, off)
  set Daytime HR feature parameters to 0
  setFeatureMode(daytime_hr, automatic)
```

## Daytime HR

Connected-live subscription flow:

```text
setFeatureMode(daytime_hr, connected_live)
setSubscriptionMode(daytime_hr, latest)
```

Packets:

```text
2f 03 22 02 03
2f 03 26 02 02
```

Get latest feature values:

```text
request:  2f 02 24 <feature_id>
response: 2f ... 25 <feature_id> <result> <status> <state> ...
```

For Daytime HR latest-value responses:

```text
response[9:11]  little-endian int16 = IBI ms
response[11:15] little-endian int32 = timestamp
response[15:17] little-endian int16 = duration/status-like field
response[17]    quality/flag byte when present
```

The parser reports an estimated BPM as `round(60000 / ibi_ms, 1)` when IBI is
positive.

## Realtime Measurements

Realtime measurement control uses legacy tag `0x06`, with status response
`0x07`.

Enabled request payload:

```text
tag: 06
payload length: 07
payload:
  uint32 measurement_bitmask
  uint16 maximum_duration_minutes
  uint8 delay
```

Measurement types:

```text
ON_DEMAND bitmask = 0x00000200, response tag 0x05
ACM       bitmask = 0x00000020, response tag 0x33
```

On-demand 1-minute start:

```text
06 07 00 02 00 00 01 00 0a
```

Disable realtime measurement:

```text
06 04 00 00 00 00
```

Status response:

```text
07 01 <status>
00 success
```

The Android realtime event parser path found during static analysis directly
handled ACM response tag `0x33`. The on-demand tag `0x05` should be logged raw
until more live captures identify its payload shape.

## Ring Mode

Ring mode values:

```text
00 normal
01 fast_hr_measurement
02 deep_sleep
```

Set ring mode uses a 32-bit little-endian value:

```text
normal: 31 04 00 00 00 00
fast:   31 04 01 00 00 00
```

## Event Tags

Event tags seen in public notes, APK symbols, or live captures:

```text
41 ring_start
42 time_sync
43 debug_event
44 ibi_event
45 state_change
46 temp_event
47 motion_event
53 wear_event
55 sleep_hr
5d hrv_event
60 ibi_and_amplitude_event
61 debug_data
62 on_demand_meas
65 on_demand_session
6c feature_session
6d meas_quality_event
6e spo2_ibi_and_amplitude_event
6f spo2_event
70 spo2_smoothed_event
71 green_ibi_and_amplitude_event
73 ehr_trace_event
74 ehr_acm_intensity_event
75 sleep_temp_event
77 spo2_dc_event
80 green_ibi_quality_event
82 scan_start
83 scan_end
86 aohr_event
87 atlas_metadata
88 atlas_raw_bioz_data
8b spo2_r_pi_event
```

Most event payloads are still only partially decoded. The current parser keeps
raw payload hex and adds conservative labels where repeated captures support an
interpretation.

## Implementation Pointers

Implemented in `src/oura_ring4_ble/protocol.py`:

```text
generate_auth_key()
build_set_auth_key_request()
build_get_auth_nonce_request()
build_authenticate_request()
build_set_feature_mode_request()
build_set_feature_subscription_request()
build_set_daytime_hr_meditation_parameters_request()
build_get_feature_latest_values_request()
build_set_realtime_measurements_request()
build_disable_realtime_measurements_request()
build_set_ring_mode_request()
parse_response()
```

Focused tests live in `tests/test_protocol.py` and
`tests/test_pi_oura_provision_auth_key.py`.
