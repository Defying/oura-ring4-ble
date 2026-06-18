use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use btleplug::api::{
    Central, CentralEvent, CharPropFlags, Manager as _, Peripheral as _, ScanFilter,
    ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use clap::Parser;
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

const OURA_SERVICE_UUID: Uuid = Uuid::from_u128(0x98ed0001_a541_11e4_b6a0_0002a5d5c51b);
const OURA_WRITE_UUID: Uuid = Uuid::from_u128(0x98ed0002_a541_11e4_b6a0_0002a5d5c51b);
const OURA_NOTIFY_UUID: Uuid = Uuid::from_u128(0x98ed0003_a541_11e4_b6a0_0002a5d5c51b);

const TAG_GET_FIRMWARE: u8 = 0x08;
const TAG_FIRMWARE_RESPONSE: u8 = 0x09;
const TAG_GET_BATTERY: u8 = 0x0c;
const TAG_BATTERY_RESPONSE: u8 = 0x0d;

#[derive(Debug, Parser)]
#[command(
    name = "oura-ring4-keepalive",
    about = "Continuously monitor an Oura Ring 4 BLE advertisement stream and try safe reads."
)]
struct Args {
    /// Exit after this many seconds. Defaults to running until Ctrl-C.
    #[arg(long)]
    duration: Option<u64>,

    /// Print heartbeat JSON every N seconds.
    #[arg(long, default_value_t = 30)]
    heartbeat: u64,

    /// Minimum seconds between read attempts for the same CoreBluetooth address.
    #[arg(long, default_value_t = 45)]
    read_cooldown: u64,

    /// Timeout for each connect/discover/read step.
    #[arg(long, default_value_t = 20)]
    connect_timeout: u64,

    /// Timeout for metadata lookups on each BLE event.
    #[arg(long, default_value_t = 5)]
    property_timeout: u64,

    /// Re-issue the BLE scan request every N seconds.
    #[arg(long, default_value_t = 120)]
    scan_refresh: u64,

    /// Inspect currently-known peripherals every N seconds. 0 disables sweeps.
    #[arg(long, default_value_t = 0)]
    sweep_interval: u64,

    /// Inspect generic device discovered/updated events through peripheral properties.
    #[arg(long)]
    inspect_device_events: bool,

    /// Only monitor advertisements; do not connect or write safe request packets.
    #[arg(long)]
    no_read: bool,

    /// Print every duplicate Oura advertisement, not just first/changed sightings.
    #[arg(long)]
    verbose_adverts: bool,

    /// Print diagnostic events for non-Oura traffic and inspection failures.
    #[arg(long)]
    trace_events: bool,
}

#[derive(Debug, Clone)]
struct OuraAdvertisement {
    address: String,
    name: Option<String>,
    rssi: Option<i16>,
    service_uuids: Vec<Uuid>,
    manufacturer_data: HashMap<u16, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Packet {
    tag: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Default, Serialize)]
struct MonitorStats {
    total_events: u64,
    device_events: u64,
    other_events: u64,
    sweep_runs: u64,
    sweep_peripherals: u64,
    property_successes: u64,
    property_errors: u64,
    non_oura_inspections: u64,
    oura_advertisements: u64,
    read_attempts: u64,
    read_successes: u64,
    read_errors: u64,
    last_device_event: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct PacketJson {
    tag: String,
    payload_length: usize,
    payload_hex: String,
    raw_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let manager = Manager::new().await.context("create BLE manager")?;
    let adapters = manager.adapters().await.context("list BLE adapters")?;
    let adapter = adapters
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Bluetooth adapters found"))?;

    emit(
        "startup",
        json!({ "adapter": adapter.adapter_info().await.ok() }),
    );
    monitor(adapter, args).await
}

async fn monitor(adapter: Adapter, args: Args) -> Result<()> {
    let mut events = adapter.events().await.context("open BLE event stream")?;
    adapter
        .start_scan(ScanFilter::default())
        .await
        .context("start BLE scan")?;

    let started = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut last_scan_refresh = Instant::now();
    let mut last_sweep = Instant::now();
    let mut last_seen: HashMap<String, String> = HashMap::new();
    let mut last_read_attempt: HashMap<String, Instant> = HashMap::new();
    let mut stats = MonitorStats::default();

    loop {
        if let Some(duration) = args.duration {
            if started.elapsed() >= Duration::from_secs(duration) {
                emit("shutdown", json!({ "reason": "duration_elapsed" }));
                return Ok(());
            }
        }

        let heartbeat_due = last_heartbeat.elapsed() >= Duration::from_secs(args.heartbeat);
        if heartbeat_due {
            last_heartbeat = Instant::now();
            emit(
                "heartbeat",
                json!({
                    "uptime_seconds": started.elapsed().as_secs(),
                    "known_oura_devices": last_seen.len(),
                    "stats": &stats,
                }),
            );
        }

        let scan_refresh_due =
            last_scan_refresh.elapsed() >= Duration::from_secs(args.scan_refresh);
        if scan_refresh_due {
            last_scan_refresh = Instant::now();
            match timeout(
                Duration::from_secs(args.property_timeout),
                adapter.start_scan(ScanFilter::default()),
            )
            .await
            {
                Ok(Ok(())) => emit("scan_refresh", json!({})),
                Ok(Err(error)) => emit("scan_refresh_error", json!({ "error": error.to_string() })),
                Err(_) => emit(
                    "scan_refresh_error",
                    json!({ "error": "scan refresh timed out" }),
                ),
            }
        }

        let sweep_due = args.sweep_interval > 0
            && last_sweep.elapsed() >= Duration::from_secs(args.sweep_interval);
        if sweep_due {
            last_sweep = Instant::now();
            sweep_peripherals(
                &adapter,
                &args,
                &mut last_seen,
                &mut last_read_attempt,
                &mut stats,
            )
            .await?;
        }

        tokio::select! {
            maybe_event = events.next() => {
                if let Some(event) = maybe_event {
                    handle_event(
                        &adapter,
                        &args,
                        event,
                        &mut last_seen,
                        &mut last_read_attempt,
                        &mut stats,
                    ).await?;
                } else {
                    bail!("BLE event stream ended");
                }
            }
            _ = sleep(Duration::from_millis(250)) => {}
            _ = tokio::signal::ctrl_c() => {
                emit("shutdown", json!({ "reason": "ctrl_c" }));
                return Ok(());
            }
        }
    }
}

async fn handle_event(
    adapter: &Adapter,
    args: &Args,
    event: CentralEvent,
    last_seen: &mut HashMap<String, String>,
    last_read_attempt: &mut HashMap<String, Instant>,
    stats: &mut MonitorStats,
) -> Result<()> {
    stats.total_events += 1;
    let kind = central_event_kind(&event);
    match event {
        CentralEvent::DeviceDiscovered(id)
        | CentralEvent::DeviceUpdated(id)
        | CentralEvent::DeviceConnected(id)
        | CentralEvent::DeviceDisconnected(id) => {
            stats.device_events += 1;
            stats.last_device_event = Some(kind.to_string());
            if !args.inspect_device_events {
                if args.trace_events {
                    emit("ble_event", json!({ "kind": kind }));
                }
                return Ok(());
            }
            let property_timeout = Duration::from_secs(args.property_timeout);
            let peripheral = timeout(property_timeout, adapter.peripheral(&id))
                .await
                .context("get peripheral timed out")?
                .context("get peripheral")?;
            inspect_peripheral(
                adapter,
                peripheral,
                args,
                "event",
                last_seen,
                last_read_attempt,
                stats,
            )
            .await
        }
        CentralEvent::ManufacturerDataAdvertisement {
            id,
            manufacturer_data,
        } => {
            stats.other_events += 1;
            stats.last_device_event = Some(kind.to_string());
            if !manufacturer_data_has_oura(&manufacturer_data) {
                return Ok(());
            }
            let property_timeout = Duration::from_secs(args.property_timeout);
            let peripheral = timeout(property_timeout, adapter.peripheral(&id))
                .await
                .context("get peripheral timed out")?
                .context("get peripheral")?;
            let advertisement = OuraAdvertisement {
                address: peripheral.address().to_string(),
                name: None,
                rssi: None,
                service_uuids: Vec::new(),
                manufacturer_data,
            };
            stats.oura_advertisements += 1;
            handle_oura_candidate(
                adapter,
                peripheral,
                args,
                "manufacturer_event",
                advertisement,
                last_seen,
                last_read_attempt,
                stats,
            )
            .await
        }
        CentralEvent::ServicesAdvertisement { id, services } => {
            stats.other_events += 1;
            stats.last_device_event = Some(kind.to_string());
            if !services_has_oura(&services) {
                return Ok(());
            }
            let property_timeout = Duration::from_secs(args.property_timeout);
            let peripheral = timeout(property_timeout, adapter.peripheral(&id))
                .await
                .context("get peripheral timed out")?
                .context("get peripheral")?;
            let advertisement = OuraAdvertisement {
                address: peripheral.address().to_string(),
                name: None,
                rssi: None,
                service_uuids: services,
                manufacturer_data: HashMap::new(),
            };
            stats.oura_advertisements += 1;
            handle_oura_candidate(
                adapter,
                peripheral,
                args,
                "services_event",
                advertisement,
                last_seen,
                last_read_attempt,
                stats,
            )
            .await
        }
        CentralEvent::ServiceDataAdvertisement { id, service_data } => {
            stats.other_events += 1;
            stats.last_device_event = Some(kind.to_string());
            if !service_data_has_oura(&service_data) {
                return Ok(());
            }
            let property_timeout = Duration::from_secs(args.property_timeout);
            let peripheral = timeout(property_timeout, adapter.peripheral(&id))
                .await
                .context("get peripheral timed out")?
                .context("get peripheral")?;
            let advertisement = OuraAdvertisement {
                address: peripheral.address().to_string(),
                name: None,
                rssi: None,
                service_uuids: service_data.keys().copied().collect(),
                manufacturer_data: HashMap::new(),
            };
            stats.oura_advertisements += 1;
            handle_oura_candidate(
                adapter,
                peripheral,
                args,
                "service_data_event",
                advertisement,
                last_seen,
                last_read_attempt,
                stats,
            )
            .await
        }
        other => {
            stats.other_events += 1;
            if args.trace_events {
                emit("ble_event", json!({ "kind": central_event_kind(&other) }));
            }
            Ok(())
        }
    }
}

async fn sweep_peripherals(
    adapter: &Adapter,
    args: &Args,
    last_seen: &mut HashMap<String, String>,
    last_read_attempt: &mut HashMap<String, Instant>,
    stats: &mut MonitorStats,
) -> Result<()> {
    stats.sweep_runs += 1;
    let property_timeout = Duration::from_secs(args.property_timeout);
    let peripherals = match timeout(property_timeout, adapter.peripherals()).await {
        Ok(Ok(peripherals)) => peripherals,
        Ok(Err(error)) => {
            stats.property_errors += 1;
            stats.last_error = Some(format!("sweep peripherals: {error}"));
            if args.trace_events {
                emit("sweep_error", json!({ "error": error.to_string() }));
            }
            return Ok(());
        }
        Err(_) => {
            stats.property_errors += 1;
            stats.last_error = Some("sweep peripherals timed out".to_string());
            if args.trace_events {
                emit(
                    "sweep_error",
                    json!({ "error": "peripheral sweep timed out" }),
                );
            }
            return Ok(());
        }
    };
    stats.sweep_peripherals += peripherals.len() as u64;
    if args.trace_events {
        emit("sweep", json!({ "peripheral_count": peripherals.len() }));
    }
    for peripheral in peripherals {
        inspect_peripheral(
            adapter,
            peripheral,
            args,
            "sweep",
            last_seen,
            last_read_attempt,
            stats,
        )
        .await?;
    }
    Ok(())
}

async fn inspect_peripheral(
    adapter: &Adapter,
    peripheral: Peripheral,
    args: &Args,
    source: &str,
    last_seen: &mut HashMap<String, String>,
    last_read_attempt: &mut HashMap<String, Instant>,
    stats: &mut MonitorStats,
) -> Result<()> {
    let property_timeout = Duration::from_secs(args.property_timeout);
    let advertisement = match oura_advertisement(&peripheral, property_timeout).await {
        Ok(Some(advertisement)) => advertisement,
        Ok(None) => {
            stats.property_successes += 1;
            stats.non_oura_inspections += 1;
            return Ok(());
        }
        Err(error) => {
            stats.property_errors += 1;
            stats.last_error = Some(error.to_string());
            if args.trace_events {
                emit(
                    "inspect_error",
                    json!({
                        "source": source,
                        "address": peripheral.address().to_string(),
                        "error": error.to_string(),
                    }),
                );
            }
            return Ok(());
        }
    };
    stats.property_successes += 1;
    stats.oura_advertisements += 1;
    handle_oura_candidate(
        adapter,
        peripheral,
        args,
        source,
        advertisement,
        last_seen,
        last_read_attempt,
        stats,
    )
    .await
}

async fn handle_oura_candidate(
    adapter: &Adapter,
    peripheral: Peripheral,
    args: &Args,
    source: &str,
    advertisement: OuraAdvertisement,
    last_seen: &mut HashMap<String, String>,
    last_read_attempt: &mut HashMap<String, Instant>,
    stats: &mut MonitorStats,
) -> Result<()> {
    let signature = serde_json::to_string(&advertisement_json(&advertisement))?;
    let should_print = args.verbose_adverts
        || last_seen
            .get(&advertisement.address)
            .map(|previous| previous != &signature)
            .unwrap_or(true);
    if should_print {
        emit(
            "advertisement",
            json!({
                "source": source,
                "device": advertisement_json(&advertisement),
            }),
        );
        last_seen.insert(advertisement.address.clone(), signature);
    }

    if args.no_read {
        return Ok(());
    }

    if advertisement.address == "00:00:00:00:00:00" {
        emit(
            "read_skipped",
            json!({
                "address": advertisement.address,
                "reason": "CoreBluetooth event did not expose a connectable peripheral address; use oura-ring4-native-read --scan-only",
            }),
        );
        return Ok(());
    }

    let cooldown = Duration::from_secs(args.read_cooldown);
    let should_read = last_read_attempt
        .get(&advertisement.address)
        .map(|last| last.elapsed() >= cooldown)
        .unwrap_or(true);
    if !should_read {
        return Ok(());
    }
    last_read_attempt.insert(advertisement.address.clone(), Instant::now());
    stats.read_attempts += 1;
    emit(
        "read_attempt",
        json!({
            "address": advertisement.address,
            "timeout_seconds": args.connect_timeout,
        }),
    );

    match read_safe_packets(peripheral, Duration::from_secs(args.connect_timeout)).await {
        Ok(value) => {
            stats.read_successes += 1;
            emit("read_result", value);
        }
        Err(error) => {
            stats.read_errors += 1;
            stats.last_error = Some(error.to_string());
            emit(
                "read_error",
                json!({
                    "address": advertisement.address,
                    "error": error.to_string(),
                }),
            );
        }
    }

    adapter
        .start_scan(ScanFilter::default())
        .await
        .context("restart BLE scan after read attempt")?;
    Ok(())
}

fn central_event_kind(event: &CentralEvent) -> &'static str {
    match event {
        CentralEvent::DeviceDiscovered(_) => "device_discovered",
        CentralEvent::DeviceUpdated(_) => "device_updated",
        CentralEvent::DeviceConnected(_) => "device_connected",
        CentralEvent::DeviceDisconnected(_) => "device_disconnected",
        CentralEvent::ManufacturerDataAdvertisement { .. } => "manufacturer_data_advertisement",
        CentralEvent::ServiceDataAdvertisement { .. } => "service_data_advertisement",
        CentralEvent::ServicesAdvertisement { .. } => "services_advertisement",
        CentralEvent::StateUpdate(_) => "state_update",
    }
}

fn manufacturer_data_has_oura(manufacturer_data: &HashMap<u16, Vec<u8>>) -> bool {
    manufacturer_data
        .iter()
        .any(|(company, data)| is_oura_manufacturer(*company, data))
}

fn services_has_oura(services: &[Uuid]) -> bool {
    services.iter().any(|uuid| *uuid == OURA_SERVICE_UUID)
}

fn service_data_has_oura(service_data: &HashMap<Uuid, Vec<u8>>) -> bool {
    service_data.keys().any(|uuid| *uuid == OURA_SERVICE_UUID)
}

async fn oura_advertisement(
    peripheral: &Peripheral,
    property_timeout: Duration,
) -> Result<Option<OuraAdvertisement>> {
    let Some(properties) = timeout(property_timeout, peripheral.properties())
        .await
        .context("read properties timed out")?
        .context("read properties")?
    else {
        return Ok(None);
    };

    let services = properties.services;
    let manufacturer_data = properties.manufacturer_data;
    let is_oura_service = services.iter().any(|uuid| *uuid == OURA_SERVICE_UUID);
    let is_oura_manufacturer = manufacturer_data
        .iter()
        .any(|(company, data)| is_oura_manufacturer(*company, data));
    let is_oura_name = properties
        .local_name
        .as_deref()
        .map(|name| name.to_ascii_lowercase().contains("oura"))
        .unwrap_or(false);

    if !(is_oura_service || is_oura_manufacturer || is_oura_name) {
        return Ok(None);
    }

    Ok(Some(OuraAdvertisement {
        address: properties.address.to_string(),
        name: properties.local_name,
        rssi: properties.rssi,
        service_uuids: services,
        manufacturer_data,
    }))
}

fn is_oura_manufacturer(company_id: u16, data: &[u8]) -> bool {
    if company_id == 0x02b2 {
        return data.is_empty() || is_oura_manufacturer_payload(data);
    }

    if data.len() >= 2 {
        let company_le = u16::from_le_bytes([data[0], data[1]]);
        let company_be = u16::from_be_bytes([data[0], data[1]]);
        if company_le == 0x02b2 || company_be == 0x02b2 {
            return data.len() == 2 || is_oura_manufacturer_payload(&data[2..]);
        }
    }

    is_oura_manufacturer_payload(data)
}

fn is_oura_manufacturer_payload(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[0] == 0x04 && payload[2] == 0x1b && payload[3] == 0x01
}

fn advertisement_json(advertisement: &OuraAdvertisement) -> Value {
    let manufacturer_data: serde_json::Map<String, Value> = advertisement
        .manufacturer_data
        .iter()
        .map(|(company, data)| (format!("0x{company:04X}"), json!(hex::encode(data))))
        .collect();

    json!({
        "address": advertisement.address,
        "name": advertisement.name,
        "rssi": advertisement.rssi,
        "service_uuids": advertisement
            .service_uuids
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>(),
        "manufacturer_data": manufacturer_data,
    })
}

async fn read_safe_packets(peripheral: Peripheral, step_timeout: Duration) -> Result<Value> {
    timeout(step_timeout, peripheral.connect())
        .await
        .context("connect timed out")?
        .context("connect")?;

    let result = read_safe_packets_connected(&peripheral, step_timeout).await;
    if let Err(error) = timeout(Duration::from_secs(5), peripheral.disconnect()).await {
        emit("disconnect_error", json!({ "error": error.to_string() }));
    }
    result
}

async fn read_safe_packets_connected(
    peripheral: &Peripheral,
    step_timeout: Duration,
) -> Result<Value> {
    timeout(step_timeout, peripheral.discover_services())
        .await
        .context("service discovery timed out")?
        .context("discover services")?;

    let characteristics = peripheral.characteristics();
    let write_char = characteristics
        .iter()
        .find(|characteristic| characteristic.uuid == OURA_WRITE_UUID)
        .or_else(|| {
            characteristics.iter().find(|characteristic| {
                characteristic.properties.contains(CharPropFlags::WRITE)
                    || characteristic
                        .properties
                        .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
            })
        })
        .cloned()
        .ok_or_else(|| anyhow!("Oura write characteristic not found"))?;
    let notify_char = characteristics
        .iter()
        .find(|characteristic| characteristic.uuid == OURA_NOTIFY_UUID)
        .or_else(|| {
            characteristics
                .iter()
                .find(|characteristic| characteristic.properties.contains(CharPropFlags::NOTIFY))
        })
        .cloned()
        .ok_or_else(|| anyhow!("Oura notify characteristic not found"))?;

    timeout(step_timeout, peripheral.subscribe(&notify_char))
        .await
        .context("subscribe timed out")?
        .context("subscribe notify")?;
    let mut notifications = peripheral
        .notifications()
        .await
        .context("open notification stream")?;

    let firmware = request_packet(
        peripheral,
        &write_char,
        &mut notifications,
        build_get_firmware_request(),
        TAG_FIRMWARE_RESPONSE,
        step_timeout,
    )
    .await
    .context("firmware request")?;

    let battery = request_packet(
        peripheral,
        &write_char,
        &mut notifications,
        build_get_battery_request(),
        TAG_BATTERY_RESPONSE,
        step_timeout,
    )
    .await
    .context("battery request")?;

    Ok(json!({
        "address": peripheral.address().to_string(),
        "firmware": packet_json(&firmware),
        "battery": packet_json(&battery),
    }))
}

async fn request_packet(
    peripheral: &Peripheral,
    write_char: &btleplug::api::Characteristic,
    notifications: &mut (impl Stream<Item = ValueNotification> + Unpin),
    request: Vec<u8>,
    expect_tag: u8,
    step_timeout: Duration,
) -> Result<Packet> {
    timeout(
        step_timeout,
        peripheral.write(write_char, &request, WriteType::WithResponse),
    )
    .await
    .context("write timed out")?
    .context("write request")?;

    let deadline = Instant::now() + step_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for response tag 0x{expect_tag:02X}");
        }
        let Some(notification) = timeout(remaining, notifications.next())
            .await
            .context("notification timed out")?
        else {
            bail!("notification stream ended");
        };
        for packet in parse_packets(&notification.value)? {
            if packet.tag == expect_tag {
                return Ok(packet);
            }
            emit(
                "rx_unexpected",
                json!({
                    "characteristic": notification.uuid.to_string(),
                    "packet": packet_json(&packet),
                }),
            );
        }
    }
}

fn build_get_firmware_request() -> Vec<u8> {
    encode_packet(TAG_GET_FIRMWARE, &[])
}

fn build_get_battery_request() -> Vec<u8> {
    encode_packet(TAG_GET_BATTERY, &[])
}

fn encode_packet(tag: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= u8::MAX as usize);
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(tag);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

fn parse_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if offset + 2 > data.len() {
            bail!("truncated packet header at offset {offset}");
        }
        let tag = data[offset];
        let length = data[offset + 1] as usize;
        offset += 2;
        let end = offset + length;
        if end > data.len() {
            bail!(
                "truncated packet payload for tag 0x{tag:02X}: wanted {length}, have {}",
                data.len() - offset
            );
        }
        packets.push(Packet {
            tag,
            payload: data[offset..end].to_vec(),
        });
        offset = end;
    }
    Ok(packets)
}

fn packet_json(packet: &Packet) -> PacketJson {
    PacketJson {
        tag: format!("0x{:02X}", packet.tag),
        payload_length: packet.payload.len(),
        payload_hex: hex::encode(&packet.payload),
        raw_hex: hex::encode(encode_packet(packet.tag, &packet.payload)),
        decoded: decode_packet(packet),
    }
}

fn decode_packet(packet: &Packet) -> Option<Value> {
    match packet.tag {
        TAG_FIRMWARE_RESPONSE => decode_firmware(&packet.payload).ok(),
        TAG_BATTERY_RESPONSE => decode_battery(&packet.payload).ok(),
        _ => None,
    }
}

fn decode_firmware(payload: &[u8]) -> Result<Value> {
    if payload.len() < 12 {
        bail!("firmware payload too short: {}", payload.len());
    }
    let mut decoded = json!({
        "api_version": semver(&payload[0..3])?,
        "firmware_version": semver(&payload[3..6])?,
        "bootloader_version": semver(&payload[6..9])?,
        "bluetooth_stack_version": semver(&payload[9..12])?,
    });
    if payload.len() >= 18 {
        decoded["mac_fragment_hex"] = json!(
            payload[12..18]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        );
    }
    if payload.len() > 18 {
        decoded["extra_hex"] = json!(hex::encode(&payload[18..]));
    }
    Ok(decoded)
}

fn decode_battery(payload: &[u8]) -> Result<Value> {
    if payload.len() < 3 {
        bail!("battery payload too short: {}", payload.len());
    }
    let mut decoded = json!({
        "battery_level_percent": payload[0],
        "charging_progress": payload[1],
        "charging_recommended": payload[2] != 0,
    });
    if payload.len() > 3 {
        decoded["unknown_hex"] = json!(hex::encode(&payload[3..]));
    }
    Ok(decoded)
}

fn semver(data: &[u8]) -> Result<String> {
    if data.len() != 3 {
        bail!("semver needs 3 bytes, got {}", data.len());
    }
    Ok(format!("{}.{}.{}", data[0], data[1], data[2]))
}

fn emit(event: &str, payload: Value) {
    let row = json!({
        "ts_unix_ms": unix_ms(),
        "event": event,
        "payload": payload,
    });
    println!("{row}");
    let _ = io::stdout().flush();
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_safe_requests() {
        assert_eq!(build_get_firmware_request(), vec![0x08, 0x00]);
        assert_eq!(build_get_battery_request(), vec![0x0c, 0x00]);
    }

    #[test]
    fn parses_battery_response() {
        let packet = parse_packets(&hex::decode("0d06640000ffffff").unwrap())
            .unwrap()
            .remove(0);
        let decoded = decode_battery(&packet.payload).unwrap();
        assert_eq!(decoded["battery_level_percent"], 100);
        assert_eq!(decoded["charging_progress"], 0);
        assert_eq!(decoded["charging_recommended"], false);
    }

    #[test]
    fn parses_firmware_response() {
        let packet =
            parse_packets(&hex::decode("0912011201020002010003050004111122223333").unwrap())
                .unwrap()
                .remove(0);
        let decoded = decode_firmware(&packet.payload).unwrap();
        assert_eq!(decoded["api_version"], "1.18.1");
        assert_eq!(decoded["firmware_version"], "2.0.2");
        assert_eq!(decoded["bootloader_version"], "1.0.3");
        assert_eq!(decoded["bluetooth_stack_version"], "5.0.4");
        assert_eq!(decoded["mac_fragment_hex"], "11:11:22:22:33:33");
    }

    #[test]
    fn matches_observed_oura_manufacturer_payloads() {
        assert!(is_oura_manufacturer(0x02b2, &[0x04, 0x60, 0x1b, 0x01]));
        assert!(is_oura_manufacturer(0x02b2, &[0x04, 0x61, 0x1b, 0x01]));
        assert!(is_oura_manufacturer(0x02b2, &[0x04, 0x62, 0x1b, 0x01]));
        assert!(is_oura_manufacturer(
            0xffff,
            &[0xb2, 0x02, 0x04, 0x62, 0x1b, 0x01]
        ));
        assert!(is_oura_manufacturer(
            0xffff,
            &[0xb2, 0x02, 0x04, 0x61, 0x1b, 0x01]
        ));
        assert!(is_oura_manufacturer(0xffff, &[0x04, 0x62, 0x1b, 0x01]));
        assert!(!is_oura_manufacturer(
            0x004c,
            &[0x13, 0x08, 0x4a, 0x68, 0x79]
        ));
    }
}
