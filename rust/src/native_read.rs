use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::Parser;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{ClassType, DeclaredClass, declare_class, msg_send_id, mutability};
use objc2_core_bluetooth::{
    CBAdvertisementDataIsConnectable, CBAdvertisementDataLocalNameKey,
    CBAdvertisementDataManufacturerDataKey, CBAdvertisementDataServiceDataKey,
    CBAdvertisementDataServiceUUIDsKey, CBCentralManager, CBCentralManagerDelegate,
    CBCentralManagerScanOptionAllowDuplicatesKey, CBCharacteristic, CBCharacteristicWriteType,
    CBConnectPeripheralOptionEnableAutoReconnect, CBConnectPeripheralOptionNotifyOnConnectionKey,
    CBConnectPeripheralOptionNotifyOnDisconnectionKey,
    CBConnectPeripheralOptionNotifyOnNotificationKey, CBManagerState, CBPeripheral,
    CBPeripheralDelegate, CBPeripheralState, CBService, CBUUID,
};
use objc2_foundation::{
    NSArray, NSData, NSDate, NSDictionary, NSError, NSMutableDictionary, NSNumber, NSObject,
    NSObjectProtocol, NSRunLoop, NSString, NSUUID,
};
use serde::Serialize;
use serde_json::{Value, json};

const OURA_SERVICE_UUID: &str = "98ed0001-a541-11e4-b6a0-0002a5d5c51b";
const OURA_WRITE_UUID: &str = "98ed0002-a541-11e4-b6a0-0002a5d5c51b";
const OURA_NOTIFY_UUID: &str = "98ed0003-a541-11e4-b6a0-0002a5d5c51b";

const TAG_GET_FIRMWARE: u8 = 0x08;
const TAG_FIRMWARE_RESPONSE: u8 = 0x09;
const TAG_GET_BATTERY: u8 = 0x0c;
const TAG_BATTERY_RESPONSE: u8 = 0x0d;

const DEFAULT_CACHED_ADDRESSES: [&str; 2] = [
    "5CA521A1-BB71-90C4-5DB0-BE0E0E0E4BF4",
    "ED154726-0A41-AEE4-8F4D-B6CE64DB7ED2",
];

#[derive(Debug, Parser)]
#[command(
    name = "oura-ring4-native-read",
    about = "Try safe Oura Ring 4 firmware and battery reads through native CoreBluetooth cached IDs."
)]
struct Args {
    /// CoreBluetooth peripheral UUID to try. Repeat for multiple IDs.
    #[arg(long = "address")]
    addresses: Vec<String>,

    /// Overall timeout per address.
    #[arg(long, default_value_t = 35)]
    timeout: u64,

    /// Timeout for the connection phase.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,

    /// Connection attempts per read cycle before returning an error.
    #[arg(long, default_value_t = 3)]
    attempts: u64,

    /// Print native progress events as JSONL.
    #[arg(long)]
    verbose: bool,

    /// Print every native advertisement callback summary.
    #[arg(long)]
    trace_adverts: bool,

    /// Ask CoreBluetooth to scan only for the Oura service UUID.
    #[arg(long)]
    scan_service_filter: bool,

    /// Pass optional CoreBluetooth connection hints while connecting.
    #[arg(long)]
    connect_options: bool,

    /// Also pass CoreBluetooth's auto-reconnect connection hint.
    #[arg(long)]
    connect_auto_reconnect: bool,

    /// Print scan state and native advertisement counters every N seconds.
    #[arg(long, default_value_t = 30)]
    scan_heartbeat: u64,

    /// Scan for Oura advertisements and connect to the discovered CBPeripheral.
    #[arg(long)]
    scan: bool,

    /// Skip cached UUID attempts and only use native connected-service lookup plus scan.
    #[arg(long)]
    scan_only: bool,

    /// Only retrieve already-connected Oura-service peripherals; do not scan.
    #[arg(long)]
    connected_service_only: bool,

    /// Check already-connected Oura-service peripherals before cached UUIDs; do not scan on miss.
    #[arg(long)]
    connected_service_first: bool,

    /// Keep retrying cached reads instead of exiting after one address cycle.
    #[arg(long)]
    repeat: bool,

    /// Total runtime for repeat mode. Defaults to one address cycle when --repeat is not set.
    #[arg(long)]
    duration: Option<u64>,

    /// Seconds to wait between repeat-mode address cycles.
    #[arg(long, default_value_t = 60)]
    interval: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Packet {
    tag: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct PacketJson {
    tag: String,
    payload_length: usize,
    payload_hex: String,
    raw_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<Value>,
}

#[derive(Debug, Clone)]
struct PendingRequest {
    name: &'static str,
    data: Vec<u8>,
    expect_tag: u8,
}

#[derive(Debug)]
struct NativeState {
    target_address: Option<String>,
    connected_service_lookup: bool,
    scan_on_connected_service_miss: bool,
    verbose: bool,
    trace_adverts: bool,
    scan_service_filter: bool,
    connect_options: bool,
    connect_auto_reconnect: bool,
    connect_timeout: Duration,
    max_attempts: u64,
    attempts: u64,
    state: String,
    state_since: Instant,
    advertisement_events: u64,
    oura_advertisement_events: u64,
    last_advertisement: Option<Value>,
    peripheral: Option<Retained<CBPeripheral>>,
    write_char: Option<Retained<CBCharacteristic>>,
    notify_char: Option<Retained<CBCharacteristic>>,
    device: Option<Value>,
    responses: Vec<PacketJson>,
    pending: VecDeque<PendingRequest>,
    done: bool,
    error: Option<String>,
}

impl NativeState {
    fn new(
        target_address: Option<String>,
        connected_service_lookup: bool,
        scan_on_connected_service_miss: bool,
        verbose: bool,
        trace_adverts: bool,
        scan_service_filter: bool,
        connect_options: bool,
        connect_auto_reconnect: bool,
        connect_timeout: Duration,
        max_attempts: u64,
    ) -> Self {
        Self {
            target_address,
            connected_service_lookup,
            scan_on_connected_service_miss,
            verbose,
            trace_adverts,
            scan_service_filter,
            connect_options,
            connect_auto_reconnect,
            connect_timeout,
            max_attempts,
            attempts: 0,
            state: "init".to_string(),
            state_since: Instant::now(),
            advertisement_events: 0,
            oura_advertisement_events: 0,
            last_advertisement: None,
            peripheral: None,
            write_char: None,
            notify_char: None,
            device: None,
            responses: Vec::new(),
            pending: VecDeque::new(),
            done: false,
            error: None,
        }
    }

    fn transition(&mut self, state: &str) {
        self.state = state.to_string();
        self.state_since = Instant::now();
    }
}

declare_class!(
    #[derive(Debug)]
    struct NativeDelegate;

    unsafe impl ClassType for NativeDelegate {
        type Super = NSObject;
        type Mutability = mutability::InteriorMutable;
        const NAME: &'static str = "OuraRing4NativeReadDelegate";
    }

    impl DeclaredClass for NativeDelegate {
        type Ivars = RefCell<NativeState>;
    }

    unsafe impl NSObjectProtocol for NativeDelegate {}

    unsafe impl CBCentralManagerDelegate for NativeDelegate {
        #[method(centralManagerDidUpdateState:)]
        fn central_manager_did_update_state(&self, central: &CBCentralManager) {
            let state = unsafe { central.state() };
            if self.with_state(|s| s.verbose) {
                emit("native_event", json!({
                    "event": "central_state",
                    "state": state.0,
                }));
            }
            if state == CBManagerState::PoweredOn {
                if self.with_state(|s| s.target_address.is_some()) {
                    self.connect_cached(central);
                } else if self.with_state(|s| s.connected_service_lookup) {
                    self.connect_connected_service(central);
                } else {
                    self.start_scan(central);
                }
            } else if state == CBManagerState::Unauthorized {
                self.fail("CoreBluetooth authorization is unauthorized");
            } else if state == CBManagerState::PoweredOff {
                self.fail("Bluetooth is powered off");
            } else if state == CBManagerState::Unsupported {
                self.fail("Bluetooth LE is unsupported");
            }
        }

        #[method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:)]
        fn central_manager_did_discover_peripheral_advertisement_data_rssi(
            &self,
            central: &CBCentralManager,
            peripheral: &CBPeripheral,
            advertisement_data: &NSDictionary<NSString, AnyObject>,
            rssi: &NSNumber,
        ) {
            let summary = advertisement_summary_json(advertisement_data);
            let maybe_oura = oura_advertisement_json(advertisement_data);
            let trace_adverts = self.with_state_mut(|s| {
                s.advertisement_events += 1;
                s.last_advertisement = Some(summary.clone());
                if maybe_oura.is_some() {
                    s.oura_advertisement_events += 1;
                }
                s.trace_adverts
            });
            if trace_adverts {
                self.verbose_event(json!({
                    "event": "advertisement_seen",
                    "oura": maybe_oura.is_some(),
                    "advertisement": summary,
                }));
            }

            if self.with_state(|s| s.peripheral.is_some() || s.done) {
                return;
            }
            let Some(advertisement) = maybe_oura else {
                return;
            };
            if advertisement_is_connectable(advertisement_data) == Some(false) {
                self.verbose_event(json!({
                    "event": "oura_not_connectable",
                    "advertisement": advertisement,
                }));
                return;
            }

            let attempt = self.with_state_mut(|s| {
                s.attempts += 1;
                s.attempts
            });
            unsafe { central.stopScan() };
            unsafe { peripheral.setDelegate(Some(ProtocolObject::from_ref(self))) };
            let peripheral_id = unsafe { peripheral.identifier() };
            let device = json!({
                "address": nsuuid_string(&peripheral_id),
                "name": unsafe { peripheral.name() }.map(|name| name.to_string()),
                "rssi": rssi.as_i16(),
                "source": "scan",
                "advertisement": advertisement,
            });
            self.verbose_event(json!({
                "event": "discovered",
                "attempt": attempt,
                "device": device.clone(),
            }));
            self.with_state_mut(|s| {
                s.peripheral = Some(peripheral.retain());
                s.device = Some(device);
                s.transition("connecting");
            });
            self.connect_peripheral(central, peripheral);
        }

        #[method(centralManager:didConnectPeripheral:)]
        fn central_manager_did_connect_peripheral(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
        ) {
            self.with_state_mut(|s| s.transition("discovering_services"));
            self.verbose_event(json!({ "event": "connected" }));
            let services = NSArray::from_vec(vec![cbuuid(OURA_SERVICE_UUID)]);
            unsafe { peripheral.discoverServices(Some(&services)) };
        }

        #[method(centralManager:didFailToConnectPeripheral:error:)]
        fn central_manager_did_fail_to_connect_peripheral_error(
            &self,
            central: &CBCentralManager,
            _peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            self.retry_or_fail(
                central,
                &format!("failed to connect: {}", error_string(error)),
            );
        }

        #[method(centralManager:didDisconnectPeripheral:error:)]
        fn central_manager_did_disconnect_peripheral_error(
            &self,
            central: &CBCentralManager,
            _peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            if self.with_state(|s| s.done) {
                return;
            }
            if self.with_state(|s| s.peripheral.is_none() && s.state == "scanning") {
                return;
            }
            self.retry_or_fail(central, &format!("disconnected: {}", error_string(error)));
        }
    }

    unsafe impl CBPeripheralDelegate for NativeDelegate {
        #[method(peripheral:didDiscoverServices:)]
        fn peripheral_did_discover_services(
            &self,
            peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            if error.is_some() {
                self.fail(&format!("service discovery failed: {}", error_string(error)));
                return;
            }

            let Some(services) = (unsafe { peripheral.services() }) else {
                self.fail("service discovery returned no services");
                return;
            };

            let mut seen = Vec::new();
            for service in services {
                let service_uuid = unsafe { service.UUID() };
                let uuid = cbuuid_string(&service_uuid);
                seen.push(uuid.clone());
                if uuid.eq_ignore_ascii_case(OURA_SERVICE_UUID) {
                    self.with_state_mut(|s| s.transition("discovering_characteristics"));
                    let chars = NSArray::from_vec(vec![cbuuid(OURA_WRITE_UUID), cbuuid(OURA_NOTIFY_UUID)]);
                    unsafe { peripheral.discoverCharacteristics_forService(Some(&chars), &service) };
                    return;
                }
            }

            self.fail(&format!("Oura service not discovered; services={seen:?}"));
        }

        #[method(peripheral:didDiscoverCharacteristicsForService:error:)]
        fn peripheral_did_discover_characteristics_for_service_error(
            &self,
            peripheral: &CBPeripheral,
            service: &CBService,
            error: Option<&NSError>,
        ) {
            if error.is_some() {
                self.fail(&format!(
                    "characteristic discovery failed: {}",
                    error_string(error)
                ));
                return;
            }

            let Some(chars) = (unsafe { service.characteristics() }) else {
                self.fail("characteristic discovery returned no characteristics");
                return;
            };

            let mut write_char = None;
            let mut notify_char = None;
            let mut seen = Vec::new();
            for char in chars {
                let char_uuid = unsafe { char.UUID() };
                let uuid = cbuuid_string(&char_uuid);
                seen.push(uuid.clone());
                if uuid.eq_ignore_ascii_case(OURA_WRITE_UUID) {
                    write_char = Some(char.clone());
                }
                if uuid.eq_ignore_ascii_case(OURA_NOTIFY_UUID) {
                    notify_char = Some(char);
                }
            }

            let (Some(write_char), Some(notify_char)) = (write_char, notify_char) else {
                self.fail(&format!(
                    "Oura write/notify characteristics not discovered; chars={seen:?}"
                ));
                return;
            };

            self.with_state_mut(|s| {
                s.transition("subscribing");
                s.write_char = Some(write_char);
                s.notify_char = Some(notify_char.clone());
            });
            unsafe { peripheral.setNotifyValue_forCharacteristic(true, &notify_char) };
        }

        #[method(peripheral:didUpdateNotificationStateForCharacteristic:error:)]
        fn peripheral_did_update_notification_state_for_characteristic_error(
            &self,
            peripheral: &CBPeripheral,
            _characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            if error.is_some() {
                self.fail(&format!("notification setup failed: {}", error_string(error)));
                return;
            }
            self.with_state_mut(|s| {
                s.transition("reading");
                s.pending.clear();
                s.pending.push_back(PendingRequest {
                    name: "firmware",
                    data: build_get_firmware_request(),
                    expect_tag: TAG_FIRMWARE_RESPONSE,
                });
                s.pending.push_back(PendingRequest {
                    name: "battery",
                    data: build_get_battery_request(),
                    expect_tag: TAG_BATTERY_RESPONSE,
                });
            });
            self.send_next_request(peripheral);
        }

        #[method(peripheral:didWriteValueForCharacteristic:error:)]
        fn peripheral_did_write_value_for_characteristic_error(
            &self,
            _peripheral: &CBPeripheral,
            _characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            if error.is_some() {
                self.fail(&format!("write failed: {}", error_string(error)));
            }
        }

        #[method(peripheral:didUpdateValueForCharacteristic:error:)]
        fn peripheral_did_update_value_for_characteristic_error(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            if error.is_some() {
                self.fail(&format!("notification failed: {}", error_string(error)));
                return;
            }

            let raw = unsafe { characteristic.value() }
                .map(|value| value.bytes().to_vec())
                .unwrap_or_default();
            self.verbose_event(json!({ "event": "rx", "raw_hex": hex::encode(&raw) }));

            let packets = match parse_packets(&raw) {
                Ok(packets) => packets,
                Err(error) => {
                    self.fail(&format!("response parse failed: {error}"));
                    return;
                }
            };

            for packet in packets {
                let json_packet = packet_json(&packet);
                let matched = self.with_state_mut(|s| {
                    s.responses.push(json_packet);
                    if s.pending
                        .front()
                        .map(|pending| pending.expect_tag == packet.tag)
                        .unwrap_or(false)
                    {
                        s.pending.pop_front();
                        true
                    } else {
                        false
                    }
                });
                if matched {
                    self.send_next_request(peripheral);
                    return;
                }
            }

            if self.with_state(|s| s.pending.is_empty()) {
                self.with_state_mut(|s| s.done = true);
            }
        }
    }
);

impl NativeDelegate {
    fn new(
        target_address: Option<String>,
        connected_service_lookup: bool,
        scan_on_connected_service_miss: bool,
        verbose: bool,
        trace_adverts: bool,
        scan_service_filter: bool,
        connect_options: bool,
        connect_auto_reconnect: bool,
        connect_timeout: Duration,
        max_attempts: u64,
    ) -> Retained<NativeDelegate> {
        let this = NativeDelegate::alloc().set_ivars(RefCell::new(NativeState::new(
            target_address,
            connected_service_lookup,
            scan_on_connected_service_miss,
            verbose,
            trace_adverts,
            scan_service_filter,
            connect_options,
            connect_auto_reconnect,
            connect_timeout,
            max_attempts,
        )));
        unsafe { msg_send_id![super(this), init] }
    }

    fn connect_cached(&self, central: &CBCentralManager) {
        let Some(target) = self.with_state(|s| s.target_address.clone()) else {
            self.start_scan(central);
            return;
        };
        let Some(ns_uuid) = nsuuid(&target) else {
            self.fail(&format!("invalid CoreBluetooth UUID: {target}"));
            return;
        };
        let identifiers = NSArray::from_vec(vec![ns_uuid]);
        let peripherals = unsafe { central.retrievePeripheralsWithIdentifiers(&identifiers) };
        let count = peripherals.len();
        self.verbose_event(json!({
            "event": "cached_lookup",
            "address": target,
            "count": count,
        }));
        let Some(peripheral) = peripherals.get_retained(0) else {
            self.fail("cached peripheral not found");
            return;
        };

        let attempt = self.with_state_mut(|s| {
            s.attempts += 1;
            s.attempts
        });
        unsafe { peripheral.setDelegate(Some(ProtocolObject::from_ref(self))) };
        let peripheral_id = unsafe { peripheral.identifier() };
        let device = json!({
            "address": nsuuid_string(&peripheral_id),
            "name": unsafe { peripheral.name() }.map(|name| name.to_string()),
            "source": "cached",
        });
        self.verbose_event(json!({
            "event": "cached_selected",
            "attempt": attempt,
            "device": device.clone(),
        }));
        self.with_state_mut(|s| {
            s.peripheral = Some(peripheral.clone());
            s.device = Some(device);
            s.transition("connecting");
        });
        self.connect_peripheral(central, &peripheral);
    }

    fn connect_connected_service(&self, central: &CBCentralManager) {
        let services = NSArray::from_vec(vec![cbuuid(OURA_SERVICE_UUID)]);
        let peripherals = unsafe { central.retrieveConnectedPeripheralsWithServices(&services) };
        let count = peripherals.len();
        self.verbose_event(json!({
            "event": "connected_service_lookup",
            "service_uuid": OURA_SERVICE_UUID,
            "count": count,
        }));
        let Some(peripheral) = peripherals.get_retained(0) else {
            if self.with_state(|s| s.scan_on_connected_service_miss) {
                self.start_scan(central);
            } else {
                self.fail("connected Oura service peripheral not found");
            }
            return;
        };

        let attempt = self.with_state_mut(|s| {
            s.attempts += 1;
            s.attempts
        });
        unsafe { peripheral.setDelegate(Some(ProtocolObject::from_ref(self))) };
        let peripheral_id = unsafe { peripheral.identifier() };
        let device = json!({
            "address": nsuuid_string(&peripheral_id),
            "name": unsafe { peripheral.name() }.map(|name| name.to_string()),
            "source": "connected_service",
        });
        self.verbose_event(json!({
            "event": "connected_service_selected",
            "attempt": attempt,
            "device": device.clone(),
        }));
        self.with_state_mut(|s| {
            s.peripheral = Some(peripheral.clone());
            s.device = Some(device);
            s.transition("connecting");
        });
        self.connect_peripheral(central, &peripheral);
    }

    fn start_scan(&self, central: &CBCentralManager) {
        self.with_state_mut(|s| s.transition("scanning"));
        let scan_service_filter = self.with_state(|s| s.scan_service_filter);
        self.verbose_event(json!({
            "event": "scan_start",
            "service_filter": scan_service_filter,
        }));
        let mut options = NSMutableDictionary::new();
        options.insert_id(
            unsafe { CBCentralManagerScanOptionAllowDuplicatesKey },
            nsnumber_bool_any(true),
        );
        let services =
            scan_service_filter.then(|| NSArray::from_vec(vec![cbuuid(OURA_SERVICE_UUID)]));
        unsafe {
            central.scanForPeripheralsWithServices_options(services.as_deref(), Some(&options))
        };
    }

    fn connect_peripheral(&self, central: &CBCentralManager, peripheral: &CBPeripheral) {
        let use_connect_options = self.with_state(|s| s.connect_options);
        let use_auto_reconnect = self.with_state(|s| s.connect_auto_reconnect);
        let options = use_connect_options.then(|| connect_options(use_auto_reconnect));
        self.verbose_event(json!({
            "event": "connect_start",
            "connect_options": use_connect_options,
            "connect_auto_reconnect": use_connect_options && use_auto_reconnect,
            "peripheral": peripheral_status_json(peripheral),
        }));
        unsafe { central.connectPeripheral_options(peripheral, options.as_deref().map(|v| &**v)) };
    }

    fn send_next_request(&self, peripheral: &CBPeripheral) {
        let next = self.with_state(|s| s.pending.front().cloned());
        let Some(next) = next else {
            self.with_state_mut(|s| s.done = true);
            return;
        };
        let Some(write_char) = self.with_state(|s| s.write_char.clone()) else {
            self.fail("cannot write: missing Oura write characteristic");
            return;
        };
        self.verbose_event(json!({
            "event": "tx",
            "name": next.name,
            "raw_hex": hex::encode(&next.data),
        }));
        let data = NSData::with_bytes(&next.data);
        unsafe {
            peripheral.writeValue_forCharacteristic_type(
                &data,
                &write_char,
                CBCharacteristicWriteType::CBCharacteristicWriteWithResponse,
            );
        }
    }

    fn tick(&self, central: &CBCentralManager) {
        let timed_out = self.with_state(|s| {
            s.state == "connecting" && s.state_since.elapsed() >= s.connect_timeout
        });
        if timed_out {
            let timeout_seconds = self.with_state(|s| s.connect_timeout.as_secs());
            self.retry_or_fail(
                central,
                &format!("connect attempt timed out after {timeout_seconds}s"),
            );
        }
    }

    fn retry_or_fail(&self, central: &CBCentralManager, reason: &str) {
        let (attempt, max_attempts, peripheral) =
            self.with_state(|s| (s.attempts, s.max_attempts, s.peripheral.clone()));
        self.verbose_event(json!({
            "event": "retryable_connection_failure",
            "attempt": attempt,
            "max_attempts": max_attempts,
            "reason": reason,
        }));

        if attempt >= max_attempts {
            self.fail(reason);
            return;
        }

        self.with_state_mut(|s| {
            s.peripheral = None;
            s.write_char = None;
            s.notify_char = None;
            s.pending.clear();
            s.transition("scanning");
        });
        if let Some(peripheral) = peripheral {
            unsafe { central.cancelPeripheralConnection(&peripheral) };
        }
        if self.with_state(|s| s.target_address.is_some()) {
            self.connect_cached(central);
        } else if self.with_state(|s| s.connected_service_lookup) {
            self.connect_connected_service(central);
        } else {
            self.start_scan(central);
        }
    }

    fn done(&self) -> bool {
        self.with_state(|s| s.done)
    }

    fn error(&self) -> Option<String> {
        self.with_state(|s| s.error.clone())
    }

    fn state_name(&self) -> String {
        self.with_state(|s| s.state.clone())
    }

    fn peripheral(&self) -> Option<Retained<CBPeripheral>> {
        self.with_state(|s| s.peripheral.clone())
    }

    fn scan_status_json(&self) -> Value {
        self.with_state(|s| {
            json!({
                "state": s.state,
                "advertisement_events": s.advertisement_events,
                "oura_advertisement_events": s.oura_advertisement_events,
                "last_advertisement": s.last_advertisement,
                "peripheral": s.peripheral.as_ref().map(|peripheral| peripheral_status_json(peripheral)),
            })
        })
    }

    fn result_json(&self) -> Value {
        self.with_state(|s| {
            json!({
                "device": s.device.clone().unwrap_or_else(|| json!({
                    "address": s.target_address.clone().unwrap_or_else(|| "scan".to_string())
                })),
                "firmware": first_response(&s.responses, TAG_FIRMWARE_RESPONSE),
                "battery": first_response(&s.responses, TAG_BATTERY_RESPONSE),
                "events": s.responses,
            })
        })
    }

    fn fail(&self, message: &str) {
        self.with_state_mut(|s| {
            s.error = Some(message.to_string());
            s.done = true;
        });
    }

    fn verbose_event(&self, payload: Value) {
        if self.with_state(|s| s.verbose) {
            emit("native_event", payload);
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&NativeState) -> R) -> R {
        f(&self.ivars().borrow())
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut NativeState) -> R) -> R {
        f(&mut self.ivars().borrow_mut())
    }
}

fn nsnumber_bool_any(value: bool) -> Retained<AnyObject> {
    Retained::into_super(Retained::into_super(Retained::into_super(
        NSNumber::new_bool(value),
    )))
}

fn connect_options(
    connect_auto_reconnect: bool,
) -> Retained<NSMutableDictionary<NSString, AnyObject>> {
    let mut options = NSMutableDictionary::new();
    options.insert_id(
        unsafe { CBConnectPeripheralOptionNotifyOnConnectionKey },
        nsnumber_bool_any(true),
    );
    options.insert_id(
        unsafe { CBConnectPeripheralOptionNotifyOnDisconnectionKey },
        nsnumber_bool_any(true),
    );
    options.insert_id(
        unsafe { CBConnectPeripheralOptionNotifyOnNotificationKey },
        nsnumber_bool_any(true),
    );
    if connect_auto_reconnect {
        options.insert_id(
            unsafe { CBConnectPeripheralOptionEnableAutoReconnect },
            nsnumber_bool_any(true),
        );
    }
    options
}

fn peripheral_status_json(peripheral: &CBPeripheral) -> Value {
    let identifier = unsafe { peripheral.identifier() };
    let name = unsafe { peripheral.name() }.map(|name| name.to_string());
    let state = unsafe { peripheral.state() };
    json!({
        "address": nsuuid_string(&identifier),
        "name": name,
        "state": state.0,
        "state_name": peripheral_state_name(state),
    })
}

fn peripheral_state_name(state: CBPeripheralState) -> &'static str {
    if state == CBPeripheralState::Disconnected {
        "disconnected"
    } else if state == CBPeripheralState::Connecting {
        "connecting"
    } else if state == CBPeripheralState::Connected {
        "connected"
    } else if state == CBPeripheralState::Disconnecting {
        "disconnecting"
    } else {
        "unknown"
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let addresses = addresses_to_try(&args);
    emit(
        "startup",
        json!({
            "addresses": addresses,
            "timeout_seconds": args.timeout,
            "connect_timeout_seconds": args.connect_timeout,
            "attempts": args.attempts,
            "trace_adverts": args.trace_adverts,
            "scan_service_filter": args.scan_service_filter,
            "connect_options": args.connect_options,
            "connect_auto_reconnect": args.connect_auto_reconnect,
            "scan_heartbeat_seconds": args.scan_heartbeat,
            "scan": args.scan,
            "scan_only": args.scan_only,
            "connected_service_only": args.connected_service_only,
            "connected_service_first": args.connected_service_first,
            "connected_service_lookup": args.scan
                || args.scan_only
                || args.connected_service_only
                || args.connected_service_first,
            "repeat": args.repeat,
            "duration_seconds": args.duration,
            "interval_seconds": args.interval,
        }),
    );

    if args.repeat || args.duration.is_some() {
        return run_repeating(&args, &addresses);
    }

    run_one_cycle(&args, &addresses, true).map(|_| ())
}

fn run_repeating(args: &Args, addresses: &[String]) -> Result<()> {
    let started = Instant::now();
    let duration = args.duration.map(Duration::from_secs);
    let mut cycle = 0_u64;

    loop {
        if duration
            .map(|duration| started.elapsed() >= duration)
            .unwrap_or(false)
        {
            emit("shutdown", json!({ "reason": "duration_elapsed" }));
            return Ok(());
        }

        cycle += 1;
        emit("cycle_start", json!({ "cycle": cycle }));
        let _ = run_one_cycle(args, addresses, false);

        let Some(sleep_for) = bounded_sleep_duration(started, duration, args.interval) else {
            emit("shutdown", json!({ "reason": "duration_elapsed" }));
            return Ok(());
        };
        emit(
            "cycle_sleep",
            json!({ "cycle": cycle, "seconds": sleep_for.as_secs() }),
        );
        std::thread::sleep(sleep_for);
    }
}

fn run_one_cycle(args: &Args, addresses: &[String], fail_on_all_errors: bool) -> Result<bool> {
    let mut errors = Vec::new();
    if args.connected_service_first {
        emit("read_attempt", json!({ "source": "connected_service" }));
        match read_connected_service_only(args) {
            Ok(payload) => {
                emit("read_result", payload);
                return Ok(true);
            }
            Err(error) => {
                let message = error.to_string();
                errors.push(json!({ "source": "connected_service", "error": message }));
                emit("read_error", errors.last().cloned().unwrap());
            }
        }
    }

    if !args.scan_only && !args.connected_service_only {
        for address in addresses.iter().cloned() {
            emit(
                "read_attempt",
                json!({ "address": address, "source": "cached" }),
            );
            match read_cached_address(&address, &args) {
                Ok(payload) => {
                    emit("read_result", payload);
                    return Ok(true);
                }
                Err(error) => {
                    let message = error.to_string();
                    errors
                        .push(json!({ "address": address, "source": "cached", "error": message }));
                    emit("read_error", errors.last().cloned().unwrap());
                }
            }
        }
    }

    if args.connected_service_only {
        emit("read_attempt", json!({ "source": "connected_service" }));
        match read_connected_service_only(args) {
            Ok(payload) => {
                emit("read_result", payload);
                return Ok(true);
            }
            Err(error) => {
                let message = error.to_string();
                errors.push(json!({ "source": "connected_service", "error": message }));
                emit("read_error", errors.last().cloned().unwrap());
            }
        }
    }

    if args.scan || args.scan_only {
        emit("read_attempt", json!({ "source": "scan" }));
        match read_scan(args) {
            Ok(payload) => {
                emit("read_result", payload);
                return Ok(true);
            }
            Err(error) => {
                let message = error.to_string();
                errors.push(json!({ "source": "scan", "error": message }));
                emit("read_error", errors.last().cloned().unwrap());
            }
        }
    }

    if fail_on_all_errors {
        bail!("all CoreBluetooth read attempts failed: {errors:?}");
    }
    Ok(false)
}

fn bounded_sleep_duration(
    started: Instant,
    duration: Option<Duration>,
    interval_seconds: u64,
) -> Option<Duration> {
    let interval = Duration::from_secs(interval_seconds);
    if let Some(duration) = duration {
        let remaining = duration.checked_sub(started.elapsed())?;
        if remaining.is_zero() {
            None
        } else {
            Some(remaining.min(interval))
        }
    } else {
        Some(interval)
    }
}

fn addresses_to_try(args: &Args) -> Vec<String> {
    if args.scan_only || args.connected_service_only {
        return Vec::new();
    }
    if args.addresses.is_empty() {
        DEFAULT_CACHED_ADDRESSES
            .iter()
            .map(|address| address.to_string())
            .collect()
    } else {
        args.addresses.clone()
    }
}

fn read_scan(args: &Args) -> Result<Value> {
    let delegate = NativeDelegate::new(
        None,
        true,
        true,
        args.verbose,
        args.trace_adverts,
        args.scan_service_filter,
        args.connect_options,
        args.connect_auto_reconnect,
        Duration::from_secs(args.connect_timeout),
        args.attempts,
    );
    read_with_delegate(delegate, args)
}

fn read_connected_service_only(args: &Args) -> Result<Value> {
    let delegate = NativeDelegate::new(
        None,
        true,
        false,
        args.verbose,
        args.trace_adverts,
        args.scan_service_filter,
        args.connect_options,
        args.connect_auto_reconnect,
        Duration::from_secs(args.connect_timeout),
        args.attempts,
    );
    read_with_delegate(delegate, args)
}

fn read_cached_address(address: &str, args: &Args) -> Result<Value> {
    let delegate = NativeDelegate::new(
        Some(address.to_string()),
        false,
        false,
        args.verbose,
        args.trace_adverts,
        args.scan_service_filter,
        args.connect_options,
        args.connect_auto_reconnect,
        Duration::from_secs(args.connect_timeout),
        args.attempts,
    );
    read_with_delegate(delegate, args)
}

fn read_with_delegate(delegate: Retained<NativeDelegate>, args: &Args) -> Result<Value> {
    let queue: *mut AnyObject = ptr::null_mut();
    let manager: Retained<CBCentralManager> = unsafe {
        msg_send_id![CBCentralManager::alloc(), initWithDelegate: &*delegate, queue: queue]
    };

    run_loop_until(
        &delegate,
        &manager,
        Duration::from_secs(args.timeout),
        Duration::from_secs(args.scan_heartbeat),
    );

    if let Some(peripheral) = delegate.peripheral() {
        unsafe { manager.cancelPeripheralConnection(&peripheral) };
    }
    unsafe { manager.stopScan() };

    if let Some(error) = delegate.error() {
        bail!("{error}");
    }
    if !delegate.done() {
        bail!("timed out in state {}", delegate.state_name());
    }
    let payload = delegate.result_json();
    if payload.get("firmware").is_none() && payload.get("battery").is_none() {
        bail!("read completed without firmware or battery responses");
    }
    Ok(payload)
}

fn run_loop_until(
    delegate: &NativeDelegate,
    manager: &CBCentralManager,
    duration: Duration,
    heartbeat_interval: Duration,
) {
    let run_loop = unsafe { NSRunLoop::currentRunLoop() };
    let started = Instant::now();
    let mut last_heartbeat = Instant::now();
    while started.elapsed() < duration && !delegate.done() && delegate.error().is_none() {
        delegate.tick(manager);
        if !heartbeat_interval.is_zero() && last_heartbeat.elapsed() >= heartbeat_interval {
            last_heartbeat = Instant::now();
            emit(
                "native_event",
                json!({
                    "event": "scan_heartbeat",
                    "elapsed_seconds": started.elapsed().as_secs(),
                    "status": delegate.scan_status_json(),
                }),
            );
        }
        let limit = unsafe { NSDate::dateWithTimeIntervalSinceNow(0.05) };
        unsafe { run_loop.runUntilDate(&limit) };
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

fn first_response(responses: &[PacketJson], tag: u8) -> Option<PacketJson> {
    let tag_text = format!("0x{tag:02X}");
    responses
        .iter()
        .find(|response| response.tag == tag_text)
        .cloned()
}

fn semver(data: &[u8]) -> Result<String> {
    if data.len() != 3 {
        bail!("semver needs 3 bytes, got {}", data.len());
    }
    Ok(format!("{}.{}.{}", data[0], data[1], data[2]))
}

fn cbuuid(uuid: &str) -> Retained<CBUUID> {
    unsafe { CBUUID::UUIDWithString(&NSString::from_str(&uuid.to_uppercase())) }
}

fn nsuuid(uuid: &str) -> Option<Retained<NSUUID>> {
    NSUUID::from_string(&NSString::from_str(uuid))
}

fn cbuuid_string(uuid: &CBUUID) -> String {
    unsafe { uuid.UUIDString() }.to_string().to_lowercase()
}

fn nsuuid_string(uuid: &NSUUID) -> String {
    uuid.to_string()
}

fn error_string(error: Option<&NSError>) -> String {
    error
        .map(|error| error.localizedDescription().to_string())
        .unwrap_or_else(|| "no error detail".to_string())
}

fn advertisement_summary_json(advertisement_data: &NSDictionary<NSString, AnyObject>) -> Value {
    json!({
        "local_name": advertisement_local_name(advertisement_data),
        "manufacturer_data_hex": advertisement_manufacturer_data(advertisement_data).map(hex::encode),
        "is_connectable": advertisement_is_connectable(advertisement_data),
        "service_uuids": advertisement_service_uuids(advertisement_data),
        "service_data": advertisement_service_data(advertisement_data)
            .into_iter()
            .map(|(uuid, data)| json!({ "uuid": uuid, "data_hex": hex::encode(data) }))
            .collect::<Vec<_>>(),
    })
}

fn oura_advertisement_json(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Option<Value> {
    let local_name = advertisement_local_name(advertisement_data);
    let manufacturer_data = advertisement_manufacturer_data(advertisement_data);
    let service_uuids = advertisement_service_uuids(advertisement_data);
    let service_data = advertisement_service_data(advertisement_data);

    let name_match = local_name
        .as_deref()
        .map(|name| name.to_ascii_lowercase().contains("oura"))
        .unwrap_or(false);
    let manufacturer_match = manufacturer_data
        .as_deref()
        .map(is_oura_manufacturer_data)
        .unwrap_or(false);
    let service_match = service_uuids
        .iter()
        .any(|uuid| uuid.eq_ignore_ascii_case(OURA_SERVICE_UUID))
        || service_data
            .iter()
            .any(|(uuid, _)| uuid.eq_ignore_ascii_case(OURA_SERVICE_UUID));

    if !(name_match || manufacturer_match || service_match) {
        return None;
    }

    Some(json!({
        "local_name": local_name,
        "manufacturer_data_hex": manufacturer_data.map(hex::encode),
        "is_connectable": advertisement_is_connectable(advertisement_data),
        "service_uuids": service_uuids,
        "service_data": service_data
            .into_iter()
            .map(|(uuid, data)| json!({ "uuid": uuid, "data_hex": hex::encode(data) }))
            .collect::<Vec<_>>(),
        "match": {
            "name": name_match,
            "manufacturer": manufacturer_match,
            "service": service_match,
        },
    }))
}

fn advertisement_local_name(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Option<String> {
    let value = advertisement_data.get(unsafe { CBAdvertisementDataLocalNameKey })?;
    let value: *const AnyObject = value;
    let value: *const NSString = value.cast();
    Some(unsafe { &*value }.to_string())
}

fn advertisement_is_connectable(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Option<bool> {
    let value = advertisement_data.get(unsafe { CBAdvertisementDataIsConnectable })?;
    let value: *const AnyObject = value;
    let value: *const NSNumber = value.cast();
    Some(unsafe { &*value }.as_bool())
}

fn advertisement_manufacturer_data(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Option<Vec<u8>> {
    let value = advertisement_data.get(unsafe { CBAdvertisementDataManufacturerDataKey })?;
    let value: *const AnyObject = value;
    let value: *const NSData = value.cast();
    Some(unsafe { &*value }.bytes().to_vec())
}

fn advertisement_service_uuids(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Vec<String> {
    let Some(value) = advertisement_data.get(unsafe { CBAdvertisementDataServiceUUIDsKey }) else {
        return Vec::new();
    };
    let value: *const AnyObject = value;
    let value: *const NSArray<CBUUID> = value.cast();
    unsafe { &*value }.into_iter().map(cbuuid_string).collect()
}

fn advertisement_service_data(
    advertisement_data: &NSDictionary<NSString, AnyObject>,
) -> Vec<(String, Vec<u8>)> {
    let Some(value) = advertisement_data.get(unsafe { CBAdvertisementDataServiceDataKey }) else {
        return Vec::new();
    };
    let value: *const AnyObject = value;
    let value: *const NSDictionary<CBUUID, NSData> = value.cast();
    let service_data = unsafe { &*value };
    service_data
        .keys()
        .map(|uuid| (cbuuid_string(uuid), service_data[uuid].bytes().to_vec()))
        .collect()
}

fn is_oura_manufacturer_data(data: &[u8]) -> bool {
    if data.len() >= 2 {
        let company_le = u16::from_le_bytes([data[0], data[1]]);
        let company_be = u16::from_be_bytes([data[0], data[1]]);
        let payload = &data[2..];
        if company_le == 0x02b2 || company_be == 0x02b2 {
            return data.len() == 2 || is_oura_manufacturer_payload(payload);
        }
    }
    is_oura_manufacturer_payload(data)
}

fn is_oura_manufacturer_payload(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[0] == 0x04 && payload[2] == 0x1b && payload[3] == 0x01
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
    fn matches_observed_oura_manufacturer_payloads() {
        assert!(is_oura_manufacturer_data(&[0x04, 0x60, 0x1b, 0x01]));
        assert!(is_oura_manufacturer_data(&[0x04, 0x61, 0x1b, 0x01]));
        assert!(is_oura_manufacturer_data(&[0x04, 0x62, 0x1b, 0x01]));
        assert!(is_oura_manufacturer_data(&[
            0xb2, 0x02, 0x04, 0x60, 0x1b, 0x01
        ]));
        assert!(is_oura_manufacturer_data(&[
            0xb2, 0x02, 0x04, 0x61, 0x1b, 0x01
        ]));
        assert!(is_oura_manufacturer_data(&[
            0x02, 0xb2, 0x04, 0x62, 0x1b, 0x01
        ]));
        assert!(!is_oura_manufacturer_data(&[
            0x4c, 0x00, 0x13, 0x08, 0x4a, 0x68
        ]));
    }
}
