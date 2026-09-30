use std::error::Error;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ble_lifecycle::{self, Deadline, Operation, Status};
use windows::core::{Array, GUID, Ref, RuntimeType};
use windows_future::{AsyncStatus, IAsyncOperation};

use windows::Devices::Bluetooth::{
    Advertisement::{
        BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
        BluetoothLEScanningMode,
    },
    BluetoothAddressType, BluetoothCacheMode, BluetoothLEDevice,
};

use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCommunicationStatus, GattWriteOption,
};

use windows::Foundation::TypedEventHandler;

use windows::Security::Cryptography::CryptographicBuffer;

pub type BleTransportError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBleProgress {
    DeviceFound,
    ChallengeDelivered,
}

const PHONEKEY_SERVICE_UUID: GUID = GUID::from_u128(0x7d2ea28af7bd485abd9d92ad6ecfe93e);

const PHONEKEY_CHALLENGE_UUID: GUID = GUID::from_u128(0x7d2ea28bf7bd485abd9d92ad6ecfe93e);

const PHONEKEY_PROOF_UUID: GUID = GUID::from_u128(0x7d2ea28cf7bd485abd9d92ad6ecfe93e);

const MAX_MESSAGE_BYTES: usize = 2048;

fn unix_time_ms() -> Result<u64, BleTransportError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let millis = duration.as_millis();

    u64::try_from(millis)
        .map_err(|_| io::Error::other("system clock exceeds supported range").into())
}

fn transport_error(message: &'static str) -> BleTransportError {
    io::Error::other(message).into()
}

// Guards are established immediately after acquisition, before the next
// fallible call. Errors and cancellation therefore take the same cleanup.
struct CloseGuard<T> {
    value: T,
    close: fn(&T) -> windows::core::Result<()>,
}
impl<T> std::ops::Deref for CloseGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> Drop for CloseGuard<T> {
    fn drop(&mut self) {
        if let Err(error) = (self.close)(&self.value) {
            eprintln!("PhoneKey BLE resource cleanup failed: {error}");
        }
    }
}
struct WatcherGuard {
    watcher: BluetoothLEAdvertisementWatcher,
    token: i64,
}
impl Drop for WatcherGuard {
    fn drop(&mut self) {
        // Attempt both calls even if Stop fails. The callback owns only an Arc.
        if let Err(error) = self.watcher.Stop() {
            eprintln!("PhoneKey BLE watcher stop failed: {error}");
        }
        if let Err(error) = self.watcher.RemoveReceived(self.token) {
            eprintln!("PhoneKey BLE watcher removal failed: {error}");
        }
    }
}
struct WinOperation<T: RuntimeType + 'static>(IAsyncOperation<T>);
impl<T: RuntimeType + 'static> Operation for WinOperation<T> {
    type Output = T;
    fn status(&self) -> Result<Status, BleTransportError> {
        match self.0.Status()? {
            AsyncStatus::Started => Ok(Status::Started),
            AsyncStatus::Completed => Ok(Status::Completed),
            AsyncStatus::Canceled => Ok(Status::Canceled),
            AsyncStatus::Error => Ok(Status::Error),
            _ => Err(transport_error("unknown WinRT operation status")),
        }
    }
    fn results(&self) -> Result<T, BleTransportError> {
        Ok(self.0.GetResults()?)
    }
    fn cancel(&self) -> Result<(), BleTransportError> {
        Ok(self.0.Cancel()?)
    }
    fn close(&self) -> Result<(), BleTransportError> {
        Ok(self.0.Close()?)
    }
}

/// Carries one already-created LocalSystem LoginChallenge
/// to the Android PhoneKey peripheral and returns the exact
/// LoginProof bytes received from Android.
///
/// SECURITY:
/// - This function creates no authentication authority.
/// - It owns no trusted phone key.
/// - It does not verify or approve the proof.
/// - The caller must submit the returned bytes to
///   LoginAuthority for authoritative verification.
/// - Each asynchronous wait observes cancellation and session expiry.
/// - Unsettled cancellation stops the service; no new exchange is admitted.
pub fn exchange_login(
    challenge_bytes: &[u8],
    expires_at_ms: u64,
    service_stop: &AtomicBool,
    mut session_cancelled: impl FnMut() -> Result<bool, BleTransportError>,
    mut progress: impl FnMut(LoginBleProgress) -> Result<(), BleTransportError>,
) -> Result<Option<Vec<u8>>, BleTransportError> {
    if challenge_bytes.is_empty() {
        return Err(transport_error("refusing empty PhoneKey challenge"));
    }

    if challenge_bytes.len() > MAX_MESSAGE_BYTES {
        return Err(transport_error(
            "PhoneKey challenge exceeds transport limit",
        ));
    }

    let deadline = Deadline::new(unix_time_ms()?, expires_at_ms)?;
    let mut cancelled = || -> Result<bool, BleTransportError> {
        Ok(service_stop.load(Ordering::SeqCst)
            || deadline.expired(unix_time_ms()?)
            || session_cancelled()?)
    };
    macro_rules! await_ble {
        ($operation:expr) => {{
            if cancelled()? {
                return Ok(None);
            }
            let operation = WinOperation($operation?);
            match ble_lifecycle::wait_operation(
                &operation,
                &mut cancelled,
                service_stop,
                ble_lifecycle::CANCEL_GRACE,
            )? {
                Some(value) => value,
                None => return Ok(None),
            }
        }};
    }
    if cancelled()? {
        return Ok(None);
    }

    // Bluetooth addresses occupy 48 bits; keep the advertised address type
    // in the same atomic value so the callback cannot publish one without
    // the other. Android commonly advertises with a random address.
    const ADDRESS_MASK: u64 = (1_u64 << 48) - 1;
    let found_device = Arc::new(AtomicU64::new(0));

    let callback_device = Arc::clone(&found_device);

    let watcher = BluetoothLEAdvertisementWatcher::new()?;

    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;

    let handler = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(
        move |_sender: Ref<'_, BluetoothLEAdvertisementWatcher>,
              args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
            let args = args.ok()?;

            let advertisement = args.Advertisement()?;

            let service_uuids = advertisement.ServiceUuids()?;

            for uuid in service_uuids {
                if uuid == PHONEKEY_SERVICE_UUID {
                    let address = args.BluetoothAddress()?;
                    let address_type = args.BluetoothAddressType()?;
                    let packed = address | ((address_type.0 as u64) << 48);

                    let _ = callback_device.compare_exchange(
                        0,
                        packed,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );

                    break;
                }
            }

            Ok(())
        },
    );

    let watcher_token = watcher.Received(&handler)?;

    let watcher_guard = WatcherGuard {
        watcher: watcher.clone(),
        token: watcher_token,
    };
    watcher.Start()?;

    while !cancelled()? {
        if found_device.load(Ordering::SeqCst) != 0 {
            break;
        }

        thread::sleep(ble_lifecycle::POLL);
    }

    drop(watcher_guard);
    if cancelled()? {
        return Ok(None);
    }

    let packed_device = found_device.load(Ordering::SeqCst);
    let address = packed_device & ADDRESS_MASK;

    if address == 0 {
        return Ok(None);
    }

    progress(LoginBleProgress::DeviceFound)?;

    let address_type = BluetoothAddressType((packed_device >> 48) as i32);
    let connection = if address_type == BluetoothAddressType::Public
        || address_type == BluetoothAddressType::Random
    {
        BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(address, address_type)
    } else {
        BluetoothLEDevice::FromBluetoothAddressAsync(address)
    };
    let device = CloseGuard {
        value: await_ble!(connection),
        close: BluetoothLEDevice::Close,
    };

    let service_result = await_ble!(device.GetGattServicesForUuidWithCacheModeAsync(
        PHONEKEY_SERVICE_UUID,
        BluetoothCacheMode::Uncached,
    ));

    if service_result.Status()? != GattCommunicationStatus::Success {
        return Err(transport_error("PhoneKey GATT service discovery failed"));
    }

    let services = service_result.Services()?;

    if services.Size()? == 0 {
        return Err(transport_error("PhoneKey GATT service missing"));
    }

    let service = CloseGuard {
        value: services.GetAt(0)?,
        close: windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService::Close,
    };

    // One uncached discovery fetches both required characteristics, avoiding
    // a second serialized BLE query without trusting stale Windows cache data.
    let characteristics_result =
        await_ble!(service.GetCharacteristicsWithCacheModeAsync(BluetoothCacheMode::Uncached));
    if characteristics_result.Status()? != GattCommunicationStatus::Success {
        return Err(transport_error("PhoneKey GATT characteristics unavailable"));
    }
    let mut challenge_characteristic = None;
    let mut proof_characteristic = None;
    for characteristic in characteristics_result.Characteristics()? {
        match characteristic.Uuid()? {
            uuid if uuid == PHONEKEY_CHALLENGE_UUID => {
                challenge_characteristic = Some(characteristic)
            }
            uuid if uuid == PHONEKEY_PROOF_UUID => proof_characteristic = Some(characteristic),
            _ => {}
        }
    }
    let (Some(challenge_characteristic), Some(proof_characteristic)) =
        (challenge_characteristic, proof_characteristic)
    else {
        return Err(transport_error("PhoneKey required characteristic missing"));
    };

    let challenge_buffer = CryptographicBuffer::CreateFromByteArray(challenge_bytes)?;

    let write_result =
        await_ble!(challenge_characteristic.WriteValueWithResultAndOptionAsync(
            &challenge_buffer,
            GattWriteOption::WriteWithResponse
        ));

    if write_result.Status()? != GattCommunicationStatus::Success {
        return Err(transport_error("PhoneKey challenge write failed"));
    }

    progress(LoginBleProgress::ChallengeDelivered)?;

    let mut received_proof: Option<Vec<u8>> = None;

    while !cancelled()? {
        let read_result = await_ble!(
            proof_characteristic.ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached)
        );

        if read_result.Status()? == GattCommunicationStatus::Success {
            let buffer = read_result.Value()?;

            let mut byte_array = Array::<u8>::new();

            CryptographicBuffer::CopyToByteArray(&buffer, &mut byte_array)?;

            let bytes = byte_array.as_slice().to_vec();

            if !bytes.is_empty() {
                if bytes.len() > MAX_MESSAGE_BYTES {
                    return Err(transport_error("PhoneKey proof exceeds transport limit"));
                }

                received_proof = Some(bytes);

                break;
            }
        }

        for _ in 0..5 {
            if cancelled()? {
                return Ok(None);
            }
            thread::sleep(ble_lifecycle::POLL);
        }
    }

    if cancelled()? {
        return Ok(None);
    }
    Ok(received_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn winrt_adapter_reads_completed_operation() {
        let op = WinOperation(IAsyncOperation::<u32>::ready(Ok(42)));
        assert_eq!(
            ble_lifecycle::wait_operation(
                &op,
                &mut || Ok(false),
                &AtomicBool::new(false),
                ble_lifecycle::CANCEL_GRACE
            )
            .unwrap(),
            Some(42)
        );
    }
    #[test]
    fn winrt_adapter_propagates_operation_error() {
        let op = WinOperation(IAsyncOperation::<u32>::ready(Err(
            windows::core::Error::from_hresult(windows::core::HRESULT(0x80004005u32 as i32)),
        )));
        assert!(
            ble_lifecycle::wait_operation(
                &op,
                &mut || Ok(false),
                &AtomicBool::new(false),
                ble_lifecycle::CANCEL_GRACE
            )
            .is_err()
        );
    }
    #[test]
    fn acquired_resource_is_closed_on_later_error() {
        use std::cell::Cell;
        let count = Cell::new(0);
        fn close(count: &&Cell<u32>) -> windows::core::Result<()> {
            count.set(count.get() + 1);
            Ok(())
        }
        let result = (|| -> Result<(), BleTransportError> {
            let _resource = CloseGuard {
                value: &count,
                close,
            };
            Err("injected discovery failure".into())
        })();
        assert!(result.is_err());
        assert_eq!(count.get(), 1);
    }
    #[test]
    fn canceled_session_does_not_start_bluetooth() {
        let result = exchange_login(
            &[1],
            unix_time_ms().unwrap() + 1000,
            &AtomicBool::new(true),
            || panic!("stop must short circuit"),
            |_| panic!("stop must short circuit progress"),
        );
        assert!(result.unwrap().is_none());
    }
}
