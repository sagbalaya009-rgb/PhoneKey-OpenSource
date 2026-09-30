//! Read-only radio diagnostic. Prints counts only, never addresses or names.
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::Duration;
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEScanningMode,
};
use windows::Foundation::TypedEventHandler;
use windows::core::{GUID, Ref};

const PHONEKEY_SERVICE_UUID: GUID = GUID::from_u128(0x7d2ea28af7bd485abd9d92ad6ecfe93e);

fn main() -> windows::core::Result<()> {
    let total = Arc::new(AtomicUsize::new(0));
    let with_uuids = Arc::new(AtomicUsize::new(0));
    let phonekey = Arc::new(AtomicUsize::new(0));
    let watcher = BluetoothLEAdvertisementWatcher::new()?;
    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
    let (total_callback, uuids_callback, phonekey_callback) =
        (Arc::clone(&total), Arc::clone(&with_uuids), Arc::clone(&phonekey));
    let handler = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(move |_, args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
        let args = args.ok()?;
        total_callback.fetch_add(1, Ordering::Relaxed);
        let uuids = args.Advertisement()?.ServiceUuids()?;
        if uuids.Size()? > 0 {
            uuids_callback.fetch_add(1, Ordering::Relaxed);
        }
        if uuids.into_iter().any(|uuid| uuid == PHONEKEY_SERVICE_UUID) {
            phonekey_callback.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    let token = watcher.Received(&handler)?;
    watcher.Start()?;
    println!("Watcher after start: {:?}", watcher.Status()?);
    thread::sleep(Duration::from_secs(10));
    println!("Watcher after 10 seconds: {:?}", watcher.Status()?);
    watcher.Stop()?;
    watcher.RemoveReceived(token)?;
    println!("BLE advertisements: {}; with service UUIDs: {}; PhoneKey: {}",
        total.load(Ordering::Relaxed),
        with_uuids.load(Ordering::Relaxed),
        phonekey.load(Ordering::Relaxed));
    Ok(())
}
