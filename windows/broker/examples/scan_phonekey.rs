//! Read-only BLE advertisement probe. Run with `cargo run -p broker --example scan_phonekey`.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
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
    let found = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&found);
    let watcher = BluetoothLEAdvertisementWatcher::new()?;
    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;

    let handler = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(
        move |_watcher: Ref<'_, BluetoothLEAdvertisementWatcher>,
              args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
            let args = args.ok()?;
            if args
                .Advertisement()?
                .ServiceUuids()?
                .into_iter()
                .any(|uuid| uuid == PHONEKEY_SERVICE_UUID)
            {
                seen.store(true, Ordering::SeqCst);
            }
            Ok(())
        },
    );

    let token = watcher.Received(&handler)?;
    watcher.Start()?;
    for _ in 0..100 {
        if found.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    watcher.Stop()?;
    watcher.RemoveReceived(token)?;

    if found.load(Ordering::SeqCst) {
        println!("PHONEKEY BLE ADVERTISEMENT FOUND");
    } else {
        eprintln!("PhoneKey BLE advertisement not found within 10 seconds");
        std::process::exit(1);
    }
    Ok(())
}
