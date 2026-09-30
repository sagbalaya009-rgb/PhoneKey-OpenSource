use broker::ipc_client;

use std::error::Error;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use phonekey_protocol::enrollment::decode_enrollment_challenge;
use phonekey_protocol::messages::decode_login_challenge;

use windows::core::{Array, GUID, Ref};

use windows::Devices::Bluetooth::{
    Advertisement::{
        BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
        BluetoothLEScanningMode,
    },
    BluetoothCacheMode, BluetoothLEDevice,
};

use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCommunicationStatus, GattWriteOption,
};

use windows::Foundation::TypedEventHandler;
use windows::Security::Cryptography::CryptographicBuffer;

const PHONEKEY_SERVICE_UUID: GUID = GUID::from_u128(0x7d2ea28af7bd485abd9d92ad6ecfe93e);

const PHONEKEY_CHALLENGE_UUID: GUID = GUID::from_u128(0x7d2ea28bf7bd485abd9d92ad6ecfe93e);

const PHONEKEY_PROOF_UUID: GUID = GUID::from_u128(0x7d2ea28cf7bd485abd9d92ad6ecfe93e);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before Unix epoch")
        .as_millis() as u64
}

fn run_enrollment() -> Result<(), Box<dyn Error>> {
    println!("PhoneKey Windows Broker");
    println!("LOCALSYSTEM-OWNED PHONE ENROLLMENT");
    println!();

    let challenge_path = ipc_client::enrollment_challenge_path();

    if !challenge_path.exists() {
        println!("ENROLLMENT NOT STARTED");
        println!();
        println!("The LocalSystem service has not issued an enrollment challenge.");
        println!("Run the privileged BEGIN helper first.");
        println!();
        println!("Challenge courier file:");
        println!("{}", challenge_path.display());

        return Ok(());
    }

    let challenge_bytes = std::fs::read(&challenge_path)?;

    let challenge = match decode_enrollment_challenge(&challenge_bytes) {
        Ok(challenge) => challenge,

        Err(error) => {
            println!("ENROLLMENT BLOCKED");
            println!("The LocalSystem challenge file is invalid: {error:?}");
            println!("Do not continue.");

            return Ok(());
        }
    };

    if now_ms() >= challenge.expires_at_ms {
        println!("ENROLLMENT EXPIRED");
        println!("The LocalSystem enrollment challenge is no longer live.");
        println!("Run privileged CANCEL, then begin again.");

        return Ok(());
    }

    println!(
        "LocalSystem EnrollmentChallenge loaded: {} bytes",
        challenge_bytes.len()
    );

    println!("Enrollment expires at Unix ms: {}", challenge.expires_at_ms);

    println!();
    println!("Scanning for PhoneKey...");

    let found_address = Arc::new(AtomicU64::new(0));
    let observed_advertisements = Arc::new(AtomicU64::new(0));

    let callback_address = Arc::clone(&found_address);
    let callback_observed = Arc::clone(&observed_advertisements);

    let watcher = BluetoothLEAdvertisementWatcher::new()?;

    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;

    let handler = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(
        move |_sender: Ref<'_, BluetoothLEAdvertisementWatcher>,
              args: Ref<'_, BluetoothLEAdvertisementReceivedEventArgs>| {
            let args = args.ok()?;
            callback_observed.fetch_add(1, Ordering::Relaxed);

            let advertisement = args.Advertisement()?;

            let service_uuids = advertisement.ServiceUuids()?;

            for uuid in service_uuids {
                if uuid == PHONEKEY_SERVICE_UUID {
                    let address = args.BluetoothAddress()?;

                    if callback_address
                        .compare_exchange(0, address, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        println!("PHONEKEY FOUND");

                        println!("Bluetooth address: {:012X}", address);
                    }

                    break;
                }
            }

            Ok(())
        },
    );

    let watcher_token = watcher.Received(&handler)?;

    watcher.Start()?;

    // Enrollment is infrequent, but the TECNO/Realtek pair can miss several
    // advertising intervals. Keep scanning until the live challenge expires
    // instead of giving up after an arbitrary ten seconds.
    while now_ms() < challenge.expires_at_ms {
        if found_address.load(Ordering::SeqCst) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let watcher_status = watcher.Status()?;

    watcher.Stop()?;

    watcher.RemoveReceived(watcher_token)?;

    let address = found_address.load(Ordering::SeqCst);

    if address == 0 {
        println!("ENROLLMENT FAILED: PhoneKey not found.");
        println!(
            "Bluetooth scan status: {watcher_status:?}; advertisements observed: {}",
            observed_advertisements.load(Ordering::Relaxed)
        );
        println!("LocalSystem trust remains unchanged.");

        return Ok(());
    }

    println!();
    println!("Connecting to PhoneKey...");

    let device = BluetoothLEDevice::FromBluetoothAddressAsync(address)?.join()?;

    let service_result = device
        .GetGattServicesForUuidWithCacheModeAsync(
            PHONEKEY_SERVICE_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    if service_result.Status()? != GattCommunicationStatus::Success {
        println!("ENROLLMENT FAILED: GATT connection failed.");
        println!("LocalSystem trust remains unchanged.");

        device.Close()?;

        return Ok(());
    }

    let services = service_result.Services()?;

    if services.Size()? == 0 {
        println!("ENROLLMENT FAILED: PhoneKey service missing.");
        println!("LocalSystem trust remains unchanged.");

        device.Close()?;

        return Ok(());
    }

    let service = services.GetAt(0)?;

    let challenge_result = service
        .GetCharacteristicsForUuidWithCacheModeAsync(
            PHONEKEY_CHALLENGE_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    let proof_result = service
        .GetCharacteristicsForUuidWithCacheModeAsync(
            PHONEKEY_PROOF_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    if challenge_result.Status()? != GattCommunicationStatus::Success
        || proof_result.Status()? != GattCommunicationStatus::Success
    {
        println!("ENROLLMENT FAILED: required GATT characteristics unavailable.");
        println!("LocalSystem trust remains unchanged.");

        service.Close()?;
        device.Close()?;

        return Ok(());
    }

    let challenge_characteristics = challenge_result.Characteristics()?;

    let proof_characteristics = proof_result.Characteristics()?;

    if challenge_characteristics.Size()? == 0 || proof_characteristics.Size()? == 0 {
        println!("ENROLLMENT FAILED: required characteristic missing.");
        println!("LocalSystem trust remains unchanged.");

        service.Close()?;
        device.Close()?;

        return Ok(());
    }

    let challenge_characteristic = challenge_characteristics.GetAt(0)?;

    let proof_characteristic = proof_characteristics.GetAt(0)?;

    println!("Connected.");
    println!();

    println!("Sending the exact LocalSystem EnrollmentChallenge...");

    let challenge_buffer = CryptographicBuffer::CreateFromByteArray(&challenge_bytes)?;

    let write_result = challenge_characteristic
        .WriteValueWithResultAndOptionAsync(&challenge_buffer, GattWriteOption::WriteWithResponse)?
        .join()?;

    if write_result.Status()? != GattCommunicationStatus::Success {
        println!("ENROLLMENT FAILED: challenge write failed.");
        println!("LocalSystem trust remains unchanged.");

        service.Close()?;
        device.Close()?;

        return Ok(());
    }

    println!("LocalSystem challenge delivered unchanged.");

    println!();

    println!(">>> CHECK YOUR PHONE <<<");
    println!("Approve enrollment using fingerprint or phone PIN.");

    println!();

    println!("Waiting for Android EnrollmentProof...");

    let mut received_proof: Option<Vec<u8>> = None;

    while now_ms() < challenge.expires_at_ms {
        let read_result = proof_characteristic
            .ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached)?
            .join()?;

        if read_result.Status()? == GattCommunicationStatus::Success {
            let buffer = read_result.Value()?;

            let mut byte_array = Array::<u8>::new();

            CryptographicBuffer::CopyToByteArray(&buffer, &mut byte_array)?;

            let bytes = byte_array.as_slice().to_vec();

            if !bytes.is_empty() {
                received_proof = Some(bytes);

                break;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    let proof_bytes = match received_proof {
        Some(bytes) => bytes,

        None => {
            println!();
            println!("ENROLLMENT FAILED");
            println!("No EnrollmentProof received before timeout.");
            println!("No trust has been written.");
            println!("Run privileged CANCEL before retrying.");

            service.Close()?;
            device.Close()?;

            return Ok(());
        }
    };

    println!();

    println!("EnrollmentProof received: {} bytes", proof_bytes.len());

    println!("Forwarding proof bytes unchanged to LocalSystem...");

    /*
     * SECURITY BOUNDARY:
     *
     * The broker does not decide whether this proof is valid.
     * LocalSystem owns verification and persistent trust.
     */
    match ipc_client::submit_enrollment_proof(&proof_bytes) {
        Ok(()) => {}

        Err(error) => {
            println!();
            println!("ENROLLMENT REJECTED BY LOCALSYSTEM");

            println!("{error}");

            println!();
            println!("No trust has been written.");

            service.Close()?;
            device.Close()?;

            return Ok(());
        }
    }

    println!();

    println!("========================================");

    println!("PHONEKEY SERVICE-OWNED PROOF VERIFIED");

    println!("========================================");

    println!();

    println!("LocalSystem accepted the signed EnrollmentProof.");

    println!("The pairing code was NOT returned to this broker.");

    println!("The pairing code was NOT written to a temp file.");

    println!();

    println!("Use the protected elevated PhoneKey administrator helper");

    println!("to display LocalSystem's pairing code.");

    println!();

    println!("No persistent trust exists yet.");

    println!("Confirmation is still required.");

    service.Close()?;
    device.Close()?;

    Ok(())
}

fn cancel_login_best_effort() {
    let _ = ipc_client::cancel_login();
}

fn run_authentication() -> Result<(), Box<dyn Error>> {
    println!("PhoneKey Windows Broker");
    println!("LOCALSYSTEM-OWNED AUTHENTICATION");
    println!();

    /*
     * Operation 1 = Logon.
     *
     * The broker does not supply:
     * - Windows device identity
     * - account binding
     * - nonce
     * - session ID
     * - trusted phone key
     *
     * LocalSystem owns all of them.
     */
    let challenge_bytes = match ipc_client::begin_login(1) {
        Ok(bytes) => bytes,

        Err(error) => {
            println!("AUTHENTICATION BLOCKED");
            println!("LocalSystem refused to create a login session: {error}");

            return Ok(());
        }
    };

    let challenge = match decode_login_challenge(&challenge_bytes) {
        Ok(challenge) => challenge,

        Err(error) => {
            cancel_login_best_effort();

            println!("AUTHENTICATION BLOCKED");
            println!("Invalid LocalSystem LoginChallenge: {error:?}");

            return Ok(());
        }
    };

    if now_ms() >= challenge.expires_at_ms {
        cancel_login_best_effort();

        println!("AUTHENTICATION FAILED");
        println!("LocalSystem LoginChallenge was already expired.");

        return Ok(());
    }

    println!(
        "LocalSystem LoginChallenge received: {} bytes",
        challenge_bytes.len()
    );

    println!("Session expires at Unix ms: {}", challenge.expires_at_ms);

    println!("Account binding was derived inside LocalSystem.");
    println!("Broker does not possess the trusted phone key.");
    println!();

    let transport_result = run_login_ble_transport(&challenge_bytes, challenge.expires_at_ms);

    let proof_bytes = match transport_result {
        Ok(Some(bytes)) => bytes,

        Ok(None) => {
            cancel_login_best_effort();

            return Ok(());
        }

        Err(error) => {
            cancel_login_best_effort();

            return Err(error);
        }
    };

    println!();
    println!("LoginProof received: {} bytes", proof_bytes.len());

    println!("Forwarding LoginProof bytes unchanged to LocalSystem...");

    match ipc_client::submit_login_proof(&proof_bytes) {
        Ok(()) => {
            println!();
            println!("========================================");
            println!("PHONEKEY AUTHENTICATION SUCCESS");
            println!("========================================");
            println!();
            println!("[OK] LocalSystem owned the login session");
            println!("[OK] Protected TECNO trust loaded by LocalSystem");
            println!("[OK] Real Windows Device ID enforced by LocalSystem");
            println!("[OK] Real Windows caller SID bound by LocalSystem");
            println!("[OK] Android identity checked by LocalSystem");
            println!("[OK] P-256 signature verified by LocalSystem");
            println!("[OK] Session atomically consumed against replay");
            println!("[OK] Broker received only the authentication decision");
        }

        Err(error) => {
            /*
             * Same-user invalid proofs are fail-closed by the
             * service and destroy the pending challenge.
             * CANCEL here is only defensive cleanup.
             */
            cancel_login_best_effort();

            println!();
            println!("========================================");
            println!("PHONEKEY AUTHENTICATION FAILED");
            println!("========================================");
            println!();
            println!("LocalSystem rejected the proof: {error}");
        }
    }

    Ok(())
}

fn run_login_ble_transport(
    challenge_bytes: &[u8],
    expires_at_ms: u64,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    println!("Scanning for PhoneKey...");

    let found_address = Arc::new(AtomicU64::new(0));

    let callback_address = Arc::clone(&found_address);

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

                    if callback_address
                        .compare_exchange(0, address, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        println!("PHONEKEY FOUND");

                        println!("Bluetooth address: {:012X}", address);
                    }

                    break;
                }
            }

            Ok(())
        },
    );

    let watcher_token = watcher.Received(&handler)?;

    watcher.Start()?;

    while now_ms() < expires_at_ms {
        if found_address.load(Ordering::SeqCst) != 0 {
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    watcher.Stop()?;

    watcher.RemoveReceived(watcher_token)?;

    let address = found_address.load(Ordering::SeqCst);

    if address == 0 {
        println!("AUTHENTICATION FAILED: PhoneKey not found.");

        return Ok(None);
    }

    println!();
    println!("Connecting to PhoneKey...");

    let device = BluetoothLEDevice::FromBluetoothAddressAsync(address)?.join()?;

    let service_result = device
        .GetGattServicesForUuidWithCacheModeAsync(
            PHONEKEY_SERVICE_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    if service_result.Status()? != GattCommunicationStatus::Success {
        println!("AUTHENTICATION FAILED: GATT connection failed.");

        device.Close()?;

        return Ok(None);
    }

    let services = service_result.Services()?;

    if services.Size()? == 0 {
        println!("AUTHENTICATION FAILED: PhoneKey service not found.");

        device.Close()?;

        return Ok(None);
    }

    let service = services.GetAt(0)?;

    let challenge_result = service
        .GetCharacteristicsForUuidWithCacheModeAsync(
            PHONEKEY_CHALLENGE_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    let proof_result = service
        .GetCharacteristicsForUuidWithCacheModeAsync(
            PHONEKEY_PROOF_UUID,
            BluetoothCacheMode::Uncached,
        )?
        .join()?;

    if challenge_result.Status()? != GattCommunicationStatus::Success
        || proof_result.Status()? != GattCommunicationStatus::Success
    {
        println!("AUTHENTICATION FAILED: PhoneKey characteristics unavailable.");

        service.Close()?;
        device.Close()?;

        return Ok(None);
    }

    let challenge_characteristics = challenge_result.Characteristics()?;

    let proof_characteristics = proof_result.Characteristics()?;

    if challenge_characteristics.Size()? == 0 || proof_characteristics.Size()? == 0 {
        println!("AUTHENTICATION FAILED: required GATT characteristic missing.");

        service.Close()?;
        device.Close()?;

        return Ok(None);
    }

    let challenge_characteristic = challenge_characteristics.GetAt(0)?;

    let proof_characteristic = proof_characteristics.GetAt(0)?;

    println!("Connected.");
    println!();

    println!("Sending exact LocalSystem LoginChallenge to Android...");

    let challenge_buffer = CryptographicBuffer::CreateFromByteArray(challenge_bytes)?;

    let write_result = challenge_characteristic
        .WriteValueWithResultAndOptionAsync(&challenge_buffer, GattWriteOption::WriteWithResponse)?
        .join()?;

    if write_result.Status()? != GattCommunicationStatus::Success {
        println!("AUTHENTICATION FAILED: challenge write failed.");

        service.Close()?;
        device.Close()?;

        return Ok(None);
    }

    println!("Challenge delivered unchanged.");
    println!();
    println!(">>> CHECK YOUR PHONE <<<");
    println!("Authenticate using fingerprint or phone PIN.");
    println!();
    println!("Waiting for signed LoginProof...");

    let mut received_proof: Option<Vec<u8>> = None;

    while now_ms() < expires_at_ms {
        let read_result = proof_characteristic
            .ReadValueWithCacheModeAsync(BluetoothCacheMode::Uncached)?
            .join()?;

        if read_result.Status()? == GattCommunicationStatus::Success {
            let buffer = read_result.Value()?;

            let mut byte_array = Array::<u8>::new();

            CryptographicBuffer::CopyToByteArray(&buffer, &mut byte_array)?;

            let bytes = byte_array.as_slice().to_vec();

            if !bytes.is_empty() {
                received_proof = Some(bytes);

                break;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    if received_proof.is_none() {
        println!("AUTHENTICATION FAILED");
        println!("No LoginProof received before timeout.");
    }

    service.Close()?;
    device.Close()?;

    Ok(received_proof)
}
fn main() -> Result<(), Box<dyn Error>> {
    let command = std::env::args().nth(1);

    match command.as_deref() {
        Some("enroll") => run_enrollment(),

        Some("revoke") => {
            println!("PHONEKEY REVOKE BLOCKED");
            println!();
            println!("The untrusted broker is no longer allowed to modify authoritative trust.");
            println!("Privileged service-owned revocation will be implemented separately.");

            Ok(())
        }

        Some(other) => {
            println!("Unknown PhoneKey command: {other}");

            println!();
            println!("Available commands:");
            println!("  cargo run -p broker");
            println!("  cargo run -p broker -- enroll");
            println!("  cargo run -p broker -- revoke");

            Ok(())
        }

        None => run_authentication(),
    }
}
