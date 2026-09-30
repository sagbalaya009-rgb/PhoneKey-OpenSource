use crate::account_binding::{self, AccountBindingError};

use crate::credential_login::{
    CredentialLoginState, CredentialLoginTransaction, CredentialRedeemError,
};

use crate::enrollment_authority::{EnrollmentAuthority, EnrollmentAuthorityError};

use crate::login_authority::{LoginAuthority, LoginAuthorityError};
use crate::password_vault;

use crate::ipc_protocol::{self, Command, HEADER_LENGTH, MAX_IPC_PAYLOAD, ResponseStatus};

use crate::state::WindowsIdentity;

use phonekey_protocol::types::DeviceId;

use std::error::Error;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::mpsc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::core::{BOOL, Error as WindowsError, PCWSTR, PWSTR, w};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, HANDLE, HLOCAL, LocalFree, WAIT_TIMEOUT, WIN32_ERROR,
};

use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};

use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};

use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};

use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use windows::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};
use windows::Win32::System::Threading::{CreateEventW, GetCurrentThread, OpenThreadToken};

type IpcError = Box<dyn Error + Send + Sync>;

const MAX_FRAME_LENGTH: usize = HEADER_LENGTH + MAX_IPC_PAYLOAD;

/*
 * Availability policy:
 *
 * - Fixed worker count: memory/thread use cannot grow per client.
 * - Multiple instances: one stalled local client cannot own the
 *   entire PhoneKey control plane.
 * - Connect polling: service shutdown is observed promptly.
 * - Read/write/response-drain deadlines: connected clients cannot
 *   hold a worker indefinitely by withholding requests or response reads.
 */
const PIPE_INSTANCE_COUNT: usize = 4;
const PIPE_BUFFER_SIZE: u32 = 4096;
const CONNECT_POLL_TIMEOUT_MS: u32 = 1_000;
const CLIENT_READ_TIMEOUT_MS: u32 = 2_000;
const CLIENT_WRITE_TIMEOUT_MS: u32 = 2_000;
const CLIENT_RESPONSE_DRAIN_TIMEOUT_MS: u32 = 2_000;

struct Authorities {
    enrollment_authority: EnrollmentAuthority,
    login_authority: LoginAuthority,
    credential_login: Option<CredentialLoginTransaction>,
}

/*
 * Work handed out only after the authority lock is released.
 *
 * session_id is carried back into the worker so stale asynchronous
 * BLE results can never mutate a newer Credential Provider login.
 */
struct CredentialLoginWork {
    session_id: phonekey_protocol::types::SessionId,
    target_sid: String,
    challenge_bytes: Vec<u8>,
    expires_at_ms: u64,
}

const _: () = {
    assert!(PIPE_INSTANCE_COUNT == 4);
    assert!(PIPE_INSTANCE_COUNT > 1);
    assert!(PIPE_INSTANCE_COUNT <= 8);

    assert!(CONNECT_POLL_TIMEOUT_MS > 0);
    assert!(CONNECT_POLL_TIMEOUT_MS <= 2_000);

    assert!(CLIENT_READ_TIMEOUT_MS > 0);
    assert!(CLIENT_READ_TIMEOUT_MS <= 5_000);

    assert!(CLIENT_WRITE_TIMEOUT_MS > 0);
    assert!(CLIENT_WRITE_TIMEOUT_MS <= 5_000);

    assert!(CLIENT_RESPONSE_DRAIN_TIMEOUT_MS > 0);
    assert!(CLIENT_RESPONSE_DRAIN_TIMEOUT_MS <= 5_000);

    assert!(PIPE_BUFFER_SIZE as usize >= MAX_FRAME_LENGTH);
};
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

struct SidGuard(PSID);

impl Drop for SidGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

struct CallerContext {
    sid: String,

    is_administrator: bool,
}

const PIPE_NAME: PCWSTR = w!(r"\\.\pipe\PhoneKey.Control.v2");
// Client rights exclude FILE_CREATE_PIPE_INSTANCE (0x4), WRITE_DAC and
// WRITE_OWNER. Only LocalSystem can create additional server instances.
const PIPE_SECURITY: PCWSTR = w!("D:P(A;;GA;;;SY)(A;;0x0012019b;;;BA)(A;;0x0012019b;;;IU)");

pub fn start(
    identity: WindowsIdentity,
    enrollment_authority: EnrollmentAuthority,
    login_authority: LoginAuthority,
    stop_requested: Arc<AtomicBool>,
    protected_state: crate::protected_state::ProtectedStateGuard,
) -> Result<thread::JoinHandle<Result<(), IpcError>>, IpcError> {
    // Acquire every listener before spawning the supervisor; propagate errors
    // to SCM instead of retrying indefinitely while reporting Running.
    let pipes = crate::ipc_lifecycle::prepare_pool(PIPE_INSTANCE_COUNT, |first| {
        create_secure_pipe(PIPE_NAME, PIPE_SECURITY, first)
    })?;
    let supervisor_stop = Arc::clone(&stop_requested);
    crate::ipc_lifecycle::start_supervisor(stop_requested, Duration::from_secs(5), move |ready| {
        serve(
            identity,
            enrollment_authority,
            login_authority,
            supervisor_stop,
            pipes,
            ready,
            protected_state,
        )
    })
}

fn serve(
    identity: WindowsIdentity,
    enrollment_authority: EnrollmentAuthority,
    login_authority: LoginAuthority,
    stop_requested: Arc<AtomicBool>,
    pipes: Vec<OwnedHandle>,
    ready: mpsc::Sender<()>,
    _protected_state: crate::protected_state::ProtectedStateGuard,
) -> Result<(), IpcError> {
    let identity = Arc::new(identity);

    let authorities = Arc::new(Mutex::new(Authorities {
        enrollment_authority,
        login_authority,
        credential_login: None,
    }));

    let ble_authorities = Arc::clone(&authorities);
    let ble_stop = Arc::clone(&stop_requested);
    let (mut ble_worker, ble_sender) =
        crate::ble_lifecycle::Worker::start(Arc::clone(&stop_requested), move |work| {
            run_credential_login_work(Arc::clone(&ble_authorities), work, Arc::clone(&ble_stop))
        })?;

    let mut workers: Vec<thread::JoinHandle<Result<(), IpcError>>> =
        Vec::with_capacity(PIPE_INSTANCE_COUNT);

    for (worker_index, pipe) in pipes.into_iter().enumerate() {
        let worker_identity = Arc::clone(&identity);
        let worker_authorities = Arc::clone(&authorities);
        let worker_stop = Arc::clone(&stop_requested);
        let worker_ble_sender = ble_sender.clone();

        let worker = match thread::Builder::new()
            .name(format!("phonekey-ipc-{worker_index}"))
            .spawn(move || {
                serve_worker(
                    pipe,
                    worker_identity,
                    worker_authorities,
                    worker_stop,
                    worker_ble_sender,
                )
            }) {
            Ok(worker) => worker,

            Err(error) => {
                stop_requested.store(true, Ordering::SeqCst);

                for worker in workers {
                    let _ = worker.join();
                }

                return Err(Box::new(error));
            }
        };

        workers.push(worker);
    }

    // Main can report Running only after every listener worker exists.
    let startup_abandoned = stop_requested.load(Ordering::SeqCst)
        || ble_worker.is_finished()
        || workers.iter().any(|worker| worker.is_finished())
        || ready.send(()).is_err();
    drop(ready);
    if startup_abandoned {
        stop_requested.store(true, Ordering::SeqCst);
    }
    let mut unexpected_worker_exit = false;

    while !stop_requested.load(Ordering::SeqCst) {
        if ble_worker.is_finished() || workers.iter().any(|worker| worker.is_finished()) {
            unexpected_worker_exit = true;
            stop_requested.store(true, Ordering::SeqCst);
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let mut worker_error = None;

    for worker in workers {
        let result = worker
            .join()
            .unwrap_or_else(|_| Err("PhoneKey IPC worker panicked".into()));
        if let Err(error) = result {
            worker_error.get_or_insert(error);
        }
    }

    if let Err(error) = ble_worker.shutdown() {
        worker_error.get_or_insert(error);
    }
    if let Some(error) = worker_error {
        return Err(error);
    }
    if startup_abandoned {
        return Err("PhoneKey IPC stopped before readiness acknowledgment".into());
    }

    if unexpected_worker_exit {
        return Err("PhoneKey IPC or BLE worker exited unexpectedly".into());
    }

    Ok(())
}

fn serve_worker(
    pipe_owner: OwnedHandle,
    identity: Arc<WindowsIdentity>,
    authorities: Arc<Mutex<Authorities>>,
    stop_requested: Arc<AtomicBool>,
    ble_sender: crate::ble_lifecycle::WorkSender<CredentialLoginWork>,
) -> Result<(), IpcError> {
    // Retain and reuse this handle for the worker's entire lifetime.
    let pipe = HANDLE(pipe_owner.as_raw_handle());
    while !stop_requested.load(Ordering::SeqCst) {
        let connected = connect_client(pipe)?;
        if connected && !stop_requested.load(Ordering::SeqCst) {
            let response_sent = match handle_client(pipe, &identity, &authorities, &ble_sender) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!("PhoneKey IPC client rejected: {error}");
                    false
                }
            };
            if response_sent && let Err(error) = wait_for_client_close_after_response(pipe) {
                eprintln!("PhoneKey IPC client response drain failed: {error}");
            }
        }
        // No FlushFileBuffers. Disconnect also resets a timed-out accept;
        // the handle stays owned, so client churn never releases the pipe name.
        disconnect_client(pipe)?;
    }
    Ok(())
}

fn disconnect_client(pipe: HANDLE) -> Result<(), IpcError> {
    match unsafe { DisconnectNamedPipe(pipe) } {
        Ok(()) => Ok(()),
        Err(error) if win32_error_is(&error, ERROR_PIPE_NOT_CONNECTED.0) => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

fn create_secure_pipe(
    name: PCWSTR,
    security: PCWSTR,
    first: bool,
) -> Result<OwnedHandle, IpcError> {
    /*
     * SY = LocalSystem
     * BA = Administrators
     * IU = Interactive Users
     *
     * Interactive users may connect because the normal
     * PhoneKey broker is intentionally unprivileged.
     *
     * Connection permission is NOT authorization.
     * Sensitive commands remain independently authorized
     * from the impersonated Windows token.
     */
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?;
    }

    let descriptor_guard = SecurityDescriptorGuard(descriptor);

    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,

        lpSecurityDescriptor: descriptor_guard.0.0,

        bInheritHandle: false.into(),
    };

    let pipe = unsafe {
        CreateNamedPipeW(
            name,
            pipe_open_mode(first),
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_INSTANCE_COUNT as u32,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            CONNECT_POLL_TIMEOUT_MS,
            Some(&attributes as *const SECURITY_ATTRIBUTES),
        )
    };

    if pipe.is_invalid() {
        return Err(Box::new(WindowsError::from_thread()));
    }

    drop(descriptor_guard);

    // Sole ownership transfers safely across threads through OwnedHandle.
    Ok(unsafe { OwnedHandle::from_raw_handle(pipe.0) })
}

fn pipe_open_mode(first: bool) -> windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES {
    let mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        mode | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        mode
    }
}

fn connect_client(pipe: HANDLE) -> Result<bool, IpcError> {
    let (mut overlapped, _event_guard) = new_overlapped_operation()?;

    let connection = unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) };

    match connection {
        Ok(()) => Ok(true),

        Err(error) if win32_error_is(&error, ERROR_PIPE_CONNECTED.0) => Ok(true),

        Err(error)
            if win32_error_is(&error, ERROR_NO_DATA.0)
                || win32_error_is(&error, ERROR_BROKEN_PIPE.0) =>
        {
            Ok(false)
        }

        Err(error) if win32_error_is(&error, ERROR_IO_PENDING.0) => {
            match wait_for_overlapped(pipe, &mut overlapped, CONNECT_POLL_TIMEOUT_MS)? {
                Some(_) => Ok(true),

                None => Ok(false),
            }
        }

        Err(error) => Err(Box::new(error)),
    }
}

fn handle_client(
    pipe: HANDLE,
    identity: &WindowsIdentity,
    authorities: &Arc<Mutex<Authorities>>,
    ble_sender: &crate::ble_lifecycle::WorkSender<CredentialLoginWork>,
) -> Result<(), IpcError> {
    /*
     * One complete PhoneKey frame must occupy one
     * message-mode named-pipe message.
     *
     * Maximum frame:
     * 12-byte header + 2048-byte payload.
     *
     * The read happens BEFORE the authority mutex is taken.
     * A silent client therefore cannot lock privileged state.
     */
    let mut request_bytes = read_message(pipe)?;

    let mut request = ipc_protocol::decode_request(&request_bytes)?;

    /*
     * The client never tells us who it is.
     *
     * LocalSystem asks Windows by impersonating the
     * actual named-pipe client.
     */
    let caller = caller_context(pipe)?;

    if let Err(status) = authorize_command(request.command, &caller) {
        if matches!(
            request.command,
            Command::ProvisionPasswordVault
                | Command::RotatePasswordVault
                | Command::ProvisionLocalPasswordVault
                | Command::RotateLocalPasswordVault
        ) {
            request_bytes.fill(0);
            request.payload.fill(0);
        }
        return send_response(pipe, status, &[]);
    }

    let mut credential_work = None;

    let (status, mut payload) = {
        /*
         * Privileged state transitions remain serialized even
         * though transport clients are concurrent.
         */
        let mut guard = authorities
            .lock()
            .map_err(|_| "PhoneKey authority lock poisoned")?;

        let authorities = &mut *guard;

        let result = dispatch_request(
            request.command,
            &request.payload,
            identity,
            &caller,
            &mut authorities.enrollment_authority,
            &mut authorities.login_authority,
            &mut authorities.credential_login,
            &mut credential_work,
        );
        if matches!(
            request.command,
            Command::ProvisionPasswordVault
                | Command::RotatePasswordVault
                | Command::ProvisionLocalPasswordVault
                | Command::RotateLocalPasswordVault
        ) {
            request_bytes.fill(0);
            request.payload.fill(0);
        }
        result?
    };

    /*
     * Any BLE work is started only after the authority mutex has
     * been released.
     */
    if let Some(work) = credential_work {
        let session_id = work.session_id;
        let target_sid = work.target_sid.clone();

        if let Err(error) = ble_sender.submit(work) {
            /*
             * Fail closed if the single worker is busy or stopping. Do not leave a
             * LoginAuthority challenge or Credential Provider transaction
             * stranded in Pending state.
             */
            let mut guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;

            let is_current = guard
                .credential_login
                .as_ref()
                .is_some_and(|transaction| transaction.session_id == session_id);

            if is_current {
                let _ = guard.login_authority.cancel(&target_sid);
                guard.credential_login = None;
            }

            drop(guard);
            eprintln!("PhoneKey BLE admission rejected: {error}");
            return send_response(pipe, ResponseStatus::Conflict, &[]);
        }
    }

    let result = send_response(pipe, status, &payload);
    if matches!(
        request.command,
        Command::RedeemCredentialProviderPassword | Command::RedeemCredentialProviderLocalPassword
    ) {
        payload.fill(0);
    }
    result
}

fn work_is_current(
    transaction: Option<&CredentialLoginTransaction>,
    session_id: &phonekey_protocol::types::SessionId,
    stop_requested: &AtomicBool,
) -> bool {
    !stop_requested.load(Ordering::SeqCst)
        && transaction.is_some_and(|transaction| {
            transaction.session_id == *session_id && !transaction.state.is_terminal()
        })
}

fn run_credential_login_work(
    authorities: Arc<Mutex<Authorities>>,
    work: CredentialLoginWork,
    stop_requested: Arc<AtomicBool>,
) -> Result<(), IpcError> {
    // Start discovery as soon as the QR is created. The updated Android app
    // holds an early challenge until the matching QR is scanned, so waiting
    // here only consumes the 60-second challenge lifetime and delays the
    // biometric prompt. Cancellation remains enforced by the BLE exchange.
    run_credential_login_work_using(
        authorities,
        work,
        stop_requested,
        |challenge, expiry, stop, cancelled, progress| {
            crate::ble_transport::exchange_login(challenge, expiry, stop, cancelled, progress)
        },
    )
}

// One transport boundary allows deterministic cancellation-race tests to run
// through the production authority/result-handling path without using a radio.
fn run_credential_login_work_using(
    authorities: Arc<Mutex<Authorities>>,
    work: CredentialLoginWork,
    stop_requested: Arc<AtomicBool>,
    exchange: impl FnOnce(
        &[u8],
        u64,
        &AtomicBool,
        &mut dyn FnMut() -> Result<bool, IpcError>,
        &mut dyn FnMut(crate::ble_transport::LoginBleProgress) -> Result<(), IpcError>,
    ) -> Result<Option<Vec<u8>>, IpcError>,
) -> Result<(), IpcError> {
    /*
     * Mark the transaction as scanning before entering BLE.
     * The lock is released before any Bluetooth operation.
     */
    {
        let mut guard = authorities
            .lock()
            .map_err(|_| "PhoneKey authority lock poisoned")?;

        let Some(transaction) = guard.credential_login.as_mut() else {
            return Ok(());
        };

        if !work_is_current(Some(transaction), &work.session_id, &stop_requested) {
            return Ok(());
        }

        transaction
            .transition(CredentialLoginState::Scanning)
            .map_err(|error| -> IpcError { error.into() })?;
    }

    let mut report_progress =
        |progress: crate::ble_transport::LoginBleProgress| -> Result<(), IpcError> {
            let mut guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;
            let Some(transaction) = guard.credential_login.as_mut() else {
                return Ok(());
            };
            if !work_is_current(Some(transaction), &work.session_id, &stop_requested) {
                return Ok(());
            }
            let next = match progress {
                crate::ble_transport::LoginBleProgress::DeviceFound => {
                    CredentialLoginState::Connecting
                }
                crate::ble_transport::LoginBleProgress::ChallengeDelivered => {
                    CredentialLoginState::WaitingForProof
                }
            };
            transaction
                .transition(next)
                .map_err(|error| -> IpcError { error.into() })
        };
    let exchange_result = exchange(
        &work.challenge_bytes,
        work.expires_at_ms,
        &stop_requested,
        &mut || {
            let guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;
            Ok(!work_is_current(
                guard.credential_login.as_ref(),
                &work.session_id,
                &stop_requested,
            ))
        },
        &mut report_progress,
    );

    match exchange_result {
        Ok(Some(proof)) => {
            let mut guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;

            /*
             * The BLE operation may have completed after cancellation
             * and even after a newer login began. Only the transaction
             * that created this worker may consume its result.
             */
            let is_current = work_is_current(
                guard.credential_login.as_ref(),
                &work.session_id,
                &stop_requested,
            );

            if !is_current {
                return Ok(());
            }

            guard
                .credential_login
                .as_mut()
                .expect("current transaction checked above")
                .transition(CredentialLoginState::Verifying)
                .map_err(|error| -> IpcError { error.into() })?;

            let now = unix_time_ms()?;

            let verification = guard
                .login_authority
                .submit_proof(&proof, &work.target_sid, now);

            /*
             * Re-check session identity before publishing the terminal
             * result. This keeps asynchronous BLE results transaction-bound.
             */
            let Some(transaction) = guard.credential_login.as_mut() else {
                return Ok(());
            };

            if !work_is_current(Some(transaction), &work.session_id, &stop_requested) {
                return Ok(());
            }

            let terminal_state = match verification {
                Ok(()) => CredentialLoginState::Authenticated,

                Err(error) => match login_error_status(&error) {
                    ResponseStatus::Expired => CredentialLoginState::Expired,
                    ResponseStatus::InternalError => CredentialLoginState::TransportError,
                    _ => CredentialLoginState::Rejected,
                },
            };

            transaction
                .transition(terminal_state)
                .map_err(|error| -> IpcError { error.into() })?;
        }

        Ok(None) => {
            let mut guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;

            let is_current = work_is_current(
                guard.credential_login.as_ref(),
                &work.session_id,
                &stop_requested,
            );

            if !is_current {
                return Ok(());
            }

            /*
             * BLE timed out. Destroy the matching LoginAuthority
             * challenge so it cannot block the next login attempt.
             */
            let _ = guard.login_authority.cancel(&work.target_sid);

            let Some(transaction) = guard.credential_login.as_mut() else {
                return Ok(());
            };

            if !work_is_current(Some(transaction), &work.session_id, &stop_requested) {
                return Ok(());
            }

            transaction
                .transition(CredentialLoginState::Expired)
                .map_err(|error| -> IpcError { error.into() })?;
        }

        Err(error) => {
            // Preserve fatal cancellation failures through the owned worker
            // join and onward to SCM instead of reporting a clean stop.
            if stop_requested.load(Ordering::SeqCst) {
                return Err(error);
            }
            eprintln!("PhoneKey BLE login transport failed: {error}");

            let mut guard = authorities
                .lock()
                .map_err(|_| "PhoneKey authority lock poisoned")?;

            let is_current = work_is_current(
                guard.credential_login.as_ref(),
                &work.session_id,
                &stop_requested,
            );

            if !is_current {
                return Ok(());
            }

            /*
             * Transport failure is terminal for this transaction.
             * Clear the underlying LoginAuthority challenge as well.
             */
            let _ = guard.login_authority.cancel(&work.target_sid);

            let Some(transaction) = guard.credential_login.as_mut() else {
                return Ok(());
            };

            if !work_is_current(Some(transaction), &work.session_id, &stop_requested) {
                return Ok(());
            }

            transaction
                .transition(CredentialLoginState::TransportError)
                .map_err(|error| -> IpcError { error.into() })?;
        }
    }

    Ok(())
}
// CallerContext is obtained from the impersonated pipe client's token, never
// from a SID supplied in the request. Administrator membership is not SYSTEM.
fn authorize_command(command: Command, caller: &CallerContext) -> Result<(), ResponseStatus> {
    if (command.requires_system() && caller.sid != "S-1-5-18")
        || (command.requires_administrator() && !caller.is_administrator)
    {
        return Err(ResponseStatus::Unauthorized);
    }
    Ok(())
}

fn dispatch_request(
    command: Command,
    payload: &[u8],
    identity: &WindowsIdentity,
    caller: &CallerContext,
    enrollment_authority: &mut EnrollmentAuthority,
    login_authority: &mut LoginAuthority,
    credential_login: &mut Option<CredentialLoginTransaction>,
    credential_work: &mut Option<CredentialLoginWork>,
) -> Result<(ResponseStatus, Vec<u8>), IpcError> {
    // Keep the authorization boundary at dispatch as well as before locking.
    if let Err(status) = authorize_command(command, caller) {
        return Ok((status, Vec::new()));
    }

    match command {
        Command::GetMachineContext => {
            let payload = ipc_protocol::encode_machine_context_payload(
                &DeviceId(identity.device_id),
                &caller.sid,
            )?;

            Ok((ResponseStatus::Success, payload))
        }

        Command::BeginEnrollment => {
            let now = unix_time_ms()?;

            let monotonic_now = Instant::now();

            match enrollment_authority.begin(
                DeviceId(identity.device_id),
                &caller.sid,
                now,
                monotonic_now,
            ) {
                Ok(challenge) => Ok((ResponseStatus::Success, challenge)),

                Err(error) => Ok((enrollment_error_status(&error), Vec::new())),
            }
        }

        Command::SubmitEnrollmentProof => {
            let now = unix_time_ms()?;

            let monotonic_now = Instant::now();

            match enrollment_authority.submit_proof(payload, now, monotonic_now) {
                /*
                 * SECURITY BOUNDARY:
                 *
                 * The unprivileged proof courier receives only
                 * Success/Failure. The derived pairing code stays
                 * inside LocalSystem.
                 */
                Ok(_) => Ok((ResponseStatus::Success, Vec::new())),

                Err(error) => Ok((enrollment_error_status(&error), Vec::new())),
            }
        }

        Command::GetEnrollmentPairingCode => {
            let now = unix_time_ms()?;

            let monotonic_now = Instant::now();

            match enrollment_authority.pairing_code_for_initiator(&caller.sid, now, monotonic_now) {
                Ok(pairing_code) => {
                    let encoded = ipc_protocol::encode_pairing_code_payload(pairing_code)?.to_vec();

                    Ok((ResponseStatus::Success, encoded))
                }

                Err(error) => Ok((enrollment_error_status(&error), Vec::new())),
            }
        }

        Command::ConfirmEnrollment => {
            let pairing_code = ipc_protocol::decode_pairing_code_payload(payload)?;

            let now = unix_time_ms()?;

            let monotonic_now = Instant::now();

            match enrollment_authority.confirm(pairing_code, &caller.sid, now, monotonic_now) {
                Ok(()) => Ok((ResponseStatus::Success, Vec::new())),

                Err(error) => Ok((enrollment_error_status(&error), Vec::new())),
            }
        }

        Command::CancelEnrollment => match enrollment_authority.cancel(&caller.sid) {
            Ok(()) => Ok((ResponseStatus::Success, Vec::new())),

            Err(error) => Ok((enrollment_error_status(&error), Vec::new())),
        },

        // Stage E accepts LoginProof only from the service-owned BLE worker.
        // Retain wire IDs 6-8, but retire the whole broker login transaction:
        // it must neither create/cancel challenges nor submit proof to the
        // authority shared with Credential Provider login. Enrollment is separate.
        Command::BeginLogin | Command::SubmitLoginProof | Command::CancelLogin => {
            Ok((ResponseStatus::BadRequest, Vec::new()))
        }

        Command::BeginCredentialProviderLogin => {
            let (operation, target_sid) =
                ipc_protocol::decode_credential_provider_begin_payload(payload)?;

            let monotonic_now = Instant::now();
            let now = unix_time_ms()?;

            /*
             * One active interactive Credential Provider login is
             * permitted system-wide in Stage E.
             *
             * A completed terminal transaction remains queryable
             * until the next explicit Begin retires it.
             */
            if let Some(transaction) = credential_login.as_ref() {
                if !transaction.state.is_terminal() {
                    return Ok((ResponseStatus::Conflict, Vec::new()));
                }

                *credential_login = None;
            }

            match login_authority.begin(&target_sid, operation, now) {
                Ok(login) => {
                    /*
                     * SECURITY BOUNDARY:
                     *
                     * The Credential Provider receives only public
                     * QR rendering material plus the opaque
                     * transaction/session ID.
                     *
                     * The raw LoginChallenge remains owned by
                     * LocalSystem and is handed only to the
                     * service-owned BLE worker.
                     */
                    let begin_response = match crate::credential_qr::encode_begin_response(
                        &DeviceId(identity.device_id),
                        &login.session_id,
                        login.expires_at_ms,
                    ) {
                        Ok(response) => response,

                        Err(_) => {
                            /*
                             * Never strand a LoginAuthority
                             * challenge if presentation-data
                             * generation fails.
                             */
                            let _ = login_authority.cancel(&target_sid);

                            return Ok((ResponseStatus::InternalError, Vec::new()));
                        }
                    };

                    *credential_login = Some(CredentialLoginTransaction::new(
                        login.session_id,
                        target_sid.clone(),
                        login.expires_at_ms,
                        monotonic_now
                            + Duration::from_millis(login.expires_at_ms.saturating_sub(now)),
                        login.trusted_android_device_id,
                        login.trusted_public_key_sec1,
                    ));

                    *credential_work = Some(CredentialLoginWork {
                        session_id: login.session_id,

                        target_sid,

                        challenge_bytes: login.challenge_bytes,

                        expires_at_ms: login.expires_at_ms,
                    });

                    Ok((ResponseStatus::Success, begin_response))
                }

                Err(error) => Ok((login_error_status(&error), Vec::new())),
            }
        }
        Command::SubmitCredentialProviderProof => {
            /*
             * IPC command ID 12 remains reserved so protocol
             * numbering never changes.
             *
             * Credential Provider-delivered LoginProof is no
             * longer an authentication path. LoginProof reaches
             * LocalSystem only through service-owned BLE.
             */
            Ok((ResponseStatus::BadRequest, Vec::new()))
        }
        Command::CancelCredentialProviderLogin => {
            let session_id = ipc_protocol::decode_credential_provider_transaction_payload(payload)?;

            let Some(transaction) = credential_login.as_ref() else {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            };

            if transaction.session_id != session_id {
                return Ok((ResponseStatus::Unauthorized, Vec::new()));
            }

            /*
             * Cancellation is idempotent for the exact completed
             * transaction and must never affect a newer session.
             */
            if transaction.state.is_terminal() {
                return Ok((ResponseStatus::Success, Vec::new()));
            }

            let target_sid = transaction.target_sid.clone();

            match login_authority.cancel(&target_sid) {
                Ok(()) => {
                    let Some(transaction) = credential_login.as_mut() else {
                        return Ok((ResponseStatus::Conflict, Vec::new()));
                    };

                    /*
                     * Defensive identity re-check before
                     * publishing terminal cancellation.
                     */
                    if transaction.session_id != session_id {
                        return Ok((ResponseStatus::Unauthorized, Vec::new()));
                    }

                    transaction
                        .cancel()
                        .map_err(|error| -> IpcError { error.into() })?;

                    /*
                     * Do NOT clear credential_login here.
                     * Cancelled is an immutable terminal result
                     * and remains queryable until the next Begin.
                     */
                    Ok((ResponseStatus::Success, Vec::new()))
                }

                Err(error) => Ok((login_error_status(&error), Vec::new())),
            }
        }
        Command::GetCredentialProviderLoginStatus => {
            let session_id = ipc_protocol::decode_credential_provider_transaction_payload(payload)?;

            let Some(transaction) = credential_login.as_ref() else {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            };

            if transaction.session_id != session_id {
                return Ok((ResponseStatus::Unauthorized, Vec::new()));
            }

            let state_byte = match transaction.state {
                CredentialLoginState::Pending => 1,
                CredentialLoginState::Scanning => 2,
                CredentialLoginState::Connecting => 3,
                CredentialLoginState::WaitingForProof => 4,
                CredentialLoginState::Verifying => 5,
                CredentialLoginState::Authenticated => 6,
                CredentialLoginState::Rejected => 7,
                CredentialLoginState::Expired => 8,
                CredentialLoginState::Cancelled => 9,
                CredentialLoginState::TransportError => 10,
            };

            Ok((ResponseStatus::Success, vec![state_byte]))
        }
        Command::RedeemCredentialProviderLogin => {
            let session_id = ipc_protocol::decode_credential_provider_transaction_payload(payload)?;
            let Some(transaction) = credential_login.as_mut() else {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            };
            if transaction.session_id != session_id {
                return Ok((ResponseStatus::Unauthorized, Vec::new()));
            }
            if transaction.state != CredentialLoginState::Authenticated {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            }
            if let Err(error) = login_authority.validate_trust_snapshot(
                &transaction.target_sid,
                transaction.trusted_android_device_id,
                &transaction.trusted_public_key_sec1,
            ) {
                return Ok((login_error_status(&error), Vec::new()));
            }
            let now = unix_time_ms()?;
            match transaction.redeem(now, Instant::now()) {
                Ok(sid) => Ok((ResponseStatus::Success, sid.as_bytes().to_vec())),
                Err(CredentialRedeemError::Unavailable) => {
                    Ok((ResponseStatus::Conflict, Vec::new()))
                }
                Err(CredentialRedeemError::Expired) => Ok((ResponseStatus::Expired, Vec::new())),
            }
        }
        Command::ProvisionPasswordVault
        | Command::RotatePasswordVault
        | Command::ProvisionLocalPasswordVault
        | Command::RotateLocalPasswordVault => {
            let bound = login_authority.bound_account_sid()?;
            if bound.as_deref() != Some(caller.sid.as_str()) {
                return Ok((ResponseStatus::Unauthorized, Vec::new()));
            }
            let mut units: Vec<u16> = payload
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let local = matches!(
                command,
                Command::ProvisionLocalPasswordVault | Command::RotateLocalPasswordVault
            );
            let vault_path = if local {
                login_authority.local_password_vault_path()
            } else {
                login_authority.password_vault_path()
            };
            let result = if matches!(
                command,
                Command::ProvisionPasswordVault | Command::ProvisionLocalPasswordVault
            ) {
                password_vault::store_new(&vault_path, &caller.sid, &units)
            } else {
                password_vault::replace(&vault_path, &caller.sid, &units)
            };
            units.fill(0);
            match result {
                Ok(()) => Ok((ResponseStatus::Success, Vec::new())),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok((ResponseStatus::Conflict, Vec::new()))
                }
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    Ok((ResponseStatus::BadRequest, Vec::new()))
                }
                Err(_) => Ok((ResponseStatus::InternalError, Vec::new())),
            }
        }
        Command::RedeemCredentialProviderPassword
        | Command::RedeemCredentialProviderLocalPassword => {
            let session_id = ipc_protocol::decode_credential_provider_transaction_payload(payload)?;
            let Some(transaction) = credential_login.as_mut() else {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            };
            if transaction.session_id != session_id {
                return Ok((ResponseStatus::Unauthorized, Vec::new()));
            }
            if transaction.state != CredentialLoginState::Authenticated {
                return Ok((ResponseStatus::Conflict, Vec::new()));
            }
            if let Err(error) = login_authority.validate_trust_snapshot(
                &transaction.target_sid,
                transaction.trusted_android_device_id,
                &transaction.trusted_public_key_sec1,
            ) {
                return Ok((login_error_status(&error), Vec::new()));
            }
            let vault_path = if command == Command::RedeemCredentialProviderLocalPassword {
                login_authority.local_password_vault_path()
            } else {
                login_authority.password_vault_path()
            };
            let password = match password_vault::load(&vault_path, &transaction.target_sid) {
                Ok(password) => password,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((ResponseStatus::Conflict, Vec::new()));
                }
                Err(_) => return Ok((ResponseStatus::InternalError, Vec::new())),
            };
            let now = unix_time_ms()?;
            match transaction.redeem(now, Instant::now()) {
                Ok(_) => {
                    let mut output = Vec::with_capacity(password.utf16.len() * 2);
                    for unit in &password.utf16 {
                        output.extend_from_slice(&unit.to_le_bytes());
                    }
                    Ok((ResponseStatus::Success, output))
                }
                Err(CredentialRedeemError::Unavailable) => {
                    Ok((ResponseStatus::Conflict, Vec::new()))
                }
                Err(CredentialRedeemError::Expired) => Ok((ResponseStatus::Expired, Vec::new())),
            }
        }
        Command::BindAuthorizedAccount => match account_binding::bind_production(&caller.sid) {
            Ok(()) => Ok((ResponseStatus::Success, Vec::new())),

            Err(error) => Ok((account_binding_error_status(&error), Vec::new())),
        },
    }
}

fn enrollment_error_status(error: &EnrollmentAuthorityError) -> ResponseStatus {
    match error {
        EnrollmentAuthorityError::Expired => ResponseStatus::Expired,

        EnrollmentAuthorityError::CallerMismatch => ResponseStatus::Unauthorized,

        EnrollmentAuthorityError::Protocol(_) => ResponseStatus::CryptographicRejection,

        EnrollmentAuthorityError::PairingCodeMismatch => ResponseStatus::CryptographicRejection,

        EnrollmentAuthorityError::AlreadyPending
        | EnrollmentAuthorityError::AlreadyEnrolled
        | EnrollmentAuthorityError::NoPendingEnrollment
        | EnrollmentAuthorityError::ProofAlreadySubmitted
        | EnrollmentAuthorityError::PairingNotReady => ResponseStatus::Conflict,

        EnrollmentAuthorityError::InvalidInitiatorSid
        | EnrollmentAuthorityError::ClockOverflow
        | EnrollmentAuthorityError::Trust(_) => ResponseStatus::InternalError,
    }
}

fn account_binding_error_status(error: &AccountBindingError) -> ResponseStatus {
    match error {
        AccountBindingError::NoTrustedPhone | AccountBindingError::AlreadyBound => {
            ResponseStatus::Conflict
        }

        AccountBindingError::InvalidSid | AccountBindingError::Io(_) => {
            ResponseStatus::InternalError
        }
    }
}

fn login_error_status(error: &LoginAuthorityError) -> ResponseStatus {
    match error {
        LoginAuthorityError::Expired => ResponseStatus::Expired,

        LoginAuthorityError::CallerMismatch | LoginAuthorityError::UnauthorizedAccount => {
            ResponseStatus::Unauthorized
        }

        LoginAuthorityError::Replay | LoginAuthorityError::ProofRejected(_) => {
            ResponseStatus::CryptographicRejection
        }

        LoginAuthorityError::NoTrustedPhone
        | LoginAuthorityError::NoAuthorizedAccount
        | LoginAuthorityError::AlreadyPending
        | LoginAuthorityError::NoPendingLogin => ResponseStatus::Conflict,

        LoginAuthorityError::AuthorizedPhoneMismatch
        | LoginAuthorityError::AccountBinding(_)
        | LoginAuthorityError::ClockOverflow
        | LoginAuthorityError::ChallengeProtocol(_)
        | LoginAuthorityError::Trust(_) => ResponseStatus::InternalError,
    }
}

fn send_response(pipe: HANDLE, status: ResponseStatus, payload: &[u8]) -> Result<(), IpcError> {
    let mut frame = ipc_protocol::encode_response(status, payload)?;
    let result = write_all(pipe, &frame);
    frame.fill(0);
    result
}

fn new_overlapped_operation() -> Result<(OVERLAPPED, HandleGuard), IpcError> {
    /*
     * Microsoft recommends a manual-reset event for an
     * OVERLAPPED operation that is waited by
     * GetOverlappedResultEx.
     */
    let event = unsafe { CreateEventW(None, true, false, PCWSTR::null())? };

    let event_guard = HandleGuard(event);

    let overlapped = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };

    Ok((overlapped, event_guard))
}

fn win32_error_is(error: &WindowsError, code: u32) -> bool {
    WIN32_ERROR::from_error(error).is_some_and(|value| value.0 == code)
}

fn cancel_and_drain_overlapped(handle: HANDLE, overlapped: &mut OVERLAPPED) {
    /*
     * The OVERLAPPED structure and any referenced buffer must
     * remain alive until cancellation has completed.
     *
     * CancelIoEx requests cancellation. GetOverlappedResult
     * then waits until that operation is no longer pending.
     */
    let _ = unsafe { CancelIoEx(handle, Some(overlapped as *const OVERLAPPED)) };

    let mut ignored = 0u32;

    let _ =
        unsafe { GetOverlappedResult(handle, overlapped as *const OVERLAPPED, &mut ignored, true) };
}

fn wait_for_overlapped(
    handle: HANDLE,
    overlapped: &mut OVERLAPPED,
    timeout_ms: u32,
) -> Result<Option<u32>, IpcError> {
    let mut transferred = 0u32;

    match unsafe {
        GetOverlappedResultEx(
            handle,
            overlapped as *const OVERLAPPED,
            &mut transferred,
            timeout_ms,
            false,
        )
    } {
        Ok(()) => Ok(Some(transferred)),

        Err(error) if win32_error_is(&error, WAIT_TIMEOUT.0) => {
            cancel_and_drain_overlapped(handle, overlapped);

            Ok(None)
        }

        Err(error) => Err(Box::new(error)),
    }
}

fn read_message(handle: HANDLE) -> Result<Vec<u8>, IpcError> {
    /*
     * One bounded message is read at a time.
     *
     * An oversized message still fails closed because the
     * supplied buffer is exactly MAX_FRAME_LENGTH.
     */
    let mut buffer = vec![0u8; MAX_FRAME_LENGTH];

    let (mut overlapped, _event_guard) = new_overlapped_operation()?;

    let read = unsafe { ReadFile(handle, Some(&mut buffer), None, Some(&mut overlapped)) };

    match read {
        Ok(()) => {}

        Err(error) if win32_error_is(&error, ERROR_IO_PENDING.0) => {}

        Err(error) => return Err(Box::new(error)),
    }

    let Some(bytes_read) = wait_for_overlapped(handle, &mut overlapped, CLIENT_READ_TIMEOUT_MS)?
    else {
        return Err("IPC client request timed out".into());
    };

    if bytes_read == 0 {
        return Err("IPC client disconnected without a request".into());
    }

    let bytes_read = usize::try_from(bytes_read)?;

    if bytes_read > MAX_FRAME_LENGTH {
        return Err("IPC frame exceeded maximum size".into());
    }

    buffer.truncate(bytes_read);

    Ok(buffer)
}

fn write_all(handle: HANDLE, source: &[u8]) -> Result<(), IpcError> {
    let mut offset = 0usize;

    while offset < source.len() {
        let (mut overlapped, _event_guard) = new_overlapped_operation()?;

        let write =
            unsafe { WriteFile(handle, Some(&source[offset..]), None, Some(&mut overlapped)) };

        match write {
            Ok(()) => {}

            Err(error) if win32_error_is(&error, ERROR_IO_PENDING.0) => {}

            Err(error) => return Err(Box::new(error)),
        }

        let Some(bytes_written) =
            wait_for_overlapped(handle, &mut overlapped, CLIENT_WRITE_TIMEOUT_MS)?
        else {
            return Err("IPC client response write timed out".into());
        };

        if bytes_written == 0 {
            return Err("IPC client disconnected during response".into());
        }

        offset += usize::try_from(bytes_written)?;
    }

    Ok(())
}

fn wait_for_client_close_after_response(handle: HANDLE) -> Result<(), IpcError> {
    /*
     * WriteFile completion alone does not prove that the client
     * consumed the response before DisconnectNamedPipe runs.
     *
     * PhoneKey IPC uses one request and one response per connection.
     * A correct client reads the complete response and then closes its
     * pipe handle. A one-byte overlapped read is therefore used as a
     * bounded close/drain wait.
     *
     * ERROR_BROKEN_PIPE means the client closed normally after consuming
     * its response. If the client refuses to read or close, timeout
     * cancellation reuses the same CancelIoEx + drain discipline used
     * by the other bounded overlapped operations.
     */
    let mut sentinel = [0u8; 1];

    let (mut overlapped, _event_guard) = new_overlapped_operation()?;

    let read = unsafe { ReadFile(handle, Some(&mut sentinel), None, Some(&mut overlapped)) };

    match read {
        Ok(()) => return Ok(()),

        Err(error) if win32_error_is(&error, ERROR_BROKEN_PIPE.0) => return Ok(()),

        Err(error) if win32_error_is(&error, ERROR_IO_PENDING.0) => {}

        Err(error) => return Err(Box::new(error)),
    }

    let mut transferred = 0u32;

    match unsafe {
        GetOverlappedResultEx(
            handle,
            &overlapped as *const OVERLAPPED,
            &mut transferred,
            CLIENT_RESPONSE_DRAIN_TIMEOUT_MS,
            false,
        )
    } {
        Ok(()) => Ok(()),

        Err(error) if win32_error_is(&error, ERROR_BROKEN_PIPE.0) => Ok(()),

        Err(error) if win32_error_is(&error, WAIT_TIMEOUT.0) => {
            cancel_and_drain_overlapped(handle, &mut overlapped);

            Ok(())
        }

        Err(error) => Err(Box::new(error)),
    }
}

// This guard stays in caller_context on the impersonating thread. The callback
// seam lets tests exercise failure/unwinding without terminating the test runner.
// Production always uses RevertToSelf and a non-returning process abort.
struct ImpersonationGuard<R: FnMut() -> bool> {
    revert: R,
    fatal: fn() -> !,
}

impl<R: FnMut() -> bool> Drop for ImpersonationGuard<R> {
    fn drop(&mut self) {
        if !(self.revert)() {
            // Do not log, dispatch, or return to the worker under a client token.
            (self.fatal)();
        }
    }
}

fn caller_context(pipe: HANDLE) -> Result<CallerContext, IpcError> {
    unsafe {
        ImpersonateNamedPipeClient(pipe)?;
    }
    let _impersonation = ImpersonationGuard {
        revert: || unsafe { RevertToSelf().is_ok() },
        fatal: std::process::abort,
    };

    // The guard reverts before any result escapes, including errors or unwinding.
    caller_context_while_impersonating()
}

fn caller_context_while_impersonating() -> Result<CallerContext, IpcError> {
    let mut token = HANDLE::default();

    unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token)?;
    }

    let _token_guard = HandleGuard(token);

    let sid = token_user_sid(token)?;

    let is_administrator = token_is_elevated_administrator(token)?;

    Ok(CallerContext {
        sid,
        is_administrator,
    })
}

fn token_user_sid(token: HANDLE) -> Result<String, IpcError> {
    let mut required_length = 0u32;

    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required_length) };

    if required_length == 0 {
        return Err("Windows returned zero TokenUser length".into());
    }

    let alignment = size_of::<usize>();

    let word_count = (required_length as usize).div_ceil(alignment);

    let mut buffer = vec![0usize; word_count];

    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required_length,
            &mut required_length,
        )?;
    }

    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

    let mut string_sid = PWSTR::null();

    unsafe {
        ConvertSidToStringSidW(token_user.User.Sid, &mut string_sid)?;
    }

    if string_sid.is_null() {
        return Err("SID conversion returned NULL".into());
    }

    let sid = unsafe { string_sid.to_string()? };

    let _ = unsafe { LocalFree(Some(HLOCAL(string_sid.0.cast()))) };

    Ok(sid)
}

fn token_is_elevated_administrator(token: HANDLE) -> Result<bool, IpcError> {
    /*
     * Built-in Administrators:
     * S-1-5-32-544
     *
     * CheckTokenMembership checks the token Windows
     * gave us while impersonating the actual client.
     *
     * A non-elevated UAC split token does not satisfy
     * this membership test as an enabled administrator.
     */
    let mut administrator_sid = PSID::default();

    unsafe {
        ConvertStringSidToSidW(w!("S-1-5-32-544"), &mut administrator_sid)?;
    }

    let _sid_guard = SidGuard(administrator_sid);

    let mut is_member = BOOL::default();

    unsafe {
        CheckTokenMembership(Some(token), administrator_sid, &mut is_member)?;
    }

    Ok(is_member.as_bool())
}

fn unix_time_ms() -> Result<u64, IpcError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let milliseconds = duration.as_millis();

    Ok(u64::try_from(milliseconds)?)
}

#[cfg(test)]
mod availability_policy_tests {
    use super::*;

    #[test]
    fn ipc_resource_policy_is_bounded() {
        let observed = std::hint::black_box((
            PIPE_INSTANCE_COUNT,
            CONNECT_POLL_TIMEOUT_MS,
            CLIENT_READ_TIMEOUT_MS,
            CLIENT_WRITE_TIMEOUT_MS,
            CLIENT_RESPONSE_DRAIN_TIMEOUT_MS,
            PIPE_BUFFER_SIZE,
            MAX_FRAME_LENGTH,
        ));

        let (
            instance_count,
            connect_timeout_ms,
            read_timeout_ms,
            write_timeout_ms,
            response_drain_timeout_ms,
            pipe_buffer_size,
            max_frame_length,
        ) = observed;

        assert_eq!(instance_count, 4);
        assert!((2..=8).contains(&instance_count));

        assert!((1..=2_000).contains(&connect_timeout_ms));
        assert!((1..=5_000).contains(&read_timeout_ms));
        assert!((1..=5_000).contains(&write_timeout_ms));
        assert!((1..=5_000).contains(&response_drain_timeout_ms));

        let pipe_buffer_size =
            usize::try_from(pipe_buffer_size).expect("PIPE_BUFFER_SIZE must fit usize");

        assert!(pipe_buffer_size >= max_frame_length);
    }
}

#[cfg(test)]
mod ipc_security_tests {
    use super::*;
    use crate::trust_store::{self, TrustedPhone};
    use p256::ecdsa::SigningKey;
    use phonekey_protocol::messages::{LoginOperation, decode_login_challenge};
    use phonekey_protocol::proof::{create_login_proof, encode_login_proof};
    use phonekey_protocol::types::SessionId;
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    const WINDOWS_ID: DeviceId = DeviceId([0x44; 16]);
    const ANDROID_ID: DeviceId = DeviceId([0x55; 16]);
    const ACCOUNT: &str = "S-1-5-21-111111111-222222222-333333333-1001";
    const CP_COMMANDS: [Command; 6] = [
        Command::BeginCredentialProviderLogin,
        Command::SubmitCredentialProviderProof,
        Command::CancelCredentialProviderLogin,
        Command::GetCredentialProviderLoginStatus,
        Command::RedeemCredentialProviderLogin,
        Command::RedeemCredentialProviderPassword,
    ];

    fn caller(sid: &str, is_administrator: bool) -> CallerContext {
        CallerContext {
            sid: sid.into(),
            is_administrator,
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        key: SigningKey,
        authorities: Authorities,
    }

    impl Fixture {
        fn new(enrolled: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let trust = directory.path().join("trusted_phone.json");
            let key = SigningKey::from_slice(&[0x01; 32]).unwrap();
            if enrolled {
                let point = key.verifying_key().to_sec1_point(false);
                let mut public_key_sec1 = [0u8; 65];
                public_key_sec1.copy_from_slice(point.as_bytes());
                trust_store::enroll_at(
                    &trust,
                    &TrustedPhone {
                        android_device_id: ANDROID_ID,
                        public_key_sec1,
                    },
                )
                .unwrap();
                account_binding::bind_at(
                    &trust.with_file_name("authorized_account.json"),
                    ACCOUNT,
                    ANDROID_ID,
                )
                .unwrap();
            }
            Self {
                _directory: directory,
                key,
                authorities: Authorities {
                    enrollment_authority: EnrollmentAuthority::from_trust_path(trust.clone()),
                    login_authority: LoginAuthority::from_trust_path(WINDOWS_ID, trust),
                    credential_login: None,
                },
            }
        }

        fn dispatch(
            &mut self,
            command: Command,
            payload: &[u8],
            who: &CallerContext,
        ) -> ((ResponseStatus, Vec<u8>), Option<CredentialLoginWork>) {
            // Never invoke the production account-binding path in a test.
            assert_ne!(command, Command::BindAuthorizedAccount);
            let mut work = None;
            let a = &mut self.authorities;
            let response = dispatch_request(
                command,
                payload,
                &WindowsIdentity {
                    device_id: WINDOWS_ID.0,
                },
                who,
                &mut a.enrollment_authority,
                &mut a.login_authority,
                &mut a.credential_login,
                &mut work,
            )
            .unwrap();
            (response, work)
        }

        fn begin_cp(&mut self) -> CredentialLoginWork {
            let payload = ipc_protocol::encode_credential_provider_begin_payload(
                LoginOperation::Logon,
                ACCOUNT,
            )
            .unwrap();
            let ((status, response), work) = self.dispatch(
                Command::BeginCredentialProviderLogin,
                &payload,
                &caller("S-1-5-18", false),
            );
            assert_eq!(status, ResponseStatus::Success);
            assert!(!response.is_empty());
            let work = work.unwrap();
            assert_eq!(work.target_sid, ACCOUNT);
            self.assert_pending(work.session_id);
            work
        }

        fn assert_pending(&self, session: SessionId) {
            let tx = self.authorities.credential_login.as_ref().unwrap();
            assert_eq!(tx.session_id, session);
            assert_eq!(tx.target_sid, ACCOUNT);
            assert_eq!(tx.state, CredentialLoginState::Pending);
            assert!(self.authorities.login_authority.has_pending());
        }
    }

    #[test]
    fn cp_authorization_requires_exact_system_sid_even_for_administrators() {
        for command in CP_COMMANDS {
            for sid in [ACCOUNT, "S-1-5-19", "S-1-5-20", "S-1-5-180", "s-1-5-18"] {
                for admin in [false, true] {
                    assert_eq!(
                        authorize_command(command, &caller(sid, admin)),
                        Err(ResponseStatus::Unauthorized)
                    );
                }
            }
            assert_eq!(
                authorize_command(command, &caller("S-1-5-18", false)),
                Ok(())
            );
        }
        for command in [
            Command::BeginEnrollment,
            Command::ConfirmEnrollment,
            Command::CancelEnrollment,
            Command::GetEnrollmentPairingCode,
            Command::BindAuthorizedAccount,
        ] {
            assert_eq!(
                authorize_command(command, &caller(ACCOUNT, false)),
                Err(ResponseStatus::Unauthorized)
            );
            assert_eq!(authorize_command(command, &caller(ACCOUNT, true)), Ok(()));
        }
        assert_eq!(
            authorize_command(Command::SubmitEnrollmentProof, &caller(ACCOUNT, false)),
            Ok(())
        );
    }

    #[test]
    fn non_system_cp_begin_cannot_create_challenge_or_queue_ble() {
        let mut f = Fixture::new(true);
        let payload =
            ipc_protocol::encode_credential_provider_begin_payload(LoginOperation::Logon, ACCOUNT)
                .unwrap();
        for admin in [false, true] {
            let (response, work) = f.dispatch(
                Command::BeginCredentialProviderLogin,
                &payload,
                &caller(ACCOUNT, admin),
            );
            assert_eq!(response, (ResponseStatus::Unauthorized, vec![]));
            assert!(work.is_none());
            assert!(f.authorities.credential_login.is_none());
            assert!(!f.authorities.login_authority.has_pending());
        }
    }

    #[test]
    fn non_system_cp_calls_cannot_read_or_change_an_active_transaction() {
        let mut f = Fixture::new(true);
        let active = f.begin_cp();
        for command in CP_COMMANDS {
            for sid in [ACCOUNT, "S-1-5-19", "S-1-5-20"] {
                let (response, work) =
                    f.dispatch(command, &active.session_id.0, &caller(sid, true));
                assert_eq!(response, (ResponseStatus::Unauthorized, vec![]));
                assert!(work.is_none());
                f.assert_pending(active.session_id);
            }
        }
    }

    #[test]
    fn retired_broker_login_commands_cannot_start_a_transaction() {
        let mut f = Fixture::new(true);
        for command in [
            Command::BeginLogin,
            Command::SubmitLoginProof,
            Command::CancelLogin,
        ] {
            for who in [
                caller(ACCOUNT, false),
                caller(ACCOUNT, true),
                caller("S-1-5-18", true),
            ] {
                let (response, work) = f.dispatch(command, &[1], &who);
                assert_eq!(response, (ResponseStatus::BadRequest, vec![]));
                assert!(work.is_none());
                assert!(f.authorities.credential_login.is_none());
                assert!(!f.authorities.login_authority.has_pending());
            }
        }
    }

    #[test]
    fn ipc_proof_and_legacy_cancel_cannot_consume_a_valid_cp_challenge() {
        let mut f = Fixture::new(true);
        let active = f.begin_cp();
        let challenge = decode_login_challenge(&active.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        for command in [
            Command::BeginLogin,
            Command::SubmitLoginProof,
            Command::CancelLogin,
            Command::SubmitCredentialProviderProof,
        ] {
            for who in [
                caller(ACCOUNT, false),
                caller(ACCOUNT, true),
                caller("S-1-5-18", true),
            ] {
                let (response, work) = f.dispatch(command, &proof, &who);
                let expected =
                    if command == Command::SubmitCredentialProviderProof && who.sid != "S-1-5-18" {
                        ResponseStatus::Unauthorized
                    } else {
                        ResponseStatus::BadRequest
                    };
                assert_eq!(response, (expected, vec![]));
                assert!(work.is_none());
                f.assert_pending(active.session_id);
            }
        }
        // The same valid proof still verifies at the trusted authority entry used
        // by the service BLE worker. Rejected IPC did not consume/cancel it.
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        assert!(!f.authorities.login_authority.has_pending());
        assert_eq!(
            f.authorities.credential_login.as_ref().unwrap().state,
            CredentialLoginState::Pending
        );
    }

    #[test]
    fn system_status_and_cancel_keep_session_binding_and_terminal_result() {
        let mut f = Fixture::new(true);
        let active = f.begin_cp();
        let system = caller("S-1-5-18", false);
        let mut wrong_session = active.session_id.0;
        wrong_session[0] ^= 1;
        for command in [
            Command::GetCredentialProviderLoginStatus,
            Command::CancelCredentialProviderLogin,
        ] {
            let (response, work) = f.dispatch(command, &wrong_session, &system);
            assert_eq!(response, (ResponseStatus::Unauthorized, vec![]));
            assert!(work.is_none());
            f.assert_pending(active.session_id);
        }
        let (response, _) = f.dispatch(
            Command::GetCredentialProviderLoginStatus,
            &active.session_id.0,
            &system,
        );
        assert_eq!(response, (ResponseStatus::Success, vec![1]));
        for _ in 0..2 {
            let (response, work) = f.dispatch(
                Command::CancelCredentialProviderLogin,
                &active.session_id.0,
                &system,
            );
            assert_eq!(response, (ResponseStatus::Success, vec![]));
            assert!(work.is_none());
            assert!(!f.authorities.login_authority.has_pending());
        }
        let (response, _) = f.dispatch(
            Command::GetCredentialProviderLoginStatus,
            &active.session_id.0,
            &system,
        );
        assert_eq!(response, (ResponseStatus::Success, vec![9]));
    }

    #[test]
    fn verified_cp_session_redeems_exactly_once_for_system() {
        let mut f = Fixture::new(true);
        let work = f.begin_cp();
        let system = caller("S-1-5-18", false);
        let (before, _) = f.dispatch(
            Command::RedeemCredentialProviderLogin,
            &work.session_id.0,
            &system,
        );
        assert_eq!(before, (ResponseStatus::Conflict, vec![]));

        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        f.authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();

        let mut wrong = work.session_id.0;
        wrong[0] ^= 1;
        let (wrong_result, _) = f.dispatch(Command::RedeemCredentialProviderLogin, &wrong, &system);
        assert_eq!(wrong_result, (ResponseStatus::Unauthorized, vec![]));
        let (ordinary_result, _) = f.dispatch(
            Command::RedeemCredentialProviderLogin,
            &work.session_id.0,
            &caller(ACCOUNT, true),
        );
        assert_eq!(ordinary_result, (ResponseStatus::Unauthorized, vec![]));

        let (first, _) = f.dispatch(
            Command::RedeemCredentialProviderLogin,
            &work.session_id.0,
            &system,
        );
        assert_eq!(
            first,
            (ResponseStatus::Success, ACCOUNT.as_bytes().to_vec())
        );
        let (second, _) = f.dispatch(
            Command::RedeemCredentialProviderLogin,
            &work.session_id.0,
            &system,
        );
        assert_eq!(second, (ResponseStatus::Conflict, vec![]));
    }

    #[test]
    fn password_vault_requires_bound_administrator_and_verified_one_time_system_proof() {
        let mut f = Fixture::new(true);
        let admin = caller(ACCOUNT, true);
        let ordinary = caller(ACCOUNT, false);
        let system = caller("S-1-5-18", false);
        let password: Vec<u16> = "dummy test password".encode_utf16().collect();
        let bytes: Vec<u8> = password
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(
            f.dispatch(Command::ProvisionPasswordVault, &bytes, &ordinary)
                .0
                .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(
                Command::ProvisionPasswordVault,
                &bytes,
                &caller("S-1-5-21-999-1001", true)
            )
            .0
            .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(Command::ProvisionPasswordVault, &bytes, &admin)
                .0
                .0,
            ResponseStatus::Success
        );
        assert_eq!(
            f.dispatch(Command::ProvisionPasswordVault, &bytes, &admin)
                .0
                .0,
            ResponseStatus::Conflict
        );
        let rotated: Vec<u8> = "dummy refreshed password"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(
            f.dispatch(Command::RotatePasswordVault, &rotated, &ordinary)
                .0
                .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(Command::RotatePasswordVault, &rotated, &admin)
                .0
                .0,
            ResponseStatus::Success
        );

        let work = f.begin_cp();
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderPassword,
                &work.session_id.0,
                &system
            )
            .0
            .0,
            ResponseStatus::Conflict
        );
        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        f.authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderPassword,
                &work.session_id.0,
                &admin
            )
            .0
            .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderPassword,
                &work.session_id.0,
                &system
            )
            .0,
            (ResponseStatus::Success, rotated)
        );
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderPassword,
                &work.session_id.0,
                &system
            )
            .0
            .0,
            ResponseStatus::Conflict
        );
    }

    #[test]
    fn local_and_microsoft_password_vaults_remain_separate() {
        let mut f = Fixture::new(true);
        let admin = caller(ACCOUNT, true);
        let ordinary = caller(ACCOUNT, false);
        let system = caller("S-1-5-18", false);
        let microsoft: Vec<u8> = "msa dummy"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let local: Vec<u8> = "local dummy"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(
            f.dispatch(Command::ProvisionPasswordVault, &microsoft, &admin)
                .0
                .0,
            ResponseStatus::Success
        );
        assert_eq!(
            f.dispatch(Command::ProvisionLocalPasswordVault, &local, &ordinary)
                .0
                .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(Command::ProvisionLocalPasswordVault, &local, &admin)
                .0
                .0,
            ResponseStatus::Success
        );
        let msa = password_vault::load(
            &f.authorities.login_authority.password_vault_path(),
            ACCOUNT,
        )
        .unwrap();
        let local_password = password_vault::load(
            &f.authorities.login_authority.local_password_vault_path(),
            ACCOUNT,
        )
        .unwrap();
        assert_eq!(msa.utf16, "msa dummy".encode_utf16().collect::<Vec<_>>());
        assert_eq!(
            local_password.utf16,
            "local dummy".encode_utf16().collect::<Vec<_>>()
        );

        let work = f.begin_cp();
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderLocalPassword,
                &work.session_id.0,
                &admin
            )
            .0
            .0,
            ResponseStatus::Unauthorized
        );
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderLocalPassword,
                &work.session_id.0,
                &system
            )
            .0
            .0,
            ResponseStatus::Conflict
        );
        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        f.authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderLocalPassword,
                &work.session_id.0,
                &system
            )
            .0,
            (ResponseStatus::Success, local)
        );
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderLocalPassword,
                &work.session_id.0,
                &system
            )
            .0
            .0,
            ResponseStatus::Conflict
        );
    }

    #[test]
    fn password_release_fails_after_phone_revocation_without_consuming_proof() {
        let mut f = Fixture::new(true);
        let work = f.begin_cp();
        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        f.authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        let system = caller("S-1-5-18", false);
        assert_eq!(
            f.dispatch(
                Command::RedeemCredentialProviderPassword,
                &work.session_id.0,
                &system
            )
            .0
            .0,
            ResponseStatus::Conflict
        ); // No vault, still unredeemed.
        assert!(
            f.authorities
                .credential_login
                .as_mut()
                .unwrap()
                .redeem(0, Instant::now())
                .is_ok()
        );

        let mut revoked = Fixture::new(true);
        let work = revoked.begin_cp();
        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&revoked.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        revoked
            .authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        revoked
            .authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        let bytes: Vec<u8> = [65u16].iter().flat_map(|unit| unit.to_le_bytes()).collect();
        assert_eq!(
            revoked
                .dispatch(
                    Command::ProvisionPasswordVault,
                    &bytes,
                    &caller(ACCOUNT, true)
                )
                .0
                .0,
            ResponseStatus::Success
        );
        std::fs::remove_file(revoked._directory.path().join("trusted_phone.json")).unwrap();
        assert_eq!(
            revoked
                .dispatch(
                    Command::RedeemCredentialProviderPassword,
                    &work.session_id.0,
                    &system
                )
                .0
                .0,
            ResponseStatus::Conflict
        );
    }

    #[test]
    fn revoking_phone_after_proof_blocks_redemption() {
        let mut f = Fixture::new(true);
        let work = f.begin_cp();
        let challenge = decode_login_challenge(&work.challenge_bytes).unwrap();
        let proof =
            encode_login_proof(&create_login_proof(&f.key, ANDROID_ID, &challenge).unwrap())
                .unwrap();
        f.authorities
            .login_authority
            .submit_proof(&proof, ACCOUNT, unix_time_ms().unwrap())
            .unwrap();
        f.authorities
            .credential_login
            .as_mut()
            .unwrap()
            .transition(CredentialLoginState::Authenticated)
            .unwrap();
        std::fs::remove_file(f._directory.path().join("trusted_phone.json")).unwrap();
        let (result, _) = f.dispatch(
            Command::RedeemCredentialProviderLogin,
            &work.session_id.0,
            &caller("S-1-5-18", false),
        );
        assert_eq!(result, (ResponseStatus::Conflict, vec![]));
    }

    #[test]
    fn administrator_enrollment_begin_and_cancel_remain_available() {
        let mut f = Fixture::new(false);
        let (response, work) = f.dispatch(Command::BeginEnrollment, &[], &caller(ACCOUNT, false));
        assert_eq!(response, (ResponseStatus::Unauthorized, vec![]));
        assert!(work.is_none());
        assert!(!f.authorities.enrollment_authority.has_pending());
        let ((status, challenge), work) =
            f.dispatch(Command::BeginEnrollment, &[], &caller(ACCOUNT, true));
        assert_eq!(status, ResponseStatus::Success);
        assert!(!challenge.is_empty());
        assert!(work.is_none());
        assert!(f.authorities.enrollment_authority.has_pending());
        let (response, work) = f.dispatch(Command::CancelEnrollment, &[], &caller(ACCOUNT, true));
        assert_eq!(response, (ResponseStatus::Success, vec![]));
        assert!(work.is_none());
        assert!(!f.authorities.enrollment_authority.has_pending());
    }

    fn unexpected_fatal() -> ! {
        panic!("unexpected fatal cleanup")
    }
    fn expected_fatal() -> ! {
        panic!("fatal cleanup selected")
    }

    #[test]
    fn impersonation_cleanup_runs_once_on_normal_return() {
        let calls = Cell::new(0);
        {
            let _guard = ImpersonationGuard {
                revert: || {
                    calls.set(calls.get() + 1);
                    true
                },
                fatal: unexpected_fatal,
            };
            assert_eq!(calls.get(), 0);
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn impersonation_cleanup_runs_before_error_escapes() {
        let calls = Cell::new(0);
        let result = (|| -> Result<(), &'static str> {
            let _guard = ImpersonationGuard {
                revert: || {
                    calls.set(calls.get() + 1);
                    true
                },
                fatal: unexpected_fatal,
            };
            Err("token query failed")?;
            Ok(())
        })();
        assert_eq!(result, Err("token query failed"));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn impersonation_cleanup_runs_during_unwinding() {
        let calls = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = ImpersonationGuard {
                revert: || {
                    calls.set(calls.get() + 1);
                    true
                },
                fatal: unexpected_fatal,
            };
            panic!("token query panicked");
        }));
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn failed_reversion_cannot_return_to_dispatch() {
        let continued = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            {
                let _guard = ImpersonationGuard {
                    revert: || false,
                    fatal: expected_fatal,
                };
            }
            continued.set(true);
        }));
        let failure = result.expect_err("failed reversion must not return");
        assert_eq!(
            failure.downcast_ref::<&str>(),
            Some(&"fatal cleanup selected")
        );
        assert!(!continued.get());
    }
}

#[cfg(test)]
mod pipe_ownership_tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, GetAce, GetSecurityDescriptorDacl, IsWellKnownSid,
        WinBuiltinAdministratorsSid, WinInteractiveSid, WinLocalSystemSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn name() -> Vec<u16> {
        format!(
            r"\\.\pipe\PhoneKey.PoolTest.{}.{}",
            std::process::id(),
            rand::random::<u64>()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect()
    }
    // Match the real service: post an accept before a client opens a reused
    // instance. A previously disconnected instance is busy until rearmed.
    fn connect_test_client(owner: &OwnedHandle, path: &str) -> std::fs::File {
        thread::scope(|scope| {
            let accept = scope.spawn(|| connect_client(HANDLE(owner.as_raw_handle())));
            let deadline = Instant::now() + Duration::from_secs(2);
            let opened = loop {
                match OpenOptions::new()
                    .access_mode(0x0012_019b)
                    .security_qos_flags(0x0009_0000)
                    .open(path)
                {
                    Ok(client) => break Ok(client),
                    Err(error)
                        if error.raw_os_error() == Some(231) && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => break Err(error),
                }
            };
            // Joining keeps the accepted operation and its event alive through
            // completion, including when the client fails to open.
            let accepted = accept.join().expect("test accept thread panicked");
            let client = opened.expect("client could not connect to rearmed test pipe");
            assert!(
                accepted.expect("test accept failed"),
                "test accept timed out"
            );
            client
        })
    }
    #[test]
    fn production_dacl_grants_instance_creation_only_to_system() {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PIPE_SECURITY,
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .unwrap();
        }
        let guard = SecurityDescriptorGuard(descriptor);
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        unsafe {
            GetSecurityDescriptorDacl(guard.0, &mut present, &mut dacl, &mut defaulted).unwrap();
        }
        assert!(present.as_bool() && !dacl.is_null());
        assert_eq!(unsafe { (*dacl).AceCount }, 3);
        for (index, (sid_type, mask)) in [
            (WinLocalSystemSid, 0x1000_0000),
            (WinBuiltinAdministratorsSid, 0x0012_019b),
            (WinInteractiveSid, 0x0012_019b),
        ]
        .into_iter()
        .enumerate()
        {
            let mut ace = std::ptr::null_mut();
            unsafe {
                GetAce(dacl, index as u32, &mut ace).unwrap();
            }
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            assert_eq!(ace.Header.AceType, 0);
            assert_eq!(ace.Mask, mask);
            let sid = PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast());
            assert!(unsafe { IsWellKnownSid(sid, sid_type) }.as_bool());
        }
    }
    #[test]
    fn exclusive_first_instance_rejects_an_existing_endpoint() {
        let bytes = name();
        let name = PCWSTR(bytes.as_ptr());
        let owner = create_secure_pipe(name, PIPE_SECURITY, true).unwrap();
        assert!(create_secure_pipe(name, PIPE_SECURITY, true).is_err());
        drop(owner);
        let _replacement = create_secure_pipe(name, PIPE_SECURITY, true).unwrap();
    }
    #[test]
    fn idle_accept_timeout_retains_ownership_and_allows_reconnect() {
        let bytes = name();
        let name = PCWSTR(bytes.as_ptr());
        let owner = create_secure_pipe(name, PIPE_SECURITY, true).unwrap();
        let pipe = HANDLE(owner.as_raw_handle());
        assert!(!connect_client(pipe).unwrap());
        disconnect_client(pipe).unwrap();
        assert!(create_secure_pipe(name, PIPE_SECURITY, true).is_err());
        let path = String::from_utf16(&bytes[..bytes.len() - 1]).unwrap();
        let mut client = connect_test_client(&owner, &path);
        client.write_all(b"reconnected").unwrap();
        assert_eq!(read_message(pipe).unwrap(), b"reconnected");
        drop(client);
        disconnect_client(pipe).unwrap();
    }
    #[test]
    fn reduced_access_clients_work_without_granting_server_creation() {
        let bytes = name();
        let name = PCWSTR(bytes.as_ptr());
        let owner = create_secure_pipe(name, PIPE_SECURITY, true).unwrap();
        let pipe = HANDLE(owner.as_raw_handle());
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
        }
        let token = HandleGuard(token);
        let expected_sid = token_user_sid(token.0).unwrap();
        let is_system = expected_sid == "S-1-5-18";
        let additional = create_secure_pipe(name, PIPE_SECURITY, false);
        if is_system {
            assert!(
                additional.is_ok(),
                "SYSTEM must be able to acquire another server instance"
            );
        } else {
            let error = additional
                .as_ref()
                .expect_err("non-SYSTEM created another server instance");
            let error = error
                .downcast_ref::<WindowsError>()
                .expect("expected a Windows access error");
            assert!(
                win32_error_is(error, 5),
                "expected ERROR_ACCESS_DENIED, got {error}"
            );
        }
        drop(additional);
        let path = String::from_utf16(&bytes[..bytes.len() - 1]).unwrap();
        // Exercise server creation directly; std OpenOptions is not a raw Win32
        // GENERIC_WRITE access-mask probe and is not the security boundary.
        for _ in 0..16 {
            let mut client = connect_test_client(&owner, &path);
            client.write_all(b"gate").unwrap();
            assert_eq!(read_message(pipe).unwrap(), b"gate");
            assert_eq!(caller_context(pipe).unwrap().sid, expected_sid);
            write_all(pipe, b"reply").unwrap();
            let mut response = [0u8; 5];
            client.read_exact(&mut response).unwrap();
            assert_eq!(&response, b"reply");
            drop(client);
            disconnect_client(pipe).unwrap();
            assert!(
                create_secure_pipe(name, PIPE_SECURITY, true).is_err(),
                "disconnect must not release ownership of the pipe name"
            );
        }
    }
}

#[cfg(test)]
mod ble_session_tests {
    use super::*;
    use phonekey_protocol::types::SessionId;

    fn fixture() -> (
        tempfile::TempDir,
        Arc<Mutex<Authorities>>,
        CredentialLoginWork,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trusted_phone.json");
        let id = SessionId([1; 16]);
        let authorities = Arc::new(Mutex::new(Authorities {
            enrollment_authority: EnrollmentAuthority::from_trust_path(path.clone()),
            login_authority: LoginAuthority::from_trust_path(DeviceId([2; 16]), path),
            credential_login: Some(CredentialLoginTransaction::new(
                id,
                "S-1-5-21-test".into(),
                unix_time_ms().unwrap() + 1000,
                Instant::now() + Duration::from_secs(1),
                DeviceId([1; 16]),
                [2; 65],
            )),
        }));
        let work = CredentialLoginWork {
            session_id: id,
            target_sid: "S-1-5-21-test".into(),
            challenge_bytes: vec![1],
            expires_at_ms: unix_time_ms().unwrap() + 1000,
        };
        (directory, authorities, work)
    }

    #[test]
    fn canceled_or_replaced_session_cannot_continue_ble_or_publish_proof() {
        // Cancellation that races an in-flight exchange must preserve its
        // terminal state, and the exchange must run without the authority lock.
        for replace in [false, true] {
            let (_directory, authorities, work) = fixture();
            let callback_authorities = authorities.clone();
            run_credential_login_work_using(
                authorities.clone(),
                work,
                Arc::new(AtomicBool::new(false)),
                move |_, _, _, cancelled, _| {
                    assert!(!cancelled()?);
                    {
                        let mut a = callback_authorities
                            .try_lock()
                            .expect("BLE must not hold authority lock");
                        if replace {
                            a.credential_login = Some(CredentialLoginTransaction::new(
                                SessionId([3; 16]),
                                "S-1-5-21-test".into(),
                                unix_time_ms().unwrap() + 1000,
                                Instant::now() + Duration::from_secs(1),
                                DeviceId([1; 16]),
                                [2; 65],
                            ));
                        } else {
                            a.credential_login.as_mut().unwrap().cancel().unwrap();
                        }
                    }
                    assert!(cancelled()?);
                    Ok(Some(vec![0xAA])) // Late transport result must be discarded, not verified.
                },
            )
            .unwrap();
            let a = authorities.lock().unwrap();
            let transaction = a.credential_login.as_ref().unwrap();
            assert_eq!(
                transaction.state,
                if replace {
                    CredentialLoginState::Pending
                } else {
                    CredentialLoginState::Cancelled
                }
            );
            if replace {
                assert_eq!(transaction.session_id, SessionId([3; 16]));
            }
        }
    }

    #[test]
    fn service_stop_blocks_current_session_results() {
        let (_directory, authorities, work) = fixture();
        run_credential_login_work_using(
            authorities.clone(),
            work,
            Arc::new(AtomicBool::new(true)),
            |_, _, _, _, _| panic!("stopped service must not start BLE"),
        )
        .unwrap();
        assert_eq!(
            authorities
                .lock()
                .unwrap()
                .credential_login
                .as_ref()
                .unwrap()
                .state,
            CredentialLoginState::Pending
        );

        let (_directory, authorities, work) = fixture();
        let stop = Arc::new(AtomicBool::new(false));
        run_credential_login_work_using(
            authorities.clone(),
            work,
            stop.clone(),
            |_, _, _, cancelled, _| {
                stop.store(true, Ordering::SeqCst);
                assert!(cancelled()?);
                Ok(Some(vec![0xAA]))
            },
        )
        .unwrap();
        assert_eq!(
            authorities
                .lock()
                .unwrap()
                .credential_login
                .as_ref()
                .unwrap()
                .state,
            CredentialLoginState::Scanning
        );
    }

    #[test]
    fn service_owned_ble_progress_reaches_login_status() {
        let (_directory, authorities, work) = fixture();
        let observed = authorities.clone();
        run_credential_login_work_using(
            authorities,
            work,
            Arc::new(AtomicBool::new(false)),
            move |_, _, _, _, progress| {
                progress(crate::ble_transport::LoginBleProgress::DeviceFound)?;
                assert_eq!(
                    observed
                        .lock()
                        .unwrap()
                        .credential_login
                        .as_ref()
                        .unwrap()
                        .state,
                    CredentialLoginState::Connecting
                );
                progress(crate::ble_transport::LoginBleProgress::ChallengeDelivered)?;
                assert_eq!(
                    observed
                        .lock()
                        .unwrap()
                        .credential_login
                        .as_ref()
                        .unwrap()
                        .state,
                    CredentialLoginState::WaitingForProof
                );
                Ok(None)
            },
        )
        .unwrap();
    }
}
