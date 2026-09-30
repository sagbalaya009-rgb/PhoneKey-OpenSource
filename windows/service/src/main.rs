pub mod account_binding;
mod ble_lifecycle;
pub mod ble_transport;
pub mod credential_login;
pub mod credential_qr;
pub mod enrollment_authority;
mod ipc;
mod ipc_lifecycle;
pub mod ipc_protocol;
pub mod login_authority;
mod password_vault;
mod protected_state;
mod state;
pub mod trust_store;

use std::error::Error;
use std::ffi::OsString;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};

use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "PhoneKeyService";

type AnyError = Box<dyn Error + Send + Sync>;

windows_service::define_windows_service!(ffi_service_main, service_main);

fn start_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(60),
        process_id: None,
    }
}

fn failed_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(1),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,

        current_state: ServiceState::Running,

        controls_accepted: ServiceControlAccept::STOP,

        exit_code: ServiceExitCode::Win32(0),

        checkpoint: 0,

        wait_hint: Duration::default(),

        process_id: None,
    }
}

fn stopped_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,

        current_state: ServiceState::Stopped,

        controls_accepted: ServiceControlAccept::empty(),

        exit_code: ServiceExitCode::Win32(0),

        checkpoint: 0,

        wait_hint: Duration::default(),

        process_id: None,
    }
}

fn service_main(arguments: Vec<OsString>) {
    // Failures are logged before the terminal SCM report. Once Stopped has
    // been reported successfully, return without performing additional work.
    let _ = run_service(arguments);
}

// The real SCM reporter and IPC spawner are injected so failure paths can be
// tested without registering a Windows service or opening a privileged pipe.
fn run_registered_service<T>(
    stop_requested: Arc<AtomicBool>,
    mut report_status: impl FnMut(ServiceStatus) -> Result<(), AnyError>,
    initialize: impl FnOnce() -> Result<T, AnyError>,
    spawn_ipc: impl FnOnce(
        T,
        Arc<AtomicBool>,
    ) -> Result<thread::JoinHandle<Result<(), AnyError>>, AnyError>,
) -> Result<(), AnyError> {
    let mut ipc_thread = None;
    let mut unexpected_exit = false;

    let mut outcome = (|| -> Result<(), AnyError> {
        report_status(start_pending_status())?;
        let initialized = initialize()?;
        ipc_thread = Some(spawn_ipc(initialized, Arc::clone(&stop_requested))?);
        report_status(running_status())?;

        while !stop_requested.load(Ordering::SeqCst) {
            if ipc_thread
                .as_ref()
                .expect("IPC supervisor was started")
                .is_finished()
            {
                unexpected_exit = true;
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    })();

    // Every ordinary error after registration converges here. In particular,
    // failing to report Running must not detach a still-serving supervisor.
    stop_requested.store(true, Ordering::SeqCst);
    if let Some(ipc_thread) = ipc_thread {
        if let Err(error) = report_status(stop_pending_status()) {
            if outcome.is_ok() {
                outcome = Err(error);
            } else {
                eprintln!("PhoneKey could not report StopPending: {error}");
            }
        }

        let joined = match ipc_thread.join() {
            Ok(result) => result,
            Err(_) => Err("PhoneKey IPC supervisor thread panicked".into()),
        };
        if let Err(error) = joined {
            if outcome.is_ok() {
                outcome = Err(error);
            } else {
                eprintln!("PhoneKey IPC cleanup also failed: {error}");
            }
        }
    }

    if unexpected_exit && outcome.is_ok() {
        outcome = Err("PhoneKey IPC server terminated unexpectedly".into());
    }

    let terminal_status = if outcome.is_ok() {
        stopped_status()
    } else {
        failed_status()
    };
    // StopPending has one honest checkpoint. Do not manufacture progress while
    // join is blocked. Transport-wide cancellation is a separate IPC concern.
    // Report Stopped exactly once and only after joining the IPC supervisor.
    // Always attempt the final report, including when initialization failed.
    if let Err(error) = &outcome {
        eprintln!("PhoneKey service failure: {error}");
    }
    match report_status(terminal_status) {
        Ok(()) => outcome,
        Err(error) => {
            eprintln!("PhoneKey could not report Stopped: {error}");
            outcome.and(Err(error))
        }
    }
}

fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service(_arguments: Vec<OsString>) -> Result<(), AnyError> {
    let stop_requested = Arc::new(AtomicBool::new(false));
    let control_stop = Arc::clone(&stop_requested);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                control_stop.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Registration precedes protected initialization. If registration itself
    // fails, no status handle exists and no IPC or protected work has started.
    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("PhoneKey SCM registration failed: {error}");
            return Err(Box::new(error));
        }
    };
    run_registered_service(
        stop_requested,
        |status| {
            status_handle
                .set_service_status(status)
                .map_err(|error| -> AnyError { Box::new(error) })
        },
        || {
            // No IPC can start until every privileged initialization succeeds.
            let protected_state = protected_state::ProtectedStateGuard::production()?;
            let windows_identity = state::load_or_create_windows_identity()?;
            let _trusted_phone_present = trust_store::validate_production_store()?;
            let _authorized_account_present = account_binding::validate_production_store()?;
            let enrollment_authority = enrollment_authority::EnrollmentAuthority::production()?;
            let login_authority = login_authority::LoginAuthority::production(
                phonekey_protocol::types::DeviceId(windows_identity.device_id),
            )?;
            Ok((
                windows_identity,
                enrollment_authority,
                login_authority,
                protected_state,
            ))
        },
        |(windows_identity, enrollment_authority, login_authority, protected_state), ipc_stop| {
            ipc::start(
                windows_identity,
                enrollment_authority,
                login_authority,
                ipc_stop,
                protected_state,
            )
        },
    )
}

fn console_self_test() -> Result<(), AnyError> {
    let authority = enrollment_authority::EnrollmentAuthority::production()?;

    println!("PhoneKey Windows Service");

    println!("IPC V2 SERVICE INTEGRATION");

    println!();

    println!("[OK] LocalSystem machine identity compiled");

    println!("[OK] Privileged enrollment authority compiled");

    println!("[OK] Privileged login authority compiled");

    println!("[OK] Protected persistent account authorization compiled");

    println!("[OK] Service-owned Windows SID account binding compiled");

    println!("[OK] Service-owned replay consumption compiled");

    println!("[OK] IPC V2 named-pipe server compiled");

    println!("[OK] Local-only pipe enforcement compiled");

    println!("[OK] Service-side caller impersonation compiled");

    println!("[OK] Administrator token authorization compiled");

    println!("[OK] Untrusted proof courier path compiled");

    println!("[OK] Trust-changing enrollment commands require administrator");

    println!();

    println!("IPC pipe:");

    println!("\\\\.\\pipe\\PhoneKey.Control.v2");

    println!();

    println!("Privileged trust:");

    println!("{}", authority.trust_path().display());

    println!();

    println!("This build has NOT been deployed.");

    Ok(())
}

fn main() -> Result<(), AnyError> {
    match std::env::args().nth(1).as_deref() {
        Some("console-self-test") => console_self_test(),

        Some("help") | Some("--help") | Some("-h") => {
            println!("cargo run -p phonekey-service -- console-self-test");

            Ok(())
        }

        Some(other) => {
            eprintln!("Unknown PhoneKey service command: {other}");

            Ok(())
        }

        None => {
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Instant;

    fn worker_until_stopped(
        stop: Arc<AtomicBool>,
        finished: Arc<AtomicBool>,
    ) -> thread::JoinHandle<Result<(), AnyError>> {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stop.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    return Err("test worker never received shutdown".into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            finished.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    #[test]
    fn failed_start_pending_never_initializes_or_spawns() {
        let mut states = Vec::new();
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                states.push(status.current_state);
                if status.current_state == ServiceState::StartPending {
                    Err("injected StartPending failure".into())
                } else {
                    assert!(matches!(status.exit_code, ServiceExitCode::Win32(1)));
                    Ok(())
                }
            },
            || -> Result<(), AnyError> { panic!("initialization must not run") },
            |(), _| panic!("IPC must not start"),
        );
        assert!(result.unwrap_err().to_string().contains("StartPending"));
        assert_eq!(states, [ServiceState::StartPending, ServiceState::Stopped]);
    }

    #[test]
    fn initialization_failure_never_starts_ipc() {
        let mut states = Vec::new();
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                states.push(status.current_state);
                if status.current_state == ServiceState::Stopped {
                    assert!(matches!(status.exit_code, ServiceExitCode::Win32(1)));
                }
                Ok(())
            },
            || -> Result<(), AnyError> { Err("injected protected-state failure".into()) },
            |(), _| panic!("IPC must not start"),
        );
        assert!(result.unwrap_err().to_string().contains("protected-state"));
        assert_eq!(states, [ServiceState::StartPending, ServiceState::Stopped]);
    }

    #[test]
    fn spawn_failure_reports_failed_stop_without_running() {
        let initialized = Cell::new(false);
        let mut states = Vec::new();
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                states.push(status.current_state);
                Ok(())
            },
            || {
                initialized.set(true);
                Ok(())
            },
            |(), _| {
                assert!(initialized.get());
                Err("injected thread creation failure".into())
            },
        );
        assert!(result.unwrap_err().to_string().contains("thread creation"));
        assert_eq!(states, [ServiceState::StartPending, ServiceState::Stopped]);
    }

    #[test]
    fn running_report_failure_stops_and_joins_before_stopped() {
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let mut states = Vec::new();
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                states.push(status.current_state);
                if status.current_state == ServiceState::Running {
                    return Err("injected Running failure".into());
                }
                if status.current_state == ServiceState::Stopped {
                    assert!(finished.load(Ordering::SeqCst));
                    assert!(matches!(status.exit_code, ServiceExitCode::Win32(1)));
                }
                Ok(())
            },
            || Ok(()),
            |(), stop| Ok(worker_until_stopped(stop, worker_finished)),
        );
        assert!(result.unwrap_err().to_string().contains("Running"));
        assert_eq!(
            states,
            [
                ServiceState::StartPending,
                ServiceState::Running,
                ServiceState::StopPending,
                ServiceState::Stopped
            ]
        );
    }

    #[test]
    fn clean_stop_joins_worker_and_reports_success_once() {
        let stop = Arc::new(AtomicBool::new(false));
        let request_stop = Arc::clone(&stop);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let mut states = Vec::new();
        let result = run_registered_service(
            stop,
            |status| {
                states.push(status.current_state);
                if status.current_state == ServiceState::Running {
                    request_stop.store(true, Ordering::SeqCst);
                }
                if status.current_state == ServiceState::Stopped {
                    assert!(finished.load(Ordering::SeqCst));
                    assert!(matches!(status.exit_code, ServiceExitCode::Win32(0)));
                }
                Ok(())
            },
            || Ok(()),
            |(), stop| Ok(worker_until_stopped(stop, worker_finished)),
        );
        result.unwrap();
        assert_eq!(
            states,
            [
                ServiceState::StartPending,
                ServiceState::Running,
                ServiceState::StopPending,
                ServiceState::Stopped
            ]
        );
    }

    #[test]
    fn unexpected_successful_worker_exit_is_a_service_failure() {
        let mut failed_stop = false;
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                if status.current_state == ServiceState::Stopped {
                    failed_stop = matches!(status.exit_code, ServiceExitCode::Win32(1));
                }
                Ok(())
            },
            || Ok(()),
            |(), _| Ok(thread::spawn(|| Ok(()))),
        );
        assert!(result.unwrap_err().to_string().contains("unexpectedly"));
        assert!(failed_stop);
    }

    #[test]
    fn supervisor_error_that_sets_stop_is_not_misreported_as_success() {
        let mut failed_stop = false;
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                if status.current_state == ServiceState::Stopped {
                    failed_stop = matches!(status.exit_code, ServiceExitCode::Win32(1));
                }
                Ok(())
            },
            || Ok(()),
            |(), stop| {
                Ok(thread::spawn(move || {
                    stop.store(true, Ordering::SeqCst);
                    Err("injected IPC worker failure".into())
                }))
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("IPC worker failure")
        );
        assert!(failed_stop);
    }

    #[test]
    fn supervisor_panic_is_joined_and_reported_as_failure() {
        let mut failed_stop = false;
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                if status.current_state == ServiceState::Stopped {
                    failed_stop = matches!(status.exit_code, ServiceExitCode::Win32(1));
                }
                Ok(())
            },
            || Ok(()),
            |(), _| Ok(thread::spawn(|| panic!("injected supervisor panic"))),
        );
        assert!(result.unwrap_err().to_string().contains("panicked"));
        assert!(failed_stop);
    }

    #[test]
    fn stop_pending_report_failure_does_not_skip_join() {
        let stop = Arc::new(AtomicBool::new(false));
        let request_stop = Arc::clone(&stop);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let mut stopped_count = 0;
        let result = run_registered_service(
            stop,
            |status| {
                if status.current_state == ServiceState::Running {
                    request_stop.store(true, Ordering::SeqCst);
                }
                if status.current_state == ServiceState::StopPending {
                    return Err("injected StopPending failure".into());
                }
                if status.current_state == ServiceState::Stopped {
                    stopped_count += 1;
                    assert!(finished.load(Ordering::SeqCst));
                    assert!(matches!(status.exit_code, ServiceExitCode::Win32(1)));
                }
                Ok(())
            },
            || Ok(()),
            |(), stop| Ok(worker_until_stopped(stop, worker_finished)),
        );
        assert!(result.unwrap_err().to_string().contains("StopPending"));
        assert_eq!(stopped_count, 1);
    }

    #[test]
    fn terminal_report_failure_is_not_retried_and_preserves_initial_error() {
        let mut stopped_count = 0;
        let result = run_registered_service(
            Arc::new(AtomicBool::new(false)),
            |status| {
                if status.current_state == ServiceState::Stopped {
                    stopped_count += 1;
                    return Err("injected terminal report failure".into());
                }
                Ok(())
            },
            || -> Result<(), AnyError> { Err("original initialization error".into()) },
            |(), _| panic!("IPC must not start"),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "original initialization error"
        );
        assert_eq!(stopped_count, 1);
    }
}
