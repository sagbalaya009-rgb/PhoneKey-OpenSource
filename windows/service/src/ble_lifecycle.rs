//! Service-owned BLE execution and cancellation policy. No authentication authority.
use std::error::Error;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub type BleError = Box<dyn Error + Send + Sync>;
pub const POLL: Duration = Duration::from_millis(20);
pub const CANCEL_GRACE: Duration = Duration::from_secs(2);
// Transport cap cannot extend the authority's independent 45-second deadline.
const MAX_EXCHANGE_MS: u64 = 45_000;

/// Wall-clock expiry remains authoritative; monotonic time also prevents a
/// backward clock adjustment from extending an already-running exchange.
pub struct Deadline {
    expires_at_ms: u64,
    until: Instant,
}
impl Deadline {
    pub fn new(now_ms: u64, expires_at_ms: u64) -> Result<Self, BleError> {
        let until = Instant::now()
            .checked_add(Duration::from_millis(
                expires_at_ms.saturating_sub(now_ms).min(MAX_EXCHANGE_MS),
            ))
            .ok_or("BLE deadline exceeds monotonic clock range")?;
        Ok(Self {
            expires_at_ms,
            until,
        })
    }
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms || Instant::now() >= self.until
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Started,
    Completed,
    Canceled,
    Error,
}

/// The real WinRT adapter and deterministic test operations use this policy.
pub trait Operation {
    type Output;
    fn status(&self) -> Result<Status, BleError>;
    fn results(&self) -> Result<Self::Output, BleError>;
    fn cancel(&self) -> Result<(), BleError>;
    fn close(&self) -> Result<(), BleError>;
}

struct OperationGuard<'a, O: Operation>(&'a O);
impl<O: Operation> Drop for OperationGuard<'_, O> {
    fn drop(&mut self) {
        // Never Close a Started operation. WinRT owns its asynchronous storage;
        // no completion callback or borrowed Rust buffer is registered here.
        match self.0.status() {
            Ok(Status::Started) | Err(_) => {
                let _ = self.0.cancel();
            }
            Ok(_) => {
                let _ = self.0.close();
            }
        }
    }
}

pub fn wait_operation<O: Operation>(
    operation: &O,
    cancelled: &mut impl FnMut() -> Result<bool, BleError>,
    service_stop: &AtomicBool,
    grace: Duration,
) -> Result<Option<O::Output>, BleError> {
    let _guard = OperationGuard(operation);
    let mut cancellation = None;
    let mut cancellation_error = None;
    loop {
        if cancellation.is_none() {
            let requested = match cancelled() {
                Ok(value) => value || service_stop.load(Ordering::SeqCst),
                Err(error) => {
                    cancellation_error = Some(error);
                    true
                }
            };
            if requested {
                cancellation = Some(Instant::now());
                if let Err(error) = operation.cancel() {
                    cancellation_error.get_or_insert(error);
                }
            }
        }
        let status = match operation.status() {
            Ok(status) => status,
            Err(error) => {
                service_stop.store(true, Ordering::SeqCst);
                return Err(error);
            }
        };
        if status != Status::Started {
            if cancellation.is_some() {
                return match cancellation_error {
                    Some(error) => Err(error),
                    None => Ok(None),
                };
            }
            // Cancellation wins even if completion raced the preceding poll.
            match cancelled() {
                Ok(false) if !service_stop.load(Ordering::SeqCst) => {}
                Ok(_) => return Ok(None),
                Err(error) => return Err(error),
            }
            return match status {
                Status::Completed => operation.results().map(Some),
                Status::Canceled => Err("BLE operation was canceled by Windows".into()),
                Status::Error => match operation.results() {
                    Err(error) => Err(error),
                    Ok(_) => Err("BLE operation reported an inconsistent error status".into()),
                },
                Status::Started => unreachable!(),
            };
        }
        if cancellation.is_some_and(|at| at.elapsed() >= grace) {
            service_stop.store(true, Ordering::SeqCst);
            return Err(
                "BLE cancellation did not settle; stopping service before another exchange".into(),
            );
        }
        thread::sleep(POLL);
    }
}

/// At most one admitted job, including a queued job. No per-request threads.
pub struct WorkSender<T> {
    sender: mpsc::SyncSender<T>,
    busy: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}
impl<T> Clone for WorkSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            busy: self.busy.clone(),
            stop: self.stop.clone(),
        }
    }
}
impl<T> WorkSender<T> {
    pub fn submit(&self, work: T) -> Result<(), BleError> {
        if self.stop.load(Ordering::SeqCst) {
            return Err("BLE worker is stopping".into());
        }
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BLE worker is still completing the previous exchange")?;
        if self.stop.load(Ordering::SeqCst) || self.sender.try_send(work).is_err() {
            self.busy.store(false, Ordering::SeqCst);
            return Err("BLE worker is unavailable".into());
        }
        Ok(())
    }
}
struct BusyGuard(Arc<AtomicBool>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub struct Worker {
    handle: Option<JoinHandle<Result<(), BleError>>>,
    stop: Arc<AtomicBool>,
}
impl Worker {
    pub fn start<T: Send + 'static>(
        stop: Arc<AtomicBool>,
        mut run: impl FnMut(T) -> Result<(), BleError> + Send + 'static,
    ) -> Result<(Self, WorkSender<T>), BleError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = busy.clone();
        let worker_stop = stop.clone();
        let handle = thread::Builder::new()
            .name("phonekey-credential-login".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    match receiver.recv_timeout(POLL) {
                        Ok(work) => {
                            let _release = BusyGuard(worker_busy.clone());
                            if !worker_stop.load(Ordering::SeqCst) {
                                run(work)?;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                Ok(())
            })?;
        Ok((
            Self {
                handle: Some(handle),
                stop: stop.clone(),
            },
            WorkSender { sender, busy, stop },
        ))
    }
    pub fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(|handle| handle.is_finished())
    }
    pub fn shutdown(&mut self) -> Result<(), BleError> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| "PhoneKey BLE worker panicked")??;
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            eprintln!("PhoneKey BLE shutdown failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Fake {
        status: Cell<Status>,
        finish_cancel: bool,
        cancel_calls: Cell<usize>,
        result_calls: Cell<usize>,
        close_calls: Cell<usize>,
        fail_status: bool,
    }
    impl Fake {
        fn new(status: Status, finish_cancel: bool) -> Self {
            Self {
                status: Cell::new(status),
                finish_cancel,
                cancel_calls: Cell::new(0),
                result_calls: Cell::new(0),
                close_calls: Cell::new(0),
                fail_status: false,
            }
        }
    }
    impl Operation for Fake {
        type Output = u8;
        fn status(&self) -> Result<Status, BleError> {
            if self.fail_status {
                Err("injected status failure".into())
            } else {
                Ok(self.status.get())
            }
        }
        fn results(&self) -> Result<u8, BleError> {
            self.result_calls.set(self.result_calls.get() + 1);
            if self.status.get() == Status::Error {
                Err("injected GATT failure".into())
            } else {
                Ok(42)
            }
        }
        fn cancel(&self) -> Result<(), BleError> {
            self.cancel_calls.set(self.cancel_calls.get() + 1);
            if self.finish_cancel {
                self.status.set(Status::Canceled);
            }
            Ok(())
        }
        fn close(&self) -> Result<(), BleError> {
            assert_ne!(self.status.get(), Status::Started);
            self.close_calls.set(self.close_calls.get() + 1);
            Ok(())
        }
    }
    #[test]
    fn completed_operation_returns_result_and_closes() {
        let op = Fake::new(Status::Completed, false);
        assert_eq!(
            wait_operation(
                &op,
                &mut || Ok(false),
                &AtomicBool::new(false),
                CANCEL_GRACE
            )
            .unwrap(),
            Some(42)
        );
        assert_eq!(op.close_calls.get(), 1);
    }
    #[test]
    fn cancellation_drains_without_consuming_proof() {
        let op = Fake::new(Status::Started, true);
        assert_eq!(
            wait_operation(&op, &mut || Ok(true), &AtomicBool::new(false), CANCEL_GRACE).unwrap(),
            None
        );
        assert_eq!(op.cancel_calls.get(), 1);
        assert_eq!(op.result_calls.get(), 0);
        assert_eq!(op.close_calls.get(), 1);
    }
    #[test]
    fn cancellation_wins_completion_race() {
        let op = Fake::new(Status::Completed, false);
        let mut polls = 0;
        assert_eq!(
            wait_operation(
                &op,
                &mut || {
                    polls += 1;
                    Ok(polls > 1)
                },
                &AtomicBool::new(false),
                CANCEL_GRACE
            )
            .unwrap(),
            None
        );
        assert_eq!(op.result_calls.get(), 0);
    }
    #[test]
    fn stuck_cancellation_stops_service_and_never_closes_started_operation() {
        let op = Fake::new(Status::Started, false);
        let stop = AtomicBool::new(false);
        assert!(wait_operation(&op, &mut || Ok(true), &stop, Duration::ZERO).is_err());
        assert!(stop.load(Ordering::SeqCst));
        assert_eq!(op.close_calls.get(), 0);
        assert_eq!(op.result_calls.get(), 0);
    }
    #[test]
    fn shutdown_requests_cancellation_even_when_session_is_current() {
        let op = Fake::new(Status::Started, true);
        assert_eq!(
            wait_operation(&op, &mut || Ok(false), &AtomicBool::new(true), CANCEL_GRACE).unwrap(),
            None
        );
        assert_eq!(op.cancel_calls.get(), 1);
    }
    #[test]
    fn failed_cancellation_predicate_cannot_publish_result() {
        let op = Fake::new(Status::Started, true);
        assert!(
            wait_operation(
                &op,
                &mut || Err("poisoned authority".into()),
                &AtomicBool::new(false),
                CANCEL_GRACE
            )
            .is_err()
        );
        assert_eq!(op.result_calls.get(), 0);
        assert_eq!(op.close_calls.get(), 1);
    }
    #[test]
    fn unreadable_operation_status_stops_service() {
        let mut op = Fake::new(Status::Started, false);
        op.fail_status = true;
        let stop = AtomicBool::new(false);
        assert!(wait_operation(&op, &mut || Ok(false), &stop, CANCEL_GRACE).is_err());
        assert!(stop.load(Ordering::SeqCst));
    }
    #[test]
    fn gatt_error_is_propagated_and_closed() {
        let op = Fake::new(Status::Error, false);
        assert!(
            wait_operation(
                &op,
                &mut || Ok(false),
                &AtomicBool::new(false),
                CANCEL_GRACE
            )
            .is_err()
        );
        assert_eq!(op.close_calls.get(), 1);
    }
    #[test]
    fn backward_clock_cannot_extend_expiry() {
        let deadline = Deadline {
            expires_at_ms: 5000,
            until: Instant::now(),
        };
        assert!(deadline.expired(1));
        assert!(Deadline::new(5000, 4000).unwrap().expired(1));
        let capped = Deadline::new(0, u64::MAX).unwrap();
        assert!(
            capped.until.saturating_duration_since(Instant::now())
                <= Duration::from_millis(MAX_EXCHANGE_MS)
        );
    }
    #[test]
    fn forward_clock_expires_exchange() {
        assert!(Deadline::new(1000, 5000).unwrap().expired(5000));
    }
    #[test]
    fn overlapping_jobs_are_rejected_and_shutdown_joins() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();
        let (mut worker, sender) = Worker::start(stop, move |_: u8| {
            entered_tx.send(()).unwrap();
            let limit = Instant::now() + Duration::from_secs(5);
            while !worker_stop.load(Ordering::SeqCst) {
                assert!(Instant::now() < limit);
                thread::yield_now();
            }
            worker_finished.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        sender.submit(1).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(sender.submit(2).is_err());
        worker.shutdown().unwrap();
        assert!(finished.load(Ordering::SeqCst));
        assert!(sender.submit(3).is_err());
    }
    #[test]
    fn worker_panic_is_joined_and_reported() {
        let (mut worker, sender) = Worker::start(Arc::new(AtomicBool::new(false)), |_: u8| {
            panic!("injected BLE panic")
        })
        .unwrap();
        sender.submit(1).unwrap();
        let limit = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() {
            assert!(Instant::now() < limit);
            thread::yield_now();
        }
        assert!(worker.shutdown().is_err());
        assert!(sender.submit(2).is_err());
    }
    #[test]
    fn dropping_worker_stops_and_joins_active_job() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (tx, rx) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let f = finished.clone();
        let (worker, sender) = Worker::start(stop, move |_: u8| {
            tx.send(()).unwrap();
            let limit = Instant::now() + Duration::from_secs(5);
            while !worker_stop.load(Ordering::SeqCst) {
                assert!(Instant::now() < limit);
                thread::yield_now();
            }
            f.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        sender.submit(1).unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(worker);
        assert!(finished.load(Ordering::SeqCst));
        assert!(sender.submit(2).is_err());
    }
    #[test]
    fn worker_error_reaches_supervisor_shutdown() {
        let (mut worker, sender) = Worker::start(Arc::new(AtomicBool::new(false)), |_: u8| {
            Err("injected fatal cancellation".into())
        })
        .unwrap();
        sender.submit(1).unwrap();
        let limit = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() {
            assert!(Instant::now() < limit);
            thread::yield_now();
        }
        assert_eq!(
            worker.shutdown().unwrap_err().to_string(),
            "injected fatal cancellation"
        );
    }
}
