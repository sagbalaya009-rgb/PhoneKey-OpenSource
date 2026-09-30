//! Own all listeners before acknowledging startup to the SCM lifecycle.
use std::error::Error;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
pub type StartupError = Box<dyn Error + Send + Sync>;

pub fn prepare_pool<T, E>(
    count: usize,
    mut create: impl FnMut(bool) -> Result<T, E>,
) -> Result<Vec<T>, E> {
    assert!(count > 0, "IPC must retain at least one listener");
    let mut pipes = Vec::with_capacity(count);
    for index in 0..count {
        // Keep the exclusive first instance alive while acquiring the rest.
        pipes.push(create(index == 0)?);
    }
    Ok(pipes)
}

pub fn start_supervisor(
    stop: Arc<AtomicBool>,
    timeout: Duration,
    serve: impl FnOnce(mpsc::Sender<()>) -> Result<(), StartupError> + Send + 'static,
) -> Result<JoinHandle<Result<(), StartupError>>, StartupError> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("phonekey-ipc-supervisor".into())
        .spawn(move || serve(ready_tx))?;
    let failure: StartupError = match ready_rx.recv_timeout(timeout) {
        Ok(()) if !worker.is_finished() && !stop.load(Ordering::SeqCst) => return Ok(worker),
        Ok(()) => "PhoneKey IPC stopped during startup".into(),
        Err(mpsc::RecvTimeoutError::Timeout) => "PhoneKey IPC listener startup timed out".into(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            "PhoneKey IPC exited before listener readiness".into()
        }
    };
    stop.store(true, Ordering::SeqCst);
    // Never detach a serving supervisor after failed startup. The existing
    // SCM lifecycle reports Stopped only after transport cleanup has completed.
    match worker.join() {
        Ok(Err(error)) => Err(error),
        Err(_) => Err("PhoneKey IPC supervisor panicked during startup".into()),
        Ok(Ok(())) => Err(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn first_instance_is_exclusive_and_all_handles_stay_owned() {
        let live = Arc::new(AtomicUsize::new(0));
        let mut calls = Vec::new();
        let pool = prepare_pool(4, |first| -> Result<_, ()> {
            calls.push(first);
            live.fetch_add(1, Ordering::SeqCst);
            Ok(Owned(Arc::clone(&live)))
        })
        .unwrap();
        assert_eq!(calls, [true, false, false, false]);
        assert_eq!(live.load(Ordering::SeqCst), 4);
        drop(pool);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn occupied_name_stops_before_any_secondary_creation() {
        let mut calls = 0;
        let result = prepare_pool::<(), _>(4, |first| {
            assert!(first);
            calls += 1;
            Err("occupied")
        });
        assert_eq!(result.unwrap_err(), "occupied");
        assert_eq!(calls, 1);
    }
    #[test]
    fn partial_pool_failure_releases_every_acquired_handle() {
        for fail_at in 1..4 {
            let live = Arc::new(AtomicUsize::new(0));
            let mut calls = 0;
            let result = prepare_pool(4, |_| {
                calls += 1;
                if calls == fail_at + 1 {
                    return Err("injected creation failure");
                }
                live.fetch_add(1, Ordering::SeqCst);
                Ok(Owned(Arc::clone(&live)))
            });
            assert!(result.is_err());
            assert_eq!(calls, fail_at + 1);
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn start_does_not_return_until_supervisor_acknowledges_readiness() {
        let stop = Arc::new(AtomicBool::new(false));
        let caller_stop = Arc::clone(&stop);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (allow_tx, allow_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let caller = thread::spawn(move || {
            let worker_stop = Arc::clone(&caller_stop);
            let result = start_supervisor(caller_stop, Duration::from_secs(3), move |ready| {
                entered_tx.send(()).unwrap();
                allow_rx.recv().unwrap();
                ready.send(()).unwrap();
                while !worker_stop.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
                Ok(())
            });
            result_tx.send(result).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        allow_tx.send(()).unwrap();
        let worker = result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap().unwrap();
        caller.join().unwrap();
    }
    #[test]
    fn startup_error_is_propagated_and_stop_is_requested() {
        let stop = Arc::new(AtomicBool::new(false));
        let result = start_supervisor(Arc::clone(&stop), Duration::from_secs(1), |_| {
            Err("injected listener error".into())
        });
        assert_eq!(result.unwrap_err().to_string(), "injected listener error");
        assert!(stop.load(Ordering::SeqCst));
    }
    #[test]
    fn missing_acknowledgment_cancels_and_joins_the_supervisor() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let result = start_supervisor(stop, Duration::from_millis(30), move |ready| {
            while !worker_stop.load(Ordering::SeqCst) {
                thread::yield_now();
            }
            drop(ready);
            worker_exited.store(true, Ordering::SeqCst);
            Ok(())
        });
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(exited.load(Ordering::SeqCst));
    }
    #[test]
    fn startup_panic_is_joined_and_reported() {
        let stop = Arc::new(AtomicBool::new(false));
        let result = start_supervisor(stop, Duration::from_secs(1), |_| panic!("injected"));
        assert!(result.unwrap_err().to_string().contains("panicked"));
    }
}
