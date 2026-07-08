//! `cf-service` — the Windows LocalSystem filter service host.
//!
//! This ticket (`svc-skeleton`) is only the *host*: SCM install/start/stop,
//! running as LocalSystem, an ACL-hardened state directory, and size-rotating
//! logs. The actual filtering machinery named in `main.rs` — embedded
//! resolver, NRPT, the WFP egress lock, the watchdog, IPC, and approval
//! enforcement — are later e-service tickets that hang off this skeleton.
//!
//! Layering:
//! - [`config`] and [`logging`] are cross-platform (compiled and tested on
//!   both CI targets).
//! - [`acl`] hardens a directory (real on Windows via `icacls`, a no-op stub
//!   elsewhere so the body compiles and runs on Linux CI).
//! - `scm` (Windows-only) owns everything that talks to the Service Control
//!   Manager.
//!
//! [`run_service_body`] is the piece all entry points share: the SCM runtime
//! path drives it under the control handler, and `console` mode drives it in
//! the foreground.

use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

pub mod acl;
pub mod config;
pub mod logging;

#[cfg(windows)]
pub mod scm;

pub use config::ServiceConfig;

/// The SCM key name. Also used by the control handler registration and every
/// management call, so it must match what `install` registers.
pub const SERVICE_NAME: &str = "ContentFilterService";

/// The friendly name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "ContentFilter Accountability Service";

/// The SCM description.
pub const SERVICE_DESCRIPTION: &str =
    "Enforces the on-device accountability filter for ContentFilter. \
     Self-imposed accountability software, not monitoring imposed by another party.";

/// Idle wake-up cadence while the skeleton has no real work loop. Kept short
/// enough to be a useful liveness signal, long enough not to spam the log.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// The cross-platform service body.
///
/// The skeleton has no work loop yet (resolver / WFP / IPC / approvals are
/// later tickets), so it: ensures its state directory exists and is
/// ACL-hardened, then blocks until asked to stop — emitting a periodic
/// heartbeat so the service is observably alive and the rotating-log path is
/// exercised. Returns `Ok(())` when `stop` receives a value *or* when the
/// sender is dropped (the control handler going away is a stop, not a hang).
///
/// The caller is expected to have installed a `tracing` subscriber already
/// (the SCM path and [`run_console`] both do); without one the `tracing`
/// calls here are simply no-ops.
pub fn run_service_body(config: &ServiceConfig, stop: Receiver<()>) -> io::Result<()> {
    // Idempotent: `install` hardens this at install time too, so the logs
    // subdirectory (created by the subscriber) inherits the hardened ACL.
    std::fs::create_dir_all(&config.data_dir)?;
    acl::harden_dir(&config.data_dir)?;

    tracing::info!(
        data_dir = %config.data_dir.display(),
        service = SERVICE_NAME,
        "cf-service started"
    );

    loop {
        match stop.recv_timeout(HEARTBEAT_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => tracing::debug!("cf-service heartbeat"),
        }
    }

    tracing::info!("cf-service stopping");
    Ok(())
}

/// Runs the service body in the foreground for local debugging. Installs the
/// rotating-file logging subscriber, runs the body on a worker thread, and
/// stops it when the operator presses Enter (or stdin closes).
pub fn run_console(config: &ServiceConfig) -> io::Result<()> {
    let subscriber = logging::file_subscriber(config)?;
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let worker_config = config.clone();
    let worker = std::thread::spawn(move || run_service_body(&worker_config, stop_rx));

    eprintln!("cf-service running in console mode; press Enter to stop.");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let _ = stop_tx.send(());

    worker
        .join()
        .map_err(|_| io::Error::other("service body thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    fn test_config(data_dir: &std::path::Path) -> ServiceConfig {
        // Round-trip through TOML so the test uses exactly the shape the
        // service parses at runtime.
        let toml = format!(
            "data_dir = {:?}\n[log]\nmax_size_bytes = 1024\nkeep_files = 2\n",
            data_dir.to_string_lossy()
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn the_service_body_returns_promptly_when_asked_to_stop() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let (stop_tx, stop_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || run_service_body(&config, stop_rx));

        stop_tx.send(()).unwrap();
        let start = Instant::now();
        let result = worker.join().unwrap();

        assert!(result.is_ok(), "body returned an error: {result:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "body should stop well within one heartbeat interval, not wait it out"
        );
        // The body creates (and on Windows hardens) its data directory.
        assert!(dir.path().exists());
    }

    #[test]
    fn the_service_body_returns_when_the_stop_sender_is_dropped() {
        // A dropped sender models the SCM control handler being torn down; the
        // body must treat that as "stop", not block forever on a dead channel.
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        drop(stop_tx);
        assert!(run_service_body(&config, stop_rx).is_ok());
    }
}
