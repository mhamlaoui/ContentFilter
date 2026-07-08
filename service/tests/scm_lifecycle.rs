//! End-to-end SCM lifecycle test (`svc-skeleton` DoD: "installs/starts/stops
//! via SCM", "runs as LocalSystem").
//!
//! This drives the *real* built `cf-service.exe` through the Service Control
//! Manager using the crate's own management API — the same code path the CLI
//! uses — so it proves the whole thing works together: install registers a
//! LocalSystem service; starting it makes the process reach `Running` (which
//! only happens if `service_main` registered its handler and reported
//! `Running`); stopping it returns to `Stopped`; uninstall removes it.
//!
//! Windows-only, and requires elevation (installing a service needs admin).
//! On the GitHub `windows-latest` runner the job is elevated, so it runs; if
//! ever run unelevated it skips rather than failing. It cannot run at all on
//! this project's dev machine (Smart App Control blocks the freshly-compiled,
//! unsigned test binary from spawning) — like every test here, it is
//! CI-verified only.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Deletes the service and removes the scratch dir on the way out, even if an
/// assertion panics mid-test — a leaked service on the runner would poison
/// re-runs.
struct Cleanup {
    dir: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = cf_service::scm::uninstall();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A scratch directory under `%SystemRoot%\Temp`. That location is chosen
/// deliberately over the user temp dir: the service runs as LocalSystem
/// (`NT AUTHORITY\SYSTEM`), which is reliably able to read this directory to
/// load its config, whereas a per-user temp dir may not grant SYSTEM access.
fn scratch_dir() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root)
        .join("Temp")
        .join(format!("cf-service-test-{}", std::process::id()))
}

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    path.exists()
}

#[test]
fn install_start_stop_uninstall_round_trip() {
    if !cf_service::scm::can_manage() {
        eprintln!("skipping: not elevated (cannot open the SCM with CREATE_SERVICE)");
        return;
    }

    // A previous crashed run might have left the service registered.
    let _ = cf_service::scm::uninstall();

    let base = scratch_dir();
    std::fs::create_dir_all(&base).unwrap();
    let _cleanup = Cleanup { dir: base.clone() };

    let data_dir = base.join("data");
    let config_path = base.join("service.toml");
    std::fs::write(
        &config_path,
        format!(
            "data_dir = {:?}\n[log]\nmax_size_bytes = 1048576\nkeep_files = 3\nlevel = \"info\"\n",
            data_dir.to_string_lossy()
        ),
    )
    .unwrap();

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_cf-service"));

    // --- install --------------------------------------------------------
    cf_service::scm::install(exe, config_path, false, &data_dir).expect("install");

    // "runs as LocalSystem": the SCM records the account the service starts
    // under, and `account_name: None` at install resolves to LocalSystem.
    assert_eq!(
        cf_service::scm::account_name().unwrap().as_deref(),
        Some("LocalSystem"),
        "the service must be registered to run as LocalSystem"
    );
    assert_eq!(
        cf_service::scm::current_state().unwrap(),
        Some(cf_service::scm::RunState::Stopped),
        "a freshly-installed service should be stopped"
    );

    // --- start ----------------------------------------------------------
    // `start` blocks until Running; reaching Running proves service_main ran
    // the dispatcher handshake and reported the state back to the SCM.
    cf_service::scm::start().expect("start");
    assert_eq!(
        cf_service::scm::current_state().unwrap(),
        Some(cf_service::scm::RunState::Running),
    );

    // Bonus: the running body actually opened its rotating log under the
    // hardened data dir.
    let log_file = data_dir
        .join(cf_service::config::LOG_SUBDIR)
        .join(format!("{}.log", cf_service::config::LOG_STEM));
    assert!(
        wait_for_file(&log_file, Duration::from_secs(5)),
        "the service should have created its log file at {}",
        log_file.display()
    );

    // --- stop -----------------------------------------------------------
    cf_service::scm::stop().expect("stop");
    assert_eq!(
        cf_service::scm::current_state().unwrap(),
        Some(cf_service::scm::RunState::Stopped),
    );

    // --- uninstall ------------------------------------------------------
    cf_service::scm::uninstall().expect("uninstall");
    assert_eq!(
        cf_service::scm::current_state().unwrap(),
        None,
        "the service should no longer exist after uninstall"
    );
}
