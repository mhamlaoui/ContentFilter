//! Windows Service Control Manager (SCM) integration (`svc-skeleton` DoD:
//! "installs/starts/stops via SCM", "runs as LocalSystem").
//!
//! This whole module is Windows-only; `lib.rs` only declares it under
//! `#[cfg(windows)]`. It provides both sides of the service lifecycle:
//!
//! - **Management** (`install`/`uninstall`/`start`/`stop`, plus `current_state`
//!   / `account_name` for inspection) — what the CLI subcommands call, and
//!   what the integration test drives against the real built binary.
//! - **Runtime** (`run` → `service_main` → `run_service`) — the code the SCM
//!   itself executes: it registers a control handler, reports `Running`,
//!   runs the cross-platform service body until asked to stop, then reports
//!   `Stopped`.
//!
//! The service is installed with `account_name: None`, which the Win32 API
//! documents as "run as LocalSystem". That is the DoD's "runs as LocalSystem"
//! requirement; [`account_name`] reads it back for the test to assert.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_service::service::{
    Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};

/// `ERROR_SERVICE_DOES_NOT_EXIST` — the SCM's "no such service" code.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// How long management calls wait for a service to reach the requested state.
const STATE_CHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum ServiceError {
    Winapi(windows_service::Error),
    Io(io::Error),
    Config(crate::config::ConfigError),
    /// A state transition did not complete within [`STATE_CHANGE_TIMEOUT`].
    Timeout(&'static str),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Winapi(e) => write!(f, "SCM error: {e}"),
            ServiceError::Io(e) => write!(f, "IO error: {e}"),
            ServiceError::Config(e) => write!(f, "config error: {e}"),
            ServiceError::Timeout(what) => write!(f, "timed out: {what}"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// A coarse view of the service's state, decoupled from `windows-service`'s
/// enum so the crate's public API (and the integration test) doesn't have to
/// name that dependency's types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    /// Pause/continue states, which this service never enters.
    Other,
}

impl From<ServiceState> for RunState {
    fn from(state: ServiceState) -> Self {
        match state {
            ServiceState::Stopped => RunState::Stopped,
            ServiceState::StartPending => RunState::StartPending,
            ServiceState::StopPending => RunState::StopPending,
            ServiceState::Running => RunState::Running,
            _ => RunState::Other,
        }
    }
}

fn is_not_found(e: &ServiceError) -> bool {
    matches!(
        e,
        ServiceError::Winapi(windows_service::Error::Winapi(io))
            if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST)
    )
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, ServiceError> {
    ServiceManager::local_computer(None::<&OsStr>, access).map_err(ServiceError::Winapi)
}

/// Whether this process can manage services (install/delete), i.e. it can
/// open the SCM with `CREATE_SERVICE`. False on a non-elevated process. Used
/// to skip the lifecycle integration test when it isn't running as admin.
pub fn can_manage() -> bool {
    manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE).is_ok()
}

fn open_service(access: ServiceAccess) -> Result<Service, ServiceError> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(SERVICE_NAME, access)
        .map_err(ServiceError::Winapi)
}

// ---------------------------------------------------------------------------
// Management API
// ---------------------------------------------------------------------------

/// Registers the service with the SCM as a LocalSystem, own-process service
/// whose image runs `cf-service run --config <config_path>`. Also creates and
/// ACL-hardens `data_dir` so the state directory is protected from before the
/// service first runs, not only once it starts.
pub fn install(
    exe_path: PathBuf,
    config_path: PathBuf,
    auto_start: bool,
    data_dir: &Path,
) -> Result<(), ServiceError> {
    std::fs::create_dir_all(data_dir).map_err(ServiceError::Io)?;
    crate::acl::harden_dir(data_dir).map_err(ServiceError::Io)?;

    let start_type = if auto_start {
        ServiceStartType::AutoStart
    } else {
        ServiceStartType::OnDemand
    };

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![
            OsString::from("run"),
            OsString::from("--config"),
            config_path.into_os_string(),
        ],
        dependencies: vec![],
        // None => LocalSystem (per the Win32 docs and windows-service's own
        // create_service example). This IS the "runs as LocalSystem" DoD.
        account_name: None,
        account_password: None,
    };

    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(ServiceError::Winapi)?;
    // A missing description is cosmetic; don't fail an install over it.
    let _ = service.set_description(SERVICE_DESCRIPTION);
    Ok(())
}

/// Stops the service if it is running, then removes it from the SCM. A no-op
/// (Ok) if the service isn't installed, so it's safe as a cleanup step.
pub fn uninstall() -> Result<(), ServiceError> {
    let service = match open_service(
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            let _ = wait_for(&service, ServiceState::Stopped, STATE_CHANGE_TIMEOUT);
        }
    }
    service.delete().map_err(ServiceError::Winapi)
}

/// Starts the installed service and waits until it reports `Running`.
pub fn start() -> Result<(), ServiceError> {
    let service = open_service(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    service
        .start(&[] as &[&OsStr])
        .map_err(ServiceError::Winapi)?;
    wait_for(&service, ServiceState::Running, STATE_CHANGE_TIMEOUT)
}

/// Stops the running service and waits until it reports `Stopped`.
pub fn stop() -> Result<(), ServiceError> {
    let service = open_service(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    service.stop().map_err(ServiceError::Winapi)?;
    wait_for(&service, ServiceState::Stopped, STATE_CHANGE_TIMEOUT)
}

/// The service's current run state, or `None` if it isn't installed.
pub fn current_state() -> Result<Option<RunState>, ServiceError> {
    match open_service(ServiceAccess::QUERY_STATUS) {
        Ok(service) => {
            let status = service.query_status().map_err(ServiceError::Winapi)?;
            Ok(Some(RunState::from(status.current_state)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The account the service is configured to run under (e.g. `"LocalSystem"`),
/// or `None` if it isn't installed.
pub fn account_name() -> Result<Option<String>, ServiceError> {
    match open_service(ServiceAccess::QUERY_CONFIG) {
        Ok(service) => {
            let config = service.query_config().map_err(ServiceError::Winapi)?;
            Ok(Some(
                config
                    .account_name
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

fn wait_for(
    service: &Service,
    target: ServiceState,
    timeout: Duration,
) -> Result<(), ServiceError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status().map_err(ServiceError::Winapi)?;
        if status.current_state == target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ServiceError::Timeout(
                "service did not reach the expected state within the timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Runtime (SCM entry point)
// ---------------------------------------------------------------------------

/// The config path is stashed here by [`run`] before handing control to the
/// SCM dispatcher, because `service_main` is invoked by the dispatcher on its
/// own thread and receives only the SCM's own start arguments, not the
/// process command line the config path rode in on.
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// SCM entry point: called by `cf-service run --config <path>` (which is what
/// the installed image path expands to). Blocks until the service stops.
pub fn run(config_path: PathBuf) -> Result<(), ServiceError> {
    let _ = CONFIG_PATH.set(config_path);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(ServiceError::Winapi)
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    // The dispatcher gives us no channel to return an error on, and logging
    // may not be up yet if config/logging init is what failed. Last-ditch to
    // the real stderr; a production build would also write the Windows event
    // log (left as a follow-up — the skeleton has no event-log wiring yet).
    if let Err(e) = run_service() {
        let _ = writeln!(io::stderr(), "cf-service: service_main failed: {e}");
    }
}

fn run_service() -> Result<(), ServiceError> {
    let config_path = CONFIG_PATH.get().ok_or(ServiceError::Timeout(
        "config path was not set before dispatch",
    ))?;
    let config = crate::config::ServiceConfig::load(config_path).map_err(ServiceError::Config)?;

    // Install logging before anything logs.
    let subscriber = crate::logging::file_subscriber(&config).map_err(ServiceError::Io)?;
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| ServiceError::Io(io::Error::other(e.to_string())))?;

    // The control handler signals the body to stop. `send` may fail only if
    // the body already returned and dropped the receiver — harmless.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handler_tx = stop_tx.clone();
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = handler_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            // Every service must acknowledge Interrogate.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(ServiceError::Winapi)?;

    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
        ServiceExitCode::Win32(0),
    )?;
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
        ServiceExitCode::Win32(0),
    )?;

    let body = crate::run_service_body(&config, stop_rx);

    let exit_code = match &body {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
        exit_code,
    )?;

    body.map_err(ServiceError::Io)
}

fn set_status(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    controls: ServiceControlAccept,
    wait_hint: Duration,
    exit_code: ServiceExitCode,
) -> Result<(), ServiceError> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
        .map_err(ServiceError::Winapi)
}
