//! `cf-service` command line.
//!
//! Windows LocalSystem filter service: this binary hosts the (future)
//! embedded resolver, NRPT, WFP egress lock, watchdog, IPC, and approval
//! enforcement. Today it is the SCM host skeleton — it installs/starts/stops
//! the service, runs as LocalSystem under an ACL-hardened state directory,
//! and rotates its logs. See `cf_service` (the library) for the actual logic.
//!
//! Subcommands:
//! - `install` / `uninstall` — register/remove the service with the SCM.
//! - `start` / `stop` — drive the installed service.
//! - `run` — the SCM entry point (the installed image runs
//!   `cf-service run --config <path>`); not meant to be run by hand.
//! - `console` — run the service body in the foreground for local debugging.
//!
//! Everything but `console` is Windows-only; on other platforms those
//! subcommands report that SCM operations require Windows, so Linux CI still
//! builds and exercises the cross-platform surface.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cf-service",
    about = "ContentFilter Windows filter service host"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register the service with the Windows SCM (runs as LocalSystem).
    Install {
        #[arg(long, default_value = "service.toml")]
        config: PathBuf,
        /// Path to a signed trust anchor (JSON) to pin at install.
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Start automatically at boot instead of on demand.
        #[arg(long)]
        auto_start: bool,
    },
    /// Stop (if running) and remove the service from the SCM.
    Uninstall,
    /// Start the installed service and wait until it is running.
    Start,
    /// Stop the running service and wait until it has stopped.
    Stop,
    /// SCM entry point — invoked by the service controller, not by hand.
    Run {
        #[arg(long, default_value = "service.toml")]
        config: PathBuf,
    },
    /// Run the service body in the foreground for local debugging.
    Console {
        #[arg(long, default_value = "service.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    match dispatch(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cf-service: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Run { config } => run_service_entry(config),
        Command::Console { config } => {
            let config = absolutize(config)?;
            let cfg = cf_service::ServiceConfig::load(&config)?;
            cf_service::run_console(&cfg)?;
            Ok(())
        }
        Command::Install {
            config,
            anchor,
            auto_start,
        } => install(config, anchor, auto_start),
        Command::Uninstall => uninstall(),
        Command::Start => start(),
        Command::Stop => stop(),
    }
}

fn absolutize(path: PathBuf) -> std::io::Result<PathBuf> {
    // SCM launches the image with cwd = C:\Windows\System32, so a relative
    // config path would resolve against the wrong directory. Resolve it here
    // (at install time it is baked absolute into the image path).
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(windows)]
fn run_service_entry(config: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    cf_service::scm::run(absolutize(config)?)?;
    Ok(())
}

#[cfg(windows)]
fn install(
    config: PathBuf,
    anchor: Option<PathBuf>,
    auto_start: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = absolutize(config)?;
    let cfg = cf_service::ServiceConfig::load(&config)?;
    let exe = std::env::current_exe()?;
    let anchor = anchor.map(absolutize).transpose()?;
    cf_service::scm::install(exe, config, auto_start, &cfg.data_dir, anchor.as_deref())?;
    println!(
        "Installed {} as LocalSystem ({}{}).",
        cf_service::SERVICE_NAME,
        if auto_start {
            "auto-start"
        } else {
            "on-demand"
        },
        if anchor.is_some() {
            ", anchor pinned"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(windows)]
fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
    cf_service::scm::uninstall()?;
    println!("Removed {}.", cf_service::SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn start() -> Result<(), Box<dyn std::error::Error>> {
    cf_service::scm::start()?;
    println!("Started {}.", cf_service::SERVICE_NAME);
    Ok(())
}

#[cfg(windows)]
fn stop() -> Result<(), Box<dyn std::error::Error>> {
    cf_service::scm::stop()?;
    println!("Stopped {}.", cf_service::SERVICE_NAME);
    Ok(())
}

#[cfg(not(windows))]
fn run_service_entry(_config: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(windows_only())
}

#[cfg(not(windows))]
fn install(
    _config: PathBuf,
    _anchor: Option<PathBuf>,
    _auto_start: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(windows_only())
}

#[cfg(not(windows))]
fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
    Err(windows_only())
}

#[cfg(not(windows))]
fn start() -> Result<(), Box<dyn std::error::Error>> {
    Err(windows_only())
}

#[cfg(not(windows))]
fn stop() -> Result<(), Box<dyn std::error::Error>> {
    Err(windows_only())
}

#[cfg(not(windows))]
fn windows_only() -> Box<dyn std::error::Error> {
    "SCM operations are only supported on Windows (use `console` to run the service body here)"
        .into()
}
