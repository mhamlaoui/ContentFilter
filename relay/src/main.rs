//! Thin cloud relay: registry, signed feeds, hash-chained log, push, time
//! anchors, and approval transport. Mints and decrypts nothing — see
//! `lib.rs` for the actual bootstrap logic this binary just wires up to
//! CLI args, structured logging, and OS shutdown signals.

use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Path to a TOML config file (see RelayConfig).
    #[arg(long, default_value = "relay.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = cf_relay::RelayConfig::load(&args.config)?;
    cf_relay::run(config, shutdown_signal()).await?;
    Ok(())
}

/// Resolves on Ctrl+C or, on Unix, SIGTERM — the two ways an operator or
/// orchestrator (systemd, a container runtime) asks a service to stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
