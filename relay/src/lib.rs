//! Relay service bootstrap (relay-bootstrap): the axum/tokio HTTP backbone
//! with TLS termination, structured logging, and graceful shutdown that
//! everything else in the relay epic builds on. Mints and decrypts
//! nothing — see the crate-level context in `main.rs`.
//!
//! There is deliberately no plaintext listening mode anywhere in this
//! crate — not even one that defaults to off. [`RelayConfig`] requires a
//! cert and key path unconditionally, and [`run`] only ever accepts
//! connections through a [`tokio_rustls::TlsAcceptor`]. "TLS enforced" is
//! a much stronger guarantee when the code path to serve plaintext doesn't
//! exist than when it exists behind a flag someone could flip.
//!
//! Hand-rolls the accept loop over `axum-server` (which would otherwise be
//! the obvious choice): `axum-server` 0.6.0's `bind_rustls().serve()`
//! unconditionally uses hyper-util's `serve_connection_with_upgrades`
//! internally, which doesn't satisfy the trait bounds axum's current body
//! type needs — a real incompatibility between the latest axum-server
//! release and current axum, not a version pin this crate can route
//! around. This server doesn't need HTTP upgrades (no WebSockets here),
//! so the plain `serve_connection` path sidesteps the issue entirely.

pub mod auth;
pub mod email;
pub mod feeds;
pub mod http;
pub mod log;
pub mod mailbox;
pub mod registry;
pub mod silence;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    /// 64 hex chars (a 32-byte Ed25519 seed) signing time beacons
    /// (relay-timeanchor). An **online, operational** key — deliberately
    /// not the offline release key (docs/KEY_CEREMONY.md): beacons attest
    /// time continuously, which an air-gapped key cannot do, and the blast
    /// radius of its compromise is bounded (a lying relay clock is already
    /// in the threat model; the floor mechanism only ever *advances*
    /// client floors, and only signed feeds/approvals gate anything
    /// stronger). Required, like the TLS paths — no beacon-less mode.
    pub beacon_key_path: PathBuf,
    /// Directory of release-key-signed `FeedEnvelope` JSON files
    /// (relay-feeds). May be empty (a relay can start before the first
    /// feed is published); must exist. See `feeds::FeedStore` for why
    /// ingestion is a directory and not an upload endpoint.
    pub feeds_dir: PathBuf,
    /// The independent alert channel (relay-email-fallback). Required —
    /// no email-less mode, same landmine shape as TLS/beacon: the
    /// threat model's row 20 depends on this channel existing.
    pub smtp: SmtpConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Path to a file holding the SMTP password (trimmed) — file, not
    /// inline TOML, same handling as the beacon key.
    pub password_path: PathBuf,
    /// The From: address on alert emails.
    pub from: String,
}

/// Everything `app` needs beyond routing: bundled so `run_with_listener`
/// stops growing a parameter per relay ticket.
pub struct AppServices {
    pub beacon_key: ed25519_dalek::SigningKey,
    pub feed_store: feeds::FeedStore,
    pub mailer: Arc<dyn email::Mailer>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "could not read config file: {e}"),
            ConfigError::Parse(e) => write!(f, "could not parse config file: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl RelayConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&text).map_err(ConfigError::Parse)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse { status: "ok" })
}

/// Builds the full application router and starts the background silence
/// sweeper — call under a tokio runtime. Endpoint tests use
/// `http::router` directly (no sweeper; they drive the tracker's clock).
pub fn app(services: AppServices) -> Router {
    let state = http::AppState::new(services);
    state.spawn_background_tasks();
    http::router(state).route("/healthz", axum::routing::get(health))
}

/// Loads the beacon signing key: a file holding exactly 64 hex chars
/// (surrounding whitespace tolerated). Anything else is an error — a
/// silently-truncated or zero-padded seed would still "work" while being
/// a different key than the operator provisioned.
pub fn load_beacon_key(path: &Path) -> std::io::Result<ed25519_dalek::SigningKey> {
    let text = std::fs::read_to_string(path)?;
    let seed: [u8; 32] = http::hex_decode(text.trim())
        .ok_or_else(|| std::io::Error::other("beacon key file must hold exactly 64 hex chars"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// How long a graceful shutdown waits for in-flight connections to finish
/// before dropping them anyway.
pub const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// rustls 0.23 refuses to guess a crypto backend when more than one is
/// compiled into the binary (this crate selects `ring`; a dev-dependency
/// like `reqwest` pulling its own rustls stack with default features can
/// unify in `aws-lc-rs` alongside it). Installing explicitly resolves the
/// ambiguity regardless of what else got linked in. Safe to call more than
/// once (e.g. once per test in the same process) — a second call just
/// finds a provider already installed, which is fine since it's the one
/// this crate wants anyway.
///
/// Public, not just called internally from `load_tls_config`: a caller
/// that also builds its own rustls-based client (integration tests using
/// `reqwest`, say) can race this crate's own install if it initializes
/// its TLS stack before an async-spawned server task gets scheduled.
/// Calling this explicitly and synchronously up front removes that race.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> std::io::Result<rustls::ServerConfig> {
    ensure_crypto_provider_installed();
    let cert_file = std::fs::File::open(cert_path)?;
    let cert_chain = certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>()?;
    let key_file = std::fs::File::open(key_path)?;
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| std::io::Error::other("no private key found in tls_key_path"))?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(std::io::Error::other)
}

/// Runs the relay until `shutdown` resolves, then stops accepting new
/// connections and waits (up to [`SHUTDOWN_GRACE_PERIOD`]) for in-flight
/// connections to finish before returning.
pub async fn run(
    config: RelayConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // A relay without the alert channel must not exist in production — a
    // no-smtp binary refuses to start rather than running email-less (the
    // local-dev feature exists only because Smart App Control blocks
    // lettre's icu build scripts on the dev machine; see Cargo.toml).
    #[cfg(not(feature = "smtp"))]
    {
        let _ = (config, shutdown);
        Err(std::io::Error::other(
            "this relay was built without the `smtp` feature; production \
             relays must be built with default features",
        ))
    }
    #[cfg(feature = "smtp")]
    {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let smtp_password = std::fs::read_to_string(&config.smtp.password_path)?;
        let mailer: Arc<dyn email::Mailer> = Arc::new(
            email::SmtpMailer::new(
                &config.smtp.host,
                config.smtp.port,
                &config.smtp.username,
                smtp_password.trim(),
                &config.smtp.from,
            )
            .map_err(std::io::Error::other)?,
        );
        let services = AppServices {
            beacon_key: load_beacon_key(&config.beacon_key_path)?,
            feed_store: feeds::FeedStore::load_dir(&config.feeds_dir)?,
            mailer,
        };
        run_with_listener(
            listener,
            config.tls_cert_path,
            config.tls_key_path,
            services,
            shutdown,
        )
        .await
    }
}

/// Same as [`run`], but takes an already-bound listener. Lets a caller
/// (tests, mainly) bind to an OS-assigned port (`127.0.0.1:0`) and read
/// back the real port via `TcpListener::local_addr` before the server
/// starts accepting — `run` alone gives no way to learn that port from
/// the outside.
///
/// Takes owned `PathBuf`s, not `&Path`: this function is meant to be
/// spawned as a background task (tests do; so might a real caller), and an
/// async fn's borrowed parameters must outlive the returned future — which
/// a `'static`-bound spawned task can't guarantee for a borrow from the
/// caller's local stack.
pub async fn run_with_listener(
    listener: TcpListener,
    tls_cert_path: PathBuf,
    tls_key_path: PathBuf,
    services: AppServices,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let tls_config = load_tls_config(&tls_cert_path, &tls_key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    tracing::info!(addr = %listener.local_addr()?, "relay starting");

    let app = app(services);
    // A JoinSet of raw tasks isn't enough for graceful shutdown: an
    // HTTP/1.1 keep-alive connection's task doesn't finish just because we
    // stop accepting new connections — it stays open waiting for a
    // possible next request until the *client* closes it, which a
    // TLS-terminating relay has no control over. GracefulShutdown solves
    // this properly: `shutdown()` signals every watched connection to
    // finish its current exchange and refuse further keep-alive reuse.
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                tracing::info!("shutdown signal received, draining in-flight connections");
                break;
            }
            accepted = listener.accept() => {
                let Ok((tcp_stream, _peer_addr)) = accepted else { continue };
                let acceptor = acceptor.clone();
                let app = app.clone();
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(tcp_stream).await else {
                        return;
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = TowerToHyperService::new(app);
                    let builder = ConnBuilder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(io, service);
                    let _ = watcher.watch(conn).await;
                });
            }
        }
    }

    let _ = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, graceful.shutdown()).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(
            &path,
            r#"
            bind_addr = "127.0.0.1:8443"
            tls_cert_path = "cert.pem"
            tls_key_path = "key.pem"
            beacon_key_path = "beacon.key"
            feeds_dir = "feeds"

            [smtp]
            host = "smtp.example.com"
            port = 465
            username = "alerts"
            password_path = "smtp.pass"
            from = "alerts@example.com"
            "#,
        )
        .unwrap();

        let config = RelayConfig::load(&path).unwrap();
        assert_eq!(config.bind_addr.port(), 8443);
        assert_eq!(config.tls_cert_path, PathBuf::from("cert.pem"));
        assert_eq!(config.beacon_key_path, PathBuf::from("beacon.key"));
        assert_eq!(config.feeds_dir, PathBuf::from("feeds"));
        assert_eq!(config.smtp.host, "smtp.example.com");
        assert_eq!(config.smtp.password_path, PathBuf::from("smtp.pass"));
    }

    #[test]
    fn config_without_an_smtp_table_is_rejected_at_parse_time() {
        // Same landmine shape as TLS/beacon/feeds: no Option, no default,
        // no email-less relay config.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(
            &path,
            r#"
            bind_addr = "127.0.0.1:8443"
            tls_cert_path = "cert.pem"
            tls_key_path = "key.pem"
            beacon_key_path = "beacon.key"
            feeds_dir = "feeds"
            "#,
        )
        .unwrap();
        assert!(RelayConfig::load(&path).is_err());
    }

    #[test]
    fn config_without_a_feeds_dir_is_rejected_at_parse_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(
            &path,
            r#"
            bind_addr = "127.0.0.1:8443"
            tls_cert_path = "cert.pem"
            tls_key_path = "key.pem"
            beacon_key_path = "beacon.key"
            "#,
        )
        .unwrap();
        assert!(RelayConfig::load(&path).is_err());
    }

    #[test]
    fn config_without_a_beacon_key_path_is_rejected_at_parse_time() {
        // Same landmine shape as the TLS one below: no Option, no default,
        // no beacon-less relay.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(
            &path,
            r#"
            bind_addr = "127.0.0.1:8443"
            tls_cert_path = "cert.pem"
            tls_key_path = "key.pem"
            feeds_dir = "feeds"
            "#,
        )
        .unwrap();
        assert!(RelayConfig::load(&path).is_err());
    }

    #[test]
    fn beacon_key_loads_from_exactly_64_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("beacon.key");
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        let key = load_beacon_key(&path).unwrap();
        assert_eq!(key.to_bytes(), [0xab; 32]);
    }

    #[test]
    fn truncated_or_non_hex_beacon_keys_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["ab".repeat(31), "zz".repeat(32), String::new()] {
            let path = dir.path().join("beacon.key");
            std::fs::write(&path, bad).unwrap();
            assert!(
                load_beacon_key(&path).is_err(),
                "a wrong-shape seed must never quietly become a key"
            );
        }
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let result = RelayConfig::load(Path::new("does/not/exist.toml"));
        assert!(matches!(result, Err(ConfigError::Io(_))));
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(&path, "this is not valid toml {{{").unwrap();
        let result = RelayConfig::load(&path);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn config_with_no_tls_paths_is_rejected_at_parse_time() {
        // Landmine: there must be no way to construct a RelayConfig
        // without TLS cert/key paths — no Option<PathBuf>, no default. If
        // someone adds one to make a field "optional," this test starts
        // failing instead of silently allowing a plaintext-capable config.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(&path, r#"bind_addr = "127.0.0.1:8443""#).unwrap();
        assert!(RelayConfig::load(&path).is_err());
    }
}
