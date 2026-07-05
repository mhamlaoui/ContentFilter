//! Integration tests for relay-bootstrap's DoD: health check succeeds over
//! real TLS, plaintext is refused (not just "discouraged"), and shutdown
//! drains in-flight work rather than dropping it.

use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::time::Duration;
use tokio::net::TcpListener;

/// Writes a fresh self-signed cert/key pair (via rcgen's pure-Rust `ring`
/// backend, matching cf-relay's own choice) into `dir`, returning their
/// paths. Generated per test run, never checked into the repo — this is
/// also why the repo's own no-private-key CI guard never has to know about
/// test certificates.
fn generate_test_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

async fn bound_loopback_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn trusting_reqwest_client(cert_pem_path: &std::path::Path) -> reqwest::Client {
    let cert_pem = std::fs::read(cert_pem_path).unwrap();
    let cert = reqwest::Certificate::from_pem(&cert_pem).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap()
}

#[tokio::test]
async fn health_check_returns_200_over_tls() {
    cf_relay::ensure_crypto_provider_installed();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        cert_path.clone(),
        key_path.clone(),
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let client = trusting_reqwest_client(&cert_path);
    let url = format!("https://localhost:{}/healthz", addr.port());
    let response = client
        .get(&url)
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server should shut down within the timeout")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn plaintext_http_is_refused_not_served() {
    // TLS enforced means a plaintext client gets no valid HTTP response at
    // all, not a redirect or an error page — the TLS handshake itself is
    // the only thing this listener speaks.
    cf_relay::ensure_crypto_provider_installed();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        cert_path.clone(),
        key_path.clone(),
        async {
            let _ = shutdown_rx.await;
        },
    ));

    // Returns the bytes actually read (possibly none), rather than just an
    // io::Result<usize>, so the assertion below can inspect their content.
    let plaintext_result: std::io::Result<Vec<u8>> = tokio::task::spawn_blocking(move || {
        let mut stream = StdTcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf)?;
        Ok(buf[..n].to_vec())
    })
    .await
    .unwrap();

    // The acceptor tries to parse the plaintext bytes as a TLS ClientHello,
    // fails, and (per the TLS spec) sends a fatal alert record before
    // closing — a handful of raw bytes (e.g. a 7-byte alert: 5-byte record
    // header + 2-byte alert body) is expected and correct. A read erroring
    // out (reset/timeout) is also fine. What must never happen is those
    // bytes forming a valid-looking HTTP response, which would mean the
    // plaintext request actually reached the health handler.
    match plaintext_result {
        Ok(bytes) if bytes.is_empty() => {} // connection closed without sending anything
        Ok(bytes) => {
            assert!(
                !bytes.starts_with(b"HTTP/"),
                "plaintext request got an HTTP-looking response: {bytes:?}"
            );
        }
        Err(_) => {} // reset or timed out, also acceptable
    }

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server should still shut down cleanly")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_does_not_hang_on_an_idle_keepalive_connection() {
    // Regression test for a real bug caught by this exact test suite in
    // CI: a naive graceful-shutdown implementation (wait for spawned
    // connection tasks to finish naturally) hangs forever on an HTTP/1.1
    // keep-alive connection, because that task doesn't finish just because
    // the server stops accepting new connections — it waits for a possible
    // next request until the *client* closes it, which the server has no
    // control over. A completed request whose connection is still open
    // (kept alive for reuse, which reqwest does by default) must not block
    // shutdown.
    cf_relay::ensure_crypto_provider_installed();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        cert_path.clone(),
        key_path.clone(),
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let client = trusting_reqwest_client(&cert_path);
    let url = format!("https://localhost:{}/healthz", addr.port());

    let response = client
        .get(&url)
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // The connection is still open at this point: reqwest's pool keeps it
    // alive for reuse rather than closing it after one request.

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("shutdown must not hang on an idle keep-alive connection")
        .unwrap()
        .unwrap();
}
