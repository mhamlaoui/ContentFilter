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
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        &cert_path,
        &key_path,
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
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        &cert_path,
        &key_path,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let plaintext_result = tokio::task::spawn_blocking(move || {
        let mut stream = StdTcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 64];
        stream.read(&mut buf)
    })
    .await
    .unwrap();

    // Either the read errors (connection reset/timeout) or returns 0 bytes
    // (clean close) — what it must never do is look like an HTTP response.
    match plaintext_result {
        Ok(0) => {} // connection closed without sending anything
        Ok(n) => panic!("expected no plaintext response, got {n} bytes"),
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
async fn shutdown_drains_an_in_flight_request_instead_of_dropping_it() {
    // A request that's already in flight when shutdown is signaled must
    // still complete successfully — graceful shutdown stops accepting
    // *new* connections, it doesn't abandon ones already being served.
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_test_cert(dir.path());
    let (listener, addr) = bound_loopback_listener().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(cf_relay::run_with_listener(
        listener,
        &cert_path,
        &key_path,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let client = trusting_reqwest_client(&cert_path);
    let url = format!("https://localhost:{}/healthz", addr.port());

    // Fire the request and the shutdown signal essentially together; the
    // request should still complete successfully.
    let request = client.get(&url).send();
    let _ = shutdown_tx.send(());
    let response = request.await.expect("in-flight request should complete");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server should shut down within the grace period")
        .unwrap()
        .unwrap();
}
