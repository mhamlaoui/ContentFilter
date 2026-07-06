//! HTTP endpoints for the household registry (relay-registry-pairing),
//! and the wire format for relay-auth's signed request statements.
//!
//! # The auth wire format
//!
//! A mutating request carries four headers — `x-cf-device-id` (hex),
//! `x-cf-timestamp` (decimal seconds), `x-cf-nonce` (hex), and
//! `x-cf-signature` (hex). Everything else the statement signs (method,
//! path, body hash) is taken from the request the relay *actually
//! received*, never from headers — so endpoint binding and body binding
//! aren't checks the handler could forget; they're how the statement is
//! reconstructed in the first place.
//!
//! # Endpoints
//!
//! - `POST /v1/households` — open a household. Authenticated by the
//!   anchor's own self-attestation (no device exists yet to sign a
//!   relay-auth statement); registers the founding device atomically.
//! - `GET /v1/households/{id}/anchor` — the stored anchor, exactly as
//!   stored. Unauthenticated: the household id is an opaque 128-bit
//!   capability, and the anchor contains only public material.
//! - `POST /v1/households/{id}/pairing-codes` — relay-auth signed, and
//!   the authenticated device must be a member of the household in the
//!   path. Empty body (its sha256 is still signed).
//! - `POST /v1/pair` — redeem a pairing code (`cf_core::RegisterRequest`
//!   in, `cf_core::RegisterResponse` out — the shapes core-relay-client
//!   already speaks). Unauthenticated: the single-use, expiring code is
//!   the bearer secret.
//!
//! No anchor-rotation endpoint yet, deliberately: `Registry::replace_anchor`
//! implements the old-key rule, but choosing *who may submit* a rotation
//! over the wire (and the recovery flow for a lost key) is
//! sec-key-recovery's design work, not something to improvise here.
//!
//! Randomness (device ids, pairing codes) comes from `ring`'s
//! `SystemRandom` — already in the dependency graph as rustls's crypto
//! backend; never hand-rolled (see RULES.md).

use crate::auth::{
    verify_mutating_request, AuthError, IncomingRequest, ReplayGuard, DEFAULT_MAX_SKEW_SECONDS,
};
use crate::feeds::FeedStore;
use crate::registry::{DeviceSubmission, PairingCode, Registry, RegistryError, PAIRING_CODE_LEN};
use axum::body::to_bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cf_core::request_auth::{body_sha256, AuthStatement, REQUEST_NONCE_LEN};
use cf_core::timeanchor::{sign_beacon, TimeBeacon};
use cf_core::{
    Device, DeviceId, DeviceRole, Ed25519PublicKey, FeedKind, HouseholdId, Platform,
    RegisterRequest, RegisterResponse, SchemaVersion, Signature, TrustAnchor,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<Shared>>,
    rng: SystemRandom,
    /// Signs time beacons (relay-timeanchor). Online operational key —
    /// see `RelayConfig::beacon_key_path` for why that's acceptable.
    beacon_key: Arc<ed25519_dalek::SigningKey>,
    /// Release-signed feeds, loaded at startup (relay-feeds). Immutable
    /// once loaded — not inside the Mutex.
    feed_store: Arc<FeedStore>,
}

struct Shared {
    registry: Registry,
    guard: ReplayGuard,
}

impl AppState {
    pub fn new(services: crate::AppServices) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Shared {
                registry: Registry::new(),
                guard: ReplayGuard::new(DEFAULT_MAX_SKEW_SECONDS),
            })),
            rng: SystemRandom::new(),
            beacon_key: Arc::new(services.beacon_key),
            feed_store: Arc::new(services.feed_store),
        }
    }

    fn random_bytes<const N: usize>(&self) -> [u8; N] {
        let mut out = [0u8; N];
        self.rng
            .fill(&mut out)
            .expect("OS CSPRNG failure is not a recoverable request error");
        out
    }
}

// No Default impl on purpose: a "default" AppState would need a beacon
// key from somewhere, and an implicitly-minted one in production would be
// a key nobody provisioned or pinned.

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/households", post(create_household))
        .route("/v1/households/:household/anchor", get(get_anchor))
        .route(
            "/v1/households/:household/pairing-codes",
            post(issue_pairing_code),
        )
        .route("/v1/pair", post(pair))
        .route("/v1/time/beacon", get(get_beacon))
        .route("/v1/time/key", get(get_beacon_key))
        .route("/v1/feeds/:kind", get(get_feed))
        .with_state(state)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_secs()
}

// --- wire types -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireDeviceSubmission {
    pub platform: Platform,
    pub role: DeviceRole,
    pub identity_key: Ed25519PublicKey,
}

impl From<WireDeviceSubmission> for DeviceSubmission {
    fn from(w: WireDeviceSubmission) -> Self {
        DeviceSubmission {
            platform: w.platform,
            role: w.role,
            identity_key: w.identity_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHouseholdRequest {
    pub version: SchemaVersion,
    pub anchor: TrustAnchor,
    pub device: WireDeviceSubmission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHouseholdResponse {
    pub version: SchemaVersion,
    pub device: Device,
    pub anchor: TrustAnchor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuePairingCodeResponse {
    pub version: SchemaVersion,
    /// Hex; redeemed via `RegisterRequest::pairing_code`.
    pub code: String,
    pub expires_at: u64,
}

/// A signed time beacon (relay-timeanchor). `seq` equals `utc` by design:
/// the emitter needs monotonic seqs that survive relay restarts, and unix
/// seconds are exactly that with zero storage. A relay clock rollback
/// stops floors advancing rather than corrupting them (clients require a
/// strictly increasing seq and treat repeats as stale no-ops), and the
/// relay never signing a future time is what keeps `floor ≤ real now` —
/// the property core-weakening's grant timestamps lean on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeaconResponse {
    pub version: SchemaVersion,
    pub utc: u64,
    pub seq: u64,
    /// Hex Ed25519 signature over the beacon's canonical bytes
    /// (cf-core `timeanchor`).
    pub signature: String,
}

/// Discovery convenience only. The beacon verify key a device *trusts* is
/// pinned at install (inst-custom-actions), not fetched from the party it
/// is meant to check — this endpoint exists for provisioning tooling and
/// tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeaconKeyResponse {
    pub version: SchemaVersion,
    pub beacon_verify_key: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: msg.into() })).into_response()
}

fn registry_error_response(e: RegistryError) -> Response {
    let status = match &e {
        RegistryError::AnchorSignature(_) | RegistryError::InvalidPairingCode => {
            StatusCode::UNAUTHORIZED
        }
        RegistryError::SchemaVersion | RegistryError::HouseholdMismatch => StatusCode::BAD_REQUEST,
        RegistryError::HouseholdExists | RegistryError::SeqNotAdvanced { .. } => {
            StatusCode::CONFLICT
        }
        RegistryError::UnknownHousehold => StatusCode::NOT_FOUND,
        RegistryError::NotAMember => StatusCode::FORBIDDEN,
        RegistryError::DeviceIdCollision => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, e.to_string())
}

// --- hand-rolled hex (formatting, not a primitive — same policy as
// cf-core's hex module, which is deliberately crate-private there) --------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

// --- auth header extraction ---------------------------------------------

// Boxed error Responses below: clippy's result_large_err is right that a
// full http::Response is a heavyweight Err variant on a hot Ok path.
fn auth_header<'h>(headers: &'h HeaderMap, name: &str) -> Result<&'h str, Box<Response>> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Box::new(error_response(
                StatusCode::UNAUTHORIZED,
                format!("missing header {name}"),
            ))
        })
}

/// Rebuilds the signed statement from the request the relay actually
/// received (method, path, body) plus the four auth headers, and runs the
/// full relay-auth pipeline. Returns the authenticated device id.
fn authenticate(
    shared: &mut Shared,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<DeviceId, Box<Response>> {
    let unauthorized =
        |e: AuthError| Box::new(error_response(StatusCode::UNAUTHORIZED, e.to_string()));
    let malformed = || {
        Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "malformed auth header",
        ))
    };

    let device_hex = auth_header(headers, "x-cf-device-id")?;
    let ts_str = auth_header(headers, "x-cf-timestamp")?;
    let nonce_hex = auth_header(headers, "x-cf-nonce")?;
    let sig_hex = auth_header(headers, "x-cf-signature")?;

    let device_id = DeviceId::from_hex(device_hex).map_err(|_| malformed())?;
    let ts: u64 = ts_str.parse().map_err(|_| malformed())?;
    let nonce: [u8; REQUEST_NONCE_LEN] = hex_decode(nonce_hex).ok_or_else(malformed)?;
    let signature = Signature::from_hex(sig_hex).map_err(|_| malformed())?;

    let statement = AuthStatement::new(device_id, method, path, body_sha256(body), ts, nonce)
        .map_err(|_| malformed())?;
    let incoming = IncomingRequest { method, path, body };
    verify_mutating_request(
        &statement,
        &signature,
        incoming,
        &shared.registry,
        &mut shared.guard,
        now,
    )
    .map_err(unauthorized)
}

// --- handlers ------------------------------------------------------------

async fn get_beacon(State(state): State<AppState>) -> Response {
    let now = unix_now();
    let beacon = TimeBeacon { utc: now, seq: now };
    let signature = sign_beacon(&beacon, &state.beacon_key);
    Json(BeaconResponse {
        version: SchemaVersion::CURRENT,
        utc: beacon.utc,
        seq: beacon.seq,
        signature: hex_encode(&signature.0),
    })
    .into_response()
}

async fn get_beacon_key(State(state): State<AppState>) -> Response {
    Json(BeaconKeyResponse {
        version: SchemaVersion::CURRENT,
        beacon_verify_key: hex_encode(&state.beacon_key.verifying_key().to_bytes()),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct FeedQuery {
    /// The client's last accepted feed_seq (cf-core `pull_feed` sends
    /// it). Present and current → 304; absent → the latest is served.
    newer_than: Option<u64>,
}

async fn get_feed(
    State(state): State<AppState>,
    Path(kind_str): Path<String>,
    Query(query): Query<FeedQuery>,
) -> Response {
    // Kind names follow FeedKind's serde spelling.
    let kind = match kind_str.as_str() {
        "blocklist" => FeedKind::Blocklist,
        "doh_endpoints" => FeedKind::DohEndpoints,
        _ => return error_response(StatusCode::NOT_FOUND, "unknown feed kind"),
    };
    let Some(envelope) = state.feed_store.latest(kind) else {
        return error_response(StatusCode::NOT_FOUND, "no feed published yet");
    };
    if let Some(have) = query.newer_than {
        if envelope.feed_seq <= have {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }
    Json(envelope.clone()).into_response()
}

async fn create_household(
    State(state): State<AppState>,
    Json(request): Json<CreateHouseholdRequest>,
) -> Response {
    if request.version.check().is_err() {
        return error_response(StatusCode::BAD_REQUEST, "unsupported schema version");
    }
    let device_id = DeviceId(state.random_bytes());
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    match shared.registry.create_household(
        request.anchor.clone(),
        request.device.into(),
        device_id,
        now,
    ) {
        Ok(device) => (
            StatusCode::CREATED,
            Json(CreateHouseholdResponse {
                version: SchemaVersion::CURRENT,
                device,
                anchor: request.anchor,
            }),
        )
            .into_response(),
        Err(e) => registry_error_response(e),
    }
}

async fn get_anchor(State(state): State<AppState>, Path(household_hex): Path<String>) -> Response {
    let Ok(household_id) = HouseholdId::from_hex(&household_hex) else {
        return error_response(StatusCode::NOT_FOUND, "household not found");
    };
    let shared = state.inner.lock().expect("registry lock poisoned");
    match shared.registry.anchor(&household_id) {
        Ok(anchor) => Json(anchor.clone()).into_response(),
        Err(e) => registry_error_response(e),
    }
}

async fn issue_pairing_code(
    State(state): State<AppState>,
    Path(household_hex): Path<String>,
    request: Request,
) -> Response {
    let Ok(household_id) = HouseholdId::from_hex(&household_hex) else {
        return error_response(StatusCode::NOT_FOUND, "household not found");
    };
    let (parts, body) = request.into_parts();
    let Ok(body_bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    };
    let code: PairingCode = state.random_bytes();
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let device_id = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        parts.uri.path(),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    match shared
        .registry
        .issue_pairing_code(&household_id, &device_id, code, now)
    {
        Ok(expires_at) => (
            StatusCode::CREATED,
            Json(IssuePairingCodeResponse {
                version: SchemaVersion::CURRENT,
                code: hex_encode(&code),
                expires_at,
            }),
        )
            .into_response(),
        Err(e) => registry_error_response(e),
    }
}

async fn pair(State(state): State<AppState>, Json(request): Json<RegisterRequest>) -> Response {
    if request.version.check().is_err() {
        return error_response(StatusCode::BAD_REQUEST, "unsupported schema version");
    }
    // A malformed code is indistinguishable from an unknown one on
    // purpose — same reasoning as the registry collapsing unknown/
    // expired/used into one error.
    let Some(code) = hex_decode::<PAIRING_CODE_LEN>(&request.pairing_code) else {
        return registry_error_response(RegistryError::InvalidPairingCode);
    };
    let submission = DeviceSubmission {
        platform: request.platform,
        role: request.role.clone(),
        identity_key: request.identity_key,
    };
    let device_id = DeviceId(state.random_bytes());
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    match shared
        .registry
        .redeem_pairing_code(&code, submission, device_id, now)
    {
        Ok((device, anchor)) => Json(RegisterResponse {
            version: SchemaVersion::CURRENT,
            device,
            anchor,
        })
        .into_response(),
        Err(e) => registry_error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use cf_core::household::sign_anchor;
    use cf_core::request_auth::{self};
    use cf_core::{Tier, X25519PublicKey};
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;

    fn partner_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn test_router() -> Router {
        test_router_with_feeds(FeedStore::empty())
    }

    fn test_router_with_feeds(feed_store: FeedStore) -> Router {
        router(AppState::new(crate::AppServices {
            beacon_key: SigningKey::from_bytes(&[0xB0; 32]),
            feed_store,
        }))
    }

    fn founder_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x70; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn signed_anchor() -> TrustAnchor {
        let (sk, vk) = partner_keys();
        let mut anchor = TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HouseholdId([4u8; 16]),
            seq: 1,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: 86_400,
            tier: Tier::Hardened,
            signature: Signature([0u8; 64]),
        };
        anchor.signature = sign_anchor(&anchor, &sk);
        anchor
    }

    async fn send_json(
        router: &Router,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    /// Signs an empty-body request the way a real device would and sends
    /// it with the four auth headers.
    async fn send_signed_empty_post(
        router: &Router,
        path: &str,
        device_id_hex: &str,
        signing_key: &SigningKey,
        nonce_byte: u8,
    ) -> (StatusCode, serde_json::Value) {
        let device_id = DeviceId::from_hex(device_id_hex).unwrap();
        let ts = unix_now();
        let nonce = [nonce_byte; REQUEST_NONCE_LEN];
        let statement =
            AuthStatement::new(device_id, "POST", path, body_sha256(b""), ts, nonce).unwrap();
        let signature = request_auth::sign(&statement, signing_key).unwrap();

        let request = HttpRequest::builder()
            .method("POST")
            .uri(path)
            .header("x-cf-device-id", device_id_hex)
            .header("x-cf-timestamp", ts.to_string())
            .header("x-cf-nonce", hex_encode(&nonce))
            .header("x-cf-signature", signature.to_hex())
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    fn create_body() -> serde_json::Value {
        let (_, founder_vk) = founder_keys();
        serde_json::json!({
            "version": 1,
            "anchor": serde_json::to_value(signed_anchor()).unwrap(),
            "device": {
                "platform": "windows",
                "role": { "role": "monitored" },
                "identity_key": founder_vk.to_hex(),
            },
        })
    }

    async fn founded_router() -> (Router, String, String) {
        let router = test_router();
        let (status, body) = send_json(&router, "POST", "/v1/households", create_body()).await;
        assert_eq!(status, StatusCode::CREATED, "create failed: {body}");
        let device_id_hex = body["device"]["id"].as_str().unwrap().to_string();
        let household_hex = body["anchor"]["household_id"].as_str().unwrap().to_string();
        (router, household_hex, device_id_hex)
    }

    #[tokio::test]
    async fn create_household_stores_and_serves_the_signed_anchor() {
        let (router, household_hex, _) = founded_router().await;
        let request = HttpRequest::builder()
            .method("GET")
            .uri(format!("/v1/households/{household_hex}/anchor"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let served: TrustAnchor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(served, signed_anchor(), "served exactly as stored");
        assert!(served.verify_self_signed().is_ok(), "served signed");
    }

    #[tokio::test]
    async fn a_tampered_anchor_cannot_open_a_household() {
        let router = test_router();
        let mut body = create_body();
        body["anchor"]["cooling_off_seconds"] = serde_json::json!(0);
        let (status, _) = send_json(&router, "POST", "/v1/households", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_full_pairing_flow_registers_the_joiner() {
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let path = format!("/v1/households/{household_hex}/pairing-codes");

        let (status, body) =
            send_signed_empty_post(&router, &path, &founder_id_hex, &founder_sk, 1).await;
        assert_eq!(status, StatusCode::CREATED, "issue failed: {body}");
        let code = body["code"].as_str().unwrap().to_string();

        let joiner_sk = SigningKey::from_bytes(&[0x71; 32]);
        let joiner_vk = Ed25519PublicKey(joiner_sk.verifying_key().to_bytes());
        let (status, body) = send_json(
            &router,
            "POST",
            "/v1/pair",
            serde_json::json!({
                "version": 1,
                "pairing_code": code,
                "platform": "android",
                "role": { "role": "monitored" },
                "identity_key": joiner_vk.to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "pair failed: {body}");
        let response: RegisterResponse = serde_json::from_value(body).unwrap();
        assert_eq!(response.device.identity_key, joiner_vk);
        assert_eq!(response.anchor, signed_anchor());

        // The joiner is now a registered member: it can authenticate a
        // mutating request of its own (issuing a fresh code) — proving the
        // pubkey registration end to end.
        let joiner_id_hex = response.device.id.to_hex();
        let (status, _) =
            send_signed_empty_post(&router, &path, &joiner_id_hex, &joiner_sk, 2).await;
        assert_eq!(status, StatusCode::CREATED);

        // And the consumed code is dead.
        let (status, _) = send_json(
            &router,
            "POST",
            "/v1/pair",
            serde_json::json!({
                "version": 1,
                "pairing_code": code,
                "platform": "ios",
                "role": { "role": "monitored" },
                "identity_key": joiner_vk.to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_unknown_or_malformed_code_is_rejected() {
        let (router, _, _) = founded_router().await;
        for bad_code in ["00".repeat(PAIRING_CODE_LEN), "not-hex".to_string()] {
            let (status, _) = send_json(
                &router,
                "POST",
                "/v1/pair",
                serde_json::json!({
                    "version": 1,
                    "pairing_code": bad_code,
                    "platform": "ios",
                    "role": { "role": "monitored" },
                    "identity_key": Ed25519PublicKey([9u8; 32]).to_hex(),
                }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn issuing_codes_requires_a_valid_signature_from_a_member() {
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let path = format!("/v1/households/{household_hex}/pairing-codes");

        // No auth headers at all:
        let request = HttpRequest::builder()
            .method("POST")
            .uri(&path)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Right device id, wrong key:
        let wrong_sk = SigningKey::from_bytes(&[0x99; 32]);
        let (status, _) =
            send_signed_empty_post(&router, &path, &founder_id_hex, &wrong_sk, 3).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_replayed_signed_request_is_rejected() {
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let path = format!("/v1/households/{household_hex}/pairing-codes");

        // Same nonce byte -> byte-identical statement both times.
        let (status, _) =
            send_signed_empty_post(&router, &path, &founder_id_hex, &founder_sk, 7).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, body) =
            send_signed_empty_post(&router, &path, &founder_id_hex, &founder_sk, 7).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "replay accepted: {body}");
    }

    // --- feeds (relay-feeds) ---------------------------------------------

    fn release_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x51; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn loaded_feed_store(seq: u64) -> FeedStore {
        // Through the real file-loading path, not a struct literal.
        let (release_sk, _) = release_keys();
        let dir = tempfile::tempdir().unwrap();
        let envelope = cf_core::relay_client::sign_feed(
            FeedKind::Blocklist,
            seq,
            1_700_000_000,
            b"blocked.example".to_vec(),
            &release_sk,
        );
        std::fs::write(
            dir.path().join("blocklist.json"),
            serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap();
        FeedStore::load_dir(dir.path()).unwrap()
    }

    async fn fetch_feed_response(
        router: &Router,
        uri: &str,
    ) -> (StatusCode, Option<cf_core::FeedEnvelope>) {
        let request = HttpRequest::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let envelope = if status == StatusCode::OK {
            Some(serde_json::from_slice(&bytes).unwrap())
        } else {
            None
        };
        (status, envelope)
    }

    #[tokio::test]
    async fn feeds_are_served_signed_and_a_client_accepts_them_end_to_end() {
        let router = test_router_with_feeds(loaded_feed_store(7));
        let (status, envelope) = fetch_feed_response(&router, "/v1/feeds/blocklist").await;
        assert_eq!(status, StatusCode::OK);
        let envelope = envelope.unwrap();
        assert_eq!(envelope.feed_seq, 7);

        // The DoD's client half, against the served bytes: cf-core's
        // client verifies the release signature and accepts.
        struct Served(Option<cf_core::FeedEnvelope>);
        impl cf_core::RelayTransport for Served {
            fn register(
                &mut self,
                _: &RegisterRequest,
            ) -> Result<RegisterResponse, cf_core::TransportError> {
                unreachable!("feed test")
            }
            fn push_event(
                &mut self,
                _: &HouseholdId,
                _: &cf_core::ChainedEvent,
            ) -> Result<(), cf_core::TransportError> {
                unreachable!("feed test")
            }
            fn fetch_feed(
                &mut self,
                _: FeedKind,
                _: Option<u64>,
            ) -> Result<Option<cf_core::FeedEnvelope>, cf_core::TransportError> {
                Ok(self.0.clone())
            }
            fn fetch_approvals(
                &mut self,
                _: &HouseholdId,
                _: &DeviceId,
            ) -> Result<Vec<cf_core::ApprovalMessage>, cf_core::TransportError> {
                unreachable!("feed test")
            }
        }

        let (_, release_vk) = release_keys();
        let mut client = cf_core::RelayClient::new(release_vk);
        let accepted = client
            .pull_feed(&mut Served(Some(envelope.clone())), FeedKind::Blocklist)
            .unwrap();
        assert_eq!(accepted.unwrap().feed_seq, 7);

        // And the other client half: a tampered envelope served over the
        // same path is rejected by the pinned-key check.
        let mut tampered = envelope;
        tampered.payload = Vec::new(); // an emptied blocklist
        let mut fresh_client = cf_core::RelayClient::new(release_vk);
        assert_eq!(
            fresh_client.pull_feed(&mut Served(Some(tampered)), FeedKind::Blocklist),
            Err(cf_core::RelayClientError::FeedSignatureInvalid)
        );
    }

    #[tokio::test]
    async fn conditional_get_returns_not_modified_when_nothing_newer() {
        let router = test_router_with_feeds(loaded_feed_store(7));
        let (status, _) = fetch_feed_response(&router, "/v1/feeds/blocklist?newer_than=7").await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        let (status, envelope) =
            fetch_feed_response(&router, "/v1/feeds/blocklist?newer_than=6").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(envelope.unwrap().feed_seq, 7);
    }

    #[tokio::test]
    async fn unpublished_and_unknown_feed_kinds_return_not_found() {
        let router = test_router_with_feeds(loaded_feed_store(7));
        let (status, _) = fetch_feed_response(&router, "/v1/feeds/doh_endpoints").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no DoH feed published");
        let (status, _) = fetch_feed_response(&router, "/v1/feeds/malware").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown kind");
    }

    // --- time beacons (relay-timeanchor) --------------------------------

    #[tokio::test]
    async fn served_beacons_verify_and_advance_a_client_floor() {
        use cf_core::timeanchor::{verify_beacon, FloorStore, TimeAnchor};
        use cf_core::Signature as CfSignature;

        #[derive(Default)]
        struct MemFloor(Option<(u64, u64)>);
        impl FloorStore for MemFloor {
            fn load_floor(&self) -> Option<(u64, u64)> {
                self.0
            }
            fn save_floor(&mut self, utc: u64, seq: u64) {
                self.0 = Some((utc, seq));
            }
        }

        let router = test_router();

        // Discover the verify key (in production this is pinned at
        // install; here it seeds the same verification code path).
        let request = HttpRequest::builder()
            .method("GET")
            .uri("/v1/time/key")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let key_body: BeaconKeyResponse = serde_json::from_slice(&bytes).unwrap();
        let verify_key = Ed25519PublicKey::from_hex(&key_body.beacon_verify_key).unwrap();

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/v1/time/beacon")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let beacon_body: BeaconResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(beacon_body.seq, beacon_body.utc, "seq = utc by design");

        let beacon = TimeBeacon {
            utc: beacon_body.utc,
            seq: beacon_body.seq,
        };
        let signature = CfSignature::from_hex(&beacon_body.signature).unwrap();
        assert!(
            verify_beacon(&beacon, &signature, &verify_key).is_ok(),
            "served beacon must verify"
        );

        // The DoD's "devices persist the floor": ingesting the served
        // beacon through the real client path lands it in the store.
        let mut anchor = TimeAnchor::new(MemFloor::default());
        anchor
            .ingest_beacon(&beacon, &signature, &verify_key)
            .unwrap();
        assert_eq!(anchor.effective_now(0), beacon.utc);

        // A tampered beacon is rejected by the same client path.
        let tampered = TimeBeacon {
            utc: beacon.utc + 999,
            seq: beacon.seq + 999,
        };
        assert!(
            anchor
                .ingest_beacon(&tampered, &signature, &verify_key)
                .is_err(),
            "a tampered beacon must not move the floor"
        );
        assert_eq!(anchor.effective_now(0), beacon.utc);
    }

    #[tokio::test]
    async fn beacon_seq_never_decreases_across_requests() {
        let router = test_router();
        let mut last = 0u64;
        for _ in 0..3 {
            let request = HttpRequest::builder()
                .method("GET")
                .uri("/v1/time/beacon")
                .body(Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
                .await
                .unwrap();
            let body: BeaconResponse = serde_json::from_slice(&bytes).unwrap();
            assert!(body.seq >= last, "beacon seq went backward");
            last = body.seq;
        }
    }

    #[tokio::test]
    async fn unknown_household_paths_return_not_found() {
        let (router, _, _) = founded_router().await;
        let missing = HouseholdId([0xEE; 16]).to_hex();
        let request = HttpRequest::builder()
            .method("GET")
            .uri(format!("/v1/households/{missing}/anchor"))
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
