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
use crate::log::{AppendOutcome, EventLog, LogError};
use crate::mailbox::{MailboxError, MailboxStore};
use crate::registry::{DeviceSubmission, PairingCode, Registry, RegistryError, PAIRING_CODE_LEN};
use crate::silence::{SilenceTracker, DEFAULT_SILENCE_THRESHOLD_SECONDS};
use axum::body::to_bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cf_core::request_auth::{body_sha256, AuthStatement, REQUEST_NONCE_LEN};
use cf_core::timeanchor::{sign_beacon, TimeBeacon};
use cf_core::{
    Device, DeviceId, DeviceRole, Ed25519PublicKey, FeedKind, HouseholdId, NotificationEvent,
    Platform, RegisterRequest, RegisterResponse, RequestId, SchemaVersion, Signature, TrustAnchor,
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

/// Pending-notification cap. This buffer is a loudly-documented stand-in
/// until relay-log (#31) persists events and #35/#37 deliver them; a cap
/// keeps a stalled pipeline from becoming unbounded memory, and dropping
/// the *oldest* (with a warning) loses the least — silence alerts repeat
/// their meaning as long as the outage lasts.
const MAX_PENDING_EVENTS: usize = 4096;

struct Shared {
    registry: Registry,
    guard: ReplayGuard,
    silence: SilenceTracker,
    log: EventLog,
    mailbox: MailboxStore,
    pending_events: std::collections::VecDeque<NotificationEvent>,
}

impl Shared {
    fn push_event(&mut self, event: NotificationEvent) {
        if self.pending_events.len() == MAX_PENDING_EVENTS {
            tracing::warn!("pending-event buffer full; dropping the oldest event");
            self.pending_events.pop_front();
        }
        tracing::info!(kind = ?event.kind, device = ?event.device_id, "notification event");
        self.pending_events.push_back(event);
    }

    fn record_liveness(&mut self, household_id: HouseholdId, device_id: DeviceId, now: u64) {
        if let Some(resumed) = self.silence.record_heartbeat(household_id, device_id, now) {
            self.push_event(resumed);
        }
    }
}

impl AppState {
    pub fn new(services: crate::AppServices) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Shared {
                registry: Registry::new(),
                guard: ReplayGuard::new(DEFAULT_MAX_SKEW_SECONDS),
                silence: SilenceTracker::new(DEFAULT_SILENCE_THRESHOLD_SECONDS),
                log: EventLog::new(),
                mailbox: MailboxStore::new(),
                pending_events: std::collections::VecDeque::new(),
            })),
            rng: SystemRandom::new(),
            beacon_key: Arc::new(services.beacon_key),
            feed_store: Arc::new(services.feed_store),
        }
    }

    /// Spawns the periodic silence sweep. Called from `app()` (under the
    /// server runtime), deliberately not from `router()` — endpoint tests
    /// drive `SilenceTracker` directly with a controlled clock instead.
    pub(crate) fn spawn_silence_sweeper(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = unix_now();
                let mut shared = state.inner.lock().expect("registry lock poisoned");
                let events = shared.silence.sweep(now);
                for event in events {
                    shared.push_event(event);
                }
            }
        });
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
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/households/:household/events", post(push_event))
        .route("/v1/households/:household/log/:device", get(get_device_log))
        .route("/v1/households/:household/messages", post(send_message))
        .route("/v1/households/:household/mailbox", get(fetch_mailbox))
        .with_state(state)
}

/// What devices sign as the statement's `path`: the path **and query**
/// exactly as received. Including the query keeps parameters like the
/// mailbox `after` floor inside the signature — CI caught the asymmetric
/// version (sign-with-query, verify-without) as an instant 401.
fn signed_path(uri: &axum::http::Uri) -> &str {
    uri.path_and_query()
        .map_or_else(|| uri.path(), |pq| pq.as_str())
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

pub(crate) fn hex_decode_any(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
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

/// Signed liveness ping (relay-heartbeat-silence). Empty body — its
/// sha256 is still inside the signed statement, and the nonce/timestamp
/// replay guard applies like any mutating request. 204 on success; the
/// subject is the authenticated device itself.
async fn heartbeat(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body_bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    };
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let device_id = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        signed_path(&parts.uri),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    // Auth guarantees the device is registered, so a missing household is
    // a registry invariant violation, not a client error.
    let Some(household_id) = shared.registry.household_of(&device_id) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "device has no household");
    };
    shared.record_liveness(household_id, device_id, now);
    StatusCode::NO_CONTENT.into_response()
}

/// A device chain's readable state (relay-log). Events ride exactly as
/// accepted — signatures intact — so the fetching side can run cf-core's
/// `verify_chain` over them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceLogResponse {
    pub version: SchemaVersion,
    pub pruned_before: u64,
    pub next_seq: u64,
    pub events: Vec<cf_core::ChainedEvent>,
}

fn log_error_response(e: LogError) -> Response {
    // Every rejection here is a flag worth keeping (THREAT_MODEL row 3):
    // gaps and forks are the censorship/rewrite signals.
    tracing::warn!(error = %e, "event append rejected");
    let status = match &e {
        LogError::UnknownDevice | LogError::InvalidSignature => StatusCode::UNAUTHORIZED,
        LogError::SeqGap { .. }
        | LogError::Fork { .. }
        | LogError::BrokenLink { .. }
        | LogError::SeqPruned { .. } => StatusCode::CONFLICT,
    };
    error_response(status, e.to_string())
}

/// Signed event push (relay-log): the wire behind
/// `RelayTransport::push_event`. Body is one `ChainedEvent`; the
/// authenticated device must be a member of the household in the path AND
/// the event's author — devices push their own history.
async fn push_event(
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
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let device_id = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        signed_path(&parts.uri),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    if !shared.registry.is_member(&household_id, &device_id) {
        return error_response(StatusCode::FORBIDDEN, "not a member of this household");
    }
    let Ok(event) = serde_json::from_slice::<cf_core::ChainedEvent>(&body_bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "body is not a chained event");
    };
    if event.device_id != device_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "events must be pushed by their author",
        );
    }
    // Pushing events is also a liveness signal — a device whose outbox is
    // draining is not silent.
    shared.record_liveness(household_id, device_id, now);
    // append needs &Registry (the key resolver) and &mut EventLog out of
    // the same &mut Shared — a destructuring split borrow provides both.
    let Shared { registry, log, .. } = &mut *shared;
    match log.append(household_id, event, &*registry) {
        Ok(AppendOutcome::Appended) => StatusCode::CREATED.into_response(),
        Ok(AppendOutcome::Duplicate) => StatusCode::OK.into_response(),
        Err(e) => log_error_response(e),
    }
}

/// Signed log fetch (relay-log): a member device (typically the partner's)
/// reads a device chain to audit it with cf-core's `verify_chain`.
async fn get_device_log(
    State(state): State<AppState>,
    Path((household_hex, device_hex)): Path<(String, String)>,
    request: Request,
) -> Response {
    let Ok(household_id) = HouseholdId::from_hex(&household_hex) else {
        return error_response(StatusCode::NOT_FOUND, "household not found");
    };
    let Ok(subject_device) = DeviceId::from_hex(&device_hex) else {
        return error_response(StatusCode::NOT_FOUND, "device not found");
    };
    let (parts, body) = request.into_parts();
    let Ok(body_bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    };
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let reader = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        signed_path(&parts.uri),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    if !shared.registry.is_member(&household_id, &reader) {
        return error_response(StatusCode::FORBIDDEN, "not a member of this household");
    }
    match shared.log.device_log(&household_id, &subject_device) {
        Some(view) => Json(DeviceLogResponse {
            version: SchemaVersion::CURRENT,
            pruned_before: view.pruned_before,
            next_seq: view.next_seq,
            events: view.events,
        })
        .into_response(),
        None => error_response(StatusCode::NOT_FOUND, "no events for this device"),
    }
}

/// The approval-transport wire encoding (relay-approvals-transport) —
/// the encoding cf-core deliberately left undefined so this ticket could
/// own it. `SealedRequest.sealed` is opaque ciphertext hex; `Verdict`
/// carries every `ApprovalStatement` field plus the signature, so the
/// receiving device reconstructs the exact signed statement and verifies
/// it at the point of consequence (`weakening::apply_approval`) — the
/// relay stores and returns these fields without interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageBody {
    SealedRequest {
        request: RequestId,
        /// Hex of cf-core's `salted_request_hash` — the rate-limit key;
        /// reveals nothing without the household salt.
        request_hash: String,
        /// Hex of the `SealedPayload` ciphertext, sealed to the partner.
        sealed: String,
    },
    Verdict {
        household: HouseholdId,
        request: RequestId,
        /// `ApprovalStatement::action`: "approve" or "veto".
        verdict: String,
        target: String,
        not_before: u64,
        not_after: u64,
        /// Hex of the statement's 24-byte nonce (`approval::NONCE_LEN`).
        nonce: String,
        /// Hex Ed25519 signature over the statement's canonical bytes.
        signature: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessageRequest {
    pub version: SchemaVersion,
    pub to: DeviceId,
    pub body: MessageBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessageResponse {
    pub version: SchemaVersion,
    pub mailbox_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessage {
    pub version: SchemaVersion,
    pub mailbox_seq: u64,
    pub from: DeviceId,
    pub body: MessageBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxResponse {
    pub version: SchemaVersion,
    pub messages: Vec<MailboxMessage>,
}

/// Signed message send: sender and recipient must both be members of the
/// household in the path. Sealed-request bodies are rate-limited by
/// their salted request hash; verdict bodies never are.
async fn send_message(
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
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let sender = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        signed_path(&parts.uri),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    if !shared.registry.is_member(&household_id, &sender) {
        return error_response(StatusCode::FORBIDDEN, "not a member of this household");
    }
    let Ok(send) = serde_json::from_slice::<SendMessageRequest>(&body_bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "body is not a message");
    };
    if send.version.check().is_err() {
        return error_response(StatusCode::BAD_REQUEST, "unsupported schema version");
    }
    if !shared.registry.is_member(&household_id, &send.to) {
        return error_response(StatusCode::BAD_REQUEST, "recipient is not a member");
    }
    let request_hash = match &send.body {
        MessageBody::SealedRequest {
            request_hash,
            sealed,
            ..
        } => {
            // Validate shape early; the stored bytes stay exactly as sent.
            if hex_decode_any(sealed).is_none() {
                return error_response(StatusCode::BAD_REQUEST, "sealed payload is not hex");
            }
            match hex_decode::<32>(request_hash) {
                Some(hash) => Some(hash),
                None => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "request_hash is not 32 hex bytes",
                    )
                }
            }
        }
        MessageBody::Verdict { .. } => None,
    };
    let body_json = match serde_json::to_string(&send.body) {
        Ok(json) => json,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "unserializable body"),
    };
    match shared
        .mailbox
        .send(household_id, send.to, sender, body_json, request_hash, now)
    {
        Ok(mailbox_seq) => (
            StatusCode::CREATED,
            Json(SendMessageResponse {
                version: SchemaVersion::CURRENT,
                mailbox_seq,
            }),
        )
            .into_response(),
        Err(MailboxError::RateLimited { retry_after }) => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            format!("rate limited until {retry_after}"),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct MailboxQuery {
    /// The recipient's persisted floor; only newer messages return.
    after: Option<u64>,
}

/// Signed mailbox fetch. The path names no device: the authenticated
/// device *is* the mailbox — reading someone else's is unrepresentable.
async fn fetch_mailbox(
    State(state): State<AppState>,
    Path(household_hex): Path<String>,
    Query(query): Query<MailboxQuery>,
    request: Request,
) -> Response {
    let Ok(household_id) = HouseholdId::from_hex(&household_hex) else {
        return error_response(StatusCode::NOT_FOUND, "household not found");
    };
    let (parts, body) = request.into_parts();
    let Ok(body_bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    };
    let now = unix_now();
    let mut shared = state.inner.lock().expect("registry lock poisoned");
    let recipient = match authenticate(
        &mut shared,
        &parts.headers,
        parts.method.as_str(),
        signed_path(&parts.uri),
        &body_bytes,
        now,
    ) {
        Ok(id) => id,
        Err(response) => return *response,
    };
    if !shared.registry.is_member(&household_id, &recipient) {
        return error_response(StatusCode::FORBIDDEN, "not a member of this household");
    }
    let messages = shared
        .mailbox
        .fetch(&household_id, &recipient, query.after.unwrap_or(0))
        .into_iter()
        .filter_map(|stored| {
            let body: MessageBody = serde_json::from_str(&stored.body_json).ok()?;
            Some(MailboxMessage {
                version: SchemaVersion::CURRENT,
                mailbox_seq: stored.mailbox_seq,
                from: stored.from,
                body,
            })
        })
        .collect();
    Json(MailboxResponse {
        version: SchemaVersion::CURRENT,
        messages,
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
        Ok(device) => {
            // Enrollment is a liveness signal: the silence clock starts
            // here, so a device killed right after install still alerts.
            shared.record_liveness(device.household_id, device.id, now);
            (
                StatusCode::CREATED,
                Json(CreateHouseholdResponse {
                    version: SchemaVersion::CURRENT,
                    device,
                    anchor: request.anchor,
                }),
            )
                .into_response()
        }
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
        signed_path(&parts.uri),
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
        Ok((device, anchor)) => {
            // Same liveness seeding as household creation.
            shared.record_liveness(device.household_id, device.id, now);
            Json(RegisterResponse {
                version: SchemaVersion::CURRENT,
                device,
                anchor,
            })
            .into_response()
        }
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

    // --- approvals transport (relay-approvals-transport) -------------------

    /// Pairs a partner device (with a seal key) into the founded
    /// household, returning its id hex and signing key.
    async fn pair_partner(
        router: &Router,
        household_hex: &str,
        founder_id_hex: &str,
        seal_pk: cf_core::X25519PublicKey,
        nonce_byte: u8,
    ) -> (String, SigningKey) {
        let (founder_sk, _) = founder_keys();
        let path = format!("/v1/households/{household_hex}/pairing-codes");
        let (_, body) =
            send_signed_empty_post(router, &path, founder_id_hex, &founder_sk, nonce_byte).await;
        let code = body["code"].as_str().unwrap().to_string();

        let partner_sk = SigningKey::from_bytes(&[0x42; 32]);
        let partner_vk = Ed25519PublicKey(partner_sk.verifying_key().to_bytes());
        let (status, body) = send_json(
            router,
            "POST",
            "/v1/pair",
            serde_json::json!({
                "version": 1,
                "pairing_code": code,
                "platform": "ios",
                "role": { "role": "partner", "seal_key": seal_pk.to_hex() },
                "identity_key": partner_vk.to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "partner pair failed: {body}");
        (
            body["device"]["id"].as_str().unwrap().to_string(),
            partner_sk,
        )
    }

    #[tokio::test]
    async fn a_sealed_request_routes_unchanged_and_only_the_partner_opens_it() {
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();

        let partner_scalar = crypto_box::SecretKey::from([0x77u8; 32]);
        let partner_seal_pk = cf_core::X25519PublicKey(*partner_scalar.public_key().as_bytes());
        let (partner_id_hex, partner_sk) = pair_partner(
            &router,
            &household_hex,
            &founder_id_hex,
            partner_seal_pk,
            41,
        )
        .await;

        // The monitored device seals {domain, reason, salt} to the partner
        // and sends it with the salted hash as the rate-limit key.
        let plaintext = br#"{"domain":"example.com","reason":"homework","salt":"s"}"#;
        let sealed = cf_core::sealing::seal(&partner_seal_pk, plaintext).unwrap();
        let sealed_hex = hex_encode(&sealed.0);
        let request_hash = cf_core::sealing::salted_request_hash(b"household-salt", "example.com");

        let send_body = serde_json::json!({
            "version": 1,
            "to": partner_id_hex,
            "body": {
                "kind": "sealed_request",
                "request": RequestId([8u8; 16]).to_hex(),
                "request_hash": hex_encode(&request_hash),
                "sealed": sealed_hex,
            },
        });
        let messages_path = format!("/v1/households/{household_hex}/messages");
        let (status, body) = send_signed_request(
            &router,
            "POST",
            &messages_path,
            &founder_id_hex,
            &founder_sk,
            42,
            send_body.to_string().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "send failed: {body}");

        // An identical-hash resend inside the window: rate limited.
        let (status, _) = send_signed_request(
            &router,
            "POST",
            &messages_path,
            &founder_id_hex,
            &founder_sk,
            43,
            send_body.to_string().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // The partner fetches its mailbox (signed; the mailbox is the
        // authenticated device's own, structurally).
        let mailbox_path = format!("/v1/households/{household_hex}/mailbox?after=0");
        let (status, body) = send_signed_request(
            &router,
            "GET",
            &mailbox_path,
            &partner_id_hex,
            &partner_sk,
            44,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "fetch failed: {body}");
        let mailbox: MailboxResponse = serde_json::from_value(body).unwrap();
        assert_eq!(mailbox.messages.len(), 1);
        let MessageBody::SealedRequest { sealed, .. } = &mailbox.messages[0].body else {
            panic!("expected a sealed request");
        };

        // DoD row 1: ciphertext routed unchanged, byte for byte.
        assert_eq!(sealed, &sealed_hex);

        // DoD row 2: only the partner scalar opens it. The relay holds no
        // X25519 secret anywhere in its state (cf-core has no private-key
        // type to even store one); any other scalar — standing in for
        // everything the relay could possibly try — fails.
        let routed = cf_core::SealedPayload(hex_decode_any(sealed).unwrap());
        let opened = cf_core::sealing::open(&partner_scalar.to_bytes(), &routed).unwrap();
        assert_eq!(opened, plaintext);
        let not_the_partner = crypto_box::SecretKey::from([0x99u8; 32]);
        assert!(cf_core::sealing::open(&not_the_partner.to_bytes(), &routed).is_err());
    }

    #[tokio::test]
    async fn a_verdict_routes_and_applies_on_the_target_device() {
        use cf_core::approval::{ApprovalStatement, NONCE_LEN};
        use cf_core::timeanchor::{FloorStore, TimeAnchor};
        use cf_core::weakening::{
            canonical_target, EffectiveVia, FilterChange, Transition, WeakeningRequest,
            APPROVE_VERDICT,
        };

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

        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let partner_scalar = crypto_box::SecretKey::from([0x77u8; 32]);
        let partner_seal_pk = cf_core::X25519PublicKey(*partner_scalar.public_key().as_bytes());
        let (partner_id_hex, partner_relay_sk) = pair_partner(
            &router,
            &household_hex,
            &founder_id_hex,
            partner_seal_pk,
            51,
        )
        .await;

        // The monitored device's pending weakening request (client-side).
        let anchor = signed_anchor();
        let now = unix_now();
        let time = TimeAnchor::new(MemFloor(Some((now, 1))));
        let request_id = RequestId([8u8; 16]);
        let mut weakening = WeakeningRequest::new(
            &anchor,
            request_id,
            FilterChange::DisableSocialBlocking,
            Some(3600),
            &time,
            now,
        )
        .unwrap();

        // The partner signs the approval with the ANCHOR's approval key
        // (seed 0x42 — the same key the founded household's anchor names)
        // and routes it through the relay.
        let approval_sk = SigningKey::from_bytes(&[0x42; 32]);
        let target = canonical_target(&FilterChange::DisableSocialBlocking, Some(3600));
        let statement = ApprovalStatement::new(
            anchor.household_id,
            request_id,
            APPROVE_VERDICT,
            target.clone(),
            now,
            now + 7200,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let signature = cf_core::approval::sign(&statement, &approval_sk).unwrap();

        let send_body = serde_json::json!({
            "version": 1,
            "to": founder_id_hex,
            "body": {
                "kind": "verdict",
                "household": statement.household_id.to_hex(),
                "request": statement.request_id.to_hex(),
                "verdict": statement.action,
                "target": statement.target,
                "not_before": statement.not_before,
                "not_after": statement.not_after,
                "nonce": hex_encode(&statement.nonce),
                "signature": signature.to_hex(),
            },
        });
        let messages_path = format!("/v1/households/{household_hex}/messages");
        let (status, body) = send_signed_request(
            &router,
            "POST",
            &messages_path,
            &partner_id_hex,
            &partner_relay_sk,
            52,
            send_body.to_string().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "verdict send failed: {body}");

        // DoD row 3: the target device fetches the verdict, reconstructs
        // the exact signed statement, and the weakening machine verifies
        // and applies it at the point of consequence.
        let mailbox_path = format!("/v1/households/{household_hex}/mailbox?after=0");
        let (status, body) = send_signed_request(
            &router,
            "GET",
            &mailbox_path,
            &founder_id_hex,
            &founder_sk,
            53,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mailbox: MailboxResponse = serde_json::from_value(body).unwrap();
        assert_eq!(mailbox.messages.len(), 1);
        let MessageBody::Verdict {
            household,
            request,
            verdict,
            target,
            not_before,
            not_after,
            nonce,
            signature,
        } = &mailbox.messages[0].body
        else {
            panic!("expected a verdict");
        };

        let reconstructed = ApprovalStatement::new(
            *household,
            *request,
            verdict.clone(),
            target.clone(),
            *not_before,
            *not_after,
            hex_decode::<NONCE_LEN>(nonce).unwrap(),
        )
        .unwrap();
        let sig = Signature::from_hex(signature).unwrap();
        let transition = weakening
            .apply_approval(&anchor, &reconstructed, &sig, &time, now + 60)
            .unwrap();
        assert!(matches!(
            transition,
            Transition::BecameEffective {
                via: EffectiveVia::PartnerApproval,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_dropped_mailbox_message_still_surfaces_in_the_chain() {
        use cf_core::hashchain::GENESIS_HASH;

        // The relay "drops" a mailbox message by simply never having it —
        // what it CANNOT drop is the sender's chained event recording that
        // the request existed: the mailbox and the log are independent
        // stores, and rewriting the chain breaks verification (relay-log's
        // fork/gap tests). The partner's audit path sees the event; the
        // missing mailbox delivery is the visible discrepancy.
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let founder_id = DeviceId::from_hex(&founder_id_hex).unwrap();

        let event = signed_chain_event(founder_id, &founder_sk, 1, GENESIS_HASH, "weakening:req8");
        let (status, _) = send_signed_request(
            &router,
            "POST",
            &format!("/v1/households/{household_hex}/events"),
            &founder_id_hex,
            &founder_sk,
            61,
            serde_json::to_vec(&event).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // No mailbox message was ever delivered…
        let partner_scalar = crypto_box::SecretKey::from([0x77u8; 32]);
        let seal_pk = cf_core::X25519PublicKey(*partner_scalar.public_key().as_bytes());
        let (partner_id_hex, partner_sk) =
            pair_partner(&router, &household_hex, &founder_id_hex, seal_pk, 62).await;
        let (_, body) = send_signed_request(
            &router,
            "GET",
            &format!("/v1/households/{household_hex}/mailbox?after=0"),
            &partner_id_hex,
            &partner_sk,
            63,
            Vec::new(),
        )
        .await;
        let mailbox: MailboxResponse = serde_json::from_value(body).unwrap();
        assert!(mailbox.messages.is_empty());

        // …but the chain still attests the event.
        let (status, body) = send_signed_request(
            &router,
            "GET",
            &format!("/v1/households/{household_hex}/log/{founder_id_hex}"),
            &partner_id_hex,
            &partner_sk,
            64,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let view: DeviceLogResponse = serde_json::from_value(body).unwrap();
        assert_eq!(view.events.len(), 1);
        assert_eq!(view.events[0].payload, b"weakening:req8");
    }

    // --- the event log (relay-log) ----------------------------------------

    /// Signs and sends a request whose body matters (event pushes): the
    /// statement's hash covers the exact bytes sent.
    async fn send_signed_request(
        router: &Router,
        method: &str,
        path: &str,
        device_id_hex: &str,
        signing_key: &SigningKey,
        nonce_byte: u8,
        body_bytes: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let device_id = DeviceId::from_hex(device_id_hex).unwrap();
        let ts = unix_now();
        let nonce = [nonce_byte; REQUEST_NONCE_LEN];
        let statement =
            AuthStatement::new(device_id, method, path, body_sha256(&body_bytes), ts, nonce)
                .unwrap();
        let signature = request_auth::sign(&statement, signing_key).unwrap();
        let request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("x-cf-device-id", device_id_hex)
            .header("x-cf-timestamp", ts.to_string())
            .header("x-cf-nonce", hex_encode(&nonce))
            .header("x-cf-signature", signature.to_hex())
            .body(Body::from(body_bytes))
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

    fn signed_chain_event(
        device_id: DeviceId,
        signing_key: &SigningKey,
        seq: u64,
        prev_hash: [u8; 32],
        payload: &str,
    ) -> cf_core::ChainedEvent {
        let mut event = cf_core::ChainedEvent {
            seq,
            prev_hash,
            device_id,
            event_type: "test.event".into(),
            ts: 1_700_000_000 + seq,
            payload: payload.as_bytes().to_vec(),
            sig: Signature([0u8; 64]),
        };
        event.sig = cf_core::hashchain::sign_event(&event, signing_key);
        event
    }

    #[tokio::test]
    async fn the_event_log_flow_works_end_to_end_over_http() {
        use cf_core::hashchain::{event_hash, verify_chain, GENESIS_HASH};

        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, founder_vk) = founder_keys();
        let founder_id = DeviceId::from_hex(&founder_id_hex).unwrap();
        let events_path = format!("/v1/households/{household_hex}/events");

        // Two chained appends.
        let e1 = signed_chain_event(founder_id, &founder_sk, 1, GENESIS_HASH, "p1");
        let (status, body) = send_signed_request(
            &router,
            "POST",
            &events_path,
            &founder_id_hex,
            &founder_sk,
            21,
            serde_json::to_vec(&e1).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "push failed: {body}");

        let e2 = signed_chain_event(founder_id, &founder_sk, 2, event_hash(&e1), "p2");
        let (status, _) = send_signed_request(
            &router,
            "POST",
            &events_path,
            &founder_id_hex,
            &founder_sk,
            22,
            serde_json::to_vec(&e2).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Idempotent duplicate (outbox retry after a lost ack): 200.
        let (status, _) = send_signed_request(
            &router,
            "POST",
            &events_path,
            &founder_id_hex,
            &founder_sk,
            23,
            serde_json::to_vec(&e2).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A gap is flagged and rejected: 409.
        let e9 = signed_chain_event(founder_id, &founder_sk, 9, event_hash(&e2), "p9");
        let (status, body) = send_signed_request(
            &router,
            "POST",
            &events_path,
            &founder_id_hex,
            &founder_sk,
            24,
            serde_json::to_vec(&e9).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "gap accepted: {body}");

        // A signed member fetch returns the chain, which verifies under
        // cf-core against the device's registered key.
        let log_path = format!("/v1/households/{household_hex}/log/{founder_id_hex}");
        let (status, body) = send_signed_request(
            &router,
            "GET",
            &log_path,
            &founder_id_hex,
            &founder_sk,
            25,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "log fetch failed: {body}");
        let view: DeviceLogResponse = serde_json::from_value(body).unwrap();
        assert_eq!(view.next_seq, 3);
        assert_eq!(view.pruned_before, 1);
        assert_eq!(view.events.len(), 2);

        struct OneKey(DeviceId, Ed25519PublicKey);
        impl cf_core::DeviceKeyResolver for OneKey {
            fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey> {
                (*device_id == self.0).then_some(self.1)
            }
        }
        assert!(verify_chain(&view.events, &OneKey(founder_id, founder_vk)).is_ok());

        // Unsigned fetch: rejected.
        let request = HttpRequest::builder()
            .method("GET")
            .uri(&log_path)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn events_must_be_pushed_by_their_author() {
        use cf_core::hashchain::GENESIS_HASH;

        // Register a second device via pairing, then have it push an
        // event CLAIMING the founder authored it. The event's signature is
        // genuine (signed with the founder key it claims), so only the
        // author check stands between this and acceptance.
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let path = format!("/v1/households/{household_hex}/pairing-codes");
        let (_, body) =
            send_signed_empty_post(&router, &path, &founder_id_hex, &founder_sk, 31).await;
        let code = body["code"].as_str().unwrap().to_string();

        let joiner_sk = SigningKey::from_bytes(&[0x71; 32]);
        let joiner_vk = Ed25519PublicKey(joiner_sk.verifying_key().to_bytes());
        let (_, body) = send_json(
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
        let joiner_id_hex = body["device"]["id"].as_str().unwrap().to_string();

        let founder_id = DeviceId::from_hex(&founder_id_hex).unwrap();
        let forged = signed_chain_event(founder_id, &founder_sk, 1, GENESIS_HASH, "not mine");
        let (status, _) = send_signed_request(
            &router,
            "POST",
            &format!("/v1/households/{household_hex}/events"),
            &joiner_id_hex,
            &joiner_sk,
            32,
            serde_json::to_vec(&forged).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // --- heartbeats (relay-heartbeat-silence) -----------------------------

    #[tokio::test]
    async fn a_signed_heartbeat_is_accepted_and_an_unsigned_one_is_not() {
        // The heartbeat endpoint's HTTP half: authenticated ingest. The
        // silence lifecycle itself (threshold, DeviceSilent, resume) is
        // SilenceTracker's own test suite — time can't be advanced through
        // a real router.
        let (router, household_hex, founder_id_hex) = founded_router().await;
        let (founder_sk, _) = founder_keys();
        let _ = household_hex;

        let (status, _) =
            send_signed_empty_post(&router, "/v1/heartbeat", &founder_id_hex, &founder_sk, 11)
                .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Unsigned: rejected, like every mutating request.
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/v1/heartbeat")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // A replayed signed heartbeat: rejected by the nonce guard.
        let (status, _) =
            send_signed_empty_post(&router, "/v1/heartbeat", &founder_id_hex, &founder_sk, 11)
                .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
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
