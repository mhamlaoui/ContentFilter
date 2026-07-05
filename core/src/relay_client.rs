//! Relay client library (core-relay-client): register, push signed events,
//! pull signed feeds, receive approvals — with offline resilience.
//!
//! # Sans-I/O, on purpose
//!
//! This module does no networking. Every relay interaction goes through
//! the [`RelayTransport`] trait, and every method that needs it takes the
//! transport as a parameter — the same seam pattern as
//! [`crate::timeanchor::FloorStore`] and
//! [`crate::hashchain::DeviceKeyResolver`]. Rejected alternative: an HTTP
//! client dependency (reqwest or hand-rolled hyper) in `cf-core`. This
//! crate is linked by every platform via UniFFI, where the idiomatic
//! network stack is NSURLSession/OkHttp, not a Rust async runtime; a
//! transport dependency here would be the heaviest dependency in the crate
//! and would impose async-runtime choices on every binding. The trait is
//! synchronous for the same reason — platforms drive their own I/O and
//! call in with results.
//!
//! Consequences the tests pin down:
//!
//! - **The protocol logic is what's here**: registration consistency
//!   checks, feed signature/kind/monotonicity enforcement, outbox
//!   ordering. A real HTTPS transport (a later ticket) only moves bytes.
//! - **Approvals are received, not verified, here.** Verification belongs
//!   to the point of consequence
//!   ([`crate::weakening::WeakeningRequest::apply_approval`]); this module
//!   just delivers the partner's words intact, and the end-to-end test
//!   proves receive → verify → effective against a mock relay.
//! - **Feed trust is pinned, not transport-derived**: a feed is accepted
//!   only if its release-key signature verifies (the key is pinned at
//!   client construction, per f-secrets-keymgmt), its kind matches the
//!   kind that was requested (a validly-signed DoH feed must not pass as
//!   a blocklist), and its `feed_seq` strictly advances the last accepted
//!   one (a replayed or downgraded feed — e.g. an old, emptier blocklist —
//!   is rejected even though its signature is genuine).
//! - **The outbox never silently drops.** Flushing stops at the first
//!   failure, retains the failed event and everything behind it, and
//!   reports how much was sent. A relay that rejects an event doesn't get
//!   to make the client forget it — dropped accountability events are
//!   exactly what the hash chain exists to surface, and the client won't
//!   volunteer the drop. Retry policy (when to flush again) is
//!   [`Backoff`], pure arithmetic: no timers here, and no jitter, because
//!   jitter needs randomness and this crate touches an RNG only for
//!   sealing. Callers that want jitter add it where they already have an
//!   RNG.
//! - **`Backoff` and the outbox are serializable** ([`RelayClient`] itself
//!   is the persistence unit, with a `SchemaVersion` and
//!   `deny_unknown_fields`), so queued events survive a restart the same
//!   way the time-anchor floor does — whoever persists it decides where.

use crate::device::{Device, DeviceRole, Platform};
use crate::hashchain::ChainedEvent;
use crate::household::TrustAnchor;
use crate::ids::{DeviceId, HouseholdId};
use crate::keys::{Ed25519PublicKey, Signature as CfSignature};
use crate::version::SchemaVersion;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

/// Versioned by its domain tag, like `ApprovalStatement` — the version is
/// inside the signed bytes, where a validator can't skip it.
const FEED_DOMAIN_TAG: &[u8] = b"ContentFilter-Feed-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    Blocklist,
    DohEndpoints,
}

impl FeedKind {
    fn tag_byte(self) -> u8 {
        match self {
            FeedKind::Blocklist => 1,
            FeedKind::DohEndpoints => 2,
        }
    }
}

/// A release-key-signed feed. `payload` is opaque here: its format belongs
/// to the consumers (svc-resolver, svc-egress-wfp) and the producer
/// (relay-feeds); this module's job is only that nobody can substitute,
/// replay, or downgrade one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEnvelope {
    pub kind: FeedKind,
    /// Strictly increases per kind on every publish (relay-feeds:
    /// "version increments").
    pub feed_seq: u64,
    /// Seconds since epoch; bookkeeping/display only, like every unsigned
    /// local timestamp in this crate — staleness *alarms* are
    /// hard-doh-feed-ops' job.
    pub published_at: u64,
    #[serde(with = "crate::hex::serde_hex_vec")]
    pub payload: Vec<u8>,
    pub signature: CfSignature,
}

impl FeedEnvelope {
    /// The exact bytes the release key signs. Fixed field order,
    /// length-prefixed payload, domain-separated — same reasoning as
    /// `ApprovalStatement::canonical_encode` (a canonicalization ambiguity
    /// in a signed encoding is a forgery vector).
    pub fn canonical_bytes(
        kind: FeedKind,
        feed_seq: u64,
        published_at: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FEED_DOMAIN_TAG.len() + 1 + 8 + 8 + 4 + payload.len());
        buf.extend_from_slice(FEED_DOMAIN_TAG);
        buf.push(kind.tag_byte());
        buf.extend_from_slice(&feed_seq.to_be_bytes());
        buf.extend_from_slice(&published_at.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    fn signed_bytes(&self) -> Vec<u8> {
        Self::canonical_bytes(self.kind, self.feed_seq, self.published_at, &self.payload)
    }
}

/// Signs a feed. Client-side code never calls this with a real release key
/// (that key exists only offline, per docs/KEY_CEREMONY.md); it exists for
/// the relay-feeds publishing pipeline and for tests.
pub fn sign_feed(
    kind: FeedKind,
    feed_seq: u64,
    published_at: u64,
    payload: Vec<u8>,
    signing_key: &SigningKey,
) -> FeedEnvelope {
    let bytes = FeedEnvelope::canonical_bytes(kind, feed_seq, published_at, &payload);
    let sig = signing_key.sign(&bytes);
    FeedEnvelope {
        kind,
        feed_seq,
        published_at,
        payload,
        signature: CfSignature(sig.to_bytes()),
    }
}

/// What a device sends to enroll. No `DeviceId` and no `HouseholdId`:
/// the relay mints the id and the pairing code resolves the household
/// (relay-registry-pairing owns both), so the request structurally cannot
/// claim either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub version: SchemaVersion,
    pub pairing_code: String,
    pub platform: Platform,
    pub role: DeviceRole,
    pub identity_key: Ed25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResponse {
    pub version: SchemaVersion,
    pub device: Device,
    pub anchor: TrustAnchor,
}

/// A partner verdict in transit. Deliberately *not* Serialize/Deserialize:
/// the wire encoding of approvals (and the sealed-payload framing around
/// them) belongs to relay-approvals-transport, and deriving serde here
/// would quietly become that ticket's de-facto format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalMessage {
    pub statement: crate::approval::ApprovalStatement,
    pub signature: CfSignature,
}

/// Transport failures, from the client's point of view. `Offline` is the
/// one the outbox logic branches on; everything else is a delivered-and-
/// refused answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The relay could not be reached at all. Queued work stays queued.
    Offline,
    /// The relay answered and said no (auth failure, unknown pairing code,
    /// malformed request...). Human-readable; no protocol is being defined
    /// by this string.
    Rejected(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Offline => write!(f, "relay unreachable"),
            TransportError::Rejected(reason) => write!(f, "relay rejected the request: {reason}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The seam every relay interaction goes through. Implementations move
/// bytes and map wire responses to these types; they hold no protocol
/// logic. Synchronous by design — see the module docs.
pub trait RelayTransport {
    fn register(&mut self, request: &RegisterRequest) -> Result<RegisterResponse, TransportError>;
    fn push_event(
        &mut self,
        household: &HouseholdId,
        event: &ChainedEvent,
    ) -> Result<(), TransportError>;
    /// `newer_than = Some(seq)` is the conditional fetch: the relay may
    /// answer `None` ("nothing newer") instead of resending the current
    /// feed.
    fn fetch_feed(
        &mut self,
        kind: FeedKind,
        newer_than: Option<u64>,
    ) -> Result<Option<FeedEnvelope>, TransportError>;
    fn fetch_approvals(
        &mut self,
        household: &HouseholdId,
        device: &DeviceId,
    ) -> Result<Vec<ApprovalMessage>, TransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayClientError {
    Transport(TransportError),
    /// Flushing sent `sent` events, then failed; the failed event and
    /// everything behind it are still queued.
    FlushInterrupted {
        sent: usize,
        cause: TransportError,
    },
    /// The feed's release-key signature did not verify (or the pinned key
    /// bytes are invalid). Covers unsigned, tampered, and wrong-key feeds
    /// alike — the feed is discarded either way.
    FeedSignatureInvalid,
    /// A validly-signed feed of a different kind than requested.
    FeedKindMismatch {
        requested: FeedKind,
        got: FeedKind,
    },
    /// The feed's seq doesn't strictly advance the last accepted one — a
    /// replay or downgrade (e.g. an older, emptier blocklist).
    FeedNotNewer {
        have: u64,
        got: u64,
    },
    /// The registration response contradicts itself or the request; the
    /// named field is the first inconsistency found.
    RegistrationInconsistent(&'static str),
}

impl fmt::Display for RelayClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayClientError::Transport(e) => write!(f, "transport failure: {e}"),
            RelayClientError::FlushInterrupted { sent, cause } => {
                write!(f, "flush interrupted after {sent} events: {cause}")
            }
            RelayClientError::FeedSignatureInvalid => {
                write!(f, "feed signature did not verify against the release key")
            }
            RelayClientError::FeedKindMismatch { requested, got } => {
                write!(f, "requested a {requested:?} feed, got {got:?}")
            }
            RelayClientError::FeedNotNewer { have, got } => {
                write!(f, "feed seq {got} does not advance the accepted {have}")
            }
            RelayClientError::RegistrationInconsistent(field) => {
                write!(f, "registration response inconsistent: {field}")
            }
        }
    }
}

impl std::error::Error for RelayClientError {}

/// Retry pacing for reconnect attempts: exponential from `base_seconds`,
/// capped at `cap_seconds`. Pure arithmetic — the caller owns the timer
/// (and any jitter; see the module docs for why none is added here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backoff {
    base_seconds: u32,
    cap_seconds: u32,
    attempt: u32,
}

impl Backoff {
    pub fn new(base_seconds: u32, cap_seconds: u32) -> Self {
        Self {
            base_seconds: base_seconds.max(1),
            cap_seconds: cap_seconds.max(1),
            attempt: 0,
        }
    }

    /// The delay to wait before the attempt about to be made, advancing
    /// the internal counter: base, 2·base, 4·base, ... capped.
    ///
    /// Computed in u64: `checked_shl` only guards the shift *amount*, not
    /// value overflow — `u32::MAX << 1` silently drops the top bit, which
    /// CI caught as a shrinking delay. `(u32 as u64) << 31` cannot
    /// overflow u64, so widening makes the cap comparison exact.
    pub fn next_delay_seconds(&mut self) -> u32 {
        let shift = self.attempt.min(31);
        let delay = (u64::from(self.base_seconds) << shift).min(u64::from(self.cap_seconds));
        self.attempt = self.attempt.saturating_add(1);
        delay as u32
    }

    /// Call on any successful relay contact.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// The client's persistent state: the pinned release verify key, the
/// offline outbox, and the last accepted feed seq per kind. Serializable
/// as a whole so queued events and downgrade floors survive restarts —
/// where it's persisted is the platform's business, same as `FloorStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayClient {
    pub version: SchemaVersion,
    release_key: Ed25519PublicKey,
    outbox: VecDeque<ChainedEvent>,
    last_blocklist_seq: Option<u64>,
    last_doh_seq: Option<u64>,
}

impl RelayClient {
    /// `release_key` is the pinned release verify key
    /// (f-secrets-keymgmt) — feed trust derives from it and nothing else.
    pub fn new(release_key: Ed25519PublicKey) -> Self {
        Self {
            version: SchemaVersion::CURRENT,
            release_key,
            outbox: VecDeque::new(),
            last_blocklist_seq: None,
            last_doh_seq: None,
        }
    }

    /// Registers this device against a pairing code and sanity-checks the
    /// response before anyone trusts it: the echoed identity key, role,
    /// and platform must match what was sent (a relay that swaps the
    /// identity key has hijacked the enrollment), the device and anchor
    /// must agree on the household, and both must carry the current
    /// schema. The anchor's *signature* is deliberately not checked here —
    /// no canonical anchor encoding exists yet; verifying and pinning it
    /// is svc-config-anchor's job, and this method's caller must treat the
    /// returned anchor as unpinned input until then.
    pub fn register<T: RelayTransport>(
        &self,
        transport: &mut T,
        request: &RegisterRequest,
    ) -> Result<RegisterResponse, RelayClientError> {
        let response = transport
            .register(request)
            .map_err(RelayClientError::Transport)?;
        if response.version.check().is_err()
            || response.device.version.check().is_err()
            || response.anchor.version.check().is_err()
        {
            return Err(RelayClientError::RegistrationInconsistent("schema version"));
        }
        if response.device.identity_key != request.identity_key {
            return Err(RelayClientError::RegistrationInconsistent("identity_key"));
        }
        if response.device.role != request.role {
            return Err(RelayClientError::RegistrationInconsistent("role"));
        }
        if response.device.platform != request.platform {
            return Err(RelayClientError::RegistrationInconsistent("platform"));
        }
        if response.device.household_id != response.anchor.household_id {
            return Err(RelayClientError::RegistrationInconsistent("household_id"));
        }
        Ok(response)
    }

    /// Queues an already-chained, already-signed event for delivery.
    /// Chaining and signing stay with core-hashchain's callers — by the
    /// time an event reaches the outbox its bytes are final.
    pub fn enqueue(&mut self, event: ChainedEvent) {
        self.outbox.push_back(event);
    }

    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Sends queued events oldest-first. Stops at the first failure,
    /// keeping the failed event and everything behind it queued (chain
    /// order must never be delivered around a gap), and reports how many
    /// were sent before the failure. Returns the number sent on full
    /// drain.
    pub fn flush<T: RelayTransport>(
        &mut self,
        transport: &mut T,
        household: &HouseholdId,
    ) -> Result<usize, RelayClientError> {
        let mut sent = 0;
        while let Some(event) = self.outbox.front() {
            match transport.push_event(household, event) {
                Ok(()) => {
                    self.outbox.pop_front();
                    sent += 1;
                }
                Err(cause) => {
                    return Err(RelayClientError::FlushInterrupted { sent, cause });
                }
            }
        }
        Ok(sent)
    }

    /// Fetches a feed conditionally (passing the last accepted seq) and
    /// accepts it only if the release-key signature verifies, the kind is
    /// the one requested, and the seq strictly advances. On acceptance the
    /// per-kind floor moves forward — it never moves back, which is the
    /// client half of relay-feeds' downgrade protection. `Ok(None)` means
    /// "nothing newer than what you have".
    pub fn pull_feed<T: RelayTransport>(
        &mut self,
        transport: &mut T,
        kind: FeedKind,
    ) -> Result<Option<FeedEnvelope>, RelayClientError> {
        let have = self.last_accepted_seq(kind);
        let Some(envelope) = transport
            .fetch_feed(kind, have)
            .map_err(RelayClientError::Transport)?
        else {
            return Ok(None);
        };
        // Signature first, over the envelope's own claimed fields —
        // nothing about the envelope is meaningful until it's proven to be
        // the release key's words.
        let Ok(vk) = VerifyingKey::from_bytes(&self.release_key.0) else {
            return Err(RelayClientError::FeedSignatureInvalid);
        };
        let sig = ed25519_dalek::Signature::from_bytes(&envelope.signature.0);
        if vk.verify_strict(&envelope.signed_bytes(), &sig).is_err() {
            return Err(RelayClientError::FeedSignatureInvalid);
        }
        if envelope.kind != kind {
            return Err(RelayClientError::FeedKindMismatch {
                requested: kind,
                got: envelope.kind,
            });
        }
        if let Some(have) = have {
            if envelope.feed_seq <= have {
                return Err(RelayClientError::FeedNotNewer {
                    have,
                    got: envelope.feed_seq,
                });
            }
        }
        *self.seq_slot(kind) = Some(envelope.feed_seq);
        Ok(Some(envelope))
    }

    pub fn last_accepted_seq(&self, kind: FeedKind) -> Option<u64> {
        match kind {
            FeedKind::Blocklist => self.last_blocklist_seq,
            FeedKind::DohEndpoints => self.last_doh_seq,
        }
    }

    fn seq_slot(&mut self, kind: FeedKind) -> &mut Option<u64> {
        match kind {
            FeedKind::Blocklist => &mut self.last_blocklist_seq,
            FeedKind::DohEndpoints => &mut self.last_doh_seq,
        }
    }

    /// Fetches pending partner verdicts. Delivered as-is: verification
    /// happens at the point of consequence
    /// ([`crate::weakening::WeakeningRequest::apply_approval`]), never in
    /// transit — a client that "pre-verified" would tempt callers to skip
    /// the real check.
    pub fn fetch_approvals<T: RelayTransport>(
        &self,
        transport: &mut T,
        household: &HouseholdId,
        device: &DeviceId,
    ) -> Result<Vec<ApprovalMessage>, RelayClientError> {
        transport
            .fetch_approvals(household, device)
            .map_err(RelayClientError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{self, ApprovalStatement, NONCE_LEN};
    use crate::hashchain::{sign_event, GENESIS_HASH};
    use crate::household::Tier;
    use crate::ids::RequestId;
    use crate::keys::{Signature, X25519PublicKey};
    use crate::timeanchor::{FloorStore, TimeAnchor};
    use crate::weakening::{
        canonical_target, EffectiveVia, FilterChange, Transition, WeakeningRequest, APPROVE_VERDICT,
    };

    const HH: HouseholdId = HouseholdId([4u8; 16]);
    const DEV: DeviceId = DeviceId([2u8; 16]);

    fn release_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x51; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn device_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x52; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn partner_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn sample_anchor() -> TrustAnchor {
        let (_, partner_vk) = partner_keys();
        TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HH,
            seq: 1,
            partner_approval_key: partner_vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: 86_400,
            tier: Tier::Hardened,
            signature: Signature([7u8; 64]),
        }
    }

    fn signed_event(seq: u64) -> ChainedEvent {
        let (sk, _) = device_keys();
        let mut event = ChainedEvent {
            seq,
            prev_hash: GENESIS_HASH,
            device_id: DEV,
            event_type: "test.event".into(),
            ts: 1_700_000_000 + seq,
            payload: format!("payload-{seq}").into_bytes(),
            sig: Signature([0u8; 64]),
        };
        event.sig = sign_event(&event, &sk);
        event
    }

    /// The mock relay: in-memory state plus a scriptable `online` flag.
    /// This is the "mock relay" the DoD means — it implements the
    /// transport seam, so everything above the seam (all the protocol
    /// logic under test) runs for real.
    struct MockRelay {
        online: bool,
        received_events: Vec<(HouseholdId, ChainedEvent)>,
        feed_response: Option<FeedEnvelope>,
        pending_approvals: Vec<ApprovalMessage>,
        register_response: Option<RegisterResponse>,
        last_newer_than: Option<Option<u64>>,
    }

    impl MockRelay {
        fn new() -> Self {
            Self {
                online: true,
                received_events: Vec::new(),
                feed_response: None,
                pending_approvals: Vec::new(),
                register_response: None,
                last_newer_than: None,
            }
        }

        fn check_online(&self) -> Result<(), TransportError> {
            if self.online {
                Ok(())
            } else {
                Err(TransportError::Offline)
            }
        }
    }

    impl RelayTransport for MockRelay {
        fn register(
            &mut self,
            _request: &RegisterRequest,
        ) -> Result<RegisterResponse, TransportError> {
            self.check_online()?;
            self.register_response
                .clone()
                .ok_or_else(|| TransportError::Rejected("no registration scripted".into()))
        }

        fn push_event(
            &mut self,
            household: &HouseholdId,
            event: &ChainedEvent,
        ) -> Result<(), TransportError> {
            self.check_online()?;
            self.received_events.push((*household, event.clone()));
            Ok(())
        }

        fn fetch_feed(
            &mut self,
            _kind: FeedKind,
            newer_than: Option<u64>,
        ) -> Result<Option<FeedEnvelope>, TransportError> {
            self.check_online()?;
            self.last_newer_than = Some(newer_than);
            Ok(self.feed_response.clone())
        }

        fn fetch_approvals(
            &mut self,
            _household: &HouseholdId,
            _device: &DeviceId,
        ) -> Result<Vec<ApprovalMessage>, TransportError> {
            self.check_online()?;
            Ok(self.pending_approvals.clone())
        }
    }

    fn client() -> RelayClient {
        let (_, release_vk) = release_keys();
        RelayClient::new(release_vk)
    }

    // --- registration -----------------------------------------------------

    fn sample_register_pair() -> (RegisterRequest, RegisterResponse) {
        let (_, identity_vk) = device_keys();
        let request = RegisterRequest {
            version: SchemaVersion::CURRENT,
            pairing_code: "PAIR-1234".into(),
            platform: Platform::Windows,
            role: DeviceRole::Monitored,
            identity_key: identity_vk,
        };
        let response = RegisterResponse {
            version: SchemaVersion::CURRENT,
            device: Device {
                version: SchemaVersion::CURRENT,
                id: DEV,
                household_id: HH,
                platform: Platform::Windows,
                role: DeviceRole::Monitored,
                identity_key: identity_vk,
                registered_at: 1_700_000_000,
            },
            anchor: sample_anchor(),
        };
        (request, response)
    }

    #[test]
    fn register_returns_a_consistent_device_and_anchor() {
        let (request, response) = sample_register_pair();
        let mut relay = MockRelay::new();
        relay.register_response = Some(response.clone());
        let got = client().register(&mut relay, &request).unwrap();
        assert_eq!(got, response);
        assert_eq!(got.device.household_id, got.anchor.household_id);
    }

    #[test]
    fn a_registration_that_swaps_the_identity_key_is_rejected() {
        // A hostile relay that echoes back a *different* identity key has
        // hijacked the enrollment: the device would believe it's
        // registered while the relay attributes its identity to another
        // key. The client must catch the swap, not trust the echo.
        let (request, mut response) = sample_register_pair();
        response.device.identity_key = Ed25519PublicKey([0xEE; 32]);
        let mut relay = MockRelay::new();
        relay.register_response = Some(response);
        assert_eq!(
            client().register(&mut relay, &request),
            Err(RelayClientError::RegistrationInconsistent("identity_key"))
        );
    }

    #[test]
    fn a_registration_with_mismatched_household_is_rejected() {
        let (request, mut response) = sample_register_pair();
        response.anchor.household_id = HouseholdId([0xDD; 16]);
        let mut relay = MockRelay::new();
        relay.register_response = Some(response);
        assert_eq!(
            client().register(&mut relay, &request),
            Err(RelayClientError::RegistrationInconsistent("household_id"))
        );
    }

    #[test]
    fn a_registration_with_a_stale_schema_is_rejected() {
        let (request, mut response) = sample_register_pair();
        response.anchor.version = SchemaVersion(0);
        let mut relay = MockRelay::new();
        relay.register_response = Some(response);
        assert_eq!(
            client().register(&mut relay, &request),
            Err(RelayClientError::RegistrationInconsistent("schema version"))
        );
    }

    // --- outbox -------------------------------------------------------------

    #[test]
    fn push_event_reaches_the_relay() {
        let mut relay = MockRelay::new();
        let mut c = client();
        c.enqueue(signed_event(1));
        let sent = c.flush(&mut relay, &HH).unwrap();
        assert_eq!(sent, 1);
        assert_eq!(c.outbox_len(), 0);
        assert_eq!(relay.received_events.len(), 1);
        assert_eq!(relay.received_events[0].0, HH);
        assert_eq!(relay.received_events[0].1.seq, 1);
    }

    #[test]
    fn events_queue_while_offline_and_drain_in_order_on_reconnect() {
        let mut relay = MockRelay::new();
        relay.online = false;
        let mut c = client();
        c.enqueue(signed_event(1));
        c.enqueue(signed_event(2));
        c.enqueue(signed_event(3));

        assert_eq!(
            c.flush(&mut relay, &HH),
            Err(RelayClientError::FlushInterrupted {
                sent: 0,
                cause: TransportError::Offline
            })
        );
        assert_eq!(c.outbox_len(), 3, "offline must lose nothing");
        assert!(relay.received_events.is_empty());

        relay.online = true;
        let sent = c.flush(&mut relay, &HH).unwrap();
        assert_eq!(sent, 3);
        assert_eq!(c.outbox_len(), 0);
        let seqs: Vec<u64> = relay.received_events.iter().map(|(_, e)| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3], "chain order must survive the outage");
    }

    #[test]
    fn a_mid_flush_failure_keeps_the_failed_event_and_the_rest() {
        // The relay goes down between event 1 and event 2: the flush must
        // report one sent and keep [2, 3] queued for the next attempt —
        // never skipping the failed event to "make progress" (delivering
        // around a gap is exactly what the hash chain would then expose as
        // our own doing).
        struct FlakyRelay {
            inner: MockRelay,
            fail_after: usize,
        }
        impl RelayTransport for FlakyRelay {
            fn register(
                &mut self,
                request: &RegisterRequest,
            ) -> Result<RegisterResponse, TransportError> {
                self.inner.register(request)
            }
            fn push_event(
                &mut self,
                household: &HouseholdId,
                event: &ChainedEvent,
            ) -> Result<(), TransportError> {
                if self.inner.received_events.len() >= self.fail_after {
                    return Err(TransportError::Offline);
                }
                self.inner.push_event(household, event)
            }
            fn fetch_feed(
                &mut self,
                kind: FeedKind,
                newer_than: Option<u64>,
            ) -> Result<Option<FeedEnvelope>, TransportError> {
                self.inner.fetch_feed(kind, newer_than)
            }
            fn fetch_approvals(
                &mut self,
                household: &HouseholdId,
                device: &DeviceId,
            ) -> Result<Vec<ApprovalMessage>, TransportError> {
                self.inner.fetch_approvals(household, device)
            }
        }

        let mut relay = FlakyRelay {
            inner: MockRelay::new(),
            fail_after: 1,
        };
        let mut c = client();
        c.enqueue(signed_event(1));
        c.enqueue(signed_event(2));
        c.enqueue(signed_event(3));
        assert_eq!(
            c.flush(&mut relay, &HH),
            Err(RelayClientError::FlushInterrupted {
                sent: 1,
                cause: TransportError::Offline
            })
        );
        assert_eq!(c.outbox_len(), 2);
        // Recovery drains the remainder in order:
        relay.fail_after = usize::MAX;
        assert_eq!(c.flush(&mut relay, &HH), Ok(2));
        let seqs: Vec<u64> = relay
            .inner
            .received_events
            .iter()
            .map(|(_, e)| e.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    // --- feeds ----------------------------------------------------------------

    fn scripted_feed(kind: FeedKind, feed_seq: u64) -> FeedEnvelope {
        let (release_sk, _) = release_keys();
        sign_feed(
            kind,
            feed_seq,
            1_700_000_000,
            b"blocked.example\nblocked2.example".to_vec(),
            &release_sk,
        )
    }

    #[test]
    fn a_feed_with_a_valid_release_signature_is_accepted() {
        let mut relay = MockRelay::new();
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 7));
        let mut c = client();
        let got = c.pull_feed(&mut relay, FeedKind::Blocklist).unwrap();
        assert_eq!(got.unwrap().feed_seq, 7);
        assert_eq!(c.last_accepted_seq(FeedKind::Blocklist), Some(7));
    }

    #[test]
    fn an_unsigned_or_tampered_feed_is_rejected() {
        let mut c = client();

        // Garbage signature:
        let mut relay = MockRelay::new();
        let mut unsigned = scripted_feed(FeedKind::Blocklist, 7);
        unsigned.signature = Signature([0u8; 64]);
        relay.feed_response = Some(unsigned);
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedSignatureInvalid)
        );

        // Valid signature, tampered payload (an emptied blocklist):
        let mut tampered = scripted_feed(FeedKind::Blocklist, 7);
        tampered.payload = Vec::new();
        relay.feed_response = Some(tampered);
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedSignatureInvalid)
        );

        // Signed by a different key entirely:
        let wrong_sk = SigningKey::from_bytes(&[0x99; 32]);
        relay.feed_response = Some(sign_feed(
            FeedKind::Blocklist,
            7,
            1_700_000_000,
            b"whatever".to_vec(),
            &wrong_sk,
        ));
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedSignatureInvalid)
        );

        // Nothing accepted along the way:
        assert_eq!(c.last_accepted_seq(FeedKind::Blocklist), None);
    }

    #[test]
    fn a_replayed_or_downgraded_feed_is_rejected() {
        let mut relay = MockRelay::new();
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 7));
        let mut c = client();
        c.pull_feed(&mut relay, FeedKind::Blocklist).unwrap();

        // Same seq again (replay):
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 7));
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedNotNewer { have: 7, got: 7 })
        );

        // Older seq (downgrade to a validly-signed but stale list):
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 3));
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedNotNewer { have: 7, got: 3 })
        );
        assert_eq!(c.last_accepted_seq(FeedKind::Blocklist), Some(7));
    }

    #[test]
    fn a_validly_signed_feed_of_the_wrong_kind_is_rejected() {
        // Landmine: the DoH-endpoints feed is release-signed too — without
        // the kind check, a relay could serve it where the blocklist was
        // requested and the signature alone would pass.
        let mut relay = MockRelay::new();
        relay.feed_response = Some(scripted_feed(FeedKind::DohEndpoints, 7));
        let mut c = client();
        assert_eq!(
            c.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedKindMismatch {
                requested: FeedKind::Blocklist,
                got: FeedKind::DohEndpoints,
            })
        );
        // And the per-kind floors are independent:
        assert_eq!(c.last_accepted_seq(FeedKind::Blocklist), None);
        assert_eq!(c.last_accepted_seq(FeedKind::DohEndpoints), None);
    }

    #[test]
    fn conditional_fetch_passes_the_accepted_floor_and_none_changes_nothing() {
        let mut relay = MockRelay::new();
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 7));
        let mut c = client();
        c.pull_feed(&mut relay, FeedKind::Blocklist).unwrap();
        assert_eq!(relay.last_newer_than, Some(None));

        relay.feed_response = None; // "nothing newer"
        let got = c.pull_feed(&mut relay, FeedKind::Blocklist).unwrap();
        assert_eq!(got, None);
        assert_eq!(relay.last_newer_than, Some(Some(7)));
        assert_eq!(c.last_accepted_seq(FeedKind::Blocklist), Some(7));
    }

    // --- approvals, end to end --------------------------------------------

    #[test]
    fn a_received_approval_verifies_and_applies_end_to_end() {
        // The full accountability spine against the mock relay: partner
        // signs → relay carries → client receives → weakening machine
        // verifies and applies. The client itself never verified anything;
        // if it had silently "fixed up" one byte, apply_approval would
        // reject here.
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

        const BASE: u64 = 1_700_000_000;
        let anchor = sample_anchor();
        let time = TimeAnchor::new(MemFloor(Some((BASE, 1))));
        let request_id = RequestId([8u8; 16]);
        let mut request = WeakeningRequest::new(
            &anchor,
            request_id,
            FilterChange::DisableSocialBlocking,
            Some(3600),
            &time,
            BASE,
        )
        .unwrap();

        let (partner_sk, _) = partner_keys();
        let statement = ApprovalStatement::new(
            HH,
            request_id,
            APPROVE_VERDICT,
            canonical_target(&FilterChange::DisableSocialBlocking, Some(3600)),
            BASE,
            BASE + 7200,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let signature = approval::sign(&statement, &partner_sk).unwrap();

        let mut relay = MockRelay::new();
        relay.pending_approvals = vec![ApprovalMessage {
            statement,
            signature,
        }];

        let c = client();
        let approvals = c.fetch_approvals(&mut relay, &HH, &DEV).unwrap();
        assert_eq!(approvals.len(), 1);

        let msg = &approvals[0];
        let transition = request
            .apply_approval(&anchor, &msg.statement, &msg.signature, &time, BASE + 60)
            .unwrap();
        assert!(matches!(
            transition,
            Transition::BecameEffective {
                via: EffectiveVia::PartnerApproval,
                ..
            }
        ));
    }

    // --- backoff ------------------------------------------------------------

    #[test]
    fn backoff_doubles_caps_and_resets() {
        let mut b = Backoff::new(5, 60);
        let delays: Vec<u32> = (0..6).map(|_| b.next_delay_seconds()).collect();
        assert_eq!(delays, vec![5, 10, 20, 40, 60, 60], "double then cap");
        b.reset();
        assert_eq!(b.next_delay_seconds(), 5);
    }

    #[test]
    fn backoff_never_overflows() {
        let mut b = Backoff::new(u32::MAX, u32::MAX);
        for _ in 0..100 {
            assert_eq!(b.next_delay_seconds(), u32::MAX);
        }
    }

    // --- persistence -----------------------------------------------------------

    #[test]
    fn client_state_round_trips_with_outbox_and_floors_intact() {
        let mut relay = MockRelay::new();
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 7));
        let mut c = client();
        c.pull_feed(&mut relay, FeedKind::Blocklist).unwrap();
        c.enqueue(signed_event(1));
        c.enqueue(signed_event(2));

        let json = serde_json::to_string(&c).unwrap();
        let mut restored: RelayClient = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, c);

        // The restored client keeps its downgrade floor...
        relay.feed_response = Some(scripted_feed(FeedKind::Blocklist, 3));
        assert_eq!(
            restored.pull_feed(&mut relay, FeedKind::Blocklist),
            Err(RelayClientError::FeedNotNewer { have: 7, got: 3 })
        );
        // ...and its queued events, in order.
        let sent = restored.flush(&mut relay, &HH).unwrap();
        assert_eq!(sent, 2);
        let seqs: Vec<u64> = relay.received_events.iter().map(|(_, e)| e.seq).collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn unknown_fields_on_persisted_client_state_are_rejected() {
        let c = client();
        let mut value = serde_json::to_value(&c).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!("payload"));
        let result: Result<RelayClient, _> = serde_json::from_value(value);
        assert!(result.is_err(), "unknown field should be rejected");
    }

    // --- known-answer vector ---------------------------------------------------
    // Self-established regression vector for the feed canonical encoding
    // and its signature, same rationale as every other KAT in this crate:
    // cross-platform byte-for-byte agreement is what keeps a feed signed
    // by the offline pipeline verifiable on every client forever.
    #[test]
    fn known_answer_vector() {
        let (release_sk, _) = release_keys();
        let envelope = sign_feed(
            FeedKind::Blocklist,
            42,
            1_700_000_000,
            b"kat-payload".to_vec(),
            &release_sk,
        );
        // Pinned from actual CI runs (local cargo test is blocked by Smart
        // App Control on this dev machine); identical on both OSes.
        // Canonical: run 28756643807. Signature: run 28756729716.
        let expected_canonical_hex =
            "436f6e74656e7446696c7465722d466565642d76310001000000000000002a\
            000000006553f1000000000b6b61742d7061796c6f6164";
        let expected_signature_hex =
            "eefee31e313c5e0dd02d6673d422b2761176011cce466b569e2c67da076ddcf7\
            cc22f672ecb9763a4f425e3212c34aeaca3787e2616a3f749cc827690204e00b";
        let canonical = FeedEnvelope::canonical_bytes(
            envelope.kind,
            envelope.feed_seq,
            envelope.published_at,
            &envelope.payload,
        );
        assert_eq!(
            (
                crate::hex::encode(&canonical),
                crate::hex::encode(&envelope.signature.0),
            ),
            (
                expected_canonical_hex.to_string(),
                expected_signature_hex.to_string(),
            ),
            "actual values printed above"
        );
    }
}
