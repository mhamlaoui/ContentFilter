//! Per-device request authentication + replay guard (relay-auth). The
//! stateful half of what `cf-core`'s `request_auth` module defines: that
//! module owns the signed bytes (shared with every device platform); this
//! one owns the judgments only the relay can make — is the device
//! registered, is the timestamp within the window by *our* clock, has the
//! nonce been seen.
//!
//! # Check order (deliberate)
//!
//! Unknown device → signature → endpoint binding → body hash → timestamp
//! → nonce. Two properties fall out:
//!
//! - **Nothing about the statement is trusted before the signature
//!   verifies**, and the nonce store is only ever written for otherwise
//!   fully-valid requests — unauthenticated traffic cannot poison or
//!   grow the replay cache.
//! - **The endpoint and body checks compare the relay's own routing
//!   context against the signed claim**, not the claim against itself. A
//!   captured signed "POST /v1/events" presented to another route fails
//!   `EndpointMismatch`; a swapped body fails the hash recheck.
//!
//! # The eviction invariant
//!
//! A nonce may be forgotten only once no request bearing it could pass
//! the timestamp check anyway. A replay carries the *same* `ts` (it's
//! inside the signed bytes — refreshing it breaks the signature), so a
//! nonce for a request stamped `ts` is dead weight once
//! `now > ts + max_skew`: from then on the staleness check rejects the
//! replay before the nonce store is even consulted. Eviction uses exactly
//! that horizon, so the replay window never reopens; the boundary is
//! pinned by a test. Future-dated timestamps beyond the skew are rejected
//! too — otherwise a device could bank a request stamped far in the
//! future and "replay" it fresh long after, having paid only one nonce.
//!
//! Rejected alternative: a global (cross-device) nonce space. Scoping per
//! device costs one `DeviceId` per key and removes any cross-device
//! interaction in the cache — nonce management stays each device's own
//! problem.
//!
//! Axum middleware wiring is deliberately absent: the mutating endpoints
//! this protects don't exist yet. relay-registry-pairing (#30) mounts
//! [`verify_mutating_request`] where routing context (method, path, body)
//! is in hand, and owns the wire format that carries the statement.

use cf_core::request_auth::{self, AuthStatement};
use cf_core::{DeviceId, DeviceKeyResolver, Signature};
use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Default acceptance window: |relay now − statement ts| ≤ 5 minutes.
pub const DEFAULT_MAX_SKEW_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    UnknownDevice,
    InvalidSignature,
    /// The signed method/path doesn't match the endpoint actually hit.
    EndpointMismatch,
    /// The received body doesn't hash to the signed `body_sha256`.
    TamperedBody,
    StaleTimestamp {
        ts: u64,
        now: u64,
    },
    FutureTimestamp {
        ts: u64,
        now: u64,
    },
    ReplayedNonce,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UnknownDevice => write!(f, "device is not registered"),
            AuthError::InvalidSignature => write!(f, "request signature did not verify"),
            AuthError::EndpointMismatch => {
                write!(f, "signed method/path does not match this endpoint")
            }
            AuthError::TamperedBody => write!(f, "body does not match the signed hash"),
            AuthError::StaleTimestamp { ts, now } => {
                write!(f, "timestamp {ts} is stale at relay time {now}")
            }
            AuthError::FutureTimestamp { ts, now } => {
                write!(f, "timestamp {ts} is in the future at relay time {now}")
            }
            AuthError::ReplayedNonce => write!(f, "nonce was already used"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The request as the relay actually received it — routing context and
/// raw body. The verifier compares this against the signed claims.
#[derive(Debug, Clone, Copy)]
pub struct IncomingRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
}

type NonceKey = (DeviceId, [u8; request_auth::REQUEST_NONCE_LEN]);

/// Sliding-window nonce store. Per-device scoping; eviction at exactly
/// the staleness horizon (see the module docs). Memory is bounded by the
/// accepted-request rate times the window — entries are only ever created
/// for requests that passed every other check.
#[derive(Debug)]
pub struct ReplayGuard {
    max_skew_seconds: u64,
    seen: HashMap<NonceKey, u64>,
    /// (key, evict_after) in insertion order. Accepted timestamps span at
    /// most `2 * max_skew`, so deadlines are near-sorted: popping from the
    /// front while expired may evict a straggler late (harmless — a stale
    /// entry only occupies memory; the timestamp check already rejects its
    /// replays) but never early (which would reopen the replay window).
    eviction_queue: VecDeque<(NonceKey, u64)>,
}

impl ReplayGuard {
    pub fn new(max_skew_seconds: u64) -> Self {
        Self {
            max_skew_seconds,
            seen: HashMap::new(),
            eviction_queue: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn purge(&mut self, now: u64) {
        // `&(key, ...)` copies the entry out, so nothing borrows the queue
        // across the two mutations below.
        while let Some(&(key, evict_after)) = self.eviction_queue.front() {
            if evict_after >= now {
                break;
            }
            self.eviction_queue.pop_front();
            self.seen.remove(&key);
        }
    }

    /// Records the nonce, rejecting a repeat. Callers (i.e.
    /// [`verify_mutating_request`]) must have fully validated the request
    /// first — this is the only write path into the store.
    fn check_and_insert(
        &mut self,
        device: DeviceId,
        statement_ts: u64,
        nonce: [u8; request_auth::REQUEST_NONCE_LEN],
        now: u64,
    ) -> Result<(), AuthError> {
        self.purge(now);
        let key = (device, nonce);
        if self.seen.contains_key(&key) {
            return Err(AuthError::ReplayedNonce);
        }
        self.seen.insert(key, statement_ts);
        self.eviction_queue
            .push_back((key, statement_ts.saturating_add(self.max_skew_seconds)));
        Ok(())
    }
}

/// Verifies one mutating request end to end and, on success, returns the
/// authenticated device id and consumes the nonce. Any error leaves the
/// replay guard untouched.
pub fn verify_mutating_request<R: DeviceKeyResolver>(
    statement: &AuthStatement,
    signature: &Signature,
    incoming: IncomingRequest<'_>,
    resolver: &R,
    guard: &mut ReplayGuard,
    now: u64,
) -> Result<DeviceId, AuthError> {
    let verify_key = resolver
        .resolve(&statement.device_id)
        .ok_or(AuthError::UnknownDevice)?;
    request_auth::verify(statement, signature, &verify_key)
        .map_err(|_| AuthError::InvalidSignature)?;
    if statement.method != incoming.method || statement.path != incoming.path {
        return Err(AuthError::EndpointMismatch);
    }
    if request_auth::body_sha256(incoming.body) != statement.body_sha256 {
        return Err(AuthError::TamperedBody);
    }
    if now.saturating_sub(statement.ts) > guard.max_skew_seconds {
        return Err(AuthError::StaleTimestamp {
            ts: statement.ts,
            now,
        });
    }
    if statement.ts.saturating_sub(now) > guard.max_skew_seconds {
        return Err(AuthError::FutureTimestamp {
            ts: statement.ts,
            now,
        });
    }
    guard.check_and_insert(statement.device_id, statement.ts, statement.nonce, now)?;
    Ok(statement.device_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_core::request_auth::{body_sha256, sign, REQUEST_NONCE_LEN};
    use cf_core::Ed25519PublicKey;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap as StdHashMap;

    const NOW: u64 = 1_700_000_000;
    const SKEW: u64 = 300;

    struct MapResolver(StdHashMap<[u8; 16], Ed25519PublicKey>);

    impl DeviceKeyResolver for MapResolver {
        fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey> {
            self.0.get(&device_id.0).copied()
        }
    }

    fn keypair(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn device() -> DeviceId {
        DeviceId([2u8; 16])
    }

    fn resolver() -> MapResolver {
        let (_, vk) = keypair(0x61);
        MapResolver(StdHashMap::from([(device().0, vk)]))
    }

    const BODY: &[u8] = br#"{"seq":1}"#;

    fn signed_statement(ts: u64, nonce_byte: u8) -> (AuthStatement, Signature) {
        let (sk, _) = keypair(0x61);
        let statement = AuthStatement::new(
            device(),
            "POST",
            "/v1/events",
            body_sha256(BODY),
            ts,
            [nonce_byte; REQUEST_NONCE_LEN],
        )
        .unwrap();
        let sig = sign(&statement, &sk).unwrap();
        (statement, sig)
    }

    fn incoming() -> IncomingRequest<'static> {
        IncomingRequest {
            method: "POST",
            path: "/v1/events",
            body: BODY,
        }
    }

    // --- the four DoD rows -------------------------------------------------

    #[test]
    fn a_valid_device_signed_request_is_accepted() {
        let (statement, sig) = signed_statement(NOW, 1);
        let mut guard = ReplayGuard::new(SKEW);
        let got =
            verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW);
        assert_eq!(got, Ok(device()));
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let (statement, sig) = signed_statement(NOW, 1);
        let mut guard = ReplayGuard::new(SKEW);
        verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW)
            .unwrap();
        // Bit-for-bit identical resend, still inside the timestamp window:
        assert_eq!(
            verify_mutating_request(
                &statement,
                &sig,
                incoming(),
                &resolver(),
                &mut guard,
                NOW + 5
            ),
            Err(AuthError::ReplayedNonce)
        );
    }

    #[test]
    fn a_stale_timestamp_is_rejected() {
        let (statement, sig) = signed_statement(NOW - SKEW - 1, 1);
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW),
            Err(AuthError::StaleTimestamp {
                ts: NOW - SKEW - 1,
                now: NOW
            })
        );
        assert!(
            guard.is_empty(),
            "rejected requests must not consume nonces"
        );
    }

    #[test]
    fn an_unknown_device_is_rejected() {
        let (statement, sig) = signed_statement(NOW, 1);
        let empty = MapResolver(StdHashMap::new());
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&statement, &sig, incoming(), &empty, &mut guard, NOW),
            Err(AuthError::UnknownDevice)
        );
    }

    // --- redteam rows --------------------------------------------------------

    #[test]
    fn a_future_dated_request_cannot_be_banked() {
        // Without the future check, a device could stamp ts = now + a year,
        // pay one nonce, and replay it "fresh" long after the nonce store
        // forgot it. Beyond-skew future timestamps are rejected outright.
        let (statement, sig) = signed_statement(NOW + SKEW + 1, 1);
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW),
            Err(AuthError::FutureTimestamp {
                ts: NOW + SKEW + 1,
                now: NOW
            })
        );
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let (wrong_sk, _) = keypair(0x99);
        let statement = AuthStatement::new(
            device(),
            "POST",
            "/v1/events",
            body_sha256(BODY),
            NOW,
            [1u8; REQUEST_NONCE_LEN],
        )
        .unwrap();
        let sig = sign(&statement, &wrong_sk).unwrap();
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW),
            Err(AuthError::InvalidSignature)
        );
        assert!(
            guard.is_empty(),
            "unauthenticated traffic must not write the nonce store"
        );
    }

    #[test]
    fn a_swapped_body_is_rejected() {
        // Valid signature over the *original* body's hash; attacker swaps
        // the body in flight. The relay must recompute, not trust.
        let (statement, sig) = signed_statement(NOW, 1);
        let tampered = IncomingRequest {
            body: br#"{"seq":999}"#,
            ..incoming()
        };
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&statement, &sig, tampered, &resolver(), &mut guard, NOW),
            Err(AuthError::TamperedBody)
        );
    }

    #[test]
    fn a_captured_request_cannot_replay_against_another_endpoint() {
        let (statement, sig) = signed_statement(NOW, 1);
        let other_endpoint = IncomingRequest {
            path: "/v1/uninstall-ack",
            ..incoming()
        };
        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(
                &statement,
                &sig,
                other_endpoint,
                &resolver(),
                &mut guard,
                NOW
            ),
            Err(AuthError::EndpointMismatch)
        );
    }

    #[test]
    fn nonce_eviction_never_reopens_the_replay_window() {
        // The landmine for the invariant: at every instant after
        // acceptance, an exact replay must fail — first as ReplayedNonce
        // (nonce still held), then, from the moment eviction is allowed,
        // as StaleTimestamp. There must be no instant where it's accepted.
        let (statement, sig) = signed_statement(NOW, 1);
        let mut guard = ReplayGuard::new(SKEW);
        verify_mutating_request(&statement, &sig, incoming(), &resolver(), &mut guard, NOW)
            .unwrap();

        // Boundary: now == ts + skew — timestamp still valid, so the nonce
        // must still be held.
        assert_eq!(
            verify_mutating_request(
                &statement,
                &sig,
                incoming(),
                &resolver(),
                &mut guard,
                NOW + SKEW
            ),
            Err(AuthError::ReplayedNonce)
        );

        // One past the boundary: staleness takes over — and only now may
        // the store forget the nonce.
        assert_eq!(
            verify_mutating_request(
                &statement,
                &sig,
                incoming(),
                &resolver(),
                &mut guard,
                NOW + SKEW + 1
            ),
            Err(AuthError::StaleTimestamp {
                ts: NOW,
                now: NOW + SKEW + 1
            })
        );

        // And the memory side: a later, unrelated valid request triggers
        // the purge and the dead entry is gone.
        let (fresh, fresh_sig) = signed_statement(NOW + SKEW + 2, 2);
        verify_mutating_request(
            &fresh,
            &fresh_sig,
            incoming(),
            &resolver(),
            &mut guard,
            NOW + SKEW + 2,
        )
        .unwrap();
        assert_eq!(guard.len(), 1, "expired nonce should have been evicted");
    }

    #[test]
    fn nonces_are_scoped_per_device() {
        // Two registered devices happening to use the same nonce bytes
        // must not collide in the store.
        let (sk_a, vk_a) = keypair(0x61);
        let (sk_b, vk_b) = keypair(0x62);
        let dev_a = DeviceId([2u8; 16]);
        let dev_b = DeviceId([3u8; 16]);
        let resolver = MapResolver(StdHashMap::from([(dev_a.0, vk_a), (dev_b.0, vk_b)]));

        let make = |dev: DeviceId, sk: &SigningKey| {
            let statement = AuthStatement::new(
                dev,
                "POST",
                "/v1/events",
                body_sha256(BODY),
                NOW,
                [1u8; REQUEST_NONCE_LEN], // same nonce bytes on purpose
            )
            .unwrap();
            let sig = sign(&statement, sk).unwrap();
            (statement, sig)
        };
        let (st_a, sig_a) = make(dev_a, &sk_a);
        let (st_b, sig_b) = make(dev_b, &sk_b);

        let mut guard = ReplayGuard::new(SKEW);
        assert_eq!(
            verify_mutating_request(&st_a, &sig_a, incoming(), &resolver, &mut guard, NOW),
            Ok(dev_a)
        );
        assert_eq!(
            verify_mutating_request(&st_b, &sig_b, incoming(), &resolver, &mut guard, NOW),
            Ok(dev_b)
        );
        assert_eq!(guard.len(), 2);
    }
}
