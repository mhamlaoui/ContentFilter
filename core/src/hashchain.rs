//! Hash-chained, signed event log (core-hashchain). The mechanism that
//! makes relay censorship leave a detectable hole: each event links to the
//! previous one's hash and carries its signing device's own signature, so
//! removing, reordering, or inserting an event breaks verification instead
//! of silently succeeding.
//!
//! [`ChainedEvent`] carries an opaque `event_type` string and `payload`
//! bytes rather than reusing [`crate::event::NotificationEvent`] directly.
//! Chain integrity (linking, monotonic seq, per-device signatures) is
//! orthogonal to the application-level event taxonomy, and NotificationEvent
//! may not be the only thing ever worth chaining (approval records, config
//! changes, ...). Coupling the two would make this module's shape hostage
//! to NotificationEvent's, for no benefit to either.

use crate::ids::DeviceId;
use crate::keys::{Ed25519PublicKey, Signature as CfSignature};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

const DOMAIN_TAG: &[u8] = b"ContentFilter-ChainedEvent-v1\0";

/// The `prev_hash` of the first event in a chain.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedEvent {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub device_id: DeviceId,
    pub event_type: String,
    pub ts: u64,
    pub payload: Vec<u8>,
    pub sig: CfSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// `seq` at this position doesn't strictly exceed the previous event's.
    SeqNotMonotonic { at_seq: u64 },
    /// `prev_hash` doesn't match the hash of the actual previous event —
    /// the link an attacker breaks by removing, reordering, or inserting
    /// an event.
    BrokenLink { at_seq: u64 },
    /// The event claims a `device_id` the resolver doesn't recognize as a
    /// member of this household.
    UnknownDevice { at_seq: u64 },
    /// The signature doesn't verify against *that specific device's* key —
    /// this is what "per-device signature enforced" means: device A's
    /// event can't be forged using device B's key, even if B is a
    /// legitimate household member.
    InvalidSignature { at_seq: u64 },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::SeqNotMonotonic { at_seq } => {
                write!(
                    f,
                    "seq {at_seq} does not strictly exceed the previous event's"
                )
            }
            ChainError::BrokenLink { at_seq } => {
                write!(
                    f,
                    "prev_hash at seq {at_seq} does not match the prior event's hash"
                )
            }
            ChainError::UnknownDevice { at_seq } => {
                write!(f, "event at seq {at_seq} claims an unrecognized device")
            }
            ChainError::InvalidSignature { at_seq } => {
                write!(
                    f,
                    "signature at seq {at_seq} does not verify against its claimed device"
                )
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// Resolves a device's current verify key. A trait, not a `HashMap`
/// parameter, so callers can back it with per-household membership state
/// (including revocation) rather than this module dictating storage.
pub trait DeviceKeyResolver {
    fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey>;
}

fn canonical_encode(event: &ChainedEvent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        DOMAIN_TAG.len() + 8 + 32 + 16 + 2 + event.event_type.len() + 8 + 4 + event.payload.len(),
    );
    buf.extend_from_slice(DOMAIN_TAG);
    buf.extend_from_slice(&event.seq.to_be_bytes());
    buf.extend_from_slice(&event.prev_hash);
    buf.extend_from_slice(&event.device_id.0);
    let type_bytes = event.event_type.as_bytes();
    buf.extend_from_slice(&(type_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(type_bytes);
    buf.extend_from_slice(&event.ts.to_be_bytes());
    buf.extend_from_slice(&(event.payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&event.payload);
    buf
}

/// The hash that becomes the *next* event's `prev_hash`. Covers everything
/// except `sig` itself (the signature is over the same canonical bytes,
/// not over this hash — there's no need to hash-then-sign when Ed25519
/// already hashes its input internally).
pub fn event_hash(event: &ChainedEvent) -> [u8; 32] {
    Sha256::digest(canonical_encode(event)).into()
}

/// Signs a not-yet-signed event's canonical bytes. Callers build a
/// `ChainedEvent` with a placeholder `sig` (any value — it isn't part of
/// the signed bytes), call this, then set the real `sig` on the event.
pub fn sign_event(event: &ChainedEvent, signing_key: &SigningKey) -> CfSignature {
    let sig = signing_key.sign(&canonical_encode(event));
    CfSignature(sig.to_bytes())
}

fn verify_event_signature(event: &ChainedEvent, verify_key: &Ed25519PublicKey) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&verify_key.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&event.sig.0);
    vk.verify_strict(&canonical_encode(event), &sig).is_ok()
}

/// Verifies a chain end to end: seq monotonicity, unbroken hash links, and
/// a valid signature from each event's own claimed device. `events` is
/// assumed to be in the order presented — this does not sort by `seq`, so
/// passing an out-of-order slice will correctly fail as non-monotonic
/// rather than being silently reordered into validity.
pub fn verify_chain<R: DeviceKeyResolver>(
    events: &[ChainedEvent],
    resolver: &R,
) -> Result<(), ChainError> {
    let mut prev_hash = GENESIS_HASH;
    let mut prev_seq: Option<u64> = None;

    for event in events {
        if let Some(p) = prev_seq {
            if event.seq <= p {
                return Err(ChainError::SeqNotMonotonic { at_seq: event.seq });
            }
        }
        if event.prev_hash != prev_hash {
            return Err(ChainError::BrokenLink { at_seq: event.seq });
        }
        let verify_key = resolver
            .resolve(&event.device_id)
            .ok_or(ChainError::UnknownDevice { at_seq: event.seq })?;
        if !verify_event_signature(event, &verify_key) {
            return Err(ChainError::InvalidSignature { at_seq: event.seq });
        }
        prev_hash = event_hash(event);
        prev_seq = Some(event.seq);
    }
    Ok(())
}

/// Returns every seq missing from `1..=max(events' seqs)`. Assumes a valid
/// chain starts at seq 1 and increments by exactly 1 — the same assumption
/// `verify_chain` doesn't need to make (it only checks strict monotonicity
/// of whatever's actually present), so run this independently of, not as a
/// replacement for, `verify_chain`.
pub fn find_gaps(events: &[ChainedEvent]) -> Vec<u64> {
    let Some(max_seq) = events.iter().map(|e| e.seq).max() else {
        return Vec::new();
    };
    let present: std::collections::HashSet<u64> = events.iter().map(|e| e.seq).collect();
    (1..=max_seq).filter(|seq| !present.contains(seq)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapResolver(HashMap<[u8; 16], Ed25519PublicKey>);

    impl DeviceKeyResolver for MapResolver {
        fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey> {
            self.0.get(&device_id.0).copied()
        }
    }

    fn keypair_from_seed(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, Ed25519PublicKey(verifying_key.to_bytes()))
    }

    /// Builds a valid, linked, signed chain of `n` events all from one
    /// device, starting at seq 1.
    fn build_chain(n: u64, device_id: DeviceId, signing_key: &SigningKey) -> Vec<ChainedEvent> {
        let mut events = Vec::new();
        let mut prev_hash = GENESIS_HASH;
        for seq in 1..=n {
            let mut event = ChainedEvent {
                seq,
                prev_hash,
                device_id,
                event_type: "test.event".to_string(),
                ts: 1_700_000_000 + seq,
                payload: format!("payload-{seq}").into_bytes(),
                sig: CfSignature([0u8; 64]), // placeholder, replaced below
            };
            event.sig = sign_event(&event, signing_key);
            prev_hash = event_hash(&event);
            events.push(event);
        }
        events
    }

    fn resolver_for(device_id: DeviceId, verify_key: Ed25519PublicKey) -> MapResolver {
        MapResolver(HashMap::from([(device_id.0, verify_key)]))
    }

    #[test]
    fn valid_chain_verifies_end_to_end() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let chain = build_chain(5, device_id, &sk);
        assert!(verify_chain(&chain, &resolver_for(device_id, vk)).is_ok());
    }

    #[test]
    fn empty_chain_is_vacuously_valid() {
        let resolver = MapResolver(HashMap::new());
        assert_eq!(verify_chain(&[], &resolver), Ok(()));
    }

    #[test]
    fn removing_a_middle_event_breaks_verification() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(5, device_id, &sk);
        chain.remove(2); // drop the seq=3 event
        let err = verify_chain(&chain, &resolver_for(device_id, vk)).unwrap_err();
        // The event that used to follow it (seq=4) now has a prev_hash
        // that doesn't match anything in the remaining chain.
        assert_eq!(err, ChainError::BrokenLink { at_seq: 4 });
    }

    #[test]
    fn reordering_two_events_breaks_verification() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(5, device_id, &sk);
        chain.swap(1, 2); // seq order becomes 1,3,2,4,5
        let err = verify_chain(&chain, &resolver_for(device_id, vk)).unwrap_err();
        assert_eq!(err, ChainError::BrokenLink { at_seq: 3 });
    }

    #[test]
    fn inserting_a_fabricated_event_breaks_verification() {
        // A standalone valid-looking event (correct signature, internally
        // consistent) spliced into the middle of an otherwise-valid chain.
        // "Valid on its own" must not be enough to pass as part of a chain
        // it was never actually linked into.
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(4, device_id, &sk);

        let mut fabricated = ChainedEvent {
            seq: 10, // doesn't even need a plausible seq to demonstrate the point
            prev_hash: [0xAA; 32],
            device_id,
            event_type: "test.event".to_string(),
            ts: 1_700_000_500,
            payload: b"fabricated".to_vec(),
            sig: CfSignature([0u8; 64]),
        };
        fabricated.sig = sign_event(&fabricated, &sk);
        chain.insert(2, fabricated);

        assert!(verify_chain(&chain, &resolver_for(device_id, vk)).is_err());
    }

    #[test]
    fn tampered_payload_breaks_verification() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(3, device_id, &sk);
        chain[1].payload = b"tampered".to_vec();
        let err = verify_chain(&chain, &resolver_for(device_id, vk)).unwrap_err();
        assert_eq!(err, ChainError::InvalidSignature { at_seq: 2 });
    }

    #[test]
    fn signature_from_a_different_device_key_is_rejected() {
        // Per-device enforcement: an event claiming device A must verify
        // against device A's key specifically, even if it was actually
        // signed by a different, otherwise-legitimate household device.
        let device_a = DeviceId([1u8; 16]);
        let device_b = DeviceId([2u8; 16]);
        let (sk_a, vk_a) = keypair_from_seed(0x20);
        let (sk_b, _vk_b) = keypair_from_seed(0x30);

        // Event claims device_a but is actually signed by device_b's key.
        let mut event = ChainedEvent {
            seq: 1,
            prev_hash: GENESIS_HASH,
            device_id: device_a,
            event_type: "test.event".to_string(),
            ts: 1_700_000_000,
            payload: vec![],
            sig: CfSignature([0u8; 64]),
        };
        event.sig = sign_event(&event, &sk_b);
        let _ = &sk_a; // device_a's own key is never used here, on purpose

        let resolver = resolver_for(device_a, vk_a);
        assert_eq!(
            verify_chain(&[event], &resolver),
            Err(ChainError::InvalidSignature { at_seq: 1 })
        );
    }

    #[test]
    fn event_from_an_unregistered_device_is_rejected() {
        let device_id = DeviceId([9u8; 16]);
        let (sk, _vk) = keypair_from_seed(0x20);
        let chain = build_chain(1, device_id, &sk);
        let empty_resolver = MapResolver(HashMap::new());
        assert_eq!(
            verify_chain(&chain, &empty_resolver),
            Err(ChainError::UnknownDevice { at_seq: 1 })
        );
    }

    #[test]
    fn duplicate_seq_is_rejected_as_non_monotonic() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(2, device_id, &sk);
        chain[1].seq = chain[0].seq; // duplicate, not advancing
        let err = verify_chain(&chain, &resolver_for(device_id, vk)).unwrap_err();
        assert_eq!(err, ChainError::SeqNotMonotonic { at_seq: 1 });
    }

    // --- gap detection --------------------------------------------------

    #[test]
    fn find_gaps_reports_missing_seqs() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, _vk) = keypair_from_seed(0x20);
        let mut chain = build_chain(6, device_id, &sk);
        chain.remove(4); // drop seq=5
        chain.remove(1); // drop seq=2 (index shifts after first remove)
        let present: Vec<u64> = chain.iter().map(|e| e.seq).collect();
        assert_eq!(present, vec![1, 3, 4, 6]);
        assert_eq!(find_gaps(&chain), vec![2, 5]);
    }

    #[test]
    fn find_gaps_on_a_complete_chain_is_empty() {
        let device_id = DeviceId([1u8; 16]);
        let (sk, _vk) = keypair_from_seed(0x20);
        let chain = build_chain(4, device_id, &sk);
        assert!(find_gaps(&chain).is_empty());
    }

    #[test]
    fn find_gaps_on_empty_chain_is_empty() {
        assert!(find_gaps(&[]).is_empty());
    }
}
