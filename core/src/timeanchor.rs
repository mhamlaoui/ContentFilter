//! Signed time anchors and effective-now logic (core-timeanchor). Defeats
//! two opposite clock attacks using one monotonic, relay-signed floor:
//!
//! - **Rollback**, to revive an expired approval: defeated by computing
//!   expiry against `max(local, floor)` — a rolled-back local clock can't
//!   pull the effective time back below what the relay has already
//!   attested.
//! - **Forward jump**, to pre-activate a `not_before` gate: defeated by
//!   never consulting the local clock for activation at all.
//!   [`TimeAnchor::has_reached`] takes no local-time parameter — that's
//!   deliberate, not an oversight. The device owner can set their local
//!   clock to anything; only the relay-signed floor can be trusted to mean
//!   "this much time has genuinely passed."
//!
//! These two checks are asymmetric on purpose. Don't unify them into one
//! `effective_now` used for both — that reintroduces the forward-jump
//! attack this module exists to prevent.

use crate::keys::{Ed25519PublicKey, Signature as CfSignature};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::fmt;

const DOMAIN_TAG: &[u8] = b"ContentFilter-TimeBeacon-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeBeacon {
    pub utc: u64,
    pub seq: u64,
}

impl TimeBeacon {
    pub fn canonical_encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DOMAIN_TAG.len() + 8 + 8);
        buf.extend_from_slice(DOMAIN_TAG);
        buf.extend_from_slice(&self.utc.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAnchorError {
    InvalidKeyMaterial,
    VerificationFailed,
    /// The beacon's `seq` doesn't strictly exceed the currently persisted
    /// floor's `seq` — a replayed or rolled-back beacon, rejected before
    /// it ever reaches the floor.
    StaleBeacon,
}

impl fmt::Display for TimeAnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeAnchorError::InvalidKeyMaterial => write!(f, "invalid Ed25519 key material"),
            TimeAnchorError::VerificationFailed => {
                write!(f, "beacon signature verification failed")
            }
            TimeAnchorError::StaleBeacon => write!(f, "beacon seq does not advance the floor"),
        }
    }
}

impl std::error::Error for TimeAnchorError {}

pub fn sign_beacon(beacon: &TimeBeacon, signing_key: &SigningKey) -> CfSignature {
    let sig = signing_key.sign(&beacon.canonical_encode());
    CfSignature(sig.to_bytes())
}

/// Verifies `signature` over `beacon` against `verify_key`. Uses
/// `verify_strict` for the same reason core-crypto-approvals does — see
/// that module's doc comment.
pub fn verify_beacon(
    beacon: &TimeBeacon,
    signature: &CfSignature,
    verify_key: &Ed25519PublicKey,
) -> Result<(), TimeAnchorError> {
    let vk =
        VerifyingKey::from_bytes(&verify_key.0).map_err(|_| TimeAnchorError::InvalidKeyMaterial)?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify_strict(&beacon.canonical_encode(), &sig)
        .map_err(|_| TimeAnchorError::VerificationFailed)
}

/// Where the floor is persisted. This crate has no file I/O of its own —
/// it's shared via UniFFI with iOS/Android, where "write a file" isn't the
/// idiomatic (or even always available) way to persist a value. Each
/// platform provides its own implementation (Keychain, SharedPreferences,
/// a file under ProgramData, ...); this trait is the seam.
pub trait FloorStore {
    fn load_floor(&self) -> Option<(u64, u64)>;
    fn save_floor(&mut self, utc: u64, seq: u64);
}

pub struct TimeAnchor<S: FloorStore> {
    store: S,
}

impl<S: FloorStore> TimeAnchor<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Recovers the underlying store, e.g. to persist it and reload it
    /// into a fresh `TimeAnchor` on the next process start.
    pub fn into_inner(self) -> S {
        self.store
    }

    fn floor_utc(&self) -> u64 {
        self.store.load_floor().map_or(0, |(utc, _)| utc)
    }

    fn floor_seq(&self) -> Option<u64> {
        self.store.load_floor().map(|(_, seq)| seq)
    }

    /// Verifies `beacon` and, only if its `seq` strictly advances the
    /// current floor, persists it as the new floor. Rejects unsigned,
    /// tampered, or non-advancing beacons before they can affect anything.
    pub fn ingest_beacon(
        &mut self,
        beacon: &TimeBeacon,
        signature: &CfSignature,
        verify_key: &Ed25519PublicKey,
    ) -> Result<(), TimeAnchorError> {
        verify_beacon(beacon, signature, verify_key)?;
        if let Some(current_seq) = self.floor_seq() {
            if beacon.seq <= current_seq {
                return Err(TimeAnchorError::StaleBeacon);
            }
        }
        self.store.save_floor(beacon.utc, beacon.seq);
        Ok(())
    }

    /// For expiry checks: the larger of `local_utc` and the floor.
    pub fn effective_now(&self, local_utc: u64) -> u64 {
        local_utc.max(self.floor_utc())
    }

    pub fn is_expired(&self, local_utc: u64, not_after: u64) -> bool {
        self.effective_now(local_utc) > not_after
    }

    /// For activation checks: whether the *relay-attested floor alone* has
    /// reached `not_before`. No `local_utc` parameter exists on this
    /// method — see the module doc comment for why that's deliberate.
    pub fn has_reached(&self, not_before: u64) -> bool {
        self.floor_utc() >= not_before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct InMemoryFloorStore(Option<(u64, u64)>);

    impl FloorStore for InMemoryFloorStore {
        fn load_floor(&self) -> Option<(u64, u64)> {
            self.0
        }
        fn save_floor(&mut self, utc: u64, seq: u64) {
            self.0 = Some((utc, seq));
        }
    }

    fn keypair_from_seed(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, Ed25519PublicKey(verifying_key.to_bytes()))
    }

    #[test]
    fn valid_beacon_verifies() {
        let (sk, vk) = keypair_from_seed(0x10);
        let beacon = TimeBeacon {
            utc: 1_700_000_000,
            seq: 1,
        };
        let sig = sign_beacon(&beacon, &sk);
        assert!(verify_beacon(&beacon, &sig, &vk).is_ok());
    }

    #[test]
    fn tampered_beacon_is_rejected() {
        let (sk, vk) = keypair_from_seed(0x10);
        let beacon = TimeBeacon {
            utc: 1_700_000_000,
            seq: 1,
        };
        let sig = sign_beacon(&beacon, &sk);
        let tampered = TimeBeacon {
            utc: beacon.utc + 1_000_000,
            ..beacon
        };
        assert_eq!(
            verify_beacon(&tampered, &sig, &vk),
            Err(TimeAnchorError::VerificationFailed)
        );
    }

    #[test]
    fn unsigned_garbage_is_rejected() {
        let (_sk, vk) = keypair_from_seed(0x10);
        let beacon = TimeBeacon {
            utc: 1_700_000_000,
            seq: 1,
        };
        let forged = CfSignature([0u8; 64]);
        assert_eq!(
            verify_beacon(&beacon, &forged, &vk),
            Err(TimeAnchorError::VerificationFailed)
        );
    }

    #[test]
    fn stale_beacon_does_not_move_the_floor() {
        let (sk, vk) = keypair_from_seed(0x10);
        let mut anchor = TimeAnchor::new(InMemoryFloorStore::default());
        let b1 = TimeBeacon {
            utc: 1_700_000_000,
            seq: 5,
        };
        anchor
            .ingest_beacon(&b1, &sign_beacon(&b1, &sk), &vk)
            .unwrap();

        // Same seq, later utc: still rejected. seq, not utc, is the
        // replay-guard; accepting this would let a compromised relay
        // repeat an old seq with a new utc to nudge the floor around.
        let replay = TimeBeacon {
            utc: 1_800_000_000,
            seq: 5,
        };
        assert_eq!(
            anchor.ingest_beacon(&replay, &sign_beacon(&replay, &sk), &vk),
            Err(TimeAnchorError::StaleBeacon)
        );
        assert_eq!(anchor.effective_now(0), 1_700_000_000);
    }

    #[test]
    fn rollback_below_floor_cannot_revive_an_expired_approval() {
        let (sk, vk) = keypair_from_seed(0x10);
        let mut anchor = TimeAnchor::new(InMemoryFloorStore::default());
        let beacon = TimeBeacon {
            utc: 2_000_000_000,
            seq: 1,
        };
        anchor
            .ingest_beacon(&beacon, &sign_beacon(&beacon, &sk), &vk)
            .unwrap();

        let not_after = 1_900_000_000; // expired well before the floor
                                       // Attacker rolls the local clock back before not_after too, hoping
                                       // to make the approval look "not yet expired."
        let rolled_back_local = 1_000_000_000;
        assert!(anchor.is_expired(rolled_back_local, not_after));
    }

    #[test]
    fn forward_jump_cannot_preactivate() {
        let (sk, vk) = keypair_from_seed(0x10);
        let mut anchor = TimeAnchor::new(InMemoryFloorStore::default());
        let beacon = TimeBeacon {
            utc: 1_000_000_000,
            seq: 1,
        };
        anchor
            .ingest_beacon(&beacon, &sign_beacon(&beacon, &sk), &vk)
            .unwrap();

        let not_before = 2_000_000_000; // not active yet per the floor
                                        // has_reached has no local-clock parameter to attack in the first
                                        // place; this just confirms the floor alone correctly says "no."
        assert!(!anchor.has_reached(not_before));
    }

    #[test]
    fn floor_advances_once_the_relay_actually_attests_more_time() {
        let (sk, vk) = keypair_from_seed(0x10);
        let mut anchor = TimeAnchor::new(InMemoryFloorStore::default());
        let b1 = TimeBeacon {
            utc: 1_000_000_000,
            seq: 1,
        };
        anchor
            .ingest_beacon(&b1, &sign_beacon(&b1, &sk), &vk)
            .unwrap();
        assert!(!anchor.has_reached(2_000_000_000));

        let b2 = TimeBeacon {
            utc: 2_000_000_000,
            seq: 2,
        };
        anchor
            .ingest_beacon(&b2, &sign_beacon(&b2, &sk), &vk)
            .unwrap();
        assert!(anchor.has_reached(2_000_000_000));
    }

    #[test]
    fn floor_persists_across_a_simulated_restart() {
        // "Restart" is simulated by moving the store out of one TimeAnchor
        // and into a brand new one — this crate has no file I/O of its own
        // (see FloorStore's doc comment), so this is the strongest
        // persistence guarantee expressible here. A real disk/Keychain-
        // backed FloorStore gets this property for free from whichever
        // ticket wires one in: the store, not TimeAnchor, is what actually
        // touches disk.
        let (sk, vk) = keypair_from_seed(0x10);
        let mut anchor = TimeAnchor::new(InMemoryFloorStore::default());
        let beacon = TimeBeacon {
            utc: 1_700_000_000,
            seq: 7,
        };
        anchor
            .ingest_beacon(&beacon, &sign_beacon(&beacon, &sk), &vk)
            .unwrap();

        let persisted_store = anchor.into_inner();
        let anchor_after_restart = TimeAnchor::new(persisted_store);
        assert_eq!(anchor_after_restart.effective_now(0), 1_700_000_000);
    }

    // --- known-answer vector ---------------------------------------------
    // Pinned from an actual CI run (local cargo test is blocked by Smart
    // App Control on this dev machine).
    #[test]
    fn known_answer_vector() {
        let signing_key = SigningKey::from_bytes(&[0x02; 32]);
        let beacon = TimeBeacon {
            utc: 1_700_000_000,
            seq: 42,
        };
        // Pinned from an actual CI run (local cargo test is blocked by
        // Smart App Control on this dev machine); identical on both OSes.
        // https://github.com/mhamlaoui/ContentFilter/actions/runs/28737155267
        let expected_canonical_hex =
            "436f6e74656e7446696c7465722d54696d65426561636f6e2d763100000000006553f100000000000000002a";
        let expected_signature_hex =
            "b5f737a5960ac3144b1bf372fbdda6d6db4b7bb71ddeb7655349aef46dfbb14\
            a1ad27ef24fc0ae50de409e4d44c493d26973549785e51f8b370f8e0e1e368807";
        let canonical = beacon.canonical_encode();
        let sig = sign_beacon(&beacon, &signing_key);
        assert_eq!(crate::hex::encode(&canonical), expected_canonical_hex);
        assert_eq!(crate::hex::encode(&sig.0), expected_signature_hex);
    }
}
