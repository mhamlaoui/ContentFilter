//! Append-only, hash-chained event log (relay-log) — the server side of
//! the transparency log. Relay censorship must leave a detectable hole:
//! the server can refuse to store an event, but it cannot silently drop
//! one it accepted, because every accepted event advances a per-device
//! head that later events must chain onto.
//!
//! # Per-device chains, not one household chain
//!
//! A household's log is a *set of per-device chains*. A single
//! household-wide chain sounds stronger but cannot exist under offline
//! operation: an offline device queues events without knowing what any
//! other device appended meanwhile, so it cannot produce the next
//! `prev_hash` of a shared chain. `prev_hash` chains what the signing
//! device itself emitted — which is also exactly the right integrity
//! unit: "device A's history is complete and unaltered" is what the
//! partner audits per device, and cf-core's `verify_chain` walks one
//! device's stream.
//!
//! # Append rules (the server is stricter than the verifier)
//!
//! cf-core's `verify_chain` accepts any strictly-increasing seqs; this
//! log requires *contiguous* seqs from 1. The client's outbox already
//! guarantees in-order delivery with retained-on-failure semantics, so a
//! gap at the server can only mean lost or withheld history — it is
//! rejected and flagged, never papered over. The outcomes:
//!
//! - `seq == next` + `prev_hash == head` + valid signature → appended.
//! - Bit-identical resend of an accepted event → `Duplicate` (accepted,
//!   idempotent): the outbox re-sends after a lost ack, and that must
//!   not be an error.
//! - Same seq, different bytes → **fork**: one device presenting two
//!   histories. Flagged, rejected.
//! - `seq` ahead of next → **gap**: flagged, rejected; the device must
//!   resend from `next`.
//! - `prev_hash != head` at the right seq → broken link (a client that
//!   lost or rewrote its own state); flagged, rejected.
//!
//! # Retention
//!
//! `prune` drops events below a seq while `head_hash`/`next_seq` stay —
//! the continuity head survives, so appends keep chaining and a
//! truncated prefix is *visible* (`pruned_before`), never silent.
//! Client-side verification of a pruned suffix against a remembered head
//! is follow-up work for the fetching side; the server's own state never
//! loses continuity.
//!
//! In-memory behind this seam, like the registry: every DoD property
//! here is a logic property; durability is relay-deploy's ticket.

use cf_core::hashchain::{event_hash, verify_event_signature, GENESIS_HASH};
use cf_core::{ChainedEvent, DeviceId, DeviceKeyResolver, HouseholdId};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// Bit-identical resend of an already-accepted event.
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// The claimed device has no registered key.
    UnknownDevice,
    InvalidSignature,
    /// seq is ahead of the expected next — missing history.
    SeqGap {
        expected: u64,
        got: u64,
    },
    /// An already-accepted seq resent with different bytes — one device,
    /// two histories.
    Fork {
        seq: u64,
    },
    /// Right seq, wrong prev_hash — the sender's chain state diverged
    /// from what this log accepted.
    BrokenLink {
        seq: u64,
    },
    /// A resend into the pruned region: the original bytes are gone, so
    /// duplicate-vs-fork cannot be proven either way. Rejected without a
    /// fork verdict; retention windows dwarf retry windows in practice.
    SeqPruned {
        seq: u64,
    },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::UnknownDevice => write!(f, "event claims an unregistered device"),
            LogError::InvalidSignature => write!(f, "event signature did not verify"),
            LogError::SeqGap { expected, got } => {
                write!(f, "seq gap: expected {expected}, got {got}")
            }
            LogError::Fork { seq } => write!(f, "fork detected at seq {seq}"),
            LogError::BrokenLink { seq } => write!(f, "prev_hash mismatch at seq {seq}"),
            LogError::SeqPruned { seq } => write!(f, "seq {seq} falls in the pruned region"),
        }
    }
}

impl std::error::Error for LogError {}

struct DeviceChain {
    events: Vec<ChainedEvent>,
    next_seq: u64,
    head_hash: [u8; 32],
    /// First seq still retained; 1 until the first prune.
    pruned_before: u64,
}

impl DeviceChain {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            next_seq: 1,
            head_hash: GENESIS_HASH,
            pruned_before: 1,
        }
    }
}

/// A device chain's readable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLogView {
    pub pruned_before: u64,
    pub next_seq: u64,
    pub events: Vec<ChainedEvent>,
}

#[derive(Default)]
pub struct EventLog {
    households: HashMap<HouseholdId, HashMap<DeviceId, DeviceChain>>,
}

impl EventLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one event to `household`'s log under the rules in the
    /// module docs. Membership (does this device belong to this
    /// household?) is the caller's check — the HTTP layer has the
    /// registry; this module has only keys.
    pub fn append<R: DeviceKeyResolver>(
        &mut self,
        household: HouseholdId,
        event: ChainedEvent,
        resolver: &R,
    ) -> Result<AppendOutcome, LogError> {
        let key = resolver
            .resolve(&event.device_id)
            .ok_or(LogError::UnknownDevice)?;
        if !verify_event_signature(&event, &key) {
            return Err(LogError::InvalidSignature);
        }
        let chain = self
            .households
            .entry(household)
            .or_default()
            .entry(event.device_id)
            .or_insert_with(DeviceChain::new);

        if event.seq < chain.next_seq {
            if event.seq < chain.pruned_before {
                return Err(LogError::SeqPruned { seq: event.seq });
            }
            let existing = chain
                .events
                .iter()
                .find(|e| e.seq == event.seq)
                .expect("retained region is contiguous");
            return if *existing == event {
                Ok(AppendOutcome::Duplicate)
            } else {
                Err(LogError::Fork { seq: event.seq })
            };
        }
        if event.seq > chain.next_seq {
            return Err(LogError::SeqGap {
                expected: chain.next_seq,
                got: event.seq,
            });
        }
        if event.prev_hash != chain.head_hash {
            return Err(LogError::BrokenLink { seq: event.seq });
        }
        chain.head_hash = event_hash(&event);
        chain.next_seq += 1;
        chain.events.push(event);
        Ok(AppendOutcome::Appended)
    }

    /// The retained chain for one device of one household, or `None` if
    /// nothing was ever accepted.
    pub fn device_log(&self, household: &HouseholdId, device: &DeviceId) -> Option<DeviceLogView> {
        let chain = self.households.get(household)?.get(device)?;
        Some(DeviceLogView {
            pruned_before: chain.pruned_before,
            next_seq: chain.next_seq,
            events: chain.events.clone(),
        })
    }

    /// Drops retained events with `seq < keep_from_seq`, returning how
    /// many were dropped. `head_hash` and `next_seq` are untouched — the
    /// continuity head survives pruning, so later appends still chain and
    /// the truncation is visible via `pruned_before`, never silent.
    pub fn prune(
        &mut self,
        household: &HouseholdId,
        device: &DeviceId,
        keep_from_seq: u64,
    ) -> usize {
        let Some(chain) = self
            .households
            .get_mut(household)
            .and_then(|h| h.get_mut(device))
        else {
            return 0;
        };
        let before = chain.events.len();
        chain.events.retain(|e| e.seq >= keep_from_seq);
        chain.pruned_before = chain.pruned_before.max(keep_from_seq.min(chain.next_seq));
        before - chain.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_core::hashchain::{sign_event, verify_chain};
    use cf_core::{Ed25519PublicKey, Signature};
    use ed25519_dalek::SigningKey;

    const HH_A: HouseholdId = HouseholdId([4u8; 16]);
    const HH_B: HouseholdId = HouseholdId([5u8; 16]);
    const DEV: DeviceId = DeviceId([2u8; 16]);

    struct MapResolver(HashMap<[u8; 16], Ed25519PublicKey>);

    impl DeviceKeyResolver for MapResolver {
        fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey> {
            self.0.get(&device_id.0).copied()
        }
    }

    fn device_keys(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn resolver() -> MapResolver {
        let (_, vk) = device_keys(0x20);
        let (_, vk_b) = device_keys(0x30);
        MapResolver(HashMap::from([(DEV.0, vk), (DeviceId([3u8; 16]).0, vk_b)]))
    }

    fn signed_event(
        device: DeviceId,
        seed: u8,
        seq: u64,
        prev_hash: [u8; 32],
        payload: &str,
    ) -> ChainedEvent {
        let (sk, _) = device_keys(seed);
        let mut event = ChainedEvent {
            seq,
            prev_hash,
            device_id: device,
            event_type: "test.event".into(),
            ts: 1_700_000_000 + seq,
            payload: payload.as_bytes().to_vec(),
            sig: Signature([0u8; 64]),
        };
        event.sig = sign_event(&event, &sk);
        event
    }

    /// Appends `n` valid events for DEV into `log` under HH_A, returning
    /// each accepted event.
    fn grow_chain(log: &mut EventLog, n: u64) -> Vec<ChainedEvent> {
        let mut prev = GENESIS_HASH;
        let mut accepted = Vec::new();
        for seq in 1..=n {
            let event = signed_event(DEV, 0x20, seq, prev, &format!("p{seq}"));
            prev = event_hash(&event);
            assert_eq!(
                log.append(HH_A, event.clone(), &resolver()),
                Ok(AppendOutcome::Appended)
            );
            accepted.push(event);
        }
        accepted
    }

    #[test]
    fn accepted_appends_form_a_chain_that_verifies_end_to_end() {
        let mut log = EventLog::new();
        grow_chain(&mut log, 5);
        let view = log.device_log(&HH_A, &DEV).unwrap();
        assert_eq!(view.events.len(), 5);
        assert_eq!(view.pruned_before, 1);
        // The DoD row: what the server accepted verifies as a chain under
        // cf-core's own verifier.
        assert!(verify_chain(&view.events, &resolver()).is_ok());
    }

    #[test]
    fn a_seq_gap_is_flagged_and_rejected() {
        let mut log = EventLog::new();
        let accepted = grow_chain(&mut log, 2);
        // Device skips seq 3 and sends 4 — missing history.
        let gapped = signed_event(DEV, 0x20, 4, event_hash(&accepted[1]), "p4");
        assert_eq!(
            log.append(HH_A, gapped, &resolver()),
            Err(LogError::SeqGap {
                expected: 3,
                got: 4
            })
        );
        // The chain is untouched by the rejected append.
        assert_eq!(log.device_log(&HH_A, &DEV).unwrap().events.len(), 2);
    }

    #[test]
    fn a_fork_is_detected_when_an_accepted_seq_returns_with_different_bytes() {
        let mut log = EventLog::new();
        let accepted = grow_chain(&mut log, 3);
        // Same seq 3, same linkage, different payload: one device, two
        // histories — the censorship/rewrite signal.
        let forged = signed_event(DEV, 0x20, 3, accepted[2].prev_hash, "rewritten");
        assert_eq!(
            log.append(HH_A, forged, &resolver()),
            Err(LogError::Fork { seq: 3 })
        );
    }

    #[test]
    fn a_bit_identical_resend_is_an_idempotent_duplicate() {
        // The outbox re-sends after a lost ack; that must succeed without
        // duplicating history.
        let mut log = EventLog::new();
        let accepted = grow_chain(&mut log, 3);
        assert_eq!(
            log.append(HH_A, accepted[1].clone(), &resolver()),
            Ok(AppendOutcome::Duplicate)
        );
        assert_eq!(log.device_log(&HH_A, &DEV).unwrap().events.len(), 3);
    }

    #[test]
    fn a_broken_link_at_the_right_seq_is_rejected() {
        let mut log = EventLog::new();
        grow_chain(&mut log, 2);
        // Correct next seq, but chained onto a head this log never
        // accepted (a client that rewrote or lost its own state).
        let unlinked = signed_event(DEV, 0x20, 3, [0xAA; 32], "p3");
        assert_eq!(
            log.append(HH_A, unlinked, &resolver()),
            Err(LogError::BrokenLink { seq: 3 })
        );
    }

    #[test]
    fn unknown_devices_and_bad_signatures_are_rejected() {
        let mut log = EventLog::new();
        let stranger = signed_event(DeviceId([9u8; 16]), 0x99, 1, GENESIS_HASH, "p1");
        assert_eq!(
            log.append(HH_A, stranger, &resolver()),
            Err(LogError::UnknownDevice)
        );
        // Registered device, but signed with the wrong key:
        let mut wrong_key = signed_event(DEV, 0x30, 1, GENESIS_HASH, "p1");
        wrong_key.device_id = DEV;
        assert_eq!(
            log.append(HH_A, wrong_key, &resolver()),
            Err(LogError::InvalidSignature)
        );
    }

    #[test]
    fn households_are_isolated() {
        // The same device id appending to two households builds two
        // independent chains; a fork flagged in one leaves the other
        // untouched.
        let mut log = EventLog::new();
        grow_chain(&mut log, 3); // HH_A
        let b1 = signed_event(DEV, 0x20, 1, GENESIS_HASH, "b1");
        assert_eq!(
            log.append(HH_B, b1.clone(), &resolver()),
            Ok(AppendOutcome::Appended)
        );

        let fork_in_b = signed_event(DEV, 0x20, 1, GENESIS_HASH, "b1-rewritten");
        assert_eq!(
            log.append(HH_B, fork_in_b, &resolver()),
            Err(LogError::Fork { seq: 1 })
        );

        assert_eq!(log.device_log(&HH_A, &DEV).unwrap().events.len(), 3);
        assert_eq!(log.device_log(&HH_B, &DEV).unwrap().events.len(), 1);
        assert!(log.device_log(&HH_B, &DeviceId([3u8; 16])).is_none());
    }

    #[test]
    fn prune_keeps_the_continuity_head() {
        let mut log = EventLog::new();
        let accepted = grow_chain(&mut log, 5);

        assert_eq!(log.prune(&HH_A, &DEV, 4), 3, "seqs 1..=3 dropped");
        let view = log.device_log(&HH_A, &DEV).unwrap();
        assert_eq!(view.pruned_before, 4);
        assert_eq!(
            view.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![4, 5]
        );

        // The head survived: the next append still chains and verifies.
        let e6 = signed_event(DEV, 0x20, 6, event_hash(&accepted[4]), "p6");
        assert_eq!(
            log.append(HH_A, e6, &resolver()),
            Ok(AppendOutcome::Appended)
        );

        // A resend into the pruned region is rejected without a fork
        // verdict — the bytes to compare are gone.
        assert_eq!(
            log.append(HH_A, accepted[0].clone(), &resolver()),
            Err(LogError::SeqPruned { seq: 1 })
        );
    }
}
