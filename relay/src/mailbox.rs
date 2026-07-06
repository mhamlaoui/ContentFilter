//! Sealed/signed message routing (relay-approvals-transport). The relay
//! carries ciphertext and signatures only: it can neither mint approvals
//! (verdicts are Ed25519-signed by the partner key it doesn't hold) nor
//! read requests (payloads are sealed to the partner's X25519 key it
//! doesn't hold — there is no private-key type anywhere in its state to
//! even store one).
//!
//! # Mailbox model
//!
//! Per-recipient queues with relay-assigned, strictly-increasing
//! `mailbox_seq`s. Delivery is pull: the recipient fetches messages with
//! `seq > after`, where `after` is a floor the *client* persists — the
//! same shape as feed seqs, and idempotent under lost responses (fetch
//! again with the same floor). Nothing is deleted on fetch; a bounded
//! per-mailbox cap drops the oldest with a warning.
//!
//! # Why mailbox loss is survivable (the log-gap DoD row)
//!
//! The mailbox is *not* the accountability record — the sender's own
//! hash chain (relay-log) is. A device that sends a weakening request
//! (or a partner that issues a verdict) also appends the corresponding
//! event to its chain, which the relay cannot alter without breaking
//! verification. A relay that drops a mailbox message therefore creates
//! a visible discrepancy: the chain attests the message existed; the
//! mailbox never produced it. Detection lives with the auditing side;
//! this module's job is only that routing adds no interpretation and no
//! mutation.
//!
//! # Rate limiting by request hash
//!
//! Sealed requests carry the salted request hash (cf-core
//! `salted_request_hash` — already relay-visible by design, revealing
//! nothing without the household salt). One sealed request per
//! (household, hash) per window: a weak moment producing a flood of
//! identical unblock requests becomes one partner notification, not a
//! pager storm — and the relay still learns nothing about the domain.

use cf_core::{DeviceId, HouseholdId};
use std::collections::{HashMap, VecDeque};

/// Oldest messages drop past this (with a warning) — the chain, not the
/// mailbox, is the durable record.
pub const MAX_MAILBOX_MESSAGES: usize = 1024;

/// Repeat sealed requests with the same salted hash are refused within
/// this window.
pub const REQUEST_HASH_RATE_LIMIT_SECONDS: u64 = 10 * 60;

/// An opaque stored message: the relay assigns `mailbox_seq`; `body` is
/// whatever the HTTP layer serialized (sealed bytes / signed verdict
/// fields) — this store never looks inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub mailbox_seq: u64,
    pub from: DeviceId,
    pub body_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    /// Same (household, request hash) inside the rate-limit window.
    RateLimited { retry_after: u64 },
}

struct Mailbox {
    next_seq: u64,
    messages: VecDeque<StoredMessage>,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            next_seq: 1,
            messages: VecDeque::new(),
        }
    }
}

#[derive(Default)]
pub struct MailboxStore {
    mailboxes: HashMap<(HouseholdId, DeviceId), Mailbox>,
    /// (household, salted request hash) → last accepted send time.
    recent_request_hashes: HashMap<(HouseholdId, [u8; 32]), u64>,
}

impl MailboxStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a message for `(household, recipient)`, assigning its seq.
    /// `request_hash` is `Some` for sealed requests (rate-limited per the
    /// module docs) and `None` for verdicts (a partner answering fast is
    /// never the failure mode being limited).
    pub fn send(
        &mut self,
        household: HouseholdId,
        recipient: DeviceId,
        from: DeviceId,
        body_json: String,
        request_hash: Option<[u8; 32]>,
        now: u64,
    ) -> Result<u64, MailboxError> {
        if let Some(hash) = request_hash {
            self.purge_hashes(now);
            if let Some(last) = self.recent_request_hashes.get(&(household, hash)) {
                let retry_after = last.saturating_add(REQUEST_HASH_RATE_LIMIT_SECONDS);
                if now < retry_after {
                    return Err(MailboxError::RateLimited { retry_after });
                }
            }
            self.recent_request_hashes.insert((household, hash), now);
        }
        let mailbox = self
            .mailboxes
            .entry((household, recipient))
            .or_insert_with(Mailbox::new);
        if mailbox.messages.len() == MAX_MAILBOX_MESSAGES {
            tracing::warn!("mailbox full; dropping the oldest message");
            mailbox.messages.pop_front();
        }
        let seq = mailbox.next_seq;
        mailbox.next_seq += 1;
        mailbox.messages.push_back(StoredMessage {
            mailbox_seq: seq,
            from,
            body_json,
        });
        Ok(seq)
    }

    /// Messages for `(household, recipient)` with `mailbox_seq > after`,
    /// oldest first. Nothing is consumed — the recipient advances its own
    /// floor, and a lost response just means fetching again.
    pub fn fetch(
        &self,
        household: &HouseholdId,
        recipient: &DeviceId,
        after: u64,
    ) -> Vec<StoredMessage> {
        self.mailboxes
            .get(&(*household, *recipient))
            .map(|m| {
                m.messages
                    .iter()
                    .filter(|msg| msg.mailbox_seq > after)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn purge_hashes(&mut self, now: u64) {
        self.recent_request_hashes
            .retain(|_, last| now.saturating_sub(*last) <= REQUEST_HASH_RATE_LIMIT_SECONDS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const HH: HouseholdId = HouseholdId([4u8; 16]);
    const HH_B: HouseholdId = HouseholdId([5u8; 16]);
    const PARTNER: DeviceId = DeviceId([7u8; 16]);
    const MONITORED: DeviceId = DeviceId([2u8; 16]);

    #[test]
    fn messages_are_delivered_in_order_above_the_floor() {
        let mut store = MailboxStore::new();
        for i in 1..=3u64 {
            store
                .send(HH, PARTNER, MONITORED, format!("m{i}"), None, NOW)
                .unwrap();
        }
        let all = store.fetch(&HH, &PARTNER, 0);
        assert_eq!(
            all.iter().map(|m| m.mailbox_seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Refetch with the same floor: idempotent (lost-response safety).
        assert_eq!(store.fetch(&HH, &PARTNER, 0).len(), 3);
        // Floor advanced: only newer.
        let newer = store.fetch(&HH, &PARTNER, 2);
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].body_json, "m3");
    }

    #[test]
    fn mailboxes_are_isolated_by_household_and_recipient() {
        let mut store = MailboxStore::new();
        store
            .send(HH, PARTNER, MONITORED, "for-partner".into(), None, NOW)
            .unwrap();
        assert!(store.fetch(&HH, &MONITORED, 0).is_empty());
        assert!(store.fetch(&HH_B, &PARTNER, 0).is_empty());
    }

    #[test]
    fn repeat_sealed_requests_with_the_same_hash_are_rate_limited() {
        let mut store = MailboxStore::new();
        let hash = [0xAB; 32];
        store
            .send(HH, PARTNER, MONITORED, "r1".into(), Some(hash), NOW)
            .unwrap();

        // Same hash inside the window: refused, with the retry horizon.
        assert_eq!(
            store.send(HH, PARTNER, MONITORED, "r2".into(), Some(hash), NOW + 60),
            Err(MailboxError::RateLimited {
                retry_after: NOW + REQUEST_HASH_RATE_LIMIT_SECONDS
            })
        );

        // A different hash is unaffected; verdicts are never limited.
        store
            .send(
                HH,
                PARTNER,
                MONITORED,
                "r3".into(),
                Some([0xCD; 32]),
                NOW + 60,
            )
            .unwrap();
        store
            .send(HH, MONITORED, PARTNER, "verdict".into(), None, NOW + 61)
            .unwrap();

        // Past the window: accepted again.
        store
            .send(
                HH,
                PARTNER,
                MONITORED,
                "r4".into(),
                Some(hash),
                NOW + REQUEST_HASH_RATE_LIMIT_SECONDS + 1,
            )
            .unwrap();

        // Same hash in a DIFFERENT household: independent.
        let mut fresh = MailboxStore::new();
        fresh
            .send(HH, PARTNER, MONITORED, "a".into(), Some(hash), NOW)
            .unwrap();
        fresh
            .send(HH_B, PARTNER, MONITORED, "b".into(), Some(hash), NOW)
            .unwrap();
    }

    #[test]
    fn a_full_mailbox_drops_the_oldest_but_seqs_never_reuse() {
        let mut store = MailboxStore::new();
        for i in 1..=(MAX_MAILBOX_MESSAGES as u64 + 2) {
            store
                .send(HH, PARTNER, MONITORED, format!("m{i}"), None, NOW)
                .unwrap();
        }
        let msgs = store.fetch(&HH, &PARTNER, 0);
        assert_eq!(msgs.len(), MAX_MAILBOX_MESSAGES);
        // The two oldest are gone; seqs keep climbing (a fetcher's floor
        // stays valid — dropped history is a visible seq jump, not a
        // renumbering).
        assert_eq!(msgs.first().unwrap().mailbox_seq, 3);
        assert_eq!(
            msgs.last().unwrap().mailbox_seq,
            MAX_MAILBOX_MESSAGES as u64 + 2
        );
    }
}
