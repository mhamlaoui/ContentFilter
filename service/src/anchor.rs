//! Config anchor pinning and validation (`svc-config-anchor`, #40).
//!
//! Security-critical parameters — the partner approval/seal keys, the
//! cooling-off delay, and the tier — come from the **signed** [`TrustAnchor`]
//! (cf-core), never from local operational config. `service.toml`
//! (`ServiceConfig`) *cannot* carry them: it is `deny_unknown_fields`, so an
//! attempt to smuggle a `cooling_off_seconds = 0` in there is a hard parse
//! error, not a silent override. This module owns pinning that anchor at
//! install and detecting tampering afterwards.
//!
//! # There is no design section for this either
//!
//! Like every other ticket that cites the missing design doc (see
//! `CLAUDE.md`; #16/#17/#19/#20/#21/#39), the model here is defined in code:
//!
//! Two files under the service's SYSTEM-only `data_dir` (hardened by
//! `crate::acl`):
//! - `anchor.pin` — the service's **trusted** last-known-good anchor. Written
//!   only by [`AnchorStore::pin`] (install) and by an accepted rotation.
//! - `anchor.json` — the **live** anchor: the copy that a rotation delivery
//!   updates and that an out-of-band editor would touch.
//!
//! On every reconcile the live file is validated against the trusted one and
//! the divergence is classified. The classification rule mirrors the relay
//! registry's (`replace_anchor`): a replacement is authoritative only if it
//! **verifies against the currently-pinned partner key and strictly advances
//! `seq`** — self-consistency under a new key is not enough. Tamper detection
//! is the anchor *signature* itself (it covers every field), so no separate
//! fingerprint is stored.
//!
//! # Outcomes
//!
//! - identical live == trusted → clean.
//! - live is a valid signed rotation → promote it to trusted (managed
//!   update, no alert).
//! - live carries a foreign partner key that doesn't chain to the pin, or is
//!   missing/corrupt → **[`EventKind::AnchorMismatch`]**; the live file is
//!   restored from trusted and enforcement stays on the pinned params.
//! - live keeps the pinned partner key but its signature no longer verifies
//!   (fields edited out-of-band) → **[`EventKind::ConfigChanged`]**
//!   `{ control: "trust_anchor" }`; restored + pinned params kept.
//!
//! The refuse-and-fall-back-to-pinned behaviour is what satisfies "refuses a
//! partner key or cooling-off weaker than the anchor": a weaker candidate is
//! never a valid rotation, so the effective params never drop below the pin.
//! [`weaker_than`] names *why* for the log.
//!
//! # Rejected alternatives
//!
//! - **Store only a fingerprint of the pinned anchor.** Then a detected
//!   tamper couldn't be *self-healed* — the service would know the live file
//!   is wrong but not what the right bytes were. Storing the full trusted
//!   anchor lets it restore the managed value, matching the "revert after an
//!   unmanaged change" behaviour the `TamperDetected`/`ConfigChanged` events
//!   were defined for.
//! - **Trust the relay to have validated rotations and accept whatever it
//!   serves.** The device pins independently; a compromised or MITM'd fetch
//!   must not be able to install a foreign anchor. The relay's own
//!   `replace_anchor` check is defence in depth, not a substitute.
//! - **Let a signed rotation be refused for lowering cooling-off.** A
//!   rotation signed by the partner key is authoritative in either direction
//!   — the partner may legitimately shorten the wait. The weaker-than guard
//!   applies to *unauthenticated* candidates (swaps/edits), which is exactly
//!   what fails the rotation check.

use std::fmt;
use std::path::{Path, PathBuf};

use cf_core::household::Tier;
use cf_core::{AnchorError, DeviceId, EventKind, NotificationEvent, SchemaVersion, TrustAnchor};

const TRUSTED_FILE: &str = "anchor.pin";
const LIVE_FILE: &str = "anchor.json";
/// `EventKind::ConfigChanged.control` value for an out-of-band anchor edit.
pub const ANCHOR_CONTROL_LABEL: &str = "trust_anchor";

#[derive(Debug)]
pub enum AnchorStoreError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    /// No trusted anchor is pinned (the service was never `pin`ned).
    NotPinned,
    /// The anchor offered at install failed its self-attestation.
    Verification(AnchorError),
    /// The anchor offered at install carries a non-current schema.
    StaleSchema,
}

impl fmt::Display for AnchorStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorStoreError::Io(e) => write!(f, "anchor store IO error: {e}"),
            AnchorStoreError::Parse(e) => write!(f, "anchor parse error: {e}"),
            AnchorStoreError::NotPinned => write!(f, "no trust anchor is pinned"),
            AnchorStoreError::Verification(e) => write!(f, "anchor verification failed: {e}"),
            AnchorStoreError::StaleSchema => write!(f, "anchor carries a non-current schema"),
        }
    }
}

impl std::error::Error for AnchorStoreError {}

/// Why a candidate anchor is weaker than the pinned one. Directly answers the
/// DoD's "refuses a partner key or cooling-off weaker than the anchor".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeakerReason {
    /// A shorter cooling-off delay than pinned (less protection of the weak
    /// moment).
    CoolingOff { pinned: u32, candidate: u32 },
    /// A lower enforcement tier than pinned (Hardened below Locked).
    Tier { pinned: Tier, candidate: Tier },
    /// A different partner approval key — a foreign anchor, not the pinned
    /// partner's.
    ForeignPartnerKey,
}

/// How a live anchor relates to the trusted (pinned) one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateVerdict {
    /// Byte-identical to the trusted anchor.
    Unchanged,
    /// Verifies against the pinned partner key and strictly advances `seq` —
    /// an authoritative rotation.
    ValidRotation,
    /// Same partner key, but the signature no longer verifies (fields edited
    /// out of band) or `seq` did not advance.
    Edited,
    /// A foreign partner key that does not chain to the pin, wrong household,
    /// or stale schema — a swap.
    Mismatch,
}

/// The result of a reconcile: which anchor to enforce, and any events the
/// caller should record/emit to the accountability log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub anchor: TrustAnchor,
    pub events: Vec<NotificationEvent>,
}

fn tier_rank(tier: Tier) -> u8 {
    match tier {
        Tier::Hardened => 0,
        Tier::Locked => 1,
    }
}

/// Names the way `candidate` is weaker than `trusted`, or `None` if it is at
/// least as strong. Used both to justify a refusal in the log and as a
/// standalone guard.
pub fn weaker_than(trusted: &TrustAnchor, candidate: &TrustAnchor) -> Option<WeakerReason> {
    if candidate.partner_approval_key != trusted.partner_approval_key {
        return Some(WeakerReason::ForeignPartnerKey);
    }
    if candidate.cooling_off_seconds < trusted.cooling_off_seconds {
        return Some(WeakerReason::CoolingOff {
            pinned: trusted.cooling_off_seconds,
            candidate: candidate.cooling_off_seconds,
        });
    }
    if tier_rank(candidate.tier) < tier_rank(trusted.tier) {
        return Some(WeakerReason::Tier {
            pinned: trusted.tier,
            candidate: candidate.tier,
        });
    }
    None
}

/// Classifies a live anchor against the trusted (pinned) one. Pure: all the
/// I/O-free security logic lives here so it can be exhaustively tested.
///
/// Mirrors the relay registry's `replace_anchor`: a replacement is
/// authoritative only if it verifies against the pinned partner key and
/// strictly advances `seq`.
pub fn classify(trusted: &TrustAnchor, live: &TrustAnchor) -> CandidateVerdict {
    if live == trusted {
        return CandidateVerdict::Unchanged;
    }
    // A non-current schema is never acceptable, whoever signed it.
    if live.version.check().is_err() {
        return CandidateVerdict::Mismatch;
    }
    // The anchor is household-scoped; a different household is a swap.
    if live.household_id != trusted.household_id {
        return CandidateVerdict::Mismatch;
    }
    // The registry rule: verifies against the *pinned* key and advances seq.
    // Covers both a same-key re-issue and a key rotation (new key inside,
    // signed by the old key) — both verify against `trusted`'s key.
    if live.seq > trusted.seq && live.verify_signed_by(&trusted.partner_approval_key).is_ok() {
        return CandidateVerdict::ValidRotation;
    }
    // Not a valid forward rotation. Distinguish an out-of-band edit (pinned
    // key kept, signature broken or seq stalled) from a foreign-key swap.
    if live.partner_approval_key == trusted.partner_approval_key {
        CandidateVerdict::Edited
    } else {
        CandidateVerdict::Mismatch
    }
}

/// Pins and validates the on-device trust anchor. Cross-platform; the
/// Windows-only ACL hardening of `data_dir` is `crate::acl`'s job.
pub struct AnchorStore {
    data_dir: PathBuf,
}

impl AnchorStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    fn trusted_path(&self) -> PathBuf {
        self.data_dir.join(TRUSTED_FILE)
    }

    fn live_path(&self) -> PathBuf {
        self.data_dir.join(LIVE_FILE)
    }

    /// Whether an anchor has been pinned (install has run).
    pub fn is_pinned(&self) -> bool {
        self.trusted_path().exists()
    }

    /// Pins `anchor` as the trust root (install). Rejects an anchor that does
    /// not self-attest or carries a stale schema — a bogus anchor must never
    /// become the root the whole weakening machinery trusts.
    pub fn pin(&self, anchor: &TrustAnchor) -> Result<(), AnchorStoreError> {
        anchor
            .version
            .check()
            .map_err(|_| AnchorStoreError::StaleSchema)?;
        anchor
            .verify_self_signed()
            .map_err(AnchorStoreError::Verification)?;
        std::fs::create_dir_all(&self.data_dir).map_err(AnchorStoreError::Io)?;
        self.write_anchor(&self.trusted_path(), anchor)?;
        self.write_anchor(&self.live_path(), anchor)?;
        Ok(())
    }

    /// The trusted (pinned) anchor — the authoritative source of enforcement
    /// params. Read-only; does not touch the live file.
    pub fn load_trusted(&self) -> Result<TrustAnchor, AnchorStoreError> {
        if !self.trusted_path().exists() {
            return Err(AnchorStoreError::NotPinned);
        }
        self.read_anchor(&self.trusted_path())
    }

    /// Validates the live anchor against the pin, self-heals any tamper, and
    /// returns the anchor to enforce plus any events to record.
    ///
    /// `now` stamps emitted events; `device_id` is the enforcing device's id
    /// (from enrollment). No event is emitted for a clean load or a valid
    /// rotation.
    pub fn reconcile(
        &self,
        now: u64,
        device_id: DeviceId,
    ) -> Result<ReloadOutcome, AnchorStoreError> {
        let trusted = self.load_trusted()?;

        let live = match self.read_anchor(&self.live_path()) {
            Ok(live) => live,
            Err(_) => {
                // Missing or unparseable live file = tamper. Restore it and
                // alert; enforcement continues on the pinned anchor.
                self.write_anchor(&self.live_path(), &trusted)?;
                let event = self.event(&trusted, device_id, now, EventKind::AnchorMismatch);
                return Ok(ReloadOutcome {
                    anchor: trusted,
                    events: vec![event],
                });
            }
        };

        match classify(&trusted, &live) {
            CandidateVerdict::Unchanged => Ok(ReloadOutcome {
                anchor: trusted,
                events: vec![],
            }),
            CandidateVerdict::ValidRotation => {
                // Promote: the partner-authoritative rotation becomes trusted.
                self.write_anchor(&self.trusted_path(), &live)?;
                Ok(ReloadOutcome {
                    anchor: live,
                    events: vec![],
                })
            }
            CandidateVerdict::Edited => {
                self.write_anchor(&self.live_path(), &trusted)?;
                let event = self.event(
                    &trusted,
                    device_id,
                    now,
                    EventKind::ConfigChanged {
                        control: ANCHOR_CONTROL_LABEL.to_string(),
                    },
                );
                Ok(ReloadOutcome {
                    anchor: trusted,
                    events: vec![event],
                })
            }
            CandidateVerdict::Mismatch => {
                self.write_anchor(&self.live_path(), &trusted)?;
                let event = self.event(&trusted, device_id, now, EventKind::AnchorMismatch);
                Ok(ReloadOutcome {
                    anchor: trusted,
                    events: vec![event],
                })
            }
        }
    }

    fn event(
        &self,
        anchor: &TrustAnchor,
        device_id: DeviceId,
        now: u64,
        kind: EventKind,
    ) -> NotificationEvent {
        NotificationEvent {
            version: SchemaVersion::CURRENT,
            household_id: anchor.household_id,
            device_id,
            occurred_at: now,
            kind,
        }
    }

    fn write_anchor(&self, path: &Path, anchor: &TrustAnchor) -> Result<(), AnchorStoreError> {
        let json = serde_json::to_string_pretty(anchor).map_err(AnchorStoreError::Parse)?;
        std::fs::write(path, json).map_err(AnchorStoreError::Io)
    }

    fn read_anchor(&self, path: &Path) -> Result<TrustAnchor, AnchorStoreError> {
        let text = std::fs::read_to_string(path).map_err(AnchorStoreError::Io)?;
        serde_json::from_str(&text).map_err(AnchorStoreError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_core::household::sign_anchor;
    use cf_core::{Ed25519PublicKey, HouseholdId, Signature, X25519PublicKey};
    use ed25519_dalek::SigningKey;

    const HH: HouseholdId = HouseholdId([4u8; 16]);
    const DEV: DeviceId = DeviceId([2u8; 16]);

    fn key(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    /// A self-attested anchor (signature by the partner key it names).
    fn self_signed(
        partner_seed: u8,
        seq: u64,
        cooling: u32,
        tier: Tier,
    ) -> (TrustAnchor, SigningKey) {
        let (sk, vk) = key(partner_seed);
        let mut anchor = TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HH,
            seq,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: cooling,
            tier,
            signature: Signature([0u8; 64]),
        };
        anchor.signature = sign_anchor(&anchor, &sk);
        (anchor, sk)
    }

    fn store() -> (tempfile::TempDir, AnchorStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = AnchorStore::new(dir.path());
        (dir, store)
    }

    // --- pin (install) --------------------------------------------------

    #[test]
    fn pinning_a_self_signed_anchor_persists_it_and_is_reported_pinned() {
        let (anchor, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        assert!(!store.is_pinned());
        store.pin(&anchor).unwrap();
        assert!(store.is_pinned());
        assert_eq!(store.load_trusted().unwrap(), anchor);
    }

    #[test]
    fn pinning_an_unsigned_anchor_is_refused() {
        // Landmine: a bogus anchor must never become the trust root.
        let (mut anchor, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        anchor.signature = Signature([0xFF; 64]);
        let (_dir, store) = store();
        assert!(matches!(
            store.pin(&anchor),
            Err(AnchorStoreError::Verification(_))
        ));
        assert!(!store.is_pinned());
    }

    #[test]
    fn pinning_a_stale_schema_anchor_is_refused() {
        let (mut anchor, sk) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        anchor.version = SchemaVersion(0);
        anchor.signature = sign_anchor(&anchor, &sk); // validly signed, wrong schema
        let (_dir, store) = store();
        assert!(matches!(
            store.pin(&anchor),
            Err(AnchorStoreError::StaleSchema)
        ));
    }

    // --- classify (pure) ------------------------------------------------

    #[test]
    fn an_untouched_live_anchor_is_unchanged() {
        let (anchor, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        assert_eq!(classify(&anchor, &anchor), CandidateVerdict::Unchanged);
    }

    #[test]
    fn a_same_key_reissue_with_higher_seq_is_a_valid_rotation() {
        let (pinned, sk) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        // Same partner key, seq advanced, re-signed by that key.
        let mut next = pinned.clone();
        next.seq = 2;
        next.cooling_off_seconds = 12 * 3600; // partner may change it
        next.signature = sign_anchor(&next, &sk);
        assert_eq!(classify(&pinned, &next), CandidateVerdict::ValidRotation);
    }

    #[test]
    fn a_key_rotation_signed_by_the_old_key_is_valid_then_chains_to_the_new_key() {
        let (pinned, old_sk) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_new_sk, new_vk) = key(0x22);
        // New key inside, signed by the OLD key, seq advanced.
        let mut rotated = pinned.clone();
        rotated.seq = 2;
        rotated.partner_approval_key = new_vk;
        rotated.signature = sign_anchor(&rotated, &old_sk);
        assert_eq!(classify(&pinned, &rotated), CandidateVerdict::ValidRotation);

        // After promotion, the next rotation must chain to the NEW key. An
        // attacker who still holds the OLD key tries to push a further
        // rotation to a key of their own; signed by the old key, it no longer
        // verifies against the new pinned key — a swap.
        let (_, thief_vk) = key(0x33);
        let mut forged = rotated.clone();
        forged.seq = 3;
        forged.partner_approval_key = thief_vk;
        forged.signature = sign_anchor(&forged, &old_sk);
        assert_eq!(classify(&rotated, &forged), CandidateVerdict::Mismatch);
    }

    #[test]
    fn a_foreign_self_signed_anchor_is_a_mismatch() {
        // A thief mints a self-consistent anchor under their own key. It
        // self-verifies (as designed) but does not chain to the pin.
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (thief, _) = self_signed(0x99, 2, 0, Tier::Hardened);
        assert_eq!(classify(&pinned, &thief), CandidateVerdict::Mismatch);
    }

    #[test]
    fn an_edited_same_key_anchor_that_breaks_the_signature_is_edited() {
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        // Someone weakens cooling-off in place without the key — signature
        // no longer verifies, partner key field unchanged.
        let mut edited = pinned.clone();
        edited.cooling_off_seconds = 0;
        assert_eq!(classify(&pinned, &edited), CandidateVerdict::Edited);
    }

    #[test]
    fn a_non_advancing_seq_is_not_a_rotation() {
        let (pinned, sk) = self_signed(0x11, 2, 86_400, Tier::Hardened);
        // Same key, validly signed, but seq goes backwards — a downgrade.
        let mut older = pinned.clone();
        older.seq = 1;
        older.signature = sign_anchor(&older, &sk);
        // Same key, so it's classified as an edit (refused), never a rotation.
        assert_eq!(classify(&pinned, &older), CandidateVerdict::Edited);
    }

    // --- weaker_than ----------------------------------------------------

    #[test]
    fn weaker_than_names_each_weakening() {
        let (pinned, sk) = self_signed(0x11, 1, 86_400, Tier::Locked);

        let mut shorter = pinned.clone();
        shorter.cooling_off_seconds = 3600;
        shorter.signature = sign_anchor(&shorter, &sk);
        assert!(matches!(
            weaker_than(&pinned, &shorter),
            Some(WeakerReason::CoolingOff { .. })
        ));

        let mut lower_tier = pinned.clone();
        lower_tier.tier = Tier::Hardened;
        lower_tier.signature = sign_anchor(&lower_tier, &sk);
        assert!(matches!(
            weaker_than(&pinned, &lower_tier),
            Some(WeakerReason::Tier { .. })
        ));

        let (foreign, _) = self_signed(0x99, 1, 86_400, Tier::Locked);
        assert_eq!(
            weaker_than(&pinned, &foreign),
            Some(WeakerReason::ForeignPartnerKey)
        );

        // A stronger (longer cooling-off) candidate is not weaker.
        let mut longer = pinned.clone();
        longer.cooling_off_seconds = 90_000;
        longer.signature = sign_anchor(&longer, &sk);
        assert_eq!(weaker_than(&pinned, &longer), None);
    }

    // --- reconcile (I/O + events + self-heal) ---------------------------

    fn corrupt_live(store: &AnchorStore, replacement: &TrustAnchor) {
        std::fs::write(
            store.live_path(),
            serde_json::to_string_pretty(replacement).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn reconcile_is_silent_and_authoritative_when_untouched() {
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        store.pin(&pinned).unwrap();
        let outcome = store.reconcile(1_700_000_000, DEV).unwrap();
        assert_eq!(outcome.anchor, pinned);
        assert!(outcome.events.is_empty());
    }

    #[test]
    fn reconcile_refuses_a_weaker_swap_keeps_pinned_params_and_alerts() {
        // The DoD: a swapped anchor with cooling_off = 0 must NOT weaken
        // enforcement. Effective cooling-off stays at the pinned 86400 and an
        // AnchorMismatch is recorded.
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        store.pin(&pinned).unwrap();

        let (thief, _) = self_signed(0x99, 5, 0, Tier::Hardened);
        assert_eq!(
            weaker_than(&pinned, &thief),
            Some(WeakerReason::ForeignPartnerKey)
        );
        corrupt_live(&store, &thief);

        let outcome = store.reconcile(1_700_000_000, DEV).unwrap();
        assert_eq!(outcome.anchor.cooling_off_seconds, 86_400);
        assert_eq!(
            outcome.anchor.partner_approval_key,
            pinned.partner_approval_key
        );
        assert_eq!(outcome.events.len(), 1);
        assert!(matches!(outcome.events[0].kind, EventKind::AnchorMismatch));
        // Self-healed: the live file is restored to the trusted anchor.
        assert_eq!(store.read_anchor(&store.live_path()).unwrap(), pinned);
    }

    #[test]
    fn reconcile_flags_an_out_of_band_edit_as_config_changed() {
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        store.pin(&pinned).unwrap();

        // Same partner key, cooling-off hand-edited (signature now broken).
        let mut edited = pinned.clone();
        edited.cooling_off_seconds = 0;
        corrupt_live(&store, &edited);

        let outcome = store.reconcile(1_700_000_000, DEV).unwrap();
        assert_eq!(outcome.anchor.cooling_off_seconds, 86_400);
        assert_eq!(outcome.events.len(), 1);
        match &outcome.events[0].kind {
            EventKind::ConfigChanged { control } => assert_eq!(control, ANCHOR_CONTROL_LABEL),
            other => panic!("expected ConfigChanged, got {other:?}"),
        }
        assert_eq!(store.read_anchor(&store.live_path()).unwrap(), pinned);
    }

    #[test]
    fn reconcile_promotes_a_valid_rotation_without_alerting() {
        let (pinned, sk) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        store.pin(&pinned).unwrap();

        let mut rotated = pinned.clone();
        rotated.seq = 2;
        rotated.cooling_off_seconds = 48 * 3600;
        rotated.signature = sign_anchor(&rotated, &sk);
        corrupt_live(&store, &rotated);

        let outcome = store.reconcile(1_700_000_000, DEV).unwrap();
        assert_eq!(outcome.anchor, rotated);
        assert!(outcome.events.is_empty());
        // The rotation is now the trusted anchor (promoted).
        assert_eq!(store.load_trusted().unwrap(), rotated);
    }

    #[test]
    fn reconcile_treats_a_missing_live_file_as_tamper() {
        let (pinned, _) = self_signed(0x11, 1, 86_400, Tier::Hardened);
        let (_dir, store) = store();
        store.pin(&pinned).unwrap();
        std::fs::remove_file(store.live_path()).unwrap();

        let outcome = store.reconcile(1_700_000_000, DEV).unwrap();
        assert_eq!(outcome.anchor, pinned);
        assert!(matches!(outcome.events[0].kind, EventKind::AnchorMismatch));
        // Restored.
        assert_eq!(store.read_anchor(&store.live_path()).unwrap(), pinned);
    }

    #[test]
    fn reconcile_without_a_pin_is_not_pinned() {
        let (_dir, store) = store();
        assert!(matches!(
            store.reconcile(1, DEV),
            Err(AnchorStoreError::NotPinned)
        ));
    }
}
