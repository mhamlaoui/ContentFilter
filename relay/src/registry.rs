//! Household registry, trust-anchor authority, and pairing codes
//! (relay-registry-pairing). Pure state machine: no I/O, no clock, no
//! randomness — the HTTP layer supplies `now` and freshly-minted
//! ids/codes, which keeps every rule here deterministic and testable and
//! keeps the CSPRNG in exactly one place.
//!
//! # What "server-authoritative anchor" means here
//!
//! - **Creation is authenticated by the anchor itself.** No device exists
//!   yet to sign a request, so the anchor's self-attestation (signed by
//!   the partner key it names — see `TrustAnchor` in cf-core) is the
//!   authentication: only the partner-key holder can open a household
//!   around that key. Creation registers the first device atomically,
//!   which breaks the chicken-and-egg with relay-auth.
//! - **Replacement requires the previous key.** A stored anchor changes
//!   only if the replacement verifies against the *current* anchor's
//!   partner key AND strictly increases `seq`. A thief can mint a
//!   perfectly self-consistent anchor under their own key; this rule is
//!   what stops it (THREAT_MODEL row 7). The cooling-off-based recovery
//!   path for a *lost* partner key is sec-key-recovery's ticket, layered
//!   on top later — deliberately absent here.
//! - **Serving is read-only.** The anchor goes out exactly as stored,
//!   signature included; nothing a device sends on any other path can
//!   modify it.
//!
//! # Pairing codes
//!
//! Issued only by an authenticated member device of the household,
//! single-use, expiring at a relay-clock deadline. The code is the bearer
//! secret for the join, so redeeming is unauthenticated by design — which
//! is exactly why codes must be CSPRNG-minted, short-lived, and consumed
//! atomically (consume-then-validate would burn a code on a malformed
//! join; validate-then-consume with two lookups would race — here it's
//! one `&mut` critical section, and the whole registry sits behind one
//! lock in the HTTP layer).
//!
//! A joiner's claimed `DeviceRole` is recorded as claimed. That is safe:
//! authority comes from *keys*, not role labels — approving a weakening
//! requires the anchor's `partner_approval_key`, which a mislabeled
//! device does not hold. The label is bookkeeping for humans.

use cf_core::{
    AnchorError, Device, DeviceId, DeviceKeyResolver, DeviceRole, Ed25519PublicKey, HouseholdId,
    Platform, SchemaVersion, TrustAnchor,
};
use std::collections::HashMap;
use std::fmt;

/// Pairing codes die after 15 minutes. Long enough to read a code off one
/// screen and type it into another; short enough that a leaked code is
/// stale before it leaks far.
pub const PAIRING_CODE_TTL_SECONDS: u64 = 15 * 60;

pub const PAIRING_CODE_LEN: usize = 16;

/// An opaque, CSPRNG-minted pairing code. The registry never mints one —
/// the HTTP layer does — but it owns their lifecycle.
pub type PairingCode = [u8; PAIRING_CODE_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The anchor's self-attestation failed (creation) or the replacement
    /// didn't verify against the current partner key (rotation).
    AnchorSignature(AnchorError),
    /// The anchor (or a device record) carries a non-current schema.
    SchemaVersion,
    HouseholdExists,
    UnknownHousehold,
    /// Replacement anchor's household_id doesn't match the household it
    /// was submitted for.
    HouseholdMismatch,
    /// Replacement anchor's seq doesn't strictly increase.
    SeqNotAdvanced {
        current: u64,
        submitted: u64,
    },
    /// Unknown, already-used, or expired pairing code — deliberately one
    /// error: a joiner learns nothing about *why* a code failed.
    InvalidPairingCode,
    /// The relay-minted device id collided (16 random bytes — effectively
    /// unreachable; surfaced rather than silently overwriting a device).
    DeviceIdCollision,
    /// The issuing device isn't a member of the household it's issuing
    /// a code for.
    NotAMember,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::AnchorSignature(e) => write!(f, "anchor signature: {e}"),
            RegistryError::SchemaVersion => write!(f, "unsupported schema version"),
            RegistryError::HouseholdExists => write!(f, "household already exists"),
            RegistryError::UnknownHousehold => write!(f, "household not found"),
            RegistryError::HouseholdMismatch => {
                write!(f, "anchor is for a different household")
            }
            RegistryError::SeqNotAdvanced { current, submitted } => {
                write!(f, "anchor seq {submitted} does not advance {current}")
            }
            RegistryError::InvalidPairingCode => write!(f, "invalid pairing code"),
            RegistryError::DeviceIdCollision => write!(f, "device id collision"),
            RegistryError::NotAMember => write!(f, "device is not a member of this household"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// What a joining (or founding) device supplies about itself. The id is
/// deliberately absent — the relay mints it (see cf-core `ids`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSubmission {
    pub platform: Platform,
    pub role: DeviceRole,
    pub identity_key: Ed25519PublicKey,
}

struct HouseholdRecord {
    anchor: TrustAnchor,
    devices: HashMap<DeviceId, Device>,
}

struct CodeRecord {
    household_id: HouseholdId,
    expires_at: u64,
    consumed: bool,
}

/// In-memory registry. Durability is deliberately out of scope — the
/// relay-deploy ticket owns persistence and data minimization; every rule
/// here is storage-agnostic and this struct is the seam a durable store
/// replaces.
#[derive(Default)]
pub struct Registry {
    households: HashMap<HouseholdId, HouseholdRecord>,
    codes: HashMap<PairingCode, CodeRecord>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a household: verifies the anchor's self-attestation and
    /// schema, then stores the anchor and registers the founding device.
    /// `device_id` and `now` come from the caller (CSPRNG and clock live
    /// in the HTTP layer).
    pub fn create_household(
        &mut self,
        anchor: TrustAnchor,
        founder: DeviceSubmission,
        device_id: DeviceId,
        now: u64,
    ) -> Result<Device, RegistryError> {
        anchor
            .version
            .check()
            .map_err(|_| RegistryError::SchemaVersion)?;
        anchor
            .verify_self_signed()
            .map_err(RegistryError::AnchorSignature)?;
        if self.households.contains_key(&anchor.household_id) {
            return Err(RegistryError::HouseholdExists);
        }
        let household_id = anchor.household_id;
        let mut record = HouseholdRecord {
            anchor,
            devices: HashMap::new(),
        };
        let device = build_device(device_id, household_id, founder, now);
        record.devices.insert(device_id, device.clone());
        self.households.insert(household_id, record);
        Ok(device)
    }

    /// The stored anchor, exactly as stored (signature included) — the
    /// "anchor served signed" DoD row is this plus nothing.
    pub fn anchor(&self, household_id: &HouseholdId) -> Result<&TrustAnchor, RegistryError> {
        self.households
            .get(household_id)
            .map(|r| &r.anchor)
            .ok_or(RegistryError::UnknownHousehold)
    }

    /// Replaces the anchor under the rotation rule: same household,
    /// strictly increasing seq, current schema, and — the part that makes
    /// the anchor server-authoritative rather than last-writer-wins —
    /// a signature that verifies against the *currently stored* anchor's
    /// partner key. Self-consistency under a new key is not enough.
    pub fn replace_anchor(
        &mut self,
        household_id: &HouseholdId,
        replacement: TrustAnchor,
    ) -> Result<(), RegistryError> {
        let record = self
            .households
            .get_mut(household_id)
            .ok_or(RegistryError::UnknownHousehold)?;
        if replacement.household_id != *household_id {
            return Err(RegistryError::HouseholdMismatch);
        }
        replacement
            .version
            .check()
            .map_err(|_| RegistryError::SchemaVersion)?;
        replacement
            .verify_signed_by(&record.anchor.partner_approval_key)
            .map_err(RegistryError::AnchorSignature)?;
        if replacement.seq <= record.anchor.seq {
            return Err(RegistryError::SeqNotAdvanced {
                current: record.anchor.seq,
                submitted: replacement.seq,
            });
        }
        record.anchor = replacement;
        Ok(())
    }

    /// Records a pairing code for a household. Authorization (is `issuer`
    /// a registered member?) is checked here, against registry state; the
    /// HTTP layer has already authenticated *that* the issuer sent this
    /// request (relay-auth).
    pub fn issue_pairing_code(
        &mut self,
        household_id: &HouseholdId,
        issuer: &DeviceId,
        code: PairingCode,
        now: u64,
    ) -> Result<u64, RegistryError> {
        let record = self
            .households
            .get(household_id)
            .ok_or(RegistryError::UnknownHousehold)?;
        if !record.devices.contains_key(issuer) {
            return Err(RegistryError::NotAMember);
        }
        let expires_at = now.saturating_add(PAIRING_CODE_TTL_SECONDS);
        self.codes.insert(
            code,
            CodeRecord {
                household_id: *household_id,
                expires_at,
                consumed: false,
            },
        );
        Ok(expires_at)
    }

    /// Redeems a code: unknown, expired, and already-consumed all collapse
    /// into [`RegistryError::InvalidPairingCode`]. On success the code is
    /// consumed and the joining device registered; the caller gets the
    /// device record and a clone of the anchor to hand back.
    pub fn redeem_pairing_code(
        &mut self,
        code: &PairingCode,
        joiner: DeviceSubmission,
        device_id: DeviceId,
        now: u64,
    ) -> Result<(Device, TrustAnchor), RegistryError> {
        let entry = self
            .codes
            .get_mut(code)
            .ok_or(RegistryError::InvalidPairingCode)?;
        if entry.consumed || now > entry.expires_at {
            return Err(RegistryError::InvalidPairingCode);
        }
        let household_id = entry.household_id;
        let record = self
            .households
            .get_mut(&household_id)
            .ok_or(RegistryError::InvalidPairingCode)?;
        if record.devices.contains_key(&device_id) {
            return Err(RegistryError::DeviceIdCollision);
        }
        // All checks passed — consume and register together, inside the
        // one &mut critical section.
        let device = build_device(device_id, household_id, joiner, now);
        record.devices.insert(device_id, device.clone());
        self.codes
            .get_mut(code)
            .expect("entry existed above")
            .consumed = true;
        Ok((device, record.anchor.clone()))
    }

    /// Membership check for request authorization: relay-auth proves *who*
    /// sent a request; this answers whether that device belongs to the
    /// household it's acting on.
    pub fn is_member(&self, household_id: &HouseholdId, device_id: &DeviceId) -> bool {
        self.households
            .get(household_id)
            .is_some_and(|r| r.devices.contains_key(device_id))
    }

    /// The household a registered device belongs to — the subject lookup
    /// for endpoints where the device itself is the topic (heartbeats).
    pub fn household_of(&self, device_id: &DeviceId) -> Option<HouseholdId> {
        self.households
            .iter()
            .find_map(|(id, r)| r.devices.contains_key(device_id).then_some(*id))
    }
}

/// The registry doubles as relay-auth's key resolver: a device's identity
/// key is exactly what registration recorded.
impl DeviceKeyResolver for Registry {
    fn resolve(&self, device_id: &DeviceId) -> Option<Ed25519PublicKey> {
        self.households
            .values()
            .find_map(|r| r.devices.get(device_id).map(|d| d.identity_key))
    }
}

fn build_device(
    id: DeviceId,
    household_id: HouseholdId,
    submission: DeviceSubmission,
    now: u64,
) -> Device {
    Device {
        version: SchemaVersion::CURRENT,
        id,
        household_id,
        platform: submission.platform,
        role: submission.role,
        identity_key: submission.identity_key,
        registered_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_core::household::sign_anchor;
    use cf_core::{Signature, Tier, X25519PublicKey};
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_700_000_000;
    const HH: HouseholdId = HouseholdId([4u8; 16]);

    fn partner_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn signed_anchor_with(seq: u64, sk: &SigningKey) -> TrustAnchor {
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        let mut anchor = TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HH,
            seq,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: 86_400,
            tier: Tier::Hardened,
            signature: Signature([0u8; 64]),
        };
        anchor.signature = sign_anchor(&anchor, sk);
        anchor
    }

    fn signed_anchor() -> TrustAnchor {
        let (sk, _) = partner_keys();
        signed_anchor_with(1, &sk)
    }

    fn submission(seed: u8) -> DeviceSubmission {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        DeviceSubmission {
            platform: Platform::Windows,
            role: DeviceRole::Monitored,
            identity_key: Ed25519PublicKey(sk.verifying_key().to_bytes()),
        }
    }

    fn founded_registry() -> (Registry, Device) {
        let mut registry = Registry::new();
        let founder = registry
            .create_household(signed_anchor(), submission(0x70), DeviceId([1u8; 16]), NOW)
            .unwrap();
        (registry, founder)
    }

    // --- creation ---------------------------------------------------------

    #[test]
    fn creating_a_household_stores_the_signed_anchor_and_founder() {
        let (registry, founder) = founded_registry();
        let stored = registry.anchor(&HH).unwrap();
        assert_eq!(stored, &signed_anchor(), "served exactly as stored");
        assert!(stored.verify_self_signed().is_ok(), "served signed");
        assert!(registry.is_member(&HH, &founder.id));
        assert_eq!(registry.resolve(&founder.id), Some(founder.identity_key));
    }

    #[test]
    fn an_unsigned_or_tampered_anchor_cannot_open_a_household() {
        let mut registry = Registry::new();
        let mut anchor = signed_anchor();
        anchor.cooling_off_seconds = 0; // tamper after signing
        assert!(matches!(
            registry.create_household(anchor, submission(0x70), DeviceId([1u8; 16]), NOW),
            Err(RegistryError::AnchorSignature(_))
        ));
        assert_eq!(registry.anchor(&HH), Err(RegistryError::UnknownHousehold));
    }

    #[test]
    fn a_duplicate_household_is_rejected() {
        let (mut registry, _) = founded_registry();
        assert_eq!(
            registry.create_household(signed_anchor(), submission(0x71), DeviceId([2u8; 16]), NOW),
            Err(RegistryError::HouseholdExists)
        );
    }

    // --- pairing ------------------------------------------------------------

    const CODE: PairingCode = [0xC0; PAIRING_CODE_LEN];

    #[test]
    fn join_with_a_code_registers_the_device_pubkey() {
        let (mut registry, founder) = founded_registry();
        let expires_at = registry
            .issue_pairing_code(&HH, &founder.id, CODE, NOW)
            .unwrap();
        assert_eq!(expires_at, NOW + PAIRING_CODE_TTL_SECONDS);

        let joiner = submission(0x71);
        let (device, anchor) = registry
            .redeem_pairing_code(&CODE, joiner.clone(), DeviceId([2u8; 16]), NOW + 60)
            .unwrap();
        assert_eq!(device.household_id, HH);
        assert_eq!(device.identity_key, joiner.identity_key);
        assert_eq!(anchor, signed_anchor(), "joiner receives the stored anchor");
        assert_eq!(registry.resolve(&device.id), Some(joiner.identity_key));
    }

    #[test]
    fn expired_unknown_and_reused_codes_are_all_rejected_identically() {
        let (mut registry, founder) = founded_registry();
        registry
            .issue_pairing_code(&HH, &founder.id, CODE, NOW)
            .unwrap();

        // Unknown:
        assert_eq!(
            registry
                .redeem_pairing_code(
                    &[0xFF; PAIRING_CODE_LEN],
                    submission(0x71),
                    DeviceId([2u8; 16]),
                    NOW
                )
                .unwrap_err(),
            RegistryError::InvalidPairingCode
        );
        // Expired (one second past the deadline; the deadline itself works):
        assert_eq!(
            registry
                .redeem_pairing_code(
                    &CODE,
                    submission(0x71),
                    DeviceId([2u8; 16]),
                    NOW + PAIRING_CODE_TTL_SECONDS + 1
                )
                .unwrap_err(),
            RegistryError::InvalidPairingCode
        );
        // (Expiry rejection must not have consumed it — still valid in time:)
        registry
            .redeem_pairing_code(&CODE, submission(0x71), DeviceId([2u8; 16]), NOW + 60)
            .unwrap();
        // Reuse:
        assert_eq!(
            registry
                .redeem_pairing_code(&CODE, submission(0x72), DeviceId([3u8; 16]), NOW + 61)
                .unwrap_err(),
            RegistryError::InvalidPairingCode
        );
    }

    #[test]
    fn only_a_member_device_can_issue_codes() {
        let (mut registry, _) = founded_registry();
        assert_eq!(
            registry.issue_pairing_code(&HH, &DeviceId([0xEE; 16]), CODE, NOW),
            Err(RegistryError::NotAMember)
        );
    }

    // --- the server-authoritative anchor -------------------------------------

    #[test]
    fn the_anchor_is_server_authoritative() {
        // The DoD row. A thief with the household id and their own key
        // mints a fully self-consistent anchor with a higher seq — it
        // verifies as self-signed, and the registry still refuses it,
        // because replacement must verify against the *stored* anchor's
        // partner key. The served anchor is unchanged afterward.
        let (mut registry, _) = founded_registry();
        let thief_sk = SigningKey::from_bytes(&[0x99; 32]);
        let stolen = signed_anchor_with(2, &thief_sk);
        assert!(stolen.verify_self_signed().is_ok());

        assert!(matches!(
            registry.replace_anchor(&HH, stolen),
            Err(RegistryError::AnchorSignature(_))
        ));
        assert_eq!(registry.anchor(&HH).unwrap(), &signed_anchor());
    }

    #[test]
    fn a_legitimate_rotation_by_the_current_key_is_accepted() {
        // The partner re-signs updated fields (here: a longer cooling-off)
        // with the *same* key and a higher seq. sec-key-recovery will add
        // the new-key path; today, same-key updates are the whole surface.
        let (mut registry, _) = founded_registry();
        let (sk, _) = partner_keys();
        let mut updated = signed_anchor_with(2, &sk);
        updated.cooling_off_seconds = 7 * 86_400;
        updated.signature = sign_anchor(&updated, &sk);

        registry.replace_anchor(&HH, updated.clone()).unwrap();
        assert_eq!(registry.anchor(&HH).unwrap(), &updated);
    }

    #[test]
    fn a_replayed_or_stale_seq_rotation_is_rejected() {
        let (mut registry, _) = founded_registry();
        let (sk, _) = partner_keys();
        // Same seq as stored (1): a replay of the original anchor.
        assert_eq!(
            registry.replace_anchor(&HH, signed_anchor_with(1, &sk)),
            Err(RegistryError::SeqNotAdvanced {
                current: 1,
                submitted: 1
            })
        );
    }

    #[test]
    fn a_rotation_for_a_different_household_is_rejected() {
        let (mut registry, _) = founded_registry();
        let (sk, vk) = partner_keys();
        let mut foreign = TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HouseholdId([0xDD; 16]),
            seq: 2,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: 86_400,
            tier: Tier::Hardened,
            signature: Signature([0u8; 64]),
        };
        foreign.signature = sign_anchor(&foreign, &sk);
        assert_eq!(
            registry.replace_anchor(&HH, foreign),
            Err(RegistryError::HouseholdMismatch)
        );
    }
}
