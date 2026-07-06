use crate::ids::HouseholdId;
use crate::keys::{Ed25519PublicKey, Signature, X25519PublicKey};
use crate::version::SchemaVersion;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Domain tag for the anchor's canonical signable bytes; versioned inside
/// the signed bytes like every other tag in this crate.
const ANCHOR_DOMAIN_TAG: &[u8] = b"ContentFilter-TrustAnchor-v1\0";

/// Hardened: strong enforcement, but a determined local admin can eventually
/// disable it — the backstop is detection/alerting, not perfect prevention.
/// Locked: opt-in hard lockdown (kernel driver / supervision / device
/// owner). See THREAT_MODEL.md's "Two tiers, two guarantees" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Hardened,
    Locked,
}

/// The signed, server-authoritative record of who can approve or veto a
/// weakening. The canonical encoding and self-attestation verification
/// live here since relay-registry-pairing defined them (an earlier doc
/// comment deferred them to core-crypto-approvals; beside the type is
/// where they belong now that they exist).
///
/// The anchor is **self-attested**: `signature` is by
/// `partner_approval_key` — the key named inside the signed bytes. That
/// proves the partner-key holder authored exactly these fields (their
/// keys, this cooling-off, this tier); it deliberately does *not* prove
/// this is the right partner for any given device — that's pinning, which
/// belongs to svc-config-anchor ("refuses a partner key or cooling-off
/// weaker than the anchor") on the device and to the relay registry's
/// old-key rotation rule on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    pub version: SchemaVersion,
    pub household_id: HouseholdId,
    /// Strictly increases on every rotation (sec-key-recovery). This crate
    /// does not enforce monotonicity — that's a stateful check belonging to
    /// whoever persists anchors (relay-registry-pairing), since it requires
    /// comparing against the previous anchor, not just this one.
    pub seq: u64,
    pub partner_approval_key: Ed25519PublicKey,
    pub partner_seal_key: X25519PublicKey,
    pub cooling_off_seconds: u32,
    pub tier: Tier,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    InvalidKeyMaterial,
    VerificationFailed,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorError::InvalidKeyMaterial => write!(f, "invalid Ed25519 key material"),
            AnchorError::VerificationFailed => write!(f, "anchor signature verification failed"),
        }
    }
}

impl std::error::Error for AnchorError {}

fn tier_byte(tier: Tier) -> u8 {
    match tier {
        Tier::Hardened => 1,
        Tier::Locked => 2,
    }
}

impl TrustAnchor {
    /// The bytes `signature` covers: everything but the signature itself.
    /// All fields are fixed-length, so no length prefixes are needed. The
    /// struct's own `version` is included (as well as the tag's `v1`) so
    /// no field of a stored anchor is outside the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ANCHOR_DOMAIN_TAG.len() + 2 + 16 + 8 + 32 + 32 + 4 + 1);
        buf.extend_from_slice(ANCHOR_DOMAIN_TAG);
        buf.extend_from_slice(&self.version.0.to_be_bytes());
        buf.extend_from_slice(&self.household_id.0);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.partner_approval_key.0);
        buf.extend_from_slice(&self.partner_seal_key.0);
        buf.extend_from_slice(&self.cooling_off_seconds.to_be_bytes());
        buf.push(tier_byte(self.tier));
        buf
    }

    /// Verifies the self-attestation: `signature` over
    /// [`Self::signable_bytes`] against the `partner_approval_key` *inside
    /// this anchor*. See the type docs for exactly what that does and does
    /// not prove.
    pub fn verify_self_signed(&self) -> Result<(), AnchorError> {
        self.verify_signed_by(&self.partner_approval_key)
    }

    /// Verifies `signature` against a caller-supplied key — the rotation
    /// path: a replacement anchor must verify against the *previous*
    /// anchor's partner key, or a thief of nothing but the household id
    /// could swap in their own self-consistent anchor.
    pub fn verify_signed_by(&self, key: &Ed25519PublicKey) -> Result<(), AnchorError> {
        let vk = VerifyingKey::from_bytes(&key.0).map_err(|_| AnchorError::InvalidKeyMaterial)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature.0);
        vk.verify_strict(&self.signable_bytes(), &sig)
            .map_err(|_| AnchorError::VerificationFailed)
    }
}

/// Signs an anchor's signable bytes. Callers build the anchor with a
/// placeholder `signature`, call this, then set the real one — the same
/// pattern as `hashchain::sign_event`.
pub fn sign_anchor(anchor: &TrustAnchor, signing_key: &SigningKey) -> Signature {
    let sig = signing_key.sign(&anchor.signable_bytes());
    Signature(sig.to_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Household {
    pub version: SchemaVersion,
    pub id: HouseholdId,
    pub anchor: TrustAnchor,
    /// Seconds since epoch; bookkeeping only, see [`crate::device::Device::registered_at`].
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_household() -> Household {
        Household {
            version: SchemaVersion::CURRENT,
            id: HouseholdId([4u8; 16]),
            anchor: TrustAnchor {
                version: SchemaVersion::CURRENT,
                household_id: HouseholdId([4u8; 16]),
                seq: 1,
                partner_approval_key: Ed25519PublicKey([5u8; 32]),
                partner_seal_key: X25519PublicKey([6u8; 32]),
                cooling_off_seconds: 24 * 60 * 60,
                tier: Tier::Hardened,
                signature: Signature([7u8; 64]),
            },
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn household_round_trips() {
        let h = sample_household();
        let json = serde_json::to_string(&h).unwrap();
        let back: Household = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn stale_anchor_version_is_rejected() {
        // Landmine: an anchor claiming schema version 0 (or any version
        // that isn't current) must fail SchemaVersion::check, even though
        // every other field deserializes fine. A downgrade attack on the
        // anchor's own schema is still an attack.
        let mut h = sample_household();
        h.anchor.version = SchemaVersion(0);
        assert!(h.anchor.version.check().is_err());
    }

    // --- anchor self-attestation (added by relay-registry-pairing) -------

    fn partner_keys() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
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
            cooling_off_seconds: 24 * 60 * 60,
            tier: Tier::Hardened,
            signature: Signature([0u8; 64]),
        };
        anchor.signature = sign_anchor(&anchor, &sk);
        anchor
    }

    #[test]
    fn a_self_signed_anchor_verifies() {
        assert!(signed_anchor().verify_self_signed().is_ok());
    }

    #[test]
    fn tampering_any_anchor_field_breaks_the_attestation() {
        let anchor = signed_anchor();

        let mut weaker_cooling = anchor.clone();
        weaker_cooling.cooling_off_seconds = 0;
        let mut weaker_tier = anchor.clone();
        weaker_tier.tier = Tier::Locked; // any change, either direction
        let mut swapped_seal = anchor.clone();
        swapped_seal.partner_seal_key = X25519PublicKey([0xEE; 32]);
        let mut bumped_seq = anchor.clone();
        bumped_seq.seq += 1;
        let mut other_household = anchor.clone();
        other_household.household_id = HouseholdId([0xDD; 16]);
        let mut downgraded_version = anchor.clone();
        downgraded_version.version = SchemaVersion(0);

        for tampered in [
            weaker_cooling,
            weaker_tier,
            swapped_seal,
            bumped_seq,
            other_household,
            downgraded_version,
        ] {
            assert_eq!(
                tampered.verify_self_signed(),
                Err(AnchorError::VerificationFailed)
            );
        }
    }

    #[test]
    fn a_swapped_partner_key_cannot_self_attest_with_the_old_signature() {
        // The heart of the self-attestation: the key is *inside* the
        // signed bytes, so replacing it invalidates the signature — an
        // attacker can't graft their key onto an existing signed anchor.
        let mut anchor = signed_anchor();
        let thief_sk = SigningKey::from_bytes(&[0x99; 32]);
        anchor.partner_approval_key = Ed25519PublicKey(thief_sk.verifying_key().to_bytes());
        assert_eq!(
            anchor.verify_self_signed(),
            Err(AnchorError::VerificationFailed)
        );
    }

    #[test]
    fn a_rotation_must_verify_against_the_previous_key() {
        // A thief who knows only the household id can mint a perfectly
        // self-consistent anchor under their own key. verify_self_signed
        // accepts it (as designed); verify_signed_by against the *old*
        // partner key — the registry's rotation rule — is what rejects it.
        let (_, old_vk) = partner_keys();
        let thief_sk = SigningKey::from_bytes(&[0x99; 32]);
        let thief_vk = Ed25519PublicKey(thief_sk.verifying_key().to_bytes());
        let mut stolen = signed_anchor();
        stolen.partner_approval_key = thief_vk;
        stolen.seq += 1;
        stolen.signature = sign_anchor(&stolen, &thief_sk);

        assert!(stolen.verify_self_signed().is_ok());
        assert_eq!(
            stolen.verify_signed_by(&old_vk),
            Err(AnchorError::VerificationFailed)
        );
    }

    #[test]
    fn tier_bytes_are_pinned() {
        // Landmine: these live inside every signed anchor; renumbering
        // would invalidate every anchor ever signed.
        assert_eq!(tier_byte(Tier::Hardened), 1);
        assert_eq!(tier_byte(Tier::Locked), 2);
    }

    #[test]
    fn anchor_known_answer_vector() {
        let (sk, vk) = partner_keys();
        let mut anchor = TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HouseholdId([0x11; 16]),
            seq: 3,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([0x22; 32]),
            cooling_off_seconds: 86_400,
            tier: Tier::Locked,
            signature: Signature([0u8; 64]),
        };
        anchor.signature = sign_anchor(&anchor, &sk);
        // Pinned from an actual CI run (local cargo test is blocked by
        // Smart App Control); identical on both OSes.
        // https://github.com/mhamlaoui/ContentFilter/actions/runs/28770924064
        let expected_signable_hex =
            "436f6e74656e7446696c7465722d5472757374416e63686f722d763100000111\
            11111111111111111111111111111100000000000000032152f8d19b791d2445\
            3242e15f2eab6cb7cffa7b6a5ed30097960e069881db12222222222222222222\
            22222222222222222222222222222222222222222222220001518002";
        let expected_signature_hex =
            "922eb5d6aa2a8885dbc9a8423ae190a84972fdbfabe6eda83fc56377ff77287b\
            47f917e433ab9f9f6f63649a564cf8d9f20f7c1dd1caceb05e2b5bffe3f36d06";
        assert_eq!(
            (
                crate::hex::encode(&anchor.signable_bytes()),
                crate::hex::encode(&anchor.signature.0),
            ),
            (
                expected_signable_hex.to_string(),
                expected_signature_hex.to_string(),
            ),
            "actual values printed above"
        );
    }

    #[test]
    fn unknown_field_on_trust_anchor_is_rejected() {
        let h = sample_household();
        let mut value = serde_json::to_value(&h).unwrap();
        value
            .get_mut("anchor")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra_partner_key".into(), serde_json::json!("00"));
        let result: Result<Household, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "unknown field on TrustAnchor should be rejected"
        );
    }
}
