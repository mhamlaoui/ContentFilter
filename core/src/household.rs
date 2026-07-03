use crate::ids::HouseholdId;
use crate::keys::{Ed25519PublicKey, Signature, X25519PublicKey};
use crate::version::SchemaVersion;
use serde::{Deserialize, Serialize};

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
/// weakening. This crate only carries the bytes and the fields that were
/// signed over; canonical encoding and signature verification belong to
/// core-crypto-approvals, not here (svc-config-anchor:
/// "refuses a partner key or cooling-off weaker than the anchor").
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
