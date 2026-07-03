use crate::ids::{DeviceId, HouseholdId};
use crate::keys::{Ed25519PublicKey, X25519PublicKey};
use crate::version::SchemaVersion;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Ios,
    Android,
}

/// Whether a device is the one being filtered or the one holding approval
/// authority over it. Modeled as an enum with the seal key attached to
/// `Partner`, not as a separate `Option<X25519PublicKey>` field on
/// [`Device`] — a monitored device having a seal key, or a partner device
/// lacking one, should be a compile error, not a runtime invariant someone
/// has to remember to check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum DeviceRole {
    Monitored,
    /// Can decrypt unblock requests sealed to `seal_key` (core-crypto-sealing)
    /// and, via its `identity_key` on [`Device`], sign approvals
    /// (core-crypto-approvals).
    Partner {
        seal_key: X25519PublicKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub version: SchemaVersion,
    pub id: DeviceId,
    pub household_id: HouseholdId,
    pub platform: Platform,
    pub role: DeviceRole,
    /// Signs every authenticated request this device makes to the relay
    /// (relay-auth). For a `Partner` device this is also the key whose
    /// public half is pinned as `TrustAnchor::partner_approval_key`.
    pub identity_key: Ed25519PublicKey,
    /// Seconds since epoch. Not trusted for security decisions — a
    /// signed, relay-issued time anchor (core-timeanchor) is the trusted
    /// clock; this field is bookkeeping/display only.
    pub registered_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device(role: DeviceRole) -> Device {
        Device {
            version: SchemaVersion::CURRENT,
            id: DeviceId([1u8; 16]),
            household_id: HouseholdId([2u8; 16]),
            platform: Platform::Windows,
            role,
            identity_key: Ed25519PublicKey([3u8; 32]),
            registered_at: 1_700_000_000,
        }
    }

    #[test]
    fn monitored_device_round_trips() {
        let d = sample_device(DeviceRole::Monitored);
        let json = serde_json::to_string(&d).unwrap();
        let back: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn partner_device_round_trips_with_seal_key() {
        let d = sample_device(DeviceRole::Partner {
            seal_key: X25519PublicKey([9u8; 32]),
        });
        let json = serde_json::to_string(&d).unwrap();
        let back: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn unknown_field_is_rejected_not_silently_dropped() {
        // Landmine: proves deny_unknown_fields is still wired up. If
        // someone removes that attribute later to "fix" a deserialization
        // error, this test starts failing instead of the smuggling risk
        // going unnoticed.
        let d = sample_device(DeviceRole::Monitored);
        let mut value: serde_json::Value = serde_json::to_value(&d).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!("payload"));
        let result: Result<Device, _> = serde_json::from_value(value);
        assert!(result.is_err(), "unknown field should be rejected");
    }
}
