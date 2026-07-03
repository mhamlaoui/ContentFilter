//! Opaque identifiers. Deliberately 128-bit random values, not sequential
//! integers — a sequential id lets anyone who observes one estimate how
//! many households/devices exist, which is a real leak for software whose
//! entire premise is that enrollment is discreet and consensual.
//!
//! This module intentionally has no `::generate()` constructor. Minting a
//! new id needs a CSPRNG, and pulling in a randomness dependency here would
//! be scope creep for a data-modeling crate — whichever ticket first
//! creates a household or device (e.g. relay-registry-pairing) owns that.

use crate::hex;
use crate::version::ModelError;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! opaque_id_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub fn from_hex(s: &str) -> Result<Self, ModelError> {
                let bytes = hex::decode_exact(s, 16)?;
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(Self(arr))
            }

            pub fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::from_hex(&s).map_err(D::Error::custom)
            }
        }
    };
}

opaque_id_type!(HouseholdId, "Opaque 128-bit household identifier.");
opaque_id_type!(DeviceId, "Opaque 128-bit device identifier.");
opaque_id_type!(
    RequestId,
    "Opaque 128-bit identifier for a single weakening/approval request. \
     Enforced single-use where it matters (svc-approvals) — that \
     bookkeeping lives with whoever tracks request state, not here."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn household_and_device_ids_are_distinct_types() {
        // Landmine: this is a compile-time guarantee (no From/Into between
        // HouseholdId and DeviceId), so mixing them up at a call site is a
        // type error, not a bug that surfaces at runtime. The test below
        // only proves the hex round-trip; the real safeguard is that this
        // file has no `impl From<DeviceId> for HouseholdId` to remove.
        let h = HouseholdId([1u8; 16]);
        let d = DeviceId([1u8; 16]);
        assert_eq!(h.to_hex(), d.to_hex()); // same bytes, still different types
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(HouseholdId::from_hex("ab").is_err());
    }
}
