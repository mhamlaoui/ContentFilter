//! Public-key and signature material. Deliberately contains no private-key
//! type: private keys live in a Secure Enclave / StrongBox+TEE / TPM and are
//! never modeled as serializable data anywhere in this crate. If you find
//! yourself adding one here to make some function's signature convenient,
//! stop — that key material should not exist outside hardware-backed
//! storage or an air-gapped machine (see docs/KEY_CEREMONY.md for the one
//! deliberate exception, which still never touches this crate).

use crate::hex;
use crate::version::ModelError;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! fixed_key_type {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn from_hex(s: &str) -> Result<Self, ModelError> {
                let bytes = hex::decode_exact(s, $len)?;
                let mut arr = [0u8; $len];
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

fixed_key_type!(
    Ed25519PublicKey,
    32,
    "An Ed25519 verify key: device identity keys (relay-auth) and the \
     partner approval key (core-crypto-approvals)."
);
fixed_key_type!(
    X25519PublicKey,
    32,
    "An X25519 public key that unblock requests are sealed to \
     (core-crypto-sealing). Only partner devices have one — see \
     [`crate::device::DeviceRole`]."
);
fixed_key_type!(
    Signature,
    64,
    "A raw Ed25519 signature. This crate carries the bytes; canonical \
     encoding and verification are core-crypto-approvals's job, not this \
     one's."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_key_round_trips_through_hex() {
        let key = Ed25519PublicKey([7u8; 32]);
        assert_eq!(Ed25519PublicKey::from_hex(&key.to_hex()).unwrap(), key);
    }

    #[test]
    fn distinct_key_types_do_not_share_a_hex_length_bypass() {
        // Landmine: this isn't really testable at the type level (that's
        // the point — Ed25519PublicKey and X25519PublicKey are unrelated
        // types with no From/Into between them, so passing one where the
        // other is expected is a compile error, not a runtime bug). This
        // test only pins the byte lengths so nobody "optimizes" the macro
        // into a single shared length constant later.
        assert_eq!(Ed25519PublicKey::LEN, 32);
        assert_eq!(X25519PublicKey::LEN, 32);
        assert_eq!(Signature::LEN, 64);
    }

    #[test]
    fn rejects_truncated_signature() {
        let short = "ab".repeat(63); // 63 bytes of hex, not 64
        assert!(Signature::from_hex(&short).is_err());
    }
}
