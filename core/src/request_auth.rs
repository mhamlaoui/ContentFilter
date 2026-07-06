//! Canonical signed-request statement for relay authentication
//! (relay-auth). Every mutating relay request is signed by the sending
//! device's identity key; this module owns the *shape* — what bytes get
//! signed — because every platform (Windows service, iOS/Android via
//! UniFFI) must produce it and the relay must verify it. The stateful half
//! (device registry lookup, timestamp window, nonce replay guard) lives in
//! `cf-relay`'s `auth` module, next to the state it needs.
//!
//! What's inside the signed bytes, and why:
//!
//! - `device_id` — binds the claim of *who* is asking into the signature,
//!   so the relay looks up exactly the claimed device's key and a
//!   signature can never be re-attributed.
//! - `method` + `path` — binds the request to one endpoint. Without this,
//!   a captured signed "POST /events" would replay cleanly against any
//!   other mutating route. The relay compares these against its own
//!   routing context, not the other way around.
//! - `sha256(body)` — binds the payload without embedding it (bodies can
//!   be large; the hash keeps the signed statement small and lets the
//!   relay verify streamed bodies after the fact). The relay MUST
//!   recompute the hash over the body it actually received.
//! - `ts` + `nonce` — the replay guard's inputs. Both are signed, so a
//!   replayer cannot refresh the timestamp or change the nonce without
//!   breaking the signature — which is precisely what makes the relay's
//!   sliding-window bookkeeping sound.
//!
//! Deliberately **no** `household_id`: the relay's device registry
//! (relay-registry-pairing) is authoritative for membership, and a signed
//! household claim would only create a second source of truth to get out
//! of sync with it.
//!
//! No serde on [`AuthStatement`]: how the statement rides an HTTP request
//! (headers vs body framing) is relay-registry-pairing's wire decision,
//! same reasoning as `relay_client::ApprovalMessage`.

use crate::ids::DeviceId;
use crate::keys::{Ed25519PublicKey, Signature as CfSignature};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Bumped alongside the schema; inside the signed bytes so an old-format
/// signature structurally cannot verify against a new-format encoding.
const DOMAIN_TAG: &[u8] = b"ContentFilter-RelayAuth-v1\0";

const MAX_FIELD_LEN: usize = 255;
pub const REQUEST_NONCE_LEN: usize = 24;

/// Hashes a request body for [`AuthStatement::body_sha256`]. Both sides
/// use this: the device before signing, the relay over the body it
/// actually received.
pub fn body_sha256(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStatement {
    pub device_id: DeviceId,
    pub method: String,
    pub path: String,
    pub body_sha256: [u8; 32],
    /// Seconds since epoch by the *device's* clock; the relay judges it
    /// against its own clock within a skew window. Signed, so a replay
    /// cannot refresh it.
    pub ts: u64,
    pub nonce: [u8; REQUEST_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAuthError {
    EmptyField(&'static str),
    FieldTooLong {
        field: &'static str,
        max: usize,
        found: usize,
    },
    InvalidKeyMaterial,
    VerificationFailed,
}

impl fmt::Display for RequestAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestAuthError::EmptyField(field) => write!(f, "{field} must not be empty"),
            RequestAuthError::FieldTooLong { field, max, found } => {
                write!(f, "{field} is {found} bytes, max is {max}")
            }
            RequestAuthError::InvalidKeyMaterial => write!(f, "invalid Ed25519 key material"),
            RequestAuthError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for RequestAuthError {}

impl AuthStatement {
    pub fn new(
        device_id: DeviceId,
        method: impl Into<String>,
        path: impl Into<String>,
        body_sha256: [u8; 32],
        ts: u64,
        nonce: [u8; REQUEST_NONCE_LEN],
    ) -> Result<Self, RequestAuthError> {
        let statement = Self {
            device_id,
            method: method.into(),
            path: path.into(),
            body_sha256,
            ts,
            nonce,
        };
        statement.validate()?;
        Ok(statement)
    }

    fn validate(&self) -> Result<(), RequestAuthError> {
        Self::validate_field("method", &self.method)?;
        Self::validate_field("path", &self.path)?;
        Ok(())
    }

    fn validate_field(name: &'static str, s: &str) -> Result<(), RequestAuthError> {
        if s.is_empty() {
            return Err(RequestAuthError::EmptyField(name));
        }
        if s.len() > MAX_FIELD_LEN {
            return Err(RequestAuthError::FieldTooLong {
                field: name,
                max: MAX_FIELD_LEN,
                found: s.len(),
            });
        }
        Ok(())
    }

    /// The exact bytes that get signed. Fixed field order, length-prefixed
    /// variable-length fields, domain-separated — and re-validated here at
    /// the point of cryptographic consequence, never trusting that the
    /// caller went through [`AuthStatement::new`]. Same construction and
    /// same reasoning as `ApprovalStatement::canonical_encode`.
    pub fn canonical_encode(&self) -> Result<Vec<u8>, RequestAuthError> {
        self.validate()?;
        let mut buf = Vec::with_capacity(
            DOMAIN_TAG.len()
                + 16
                + 2
                + self.method.len()
                + 2
                + self.path.len()
                + 32
                + 8
                + REQUEST_NONCE_LEN,
        );
        buf.extend_from_slice(DOMAIN_TAG);
        buf.extend_from_slice(&self.device_id.0);
        write_length_prefixed(&mut buf, self.method.as_bytes());
        write_length_prefixed(&mut buf, self.path.as_bytes());
        buf.extend_from_slice(&self.body_sha256);
        buf.extend_from_slice(&self.ts.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        Ok(buf)
    }
}

fn write_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    // bytes.len() <= MAX_FIELD_LEN (255): validate() always runs first, so
    // this cast never truncates.
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Signs `statement` with the device's identity key. Deterministic — no
/// RNG involved; the *nonce* inside the statement is the caller's to mint
/// from a platform CSPRNG (this crate deliberately has none outside
/// sealing).
pub fn sign(
    statement: &AuthStatement,
    signing_key: &SigningKey,
) -> Result<CfSignature, RequestAuthError> {
    let bytes = statement.canonical_encode()?;
    let sig = signing_key.sign(&bytes);
    Ok(CfSignature(sig.to_bytes()))
}

/// Verifies `signature` over `statement` against the claimed device's
/// verify key. `verify_strict`, as everywhere in this crate — the relay's
/// replay cache is keyed on nonces, but signature bytes must still never
/// be malleable-equivalent.
pub fn verify(
    statement: &AuthStatement,
    signature: &CfSignature,
    verify_key: &Ed25519PublicKey,
) -> Result<(), RequestAuthError> {
    let bytes = statement.canonical_encode()?;
    let vk = VerifyingKey::from_bytes(&verify_key.0)
        .map_err(|_| RequestAuthError::InvalidKeyMaterial)?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| RequestAuthError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair_from_seed(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, Ed25519PublicKey(verifying_key.to_bytes()))
    }

    fn sample_statement() -> AuthStatement {
        AuthStatement::new(
            DeviceId([2u8; 16]),
            "POST",
            "/v1/events",
            body_sha256(b"{\"seq\":1}"),
            1_700_000_000,
            [7u8; REQUEST_NONCE_LEN],
        )
        .unwrap()
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, vk) = keypair_from_seed(0x61);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();
        assert!(verify(&statement, &sig, &vk).is_ok());
    }

    #[test]
    fn tampering_any_field_breaks_verification() {
        let (sk, vk) = keypair_from_seed(0x61);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();

        let mut wrong_path = statement.clone();
        wrong_path.path = "/v1/uninstall-ack".into();
        let mut refreshed_ts = statement.clone();
        refreshed_ts.ts += 3600; // the replayer's dream: a newer timestamp
        let mut swapped_body = statement.clone();
        swapped_body.body_sha256 = body_sha256(b"{\"seq\":999}");
        let mut new_nonce = statement.clone();
        new_nonce.nonce = [8u8; REQUEST_NONCE_LEN];
        let mut other_device = statement.clone();
        other_device.device_id = DeviceId([9u8; 16]);

        for tampered in [
            wrong_path,
            refreshed_ts,
            swapped_body,
            new_nonce,
            other_device,
        ] {
            assert_eq!(
                verify(&tampered, &sig, &vk),
                Err(RequestAuthError::VerificationFailed)
            );
        }
    }

    #[test]
    fn wrong_key_and_garbage_signatures_fail() {
        let (sk, _vk) = keypair_from_seed(0x61);
        let (_other, wrong_vk) = keypair_from_seed(0x62);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();
        assert_eq!(
            verify(&statement, &sig, &wrong_vk),
            Err(RequestAuthError::VerificationFailed)
        );
        assert_eq!(
            verify(&statement, &CfSignature([0xAA; 64]), &wrong_vk),
            Err(RequestAuthError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_fields() {
        let result = AuthStatement::new(
            DeviceId([2u8; 16]),
            "",
            "/v1/events",
            [0u8; 32],
            0,
            [0u8; REQUEST_NONCE_LEN],
        );
        assert_eq!(result, Err(RequestAuthError::EmptyField("method")));

        let huge = "p".repeat(MAX_FIELD_LEN + 1);
        let result = AuthStatement::new(
            DeviceId([2u8; 16]),
            "POST",
            huge,
            [0u8; 32],
            0,
            [0u8; REQUEST_NONCE_LEN],
        );
        assert!(matches!(result, Err(RequestAuthError::FieldTooLong { .. })));
    }

    #[test]
    fn canonical_encode_revalidates_hand_built_structs() {
        // Landmine: struct-literal construction (fields are pub) must not
        // bypass validation at the point of cryptographic consequence.
        let statement = AuthStatement {
            device_id: DeviceId([2u8; 16]),
            method: String::new(),
            path: "/v1/events".into(),
            body_sha256: [0u8; 32],
            ts: 0,
            nonce: [0u8; REQUEST_NONCE_LEN],
        };
        assert!(statement.canonical_encode().is_err());
    }

    #[test]
    fn length_prefixing_prevents_field_concatenation_ambiguity() {
        let a = AuthStatement::new(
            DeviceId([2u8; 16]),
            "POSTx",
            "y",
            [0u8; 32],
            0,
            [0u8; REQUEST_NONCE_LEN],
        )
        .unwrap();
        let b = AuthStatement::new(
            DeviceId([2u8; 16]),
            "POST",
            "xy",
            [0u8; 32],
            0,
            [0u8; REQUEST_NONCE_LEN],
        )
        .unwrap();
        assert_ne!(a.canonical_encode().unwrap(), b.canonical_encode().unwrap());
    }

    // --- known-answer vector ---------------------------------------------
    // Self-established regression vector, same rationale as every KAT in
    // this crate: devices on every platform must produce these exact bytes
    // forever, or relay-side verification breaks.
    #[test]
    fn known_answer_vector() {
        let (sk, _vk) = keypair_from_seed(0x03);
        let statement = AuthStatement::new(
            DeviceId([0x44; 16]),
            "POST",
            "/v1/events",
            body_sha256(b"kat-body"),
            1_700_000_000,
            [0x55; REQUEST_NONCE_LEN],
        )
        .unwrap();
        // PENDING_CI_RUN: pinned from an actual CI run (local cargo test is
        // blocked by Smart App Control on this dev machine). Tuple assert
        // so one failure prints every actual value at once.
        let expected_canonical_hex = "PENDING_CI_RUN";
        let expected_signature_hex = "PENDING_CI_RUN";
        let canonical = statement.canonical_encode().unwrap();
        let sig = sign(&statement, &sk).unwrap();
        assert_eq!(
            (crate::hex::encode(&canonical), crate::hex::encode(&sig.0),),
            (
                expected_canonical_hex.to_string(),
                expected_signature_hex.to_string(),
            ),
            "actual values printed above"
        );
    }
}
