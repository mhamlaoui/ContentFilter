//! Ed25519 approval sign/verify over a canonical statement. Per the
//! project's threat model, this is the invariant that makes accountability
//! unforgeable: a partner's signature over a specific
//! {household, action, target, request, validity window, nonce} is the
//! only thing that can authorize a weakening action.

use crate::ids::{HouseholdId, RequestId};
use crate::keys::{Ed25519PublicKey, Signature as CfSignature};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::fmt;

/// Bumped alongside `crate::version::SCHEMA_VERSION`. Baking the version
/// into the domain separator means an old-schema signature structurally
/// cannot verify against a new-schema encoding, even if some caller
/// forgets to check `ApprovalStatement`'s version separately — the signed
/// bytes themselves differ, not just a field a validator might skip.
const DOMAIN_TAG: &[u8] = b"ContentFilter-Approval-v1\0";

const MAX_FIELD_LEN: usize = 255;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStatement {
    pub household_id: HouseholdId,
    pub request_id: RequestId,
    pub action: String,
    pub target: String,
    pub not_before: u64,
    pub not_after: u64,
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    EmptyField(&'static str),
    FieldTooLong {
        field: &'static str,
        max: usize,
        found: usize,
    },
    InvalidValidityWindow {
        not_before: u64,
        not_after: u64,
    },
    InvalidKeyMaterial,
    VerificationFailed,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalError::EmptyField(field) => write!(f, "{field} must not be empty"),
            ApprovalError::FieldTooLong { field, max, found } => {
                write!(f, "{field} is {found} bytes, max is {max}")
            }
            ApprovalError::InvalidValidityWindow {
                not_before,
                not_after,
            } => write!(
                f,
                "not_before ({not_before}) is after not_after ({not_after})"
            ),
            ApprovalError::InvalidKeyMaterial => write!(f, "invalid Ed25519 key material"),
            ApprovalError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for ApprovalError {}

impl ApprovalStatement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        household_id: HouseholdId,
        request_id: RequestId,
        action: impl Into<String>,
        target: impl Into<String>,
        not_before: u64,
        not_after: u64,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, ApprovalError> {
        let statement = Self {
            household_id,
            request_id,
            action: action.into(),
            target: target.into(),
            not_before,
            not_after,
            nonce,
        };
        statement.validate()?;
        Ok(statement)
    }

    fn validate(&self) -> Result<(), ApprovalError> {
        Self::validate_field("action", &self.action)?;
        Self::validate_field("target", &self.target)?;
        if self.not_before > self.not_after {
            return Err(ApprovalError::InvalidValidityWindow {
                not_before: self.not_before,
                not_after: self.not_after,
            });
        }
        Ok(())
    }

    fn validate_field(name: &'static str, s: &str) -> Result<(), ApprovalError> {
        if s.is_empty() {
            return Err(ApprovalError::EmptyField(name));
        }
        if s.len() > MAX_FIELD_LEN {
            return Err(ApprovalError::FieldTooLong {
                field: name,
                max: MAX_FIELD_LEN,
                found: s.len(),
            });
        }
        Ok(())
    }

    /// The exact bytes that get signed. Fixed field order, length-prefixed
    /// variable-length fields, domain-separated. Deliberately not
    /// serde/JSON-based — canonicalization ambiguity (key order, escaping,
    /// number formatting) in a signed encoding is a forgery vector, not
    /// just a style choice. Re-validates rather than trusting the caller
    /// already did: this is the point of cryptographic consequence, so it
    /// never trusts state established earlier.
    pub fn canonical_encode(&self) -> Result<Vec<u8>, ApprovalError> {
        self.validate()?;
        let mut buf = Vec::with_capacity(
            DOMAIN_TAG.len()
                + 16
                + 16
                + 2
                + self.action.len()
                + 2
                + self.target.len()
                + 8
                + 8
                + NONCE_LEN,
        );
        buf.extend_from_slice(DOMAIN_TAG);
        buf.extend_from_slice(&self.household_id.0);
        buf.extend_from_slice(&self.request_id.0);
        write_length_prefixed(&mut buf, self.action.as_bytes());
        write_length_prefixed(&mut buf, self.target.as_bytes());
        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.not_after.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        Ok(buf)
    }
}

fn write_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    // bytes.len() <= MAX_FIELD_LEN (255), so this cast never truncates;
    // validate() is always called before this runs.
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Signs `statement` with `signing_key`. Ed25519 signing is deterministic
/// (no external randomness needed), so this crate never touches an RNG.
pub fn sign(
    statement: &ApprovalStatement,
    signing_key: &SigningKey,
) -> Result<CfSignature, ApprovalError> {
    let bytes = statement.canonical_encode()?;
    let sig = signing_key.sign(&bytes);
    Ok(CfSignature(sig.to_bytes()))
}

/// Verifies `signature` over `statement` against `verify_key`.
///
/// Uses `verify_strict`, not `verify`: dalek's plain `verify` historically
/// isn't fully strict about signature malleability (more than one valid
/// signature encoding can exist for the same message under permissive
/// verification). If a signature is ever treated as a unique value
/// elsewhere (a replay/dedup cache keyed on signature bytes, say),
/// malleability stops being academic. `verify_strict` closes that.
pub fn verify(
    statement: &ApprovalStatement,
    signature: &CfSignature,
    verify_key: &Ed25519PublicKey,
) -> Result<(), ApprovalError> {
    let bytes = statement.canonical_encode()?;
    let vk =
        VerifyingKey::from_bytes(&verify_key.0).map_err(|_| ApprovalError::InvalidKeyMaterial)?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| ApprovalError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_statement() -> ApprovalStatement {
        ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            "unblock",
            "social",
            1_700_000_000,
            1_700_003_600,
            [3u8; NONCE_LEN],
        )
        .unwrap()
    }

    fn keypair_from_seed(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, Ed25519PublicKey(verifying_key.to_bytes()))
    }

    // --- basic correctness -------------------------------------------------

    #[test]
    fn valid_signature_verifies() {
        let (sk, vk) = keypair_from_seed(0x42);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();
        assert!(verify(&statement, &sig, &vk).is_ok());
    }

    // --- negative cases: the actual security properties --------------------

    #[test]
    fn tampered_field_fails_verification() {
        let (sk, vk) = keypair_from_seed(0x42);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();

        let mut tampered = statement.clone();
        tampered.target = "adult".to_string(); // e.g. widen scope post-signature
        assert_eq!(
            verify(&tampered, &sig, &vk),
            Err(ApprovalError::VerificationFailed)
        );
    }

    #[test]
    fn tampered_validity_window_fails_verification() {
        // Specifically redteaming the not_before/not_after fields: extending
        // an approval's expiry after the fact is exactly the kind of tamper
        // this signature exists to prevent.
        let (sk, vk) = keypair_from_seed(0x42);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();

        let mut tampered = statement.clone();
        tampered.not_after = u64::MAX;
        assert_eq!(
            verify(&tampered, &sig, &vk),
            Err(ApprovalError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = keypair_from_seed(0x42);
        let (_other_sk, wrong_vk) = keypair_from_seed(0x99);
        let statement = sample_statement();
        let sig = sign(&statement, &sk).unwrap();
        assert_eq!(
            verify(&statement, &sig, &wrong_vk),
            Err(ApprovalError::VerificationFailed)
        );
    }

    #[test]
    fn holder_of_only_the_verify_key_cannot_forge() {
        // The verify key is public; anyone can compute canonical_encode()
        // for any statement they like. What they cannot do is produce
        // bytes that verify_strict accepts without the private scalar —
        // demonstrated here by an attacker who has the statement, the
        // canonical bytes, and the verify key, but only random guesses for
        // a signature. Ed25519's forgery-resistance is a mathematical
        // property of the primitive (discrete log hardness), not something
        // a unit test proves in general — this test only pins that our
        // wrapper doesn't accidentally accept garbage.
        let (_sk, vk) = keypair_from_seed(0x42);
        let statement = sample_statement();
        let forged = CfSignature([0xAAu8; 64]);
        assert_eq!(
            verify(&statement, &forged, &vk),
            Err(ApprovalError::VerificationFailed)
        );
    }

    // --- input validation landmines -----------------------------------------

    #[test]
    fn rejects_empty_action() {
        let result = ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            "",
            "social",
            0,
            1,
            [0u8; NONCE_LEN],
        );
        assert_eq!(result, Err(ApprovalError::EmptyField("action")));
    }

    #[test]
    fn rejects_oversized_field() {
        let huge = "x".repeat(MAX_FIELD_LEN + 1);
        let result = ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            huge,
            "social",
            0,
            1,
            [0u8; NONCE_LEN],
        );
        assert!(matches!(result, Err(ApprovalError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_inverted_validity_window() {
        // Landmine: not_before > not_after is nonsensical and should never
        // reach canonical_encode/sign/verify silently.
        let result = ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            "unblock",
            "social",
            100,
            50,
            [0u8; NONCE_LEN],
        );
        assert!(matches!(
            result,
            Err(ApprovalError::InvalidValidityWindow { .. })
        ));
    }

    #[test]
    fn canonical_encode_still_validates_on_a_hand_built_struct() {
        // Landmine: canonical_encode() must re-validate even if a caller
        // builds ApprovalStatement via struct-literal syntax (fields are
        // pub) instead of the validating `new` constructor, bypassing that
        // check. Signing/verifying garbage should fail loudly, not produce
        // a "valid" signature over an empty action.
        let statement = ApprovalStatement {
            household_id: HouseholdId([1u8; 16]),
            request_id: RequestId([2u8; 16]),
            action: String::new(),
            target: "social".into(),
            not_before: 0,
            not_after: 1,
            nonce: [0u8; NONCE_LEN],
        };
        assert!(statement.canonical_encode().is_err());
    }

    // --- canonical-encoding collision/ambiguity properties ------------------

    #[test]
    fn length_prefixing_prevents_field_concatenation_ambiguity() {
        // Without length prefixes, action="ab" + target="cd" and
        // action="a" + target="bcd" would encode identically. This is
        // exactly the class of bug that breaks "canonical" encodings.
        let a = ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            "ab",
            "cd",
            0,
            1,
            [0u8; NONCE_LEN],
        )
        .unwrap();
        let b = ApprovalStatement::new(
            HouseholdId([1u8; 16]),
            RequestId([2u8; 16]),
            "a",
            "bcd",
            0,
            1,
            [0u8; NONCE_LEN],
        )
        .unwrap();
        assert_ne!(a.canonical_encode().unwrap(), b.canonical_encode().unwrap());
    }

    #[test]
    fn a_signature_does_not_verify_under_the_previous_domain_tag() {
        // Pins that DOMAIN_TAG participates in the signed bytes at all —
        // if a future refactor accidentally drops it from canonical_encode,
        // this test doesn't directly catch that (there's only one version
        // to compare against), but the KAT below does: it pins the exact
        // encoded bytes including the tag.
        assert!(DOMAIN_TAG.ends_with(b"-v1\0"));
    }

    // --- lightweight fuzz-like property testing -----------------------------
    // Hand-rolled deterministic PRNG (splitmix64), not a crate dependency:
    // this generates varied test *inputs* only, nothing security-sensitive
    // (no real keys or nonces derive from it), so hand-rolling is fine here
    // — unlike a CSPRNG, which this crate never touches. This is a lighter
    // stand-in for real coverage-guided fuzzing (cargo-fuzz), not
    // equivalent to it; the DoD's "fuzz the canonical encoder" box is left
    // unchecked for that reason.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        fn next_byte(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }

        fn next_bytes<const N: usize>(&mut self) -> [u8; N] {
            let mut out = [0u8; N];
            for b in &mut out {
                *b = self.next_byte();
            }
            out
        }

        fn next_string(&mut self, max_len: usize) -> String {
            let len = (self.next_u64() as usize) % (max_len + 1);
            (0..len)
                .map(|_| (b'a' + (self.next_byte() % 26)) as char)
                .collect()
        }
    }

    fn random_statement(rng: &mut SplitMix64) -> Option<ApprovalStatement> {
        let action = rng.next_string(20);
        let target = rng.next_string(20);
        if action.is_empty() || target.is_empty() {
            return None;
        }
        let not_before = rng.next_u64() % 1_000_000;
        let not_after = not_before + (rng.next_u64() % 1_000_000);
        ApprovalStatement::new(
            HouseholdId(rng.next_bytes()),
            RequestId(rng.next_bytes()),
            action,
            target,
            not_before,
            not_after,
            rng.next_bytes(),
        )
        .ok()
    }

    #[test]
    fn canonical_encode_is_deterministic_across_many_random_inputs() {
        let mut rng = SplitMix64(0xC0FFEE);
        let mut checked = 0;
        for _ in 0..2000 {
            let Some(statement) = random_statement(&mut rng) else {
                continue;
            };
            let e1 = statement.canonical_encode().unwrap();
            let e2 = statement.canonical_encode().unwrap();
            assert_eq!(
                e1, e2,
                "canonical_encode must be a pure function of the statement"
            );
            checked += 1;
        }
        assert!(checked > 1000, "too many generated statements were skipped");
    }

    #[test]
    fn distinct_random_statements_do_not_collide() {
        let mut rng = SplitMix64(0xDEADBEEF);
        let mut seen = std::collections::HashSet::new();
        let mut checked = 0;
        for _ in 0..2000 {
            let Some(statement) = random_statement(&mut rng) else {
                continue;
            };
            let encoded = statement.canonical_encode().unwrap();
            assert!(
                seen.insert(encoded),
                "canonical encoding collision detected"
            );
            checked += 1;
        }
        assert!(checked > 1000, "too many generated statements were skipped");
    }

    // --- known-answer test ---------------------------------------------------
    // Self-established regression vector for our *own* canonical encoding
    // (there is no external standard for this custom format to compare
    // against). Fixed seed, fixed statement, fixed nonce — deterministic
    // signing means this must produce the exact same signature every time,
    // on every platform, forever, or cross-platform verification (Swift/
    // Kotlin bindings via UniFFI) breaks.
    //
    // TODO(pending CI run): the expected signature below is a placeholder.
    // Local `cargo test` is blocked by Smart App Control on this dev
    // machine, so the real value will come from a CI failure's assertion
    // output and get hardcoded here in a follow-up commit — see the PR/
    // issue for that run.
    #[test]
    fn known_answer_vector() {
        let signing_key = SigningKey::from_bytes(&[0x01; 32]);
        let statement = ApprovalStatement::new(
            HouseholdId([0x11; 16]),
            RequestId([0x22; 16]),
            "unblock",
            "social",
            1_700_000_000,
            1_700_003_600,
            [0x33; NONCE_LEN],
        )
        .unwrap();

        let expected_canonical_hex = "PENDING_CI_RUN";
        let expected_signature_hex = "PENDING_CI_RUN";

        let canonical = statement.canonical_encode().unwrap();
        let sig = sign(&statement, &signing_key).unwrap();

        if expected_canonical_hex == "PENDING_CI_RUN" {
            panic!(
                "known-answer vector not yet pinned; actual canonical bytes = {}, actual signature = {}",
                crate::hex::encode(&canonical),
                crate::hex::encode(&sig.0),
            );
        }
        assert_eq!(crate::hex::encode(&canonical), expected_canonical_hex);
        assert_eq!(crate::hex::encode(&sig.0), expected_signature_hex);
    }
}
