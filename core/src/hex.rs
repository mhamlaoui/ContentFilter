//! Minimal hand-rolled hex codec. Hand-rolling is fine here because this is
//! pure data formatting, not a security primitive — unlike randomness or
//! signing, which this crate deliberately never implements itself.

use crate::version::ModelError;

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble_to_char(b >> 4));
        s.push(nibble_to_char(b & 0x0f));
    }
    s
}

pub(crate) fn decode_exact(s: &str, expected_len: usize) -> Result<Vec<u8>, ModelError> {
    if s.len() != expected_len * 2 {
        return Err(ModelError::InvalidLength {
            expected: expected_len,
            found: s.len() / 2,
        });
    }
    decode_any(s)
}

/// Decodes hex without a fixed expected length, for variable-length
/// payloads (e.g. sealed-box ciphertext, whose length depends on the
/// plaintext). Fixed-size key/id types use [`decode_exact`] instead, since
/// their length is itself a property worth checking.
pub(crate) fn decode_any(s: &str) -> Result<Vec<u8>, ModelError> {
    if !s.len().is_multiple_of(2) {
        return Err(ModelError::InvalidLength {
            expected: s.len() / 2 + 1,
            found: s.len() / 2,
        });
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = char_to_nibble(chunk[0])?;
        let lo = char_to_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// `#[serde(with = ...)]` helpers for hex-encoding byte fields on wire
/// types — a JSON array of integers is the serde default for bytes and is
/// both bloated and inconsistent with how every key/id type here already
/// serializes.
pub(crate) mod serde_hex_vec {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        super::decode_any(&s).map_err(D::Error::custom)
    }
}

pub(crate) mod serde_hex_32 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = super::decode_exact(&s, 32).map_err(D::Error::custom)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

fn nibble_to_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!("nibble is masked to 4 bits"),
    }
}

fn char_to_nibble(c: u8) -> Result<u8, ModelError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ModelError::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0u8, 1, 15, 16, 255, 128];
        let s = encode(&bytes);
        assert_eq!(decode_exact(&s, bytes.len()).unwrap(), bytes);
    }

    #[test]
    fn rejects_odd_length() {
        assert!(decode_exact("abc", 2).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        // Landmine: a 31-byte key must never be silently zero-padded or
        // truncated to fit a 32-byte field.
        let bytes = [0u8; 31];
        let s = encode(&bytes);
        assert!(decode_exact(&s, 32).is_err());
    }

    #[test]
    fn rejects_non_hex_chars() {
        assert!(decode_exact("zz", 1).is_err());
    }

    #[test]
    fn is_case_insensitive_on_decode() {
        assert_eq!(
            decode_exact("AB", 1).unwrap(),
            decode_exact("ab", 1).unwrap()
        );
    }
}
