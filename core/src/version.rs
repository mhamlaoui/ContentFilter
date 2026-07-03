//! Schema versioning. Every persisted/wire type embeds a [`SchemaVersion`]
//! as its first field and checks it explicitly rather than trusting serde
//! to have deserialized "some struct that happens to have the right
//! fields" — an old or forged payload one field short of the current
//! shape should fail loudly, not get silently accepted with defaults.

use std::fmt;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(pub u16);

impl SchemaVersion {
    pub const CURRENT: SchemaVersion = SchemaVersion(SCHEMA_VERSION);

    /// Landmine: this must stay a strict equality check. A future editor
    /// "helpfully" changing this to `found <= expected` would silently
    /// accept a stale schema forever instead of forcing a migration.
    pub fn check(self) -> Result<(), ModelError> {
        if self == Self::CURRENT {
            Ok(())
        } else {
            Err(ModelError::UnsupportedVersion {
                found: self.0,
                expected: SCHEMA_VERSION,
            })
        }
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    UnsupportedVersion { found: u16, expected: u16 },
    InvalidHex,
    InvalidLength { expected: usize, found: usize },
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelError::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported schema version {found} (expected {expected})"
            ),
            ModelError::InvalidHex => write!(f, "invalid hex encoding"),
            ModelError::InvalidLength { expected, found } => {
                write!(
                    f,
                    "invalid length: expected {expected} bytes, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for ModelError {}
