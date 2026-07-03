//! Shared crypto, approvals, and state logic used by the Windows service,
//! relay, iOS, and Android clients.
//!
//! Data models (core-models) plus Ed25519 approval sign/verify
//! (core-crypto-approvals). Still no randomness anywhere in this crate —
//! Ed25519 signing is deterministic, and nothing here generates keys, ids,
//! or nonces; those come from a hardware-backed keystore or whichever
//! ticket first mints an id. Downstream tickets build on top:
//! core-crypto-sealing adds X25519 sealed-box open/seal, core-weakening
//! adds the state machine. Keeping this crate's dependency footprint
//! minimal (`serde`, `ed25519-dalek`) is deliberate: it's the one crate
//! every platform (Windows, relay, iOS via UniFFI, Android via UniFFI)
//! links against, so its supply-chain surface should stay small and each
//! addition should be individually justified — `ed25519-dalek` is, as a
//! cryptographic primitive nobody should hand-roll; hex encoding elsewhere
//! in this crate isn't a primitive, so it's hand-rolled instead.

mod hex;

pub mod approval;
pub mod device;
pub mod event;
pub mod filter_state;
pub mod household;
pub mod ids;
pub mod keys;
pub mod version;

pub use approval::{ApprovalError, ApprovalStatement};
pub use device::{Device, DeviceRole, Platform};
pub use event::{EventKind, NotificationEvent};
pub use filter_state::FilterState;
pub use household::{Household, Tier, TrustAnchor};
pub use ids::{DeviceId, HouseholdId, RequestId};
pub use keys::{Ed25519PublicKey, Signature, X25519PublicKey};
pub use version::{ModelError, SchemaVersion, SCHEMA_VERSION};
