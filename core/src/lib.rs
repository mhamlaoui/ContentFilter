//! Shared crypto, approvals, and state logic used by the Windows service,
//! relay, iOS, and Android clients.
//!
//! This crate currently defines the shared data models only
//! (core-models) — no crypto, no signature verification, no randomness.
//! Downstream tickets build on top: core-crypto-approvals adds canonical
//! encoding and Ed25519 verify, core-crypto-sealing adds X25519 sealed-box
//! open/seal, core-weakening adds the state machine. Keeping this crate's
//! dependency footprint at just `serde` is deliberate: it's the one crate
//! every platform (Windows, relay, iOS via UniFFI, Android via UniFFI)
//! links against, so its supply-chain surface should stay minimal.

mod hex;

pub mod device;
pub mod event;
pub mod filter_state;
pub mod household;
pub mod ids;
pub mod keys;
pub mod version;

pub use device::{Device, DeviceRole, Platform};
pub use event::{EventKind, NotificationEvent};
pub use filter_state::FilterState;
pub use household::{Household, Tier, TrustAnchor};
pub use ids::{DeviceId, HouseholdId};
pub use keys::{Ed25519PublicKey, Signature, X25519PublicKey};
pub use version::{ModelError, SchemaVersion, SCHEMA_VERSION};
