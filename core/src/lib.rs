//! Shared crypto, approvals, and state logic used by the Windows service,
//! relay, iOS, and Android clients.
//!
//! Data models (core-models), Ed25519 approval sign/verify
//! (core-crypto-approvals), and X25519 sealed-box encryption
//! (core-crypto-sealing). Ed25519 signing is deterministic and needs no
//! randomness; sealing does (a fresh ephemeral keypair per call), which is
//! the one legitimate use of a CSPRNG in this crate — everything else
//! (keys, ids, nonces) still comes from a hardware-backed keystore or
//! whichever ticket first mints an id, never from code here. Keeping this
//! crate's dependency footprint deliberate matters: it's the one crate
//! every platform (Windows, relay, iOS via UniFFI, Android via UniFFI)
//! links against. Each addition should be individually justified —
//! `ed25519-dalek`, `crypto_box`, `hmac`/`sha2` are, as cryptographic
//! primitives nobody should hand-roll; hex encoding elsewhere in this
//! crate isn't a primitive, so it's hand-rolled instead.

mod hex;

pub mod approval;
pub mod device;
pub mod event;
pub mod filter_state;
pub mod hashchain;
pub mod household;
pub mod ids;
pub mod keys;
pub mod sealing;
pub mod timeanchor;
pub mod version;
pub mod weakening;

pub use approval::{ApprovalError, ApprovalStatement};
pub use device::{Device, DeviceRole, Platform};
pub use event::{EventKind, NotificationEvent};
pub use filter_state::FilterState;
pub use hashchain::{ChainError, ChainedEvent, DeviceKeyResolver};
pub use household::{Household, Tier, TrustAnchor};
pub use ids::{DeviceId, HouseholdId, RequestId};
pub use keys::{Ed25519PublicKey, Signature, X25519PublicKey};
pub use sealing::{SealError, SealedPayload};
pub use timeanchor::{FloorStore, TimeAnchor, TimeAnchorError, TimeBeacon};
pub use version::{ModelError, SchemaVersion, SCHEMA_VERSION};
pub use weakening::{
    ChangeDirection, EffectiveVia, FilterChange, Policy, RequestStatus, SaltedDomainHash,
    Transition, WeakeningError, WeakeningRequest,
};
