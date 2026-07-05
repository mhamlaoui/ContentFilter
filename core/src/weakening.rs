//! Weakening state machine (core-weakening): strengthening is instant,
//! weakening is delayed and/or approved. This is the mechanism that defends
//! the weak moment (THREAT_MODEL.md row 5).
//!
//! The referenced "design doc section 7.3" policy matrix does not exist
//! (no design doc does — see CLAUDE.md); the matrix defined by
//! [`FilterChange::direction`] + [`policy_for`] and pinned row-by-row in
//! this module's tests is the authoritative version.
//!
//! # The clock rules (why three different time checks)
//!
//! Every security-relevant time decision here goes through the signed
//! anchor floor (core-timeanchor), and the *direction* of each check
//! decides which primitive it uses:
//!
//! - **Cooling-off completion** asks "has this much time genuinely
//!   passed?" — [`TimeAnchor::has_reached`], floor only. A forward local
//!   jump cannot complete the wait, and because the floor only advances
//!   when a relay-signed beacon is ingested, a cooling-off structurally
//!   cannot complete on a device that has had no relay contact since the
//!   request — which is exactly when the partner could not have been
//!   notified of it.
//! - **Expiry** (of an approval's validity window, or of a temporary
//!   weakening) asks "is it over yet?", where the attacker's move is a
//!   rollback — `max(local, floor)` via [`TimeAnchor::is_expired`]. An
//!   honest local clock can end a window while offline; a rolled-back one
//!   is overruled by the floor.
//! - **`requested_at`** is `max(local, floor)` at creation. Floor-only was
//!   rejected: go beacon-dark for a week, then request — the stale floor
//!   would understate the request time and the next fresh beacon would
//!   complete the cooling-off instantly. With `max`, understating
//!   `requested_at` requires a local rollback *and* beacon starvation
//!   together, is bounded by the starvation window, and still doesn't
//!   grant anything until post-request beacons walk the floor to the
//!   deadline (see THREAT_MODEL.md residuals).
//!
//! # Other decisions (and rejected alternatives)
//!
//! - **Verdicts are verified here, at the point of consequence**, not by
//!   the caller. `svc-ipc`'s invariant ("IPC alone cannot apply a
//!   weakening without a partner signature") holds because this module
//!   offers no unsigned path to `Effective` other than the anchor-clocked
//!   timeout: rejected the alternative of trusting the service to have
//!   verified, which makes one forgotten call site a bypass.
//! - **Vetoes are partner-signed too.** An unsigned veto would be "safe"
//!   for the weak-moment threat model (forging one only adds restriction)
//!   but would let anyone put words in the partner's mouth in the
//!   accountability log. Same statement format, verdict string `"veto"`.
//! - **The approval's `target` binds change *and* duration**
//!   ([`canonical_target`]): otherwise a signature over "unblock X for an
//!   hour" would apply "unblock X forever".
//! - **Domains never appear in this module.** `UnblockDomain` carries only
//!   the salted hash ([`crate::sealing::salted_request_hash`]); the domain
//!   itself travels sealed to the partner (core-crypto-sealing) and stays
//!   in the enforcing service's local custody. A request or event from
//!   this module is relay-safe by construction, not by discipline.
//! - **No stored deadline.** Cooling-off is recomputed from the current
//!   pinned [`TrustAnchor`] on every poll — the anchor is
//!   server-authoritative (svc-config-anchor), while a deadline stored in
//!   the request would be one more locally-tamperable value.
//! - **No `DelayAndApproval` policy** (both required): no ticket demands
//!   it; the DoD's "approval shortcuts the wait" is OR-semantics. Add a
//!   variant if a real need appears — the matrix tests will force every
//!   row to be re-stated consciously.
//! - **After `Effective`, there is no veto/cancel** — undoing an effective
//!   weakening is a strengthening, which is instant and needs no
//!   authorization. Terminal states are terminal.
//!
//! [`TimeAnchor::has_reached`]: crate::timeanchor::TimeAnchor::has_reached
//! [`TimeAnchor::is_expired`]: crate::timeanchor::TimeAnchor::is_expired

use crate::approval::{self, ApprovalError, ApprovalStatement};
use crate::hex;
use crate::household::{Tier, TrustAnchor};
use crate::ids::{HouseholdId, RequestId};
use crate::keys::Signature as CfSignature;
use crate::timeanchor::{FloorStore, TimeAnchor};
use crate::version::{ModelError, SchemaVersion};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// `ApprovalStatement::action` value for an approval.
pub const APPROVE_VERDICT: &str = "approve";
/// `ApprovalStatement::action` value for a veto.
pub const VETO_VERDICT: &str = "veto";

/// Output of [`crate::sealing::salted_request_hash`]: identifies a domain
/// to parties that know the household salt while revealing nothing to the
/// relay. This is the only form in which a domain-shaped thing may appear
/// in a weakening request, its canonical target, or its events.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SaltedDomainHash(pub [u8; 32]);

impl SaltedDomainHash {
    pub fn from_hex(s: &str) -> Result<Self, ModelError> {
        let bytes = hex::decode_exact(s, 32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for SaltedDomainHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SaltedDomainHash({})", self.to_hex())
    }
}

impl Serialize for SaltedDomainHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SaltedDomainHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

/// A requested change to filter posture. Deliberately **not**
/// `#[non_exhaustive]` (unlike [`crate::event::EventKind`]): the enforcing
/// service must match on this exhaustively to apply it, and a new variant
/// silently falling into a `_ =>` arm would mean a policy action nothing
/// enforces. Adding a variant is supposed to break every match site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum FilterChange {
    EnableSocialBlocking,
    DisableSocialBlocking,
    EnableYoutubeBlocking,
    DisableYoutubeBlocking,
    /// Ends a [`FilterChange::PauseFiltering`] early. Instant, like every
    /// strengthening.
    ResumeFiltering,
    /// Suspends filtering entirely; inherently temporary, so a duration is
    /// required at request time.
    PauseFiltering,
    ReblockDomain {
        domain_hash: SaltedDomainHash,
    },
    UnblockDomain {
        domain_hash: SaltedDomainHash,
    },
    EnableQuicBlock,
    /// svc-quic-block: "disabling the block is a cooling-off + notify
    /// action".
    DisableQuicBlock,
    /// Removing the tool. In Locked tier this is approval-only
    /// (lock-uninstall-approval); permanent by nature, so a duration is
    /// forbidden.
    Uninstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeDirection {
    Strengthen,
    Weaken,
}

impl FilterChange {
    pub fn direction(&self) -> ChangeDirection {
        match self {
            FilterChange::EnableSocialBlocking
            | FilterChange::EnableYoutubeBlocking
            | FilterChange::ResumeFiltering
            | FilterChange::ReblockDomain { .. }
            | FilterChange::EnableQuicBlock => ChangeDirection::Strengthen,
            FilterChange::DisableSocialBlocking
            | FilterChange::DisableYoutubeBlocking
            | FilterChange::PauseFiltering
            | FilterChange::UnblockDomain { .. }
            | FilterChange::DisableQuicBlock
            | FilterChange::Uninstall => ChangeDirection::Weaken,
        }
    }

    fn duration_rule(&self) -> DurationRule {
        match self {
            FilterChange::PauseFiltering => DurationRule::Required,
            FilterChange::Uninstall => DurationRule::Forbidden,
            _ => DurationRule::Optional,
        }
    }
}

enum DurationRule {
    Required,
    Forbidden,
    Optional,
}

/// How a change may be applied. `Instant` is derived, never chosen: it
/// exists so the policy matrix can state "strengthening is instant" as a
/// tested row rather than an unwritten assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Apply now; no request, no signature, no wait. Strengthening only.
    Instant,
    /// Effective when the anchor-clocked cooling-off elapses **or** a
    /// valid partner approval arrives, whichever is first.
    DelayOrApproval,
    /// Only a valid partner approval makes it effective; no timeout path
    /// exists. Every Locked-tier weakening.
    ApprovalOnly,
}

/// The policy matrix. Two rules generate it — direction decides
/// instant-vs-gated, tier decides whether the timeout path exists — and
/// the tests pin every generated row as an explicit table, so any future
/// per-action exception has to consciously restate the whole matrix.
pub fn policy_for(change: &FilterChange, tier: Tier) -> Policy {
    match change.direction() {
        ChangeDirection::Strengthen => Policy::Instant,
        ChangeDirection::Weaken => match tier {
            Tier::Hardened => Policy::DelayOrApproval,
            Tier::Locked => Policy::ApprovalOnly,
        },
    }
}

/// The string a partner signs over as `ApprovalStatement::target`. Binds
/// the change **and** its duration under a fixed grammar with no
/// user-controlled substrings (domains appear only as fixed-length hex of
/// their salted hash), so no component can smuggle a separator.
pub fn canonical_target(change: &FilterChange, duration_seconds: Option<u32>) -> String {
    let base: String = match change {
        FilterChange::EnableSocialBlocking => "category:social:on".into(),
        FilterChange::DisableSocialBlocking => "category:social:off".into(),
        FilterChange::EnableYoutubeBlocking => "category:youtube:on".into(),
        FilterChange::DisableYoutubeBlocking => "category:youtube:off".into(),
        FilterChange::ResumeFiltering => "filter:resume".into(),
        FilterChange::PauseFiltering => "filter:pause".into(),
        FilterChange::ReblockDomain { domain_hash } => {
            format!("domain:{}:reblock", domain_hash.to_hex())
        }
        FilterChange::UnblockDomain { domain_hash } => {
            format!("domain:{}:unblock", domain_hash.to_hex())
        }
        FilterChange::EnableQuicBlock => "quic:on".into(),
        FilterChange::DisableQuicBlock => "quic:off".into(),
        FilterChange::Uninstall => "uninstall".into(),
    };
    match duration_seconds {
        Some(d) => format!("{base}:d{d}"),
        None => format!("{base}:permanent"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveVia {
    CoolingOff,
    PartnerApproval,
}

/// Issue #25 names these PENDING/EFFECT/VETOED/CANCELLED/REVERTED;
/// `EFFECT` is spelled out as `Effective`. All timestamps are
/// anchor-derived except `cancelled_at` (see [`WeakeningRequest::cancel`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Effective {
        via: EffectiveVia,
        effective_at: u64,
        /// `None` = permanent (until strengthened, which happens outside
        /// this request's lifecycle).
        effective_until: Option<u64>,
    },
    Vetoed {
        vetoed_at: u64,
    },
    Cancelled {
        cancelled_at: u64,
    },
    Reverted {
        reverted_at: u64,
    },
}

/// What a state-changing call did, for the caller to persist and turn into
/// `NotificationEvent`s. Not serialized — it's an in-process signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    BecameEffective {
        via: EffectiveVia,
        effective_at: u64,
        effective_until: Option<u64>,
    },
    Vetoed {
        vetoed_at: u64,
    },
    Cancelled {
        cancelled_at: u64,
    },
    Reverted {
        reverted_at: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeakeningError {
    /// Strengthening never enters the request machine — apply it now.
    StrengtheningIsInstant,
    DurationRequired,
    DurationForbidden,
    ZeroDuration,
    /// The request is not `Pending`; verdicts and cancellation only apply
    /// to pending requests, which also makes re-applying a consumed
    /// approval a no-op rejection rather than a second grant.
    NotPending,
    /// Signature or statement-encoding failure from core-crypto-approvals.
    ApprovalInvalid(ApprovalError),
    WrongHousehold,
    WrongRequest,
    /// An approval offered where a veto was expected, or vice versa.
    WrongVerdict,
    /// The signed target doesn't match this request's change + duration.
    TargetMismatch,
    /// The floor hasn't reached the statement's `not_before`.
    ApprovalNotYetActive,
    /// `max(local, floor)` is past the statement's `not_after`.
    ApprovalExpired,
}

impl fmt::Display for WeakeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WeakeningError::StrengtheningIsInstant => {
                write!(f, "strengthening is instant and never forms a request")
            }
            WeakeningError::DurationRequired => write!(f, "this change requires a duration"),
            WeakeningError::DurationForbidden => write!(f, "this change cannot take a duration"),
            WeakeningError::ZeroDuration => write!(f, "duration must be at least one second"),
            WeakeningError::NotPending => write!(f, "request is not pending"),
            WeakeningError::ApprovalInvalid(e) => write!(f, "invalid approval statement: {e}"),
            WeakeningError::WrongHousehold => write!(f, "statement is for a different household"),
            WeakeningError::WrongRequest => write!(f, "statement is for a different request"),
            WeakeningError::WrongVerdict => write!(f, "statement verdict does not match the call"),
            WeakeningError::TargetMismatch => {
                write!(f, "statement target does not match this request")
            }
            WeakeningError::ApprovalNotYetActive => {
                write!(f, "statement is not yet active per the anchor floor")
            }
            WeakeningError::ApprovalExpired => write!(f, "statement validity window has passed"),
        }
    }
}

impl std::error::Error for WeakeningError {}

/// One weakening request's lifecycle. This crate holds no request store —
/// persistence, request-id single-use bookkeeping, and event emission
/// belong to the service (svc-approvals), which persists this struct and
/// replays transitions into `NotificationEvent`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeakeningRequest {
    pub version: SchemaVersion,
    pub household_id: HouseholdId,
    pub request_id: RequestId,
    pub change: FilterChange,
    pub duration_seconds: Option<u32>,
    /// `max(local, floor)` at creation — see the module docs for why
    /// neither input alone is safe.
    pub requested_at: u64,
    pub status: RequestStatus,
}

impl WeakeningRequest {
    /// Opens a weakening request. Rejects strengthening changes outright:
    /// the instant path must not acquire a signature/waiting ceremony that
    /// would train users to expect delay where none is owed.
    pub fn new<S: FloorStore>(
        anchor: &TrustAnchor,
        request_id: RequestId,
        change: FilterChange,
        duration_seconds: Option<u32>,
        time: &TimeAnchor<S>,
        local_now: u64,
    ) -> Result<Self, WeakeningError> {
        if matches!(change.direction(), ChangeDirection::Strengthen) {
            return Err(WeakeningError::StrengtheningIsInstant);
        }
        match (change.duration_rule(), duration_seconds) {
            (DurationRule::Required, None) => return Err(WeakeningError::DurationRequired),
            (DurationRule::Forbidden, Some(_)) => return Err(WeakeningError::DurationForbidden),
            (_, Some(0)) => return Err(WeakeningError::ZeroDuration),
            _ => {}
        }
        Ok(Self {
            version: SchemaVersion::CURRENT,
            household_id: anchor.household_id,
            request_id,
            change,
            duration_seconds,
            requested_at: time.effective_now(local_now),
            status: RequestStatus::Pending,
        })
    }

    /// Advances time-driven transitions: cooling-off completion (floor
    /// only) and temporary-weakening expiry (`max(local, floor)`). Both
    /// can fire in one call — a grant whose window has already elapsed by
    /// the time it's granted reverts in the same poll, never leaving a
    /// request effective past its window.
    ///
    /// The deadline and policy are recomputed from `anchor` on every call
    /// rather than stored: the pinned anchor is server-authoritative,
    /// stored copies would be locally tamperable.
    pub fn poll<S: FloorStore>(
        &mut self,
        anchor: &TrustAnchor,
        time: &TimeAnchor<S>,
        local_now: u64,
    ) -> Result<Vec<Transition>, WeakeningError> {
        if anchor.household_id != self.household_id {
            return Err(WeakeningError::WrongHousehold);
        }
        let mut transitions = Vec::new();
        if matches!(self.status, RequestStatus::Pending)
            && matches!(
                policy_for(&self.change, anchor.tier),
                Policy::DelayOrApproval
            )
        {
            let deadline = self
                .requested_at
                .saturating_add(u64::from(anchor.cooling_off_seconds));
            if time.has_reached(deadline) {
                // The window starts at the floor as of this poll, not at
                // the deadline: a request polled long after its deadline
                // (device asleep/offline) still gets its full duration
                // from the moment it's actually granted. The floor can't
                // exceed relay-attested real time, so this start can't be
                // used to push `effective_until` into the far future.
                let effective_at = time.floor_utc();
                transitions.push(self.make_effective(EffectiveVia::CoolingOff, effective_at));
            }
        }
        if let RequestStatus::Effective {
            effective_until: Some(until),
            ..
        } = self.status
        {
            if time.is_expired(local_now, until) {
                let reverted_at = time.effective_now(local_now);
                self.status = RequestStatus::Reverted { reverted_at };
                transitions.push(Transition::Reverted { reverted_at });
            }
        }
        Ok(transitions)
    }

    /// Applies a partner approval, shortcutting the cooling-off (or, under
    /// [`Policy::ApprovalOnly`], providing the only path to `Effective`).
    /// Verification happens here, at the point of consequence.
    ///
    /// `effective_until` derives from `max(local, floor)` at application;
    /// the expiry check just performed bounds that by the statement's
    /// `not_after`, so a forward-jumped local clock cannot stretch the
    /// window beyond what the partner's own validity window allows.
    pub fn apply_approval<S: FloorStore>(
        &mut self,
        anchor: &TrustAnchor,
        statement: &ApprovalStatement,
        signature: &CfSignature,
        time: &TimeAnchor<S>,
        local_now: u64,
    ) -> Result<Transition, WeakeningError> {
        self.verify_verdict(
            anchor,
            statement,
            signature,
            time,
            local_now,
            APPROVE_VERDICT,
        )?;
        let effective_at = time.effective_now(local_now);
        Ok(self.make_effective(EffectiveVia::PartnerApproval, effective_at))
    }

    /// Applies a partner veto: `Pending` → `Vetoed`, terminal. Signed for
    /// the same reason approvals are — the accountability log must not be
    /// able to attribute to the partner a veto they never made.
    pub fn apply_veto<S: FloorStore>(
        &mut self,
        anchor: &TrustAnchor,
        statement: &ApprovalStatement,
        signature: &CfSignature,
        time: &TimeAnchor<S>,
        local_now: u64,
    ) -> Result<Transition, WeakeningError> {
        self.verify_verdict(anchor, statement, signature, time, local_now, VETO_VERDICT)?;
        let vetoed_at = time.effective_now(local_now);
        self.status = RequestStatus::Vetoed { vetoed_at };
        Ok(Transition::Vetoed { vetoed_at })
    }

    /// The requester withdraws their own pending request. Unsigned:
    /// cancelling a weakening is strengthening-direction, so there is
    /// nothing here worth forging (caller authentication is svc-ipc's
    /// job). `local_now` is bookkeeping only, like
    /// [`crate::device::Device::registered_at`].
    pub fn cancel(&mut self, local_now: u64) -> Result<Transition, WeakeningError> {
        if !matches!(self.status, RequestStatus::Pending) {
            return Err(WeakeningError::NotPending);
        }
        self.status = RequestStatus::Cancelled {
            cancelled_at: local_now,
        };
        Ok(Transition::Cancelled {
            cancelled_at: local_now,
        })
    }

    fn make_effective(&mut self, via: EffectiveVia, effective_at: u64) -> Transition {
        let effective_until = self
            .duration_seconds
            .map(|d| effective_at.saturating_add(u64::from(d)));
        self.status = RequestStatus::Effective {
            via,
            effective_at,
            effective_until,
        };
        Transition::BecameEffective {
            via,
            effective_at,
            effective_until,
        }
    }

    fn verify_verdict<S: FloorStore>(
        &self,
        anchor: &TrustAnchor,
        statement: &ApprovalStatement,
        signature: &CfSignature,
        time: &TimeAnchor<S>,
        local_now: u64,
        expected_verdict: &str,
    ) -> Result<(), WeakeningError> {
        if anchor.household_id != self.household_id {
            return Err(WeakeningError::WrongHousehold);
        }
        if !matches!(self.status, RequestStatus::Pending) {
            return Err(WeakeningError::NotPending);
        }
        // Signature first: no field of the statement is treated as
        // meaningful until it's proven to be the partner's words. The
        // anchor's own signature is *not* checked here — verifying and
        // pinning the anchor is svc-config-anchor's job; this module
        // trusts the caller to hand it the pinned anchor.
        approval::verify(statement, signature, &anchor.partner_approval_key)
            .map_err(WeakeningError::ApprovalInvalid)?;
        if statement.household_id != self.household_id {
            return Err(WeakeningError::WrongHousehold);
        }
        if statement.request_id != self.request_id {
            return Err(WeakeningError::WrongRequest);
        }
        if statement.action != expected_verdict {
            return Err(WeakeningError::WrongVerdict);
        }
        if statement.target != canonical_target(&self.change, self.duration_seconds) {
            return Err(WeakeningError::TargetMismatch);
        }
        if !time.has_reached(statement.not_before) {
            return Err(WeakeningError::ApprovalNotYetActive);
        }
        if time.is_expired(local_now, statement.not_after) {
            return Err(WeakeningError::ApprovalExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::NONCE_LEN;
    use crate::keys::{Ed25519PublicKey, Signature, X25519PublicKey};
    use crate::timeanchor::{sign_beacon, TimeBeacon};
    use ed25519_dalek::SigningKey;

    const BASE: u64 = 1_700_000_000;
    const COOLING: u32 = 86_400; // 24h
    const HH: HouseholdId = HouseholdId([4u8; 16]);
    const REQ: RequestId = RequestId([8u8; 16]);

    struct InMemoryFloorStore(Option<(u64, u64)>);

    impl FloorStore for InMemoryFloorStore {
        fn load_floor(&self) -> Option<(u64, u64)> {
            self.0
        }
        fn save_floor(&mut self, utc: u64, seq: u64) {
            self.0 = Some((utc, seq));
        }
    }

    fn partner() -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let vk = Ed25519PublicKey(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    fn anchor(tier: Tier) -> TrustAnchor {
        let (_, vk) = partner();
        TrustAnchor {
            version: SchemaVersion::CURRENT,
            household_id: HH,
            seq: 1,
            partner_approval_key: vk,
            partner_seal_key: X25519PublicKey([6u8; 32]),
            cooling_off_seconds: COOLING,
            tier,
            // The anchor's own signature is svc-config-anchor's concern,
            // not this module's — a placeholder is deliberate here.
            signature: Signature([7u8; 64]),
        }
    }

    /// A TimeAnchor whose floor is `floor_utc`, built directly through the
    /// FloorStore seam. Beacon signature verification on the way *into*
    /// the floor is core-timeanchor's own tested job; one end-to-end test
    /// below uses real signed beacons anyway.
    fn time_at(floor_utc: u64) -> TimeAnchor<InMemoryFloorStore> {
        TimeAnchor::new(InMemoryFloorStore(Some((floor_utc, 1))))
    }

    fn pending(
        tier: Tier,
        change: FilterChange,
        duration: Option<u32>,
        floor: u64,
        local: u64,
    ) -> WeakeningRequest {
        WeakeningRequest::new(&anchor(tier), REQ, change, duration, &time_at(floor), local)
            .expect("test request should be constructible")
    }

    fn signed_verdict(
        verdict: &str,
        target: &str,
        not_before: u64,
        not_after: u64,
    ) -> (ApprovalStatement, CfSignature) {
        signed_verdict_for(REQ, verdict, target, not_before, not_after)
    }

    fn signed_verdict_for(
        request: RequestId,
        verdict: &str,
        target: &str,
        not_before: u64,
        not_after: u64,
    ) -> (ApprovalStatement, CfSignature) {
        let (sk, _) = partner();
        let statement = ApprovalStatement::new(
            HH,
            request,
            verdict,
            target,
            not_before,
            not_after,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let sig = approval::sign(&statement, &sk).unwrap();
        (statement, sig)
    }

    fn sample_hash() -> SaltedDomainHash {
        SaltedDomainHash([0xAB; 32])
    }

    fn all_changes() -> Vec<FilterChange> {
        let list = vec![
            FilterChange::EnableSocialBlocking,
            FilterChange::DisableSocialBlocking,
            FilterChange::EnableYoutubeBlocking,
            FilterChange::DisableYoutubeBlocking,
            FilterChange::ResumeFiltering,
            FilterChange::PauseFiltering,
            FilterChange::ReblockDomain {
                domain_hash: sample_hash(),
            },
            FilterChange::UnblockDomain {
                domain_hash: sample_hash(),
            },
            FilterChange::EnableQuicBlock,
            FilterChange::DisableQuicBlock,
            FilterChange::Uninstall,
        ];
        // Exhaustiveness guard: adding a FilterChange variant without
        // adding it to this list (and thus to every table-driven test that
        // iterates it) must fail to compile, not silently under-test.
        for change in &list {
            match change {
                FilterChange::EnableSocialBlocking
                | FilterChange::DisableSocialBlocking
                | FilterChange::EnableYoutubeBlocking
                | FilterChange::DisableYoutubeBlocking
                | FilterChange::ResumeFiltering
                | FilterChange::PauseFiltering
                | FilterChange::ReblockDomain { .. }
                | FilterChange::UnblockDomain { .. }
                | FilterChange::EnableQuicBlock
                | FilterChange::DisableQuicBlock
                | FilterChange::Uninstall => {}
            }
        }
        list
    }

    fn valid_duration_for(change: &FilterChange) -> Option<u32> {
        match change.duration_rule() {
            DurationRule::Required => Some(900),
            DurationRule::Forbidden => None,
            DurationRule::Optional => None,
        }
    }

    // --- the policy matrix ------------------------------------------------

    #[test]
    fn every_policy_matrix_row_matches_the_table() {
        use FilterChange as C;
        use Policy::{ApprovalOnly, DelayOrApproval, Instant};
        use Tier::{Hardened, Locked};
        // The authoritative matrix, stated row by row (the design doc's
        // "section 7.3" does not exist; this table is the spec). Changing
        // policy_for or adding a variant must force an edit here.
        let matrix: Vec<(FilterChange, Tier, Policy)> = vec![
            (C::EnableSocialBlocking, Hardened, Instant),
            (C::EnableSocialBlocking, Locked, Instant),
            (C::DisableSocialBlocking, Hardened, DelayOrApproval),
            (C::DisableSocialBlocking, Locked, ApprovalOnly),
            (C::EnableYoutubeBlocking, Hardened, Instant),
            (C::EnableYoutubeBlocking, Locked, Instant),
            (C::DisableYoutubeBlocking, Hardened, DelayOrApproval),
            (C::DisableYoutubeBlocking, Locked, ApprovalOnly),
            (C::ResumeFiltering, Hardened, Instant),
            (C::ResumeFiltering, Locked, Instant),
            (C::PauseFiltering, Hardened, DelayOrApproval),
            (C::PauseFiltering, Locked, ApprovalOnly),
            (
                C::ReblockDomain {
                    domain_hash: sample_hash(),
                },
                Hardened,
                Instant,
            ),
            (
                C::ReblockDomain {
                    domain_hash: sample_hash(),
                },
                Locked,
                Instant,
            ),
            (
                C::UnblockDomain {
                    domain_hash: sample_hash(),
                },
                Hardened,
                DelayOrApproval,
            ),
            (
                C::UnblockDomain {
                    domain_hash: sample_hash(),
                },
                Locked,
                ApprovalOnly,
            ),
            (C::EnableQuicBlock, Hardened, Instant),
            (C::EnableQuicBlock, Locked, Instant),
            (C::DisableQuicBlock, Hardened, DelayOrApproval),
            (C::DisableQuicBlock, Locked, ApprovalOnly),
            (C::Uninstall, Hardened, DelayOrApproval),
            (C::Uninstall, Locked, ApprovalOnly),
        ];
        assert_eq!(
            matrix.len(),
            all_changes().len() * 2,
            "the table must cover every (change, tier) row"
        );
        for (change, tier, expected) in &matrix {
            assert_eq!(
                policy_for(change, *tier),
                *expected,
                "matrix row for {change:?} in {tier:?}"
            );
        }
    }

    #[test]
    fn strengthening_is_instant_and_never_forms_a_request() {
        for change in all_changes() {
            if !matches!(change.direction(), ChangeDirection::Strengthen) {
                continue;
            }
            for tier in [Tier::Hardened, Tier::Locked] {
                assert_eq!(policy_for(&change, tier), Policy::Instant);
                let result = WeakeningRequest::new(
                    &anchor(tier),
                    REQ,
                    change.clone(),
                    None,
                    &time_at(BASE),
                    BASE,
                );
                assert_eq!(
                    result,
                    Err(WeakeningError::StrengtheningIsInstant),
                    "{change:?} must not enter the request machine"
                );
            }
        }
    }

    #[test]
    fn no_weakening_is_instant_in_any_tier() {
        // Landmine: if someone ever adds an Instant row for a weakening
        // ("just this once, for convenience"), this fails before any
        // matrix-table edit is even reviewed.
        for change in all_changes() {
            if !matches!(change.direction(), ChangeDirection::Weaken) {
                continue;
            }
            for tier in [Tier::Hardened, Tier::Locked] {
                assert_ne!(
                    policy_for(&change, tier),
                    Policy::Instant,
                    "{change:?} in {tier:?} must never be instant"
                );
            }
        }
    }

    #[test]
    fn locked_tier_weakenings_never_complete_by_timeout() {
        for change in all_changes() {
            if !matches!(change.direction(), ChangeDirection::Weaken) {
                continue;
            }
            let duration = valid_duration_for(&change);
            let mut request = pending(Tier::Locked, change.clone(), duration, BASE, BASE);
            // Floor a thousand cooling-off windows past the deadline:
            let far = BASE + 1000 * u64::from(COOLING);
            let transitions = request
                .poll(&anchor(Tier::Locked), &time_at(far), far)
                .unwrap();
            assert!(transitions.is_empty(), "{change:?} completed by timeout");
            assert_eq!(request.status, RequestStatus::Pending);
        }
    }

    // --- cooling-off is anchor-clocked -------------------------------------

    #[test]
    fn cooling_off_completes_when_the_signed_floor_reaches_the_deadline() {
        // End-to-end through real signed beacons, not a hand-set store.
        let beacon_sk = SigningKey::from_bytes(&[0x10; 32]);
        let beacon_vk = Ed25519PublicKey(beacon_sk.verifying_key().to_bytes());
        let mut time = TimeAnchor::new(InMemoryFloorStore(None));
        let ingest = |time: &mut TimeAnchor<InMemoryFloorStore>, utc: u64, seq: u64| {
            let beacon = TimeBeacon { utc, seq };
            time.ingest_beacon(&beacon, &sign_beacon(&beacon, &beacon_sk), &beacon_vk)
                .unwrap();
        };
        ingest(&mut time, BASE, 1);

        let hardened = anchor(Tier::Hardened);
        let mut request = WeakeningRequest::new(
            &hardened,
            REQ,
            FilterChange::DisableSocialBlocking,
            None,
            &time,
            BASE,
        )
        .unwrap();
        assert_eq!(request.requested_at, BASE);

        let deadline = BASE + u64::from(COOLING);
        ingest(&mut time, deadline - 1, 2);
        assert!(request
            .poll(&hardened, &time, deadline - 1)
            .unwrap()
            .is_empty());

        ingest(&mut time, deadline, 3);
        let transitions = request.poll(&hardened, &time, deadline).unwrap();
        assert_eq!(
            transitions,
            vec![Transition::BecameEffective {
                via: EffectiveVia::CoolingOff,
                effective_at: deadline,
                effective_until: None,
            }]
        );
        assert!(matches!(
            request.status,
            RequestStatus::Effective {
                via: EffectiveVia::CoolingOff,
                ..
            }
        ));
    }

    #[test]
    fn cooling_off_uses_the_signed_anchor_not_the_local_clock() {
        // The DoD row, and the liveness flip side of the same property: the
        // floor only moves on relay contact, so a device that has been
        // beacon-dark since the request can wait forever — no local clock
        // value can substitute for the relay having attested that the
        // cooling-off genuinely elapsed (and that the partner's
        // notification had a chance to go out).
        let hardened = anchor(Tier::Hardened);
        let frozen = time_at(BASE);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        for local in [
            BASE + u64::from(COOLING),
            BASE + 100 * u64::from(COOLING),
            u64::MAX,
        ] {
            let transitions = request.poll(&hardened, &frozen, local).unwrap();
            assert!(
                transitions.is_empty(),
                "local clock {local} completed a cooling-off the floor never attested"
            );
            assert_eq!(request.status, RequestStatus::Pending);
        }
    }

    #[test]
    fn understating_requested_at_needs_rollback_and_beacon_starvation_together() {
        let hardened = anchor(Tier::Hardened);
        let week = 7 * 86_400;

        // (a) Floor a week stale, local honest: requested_at comes from
        // local, and the wait is the full cooling-off from *now*.
        let request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE - week,
            BASE,
        );
        assert_eq!(request.requested_at, BASE);
        let mut r = request.clone();
        // A fresh beacon arriving right after the request must not grant:
        assert!(r.poll(&hardened, &time_at(BASE), BASE).unwrap().is_empty());
        assert!(r
            .poll(&hardened, &time_at(BASE + u64::from(COOLING) - 1), BASE)
            .unwrap()
            .is_empty());

        // (b) Local rolled back a week, floor fresh: requested_at comes
        // from the floor instead.
        let request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE - week,
        );
        assert_eq!(request.requested_at, BASE);
        // Understating requested_at therefore requires *both* a rollback
        // and beacon starvation at request time — the documented residual,
        // bounded by the starvation window and still gated on post-request
        // relay contact (see cooling_off_uses_the_signed_anchor test).
    }

    #[test]
    fn cooling_off_duration_comes_from_the_current_anchor_not_a_stored_copy() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        // The household rotates to a *longer* cooling-off while pending;
        // the old deadline must not linger anywhere in the request.
        let mut longer = anchor(Tier::Hardened);
        longer.cooling_off_seconds = 2 * COOLING;
        let old_deadline = BASE + u64::from(COOLING);
        assert!(request
            .poll(&longer, &time_at(old_deadline), old_deadline)
            .unwrap()
            .is_empty());
        let new_deadline = BASE + 2 * u64::from(COOLING);
        let transitions = request
            .poll(&longer, &time_at(new_deadline), new_deadline)
            .unwrap();
        assert_eq!(transitions.len(), 1);
    }

    // --- the approval shortcut ---------------------------------------------

    #[test]
    fn a_valid_partner_approval_shortcuts_the_wait() {
        for tier in [Tier::Hardened, Tier::Locked] {
            let mut request = pending(
                tier,
                FilterChange::UnblockDomain {
                    domain_hash: sample_hash(),
                },
                Some(3600),
                BASE,
                BASE,
            );
            let target = canonical_target(&request.change, request.duration_seconds);
            let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 7200);
            // Well before the cooling-off deadline (and in Locked there is
            // no deadline at all):
            let now = BASE + 60;
            let transition = request
                .apply_approval(&anchor(tier), &statement, &sig, &time_at(BASE), now)
                .unwrap();
            assert_eq!(
                transition,
                Transition::BecameEffective {
                    via: EffectiveVia::PartnerApproval,
                    effective_at: now,
                    effective_until: Some(now + 3600),
                }
            );
        }
    }

    #[test]
    fn a_forged_approval_is_rejected() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);

        // Signed by the wrong key entirely:
        let wrong_sk = SigningKey::from_bytes(&[0x99; 32]);
        let statement = ApprovalStatement::new(
            HH,
            REQ,
            APPROVE_VERDICT,
            target.clone(),
            BASE,
            BASE + 7200,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let wrong_sig = approval::sign(&statement, &wrong_sk).unwrap();
        assert_eq!(
            request.apply_approval(&hardened, &statement, &wrong_sig, &time, BASE),
            Err(WeakeningError::ApprovalInvalid(
                ApprovalError::VerificationFailed
            ))
        );

        // Garbage bytes:
        let garbage = CfSignature([0xAA; 64]);
        assert_eq!(
            request.apply_approval(&hardened, &statement, &garbage, &time, BASE),
            Err(WeakeningError::ApprovalInvalid(
                ApprovalError::VerificationFailed
            ))
        );
        assert_eq!(request.status, RequestStatus::Pending);
    }

    #[test]
    fn an_approval_bound_to_a_different_request_or_household_is_rejected() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);

        // Same partner key, different request id — e.g. an approval for an
        // earlier request replayed against this one:
        let (statement, sig) = signed_verdict_for(
            RequestId([0xEE; 16]),
            APPROVE_VERDICT,
            &target,
            BASE,
            BASE + 7200,
        );
        assert_eq!(
            request.apply_approval(&hardened, &statement, &sig, &time, BASE),
            Err(WeakeningError::WrongRequest)
        );

        // Same partner key, different household (one partner can serve two
        // households):
        let (sk, _) = partner();
        let other_hh = ApprovalStatement::new(
            HouseholdId([0xDD; 16]),
            REQ,
            APPROVE_VERDICT,
            target,
            BASE,
            BASE + 7200,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let other_sig = approval::sign(&other_hh, &sk).unwrap();
        assert_eq!(
            request.apply_approval(&hardened, &other_hh, &other_sig, &time, BASE),
            Err(WeakeningError::WrongHousehold)
        );
        assert_eq!(request.status, RequestStatus::Pending);
    }

    #[test]
    fn an_approval_over_a_different_change_or_duration_is_rejected() {
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);

        // Partner approved a ONE-HOUR unblock; request claims permanent.
        let mut permanent = pending(
            Tier::Hardened,
            FilterChange::UnblockDomain {
                domain_hash: sample_hash(),
            },
            None,
            BASE,
            BASE,
        );
        let hourly_target = canonical_target(&permanent.change, Some(3600));
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &hourly_target, BASE, BASE + 7200);
        assert_eq!(
            permanent.apply_approval(&hardened, &statement, &sig, &time, BASE),
            Err(WeakeningError::TargetMismatch)
        );

        // Partner approved disabling YouTube; request disables social.
        let mut social = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let youtube_target = canonical_target(&FilterChange::DisableYoutubeBlocking, None);
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &youtube_target, BASE, BASE + 7200);
        assert_eq!(
            social.apply_approval(&hardened, &statement, &sig, &time, BASE),
            Err(WeakeningError::TargetMismatch)
        );
    }

    #[test]
    fn a_veto_statement_cannot_act_as_an_approval_or_vice_versa() {
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);

        let (veto_stmt, veto_sig) = signed_verdict(VETO_VERDICT, &target, BASE, BASE + 7200);
        assert_eq!(
            request.apply_approval(&hardened, &veto_stmt, &veto_sig, &time, BASE),
            Err(WeakeningError::WrongVerdict),
            "a signed veto must never grant the weakening it rejects"
        );

        let (approve_stmt, approve_sig) =
            signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 7200);
        assert_eq!(
            request.apply_veto(&hardened, &approve_stmt, &approve_sig, &time, BASE),
            Err(WeakeningError::WrongVerdict),
            "a signed approval must never be recorded as the partner saying no"
        );
        assert_eq!(request.status, RequestStatus::Pending);
    }

    #[test]
    fn an_expired_approval_is_rejected_even_with_a_rolled_back_local_clock() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 100);
        // Floor has attested past not_after; attacker rolls local to zero.
        assert_eq!(
            request.apply_approval(
                &anchor(Tier::Hardened),
                &statement,
                &sig,
                &time_at(BASE + 200),
                0
            ),
            Err(WeakeningError::ApprovalExpired)
        );
    }

    #[test]
    fn a_future_dated_approval_cannot_be_activated_by_a_local_forward_jump() {
        // The partner scheduled this approval for later (not_before in the
        // future). Only the floor may activate it — has_reached takes no
        // local time at all, so the jump has nothing to attack.
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let (statement, sig) =
            signed_verdict(APPROVE_VERDICT, &target, BASE + 1000, BASE + 100_000);
        assert_eq!(
            request.apply_approval(
                &anchor(Tier::Hardened),
                &statement,
                &sig,
                &time_at(BASE),
                BASE + 50_000 // local claims we're well past not_before
            ),
            Err(WeakeningError::ApprovalNotYetActive)
        );
    }

    #[test]
    fn approval_window_edges_are_pinned() {
        // Boundary semantics, pinned so they can't drift silently:
        // active from floor == not_before (inclusive), usable through
        // max(local, floor) == not_after (inclusive; is_expired is strict).
        let hardened = anchor(Tier::Hardened);
        let target = canonical_target(&FilterChange::DisableSocialBlocking, None);

        let mut at_start = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE + 100, BASE + 100);
        assert_eq!(
            at_start.apply_approval(&hardened, &statement, &sig, &time_at(BASE + 99), BASE + 99),
            Err(WeakeningError::ApprovalNotYetActive)
        );
        at_start
            .apply_approval(
                &hardened,
                &statement,
                &sig,
                &time_at(BASE + 100),
                BASE + 100,
            )
            .expect("single-instant window must be usable at exactly its boundary");
    }

    #[test]
    fn a_settled_request_rejects_every_further_verdict() {
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);
        let change = FilterChange::DisableSocialBlocking;
        let target = canonical_target(&change, None);
        let (approve_stmt, approve_sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, u64::MAX);
        let (veto_stmt, veto_sig) = signed_verdict(VETO_VERDICT, &target, BASE, u64::MAX);

        let approved = {
            let mut r = pending(Tier::Hardened, change.clone(), None, BASE, BASE);
            r.apply_approval(&hardened, &approve_stmt, &approve_sig, &time, BASE)
                .unwrap();
            r
        };
        let vetoed = {
            let mut r = pending(Tier::Hardened, change.clone(), None, BASE, BASE);
            r.apply_veto(&hardened, &veto_stmt, &veto_sig, &time, BASE)
                .unwrap();
            r
        };
        let cancelled = {
            let mut r = pending(Tier::Hardened, change.clone(), None, BASE, BASE);
            r.cancel(BASE).unwrap();
            r
        };

        for settled in [approved, vetoed, cancelled] {
            // Re-applying the same (real, validly signed) approval must be
            // rejected — this is the in-request replay guard.
            let mut r = settled.clone();
            assert_eq!(
                r.apply_approval(&hardened, &approve_stmt, &approve_sig, &time, BASE),
                Err(WeakeningError::NotPending)
            );
            let mut r = settled.clone();
            assert_eq!(
                r.apply_veto(&hardened, &veto_stmt, &veto_sig, &time, BASE),
                Err(WeakeningError::NotPending)
            );
            let mut r = settled.clone();
            assert_eq!(r.cancel(BASE), Err(WeakeningError::NotPending));
            // And time alone must not move a permanent effective/vetoed/
            // cancelled request anywhere:
            let mut r = settled.clone();
            let far = u64::MAX / 2;
            assert!(r.poll(&hardened, &time_at(far), far).unwrap().is_empty());
            assert_eq!(r.status, settled.status);
        }
    }

    // --- veto and cancel ----------------------------------------------------

    #[test]
    fn a_valid_partner_veto_ends_a_pending_request() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let (statement, sig) = signed_verdict(VETO_VERDICT, &target, BASE, BASE + 7200);
        let transition = request
            .apply_veto(
                &anchor(Tier::Hardened),
                &statement,
                &sig,
                &time_at(BASE),
                BASE + 10,
            )
            .unwrap();
        assert_eq!(
            transition,
            Transition::Vetoed {
                vetoed_at: BASE + 10
            }
        );
        assert_eq!(
            request.status,
            RequestStatus::Vetoed {
                vetoed_at: BASE + 10
            }
        );
    }

    #[test]
    fn a_forged_veto_is_rejected() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, None);
        let wrong_sk = SigningKey::from_bytes(&[0x99; 32]);
        let statement = ApprovalStatement::new(
            HH,
            REQ,
            VETO_VERDICT,
            target,
            BASE,
            BASE + 7200,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        let sig = approval::sign(&statement, &wrong_sk).unwrap();
        assert_eq!(
            request.apply_veto(
                &anchor(Tier::Hardened),
                &statement,
                &sig,
                &time_at(BASE),
                BASE
            ),
            Err(WeakeningError::ApprovalInvalid(
                ApprovalError::VerificationFailed
            ))
        );
        assert_eq!(request.status, RequestStatus::Pending);
    }

    #[test]
    fn the_requester_can_cancel_a_pending_request() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let transition = request.cancel(BASE + 5).unwrap();
        assert_eq!(
            transition,
            Transition::Cancelled {
                cancelled_at: BASE + 5
            }
        );
        // Even once the cooling-off deadline passes, a cancelled request
        // stays cancelled:
        let far = BASE + 10 * u64::from(COOLING);
        assert!(request
            .poll(&anchor(Tier::Hardened), &time_at(far), far)
            .unwrap()
            .is_empty());
        assert_eq!(
            request.status,
            RequestStatus::Cancelled {
                cancelled_at: BASE + 5
            }
        );
    }

    // --- auto-revert ---------------------------------------------------------

    #[test]
    fn a_temporary_weakening_auto_reverts_when_its_window_ends() {
        let hardened = anchor(Tier::Hardened);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::UnblockDomain {
                domain_hash: sample_hash(),
            },
            Some(3600),
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, Some(3600));
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 7200);
        request
            .apply_approval(&hardened, &statement, &sig, &time_at(BASE), BASE)
            .unwrap();

        // Inside the window: nothing to do.
        assert!(request
            .poll(&hardened, &time_at(BASE + 3599), BASE + 3599)
            .unwrap()
            .is_empty());

        // Window over (floor attested): revert.
        let transitions = request
            .poll(&hardened, &time_at(BASE + 3601), BASE + 3601)
            .unwrap();
        assert_eq!(
            transitions,
            vec![Transition::Reverted {
                reverted_at: BASE + 3601
            }]
        );
        assert_eq!(
            request.status,
            RequestStatus::Reverted {
                reverted_at: BASE + 3601
            }
        );
    }

    #[test]
    fn a_rolled_back_local_clock_cannot_extend_a_temporary_weakening() {
        let hardened = anchor(Tier::Hardened);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::PauseFiltering,
            Some(900),
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, Some(900));
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 7200);
        request
            .apply_approval(&hardened, &statement, &sig, &time_at(BASE), BASE)
            .unwrap();
        // Floor says the window ended; local claims it's 1970 again.
        let transitions = request.poll(&hardened, &time_at(BASE + 901), 0).unwrap();
        assert_eq!(transitions.len(), 1);
        assert!(matches!(request.status, RequestStatus::Reverted { .. }));
    }

    #[test]
    fn an_honest_local_clock_reverts_a_temporary_weakening_while_offline() {
        // No beacon since the grant (floor frozen at BASE) — the honest
        // local clock alone must still end the window, because expiry uses
        // max(local, floor). This is the direction where trusting local is
        // safe: lying forward only shortens the weakening.
        let hardened = anchor(Tier::Hardened);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::PauseFiltering,
            Some(900),
            BASE,
            BASE,
        );
        let target = canonical_target(&request.change, Some(900));
        let (statement, sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, BASE + 7200);
        request
            .apply_approval(&hardened, &statement, &sig, &time_at(BASE), BASE)
            .unwrap();
        let transitions = request.poll(&hardened, &time_at(BASE), BASE + 901).unwrap();
        assert_eq!(transitions.len(), 1);
        assert!(matches!(request.status, RequestStatus::Reverted { .. }));
    }

    #[test]
    fn a_permanent_weakening_does_not_auto_revert() {
        let hardened = anchor(Tier::Hardened);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let deadline = BASE + u64::from(COOLING);
        request
            .poll(&hardened, &time_at(deadline), deadline)
            .unwrap();
        assert!(matches!(request.status, RequestStatus::Effective { .. }));

        let far = u64::MAX / 2;
        assert!(request
            .poll(&hardened, &time_at(far), far)
            .unwrap()
            .is_empty());
        assert!(matches!(
            request.status,
            RequestStatus::Effective {
                effective_until: None,
                ..
            }
        ));
    }

    #[test]
    fn a_grant_into_an_already_elapsed_window_reverts_in_the_same_poll() {
        // Device offline for ages: the deadline passed long ago AND the
        // granted window has already elapsed by honest local time. One
        // poll must both grant and revert — never returning with the
        // request left effective past its window.
        let hardened = anchor(Tier::Hardened);
        let mut request = pending(
            Tier::Hardened,
            FilterChange::PauseFiltering,
            Some(900),
            BASE,
            BASE,
        );
        let floor = BASE + u64::from(COOLING); // beacon arrives at the deadline
        let local = floor + 86_400; // a day later by honest local time
        let transitions = request.poll(&hardened, &time_at(floor), local).unwrap();
        assert_eq!(
            transitions,
            vec![
                Transition::BecameEffective {
                    via: EffectiveVia::CoolingOff,
                    effective_at: floor,
                    effective_until: Some(floor + 900),
                },
                Transition::Reverted { reverted_at: local },
            ]
        );
        assert!(matches!(request.status, RequestStatus::Reverted { .. }));
    }

    // --- duration validation --------------------------------------------------

    #[test]
    fn pause_requires_a_duration_and_uninstall_forbids_one() {
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);
        assert_eq!(
            WeakeningRequest::new(
                &hardened,
                REQ,
                FilterChange::PauseFiltering,
                None,
                &time,
                BASE
            ),
            Err(WeakeningError::DurationRequired)
        );
        assert_eq!(
            WeakeningRequest::new(
                &hardened,
                REQ,
                FilterChange::Uninstall,
                Some(3600),
                &time,
                BASE
            ),
            Err(WeakeningError::DurationForbidden)
        );
        assert_eq!(
            WeakeningRequest::new(
                &hardened,
                REQ,
                FilterChange::PauseFiltering,
                Some(0),
                &time,
                BASE
            ),
            Err(WeakeningError::ZeroDuration)
        );
    }

    // --- model hygiene ----------------------------------------------------------

    #[test]
    fn requests_round_trip_in_every_status() {
        let hardened = anchor(Tier::Hardened);
        let time = time_at(BASE);
        let change = FilterChange::UnblockDomain {
            domain_hash: sample_hash(),
        };
        let target = canonical_target(&change, Some(3600));
        let (approve_stmt, approve_sig) = signed_verdict(APPROVE_VERDICT, &target, BASE, u64::MAX);
        let (veto_stmt, veto_sig) = signed_verdict(VETO_VERDICT, &target, BASE, u64::MAX);

        // Every status is reached through real transitions, not struct
        // literals — if a transition path breaks, so does this test.
        let pending_r = pending(Tier::Hardened, change.clone(), Some(3600), BASE, BASE);
        let effective = {
            let mut r = pending_r.clone();
            r.apply_approval(&hardened, &approve_stmt, &approve_sig, &time, BASE)
                .unwrap();
            r
        };
        let vetoed = {
            let mut r = pending_r.clone();
            r.apply_veto(&hardened, &veto_stmt, &veto_sig, &time, BASE)
                .unwrap();
            r
        };
        let cancelled = {
            let mut r = pending_r.clone();
            r.cancel(BASE).unwrap();
            r
        };
        let reverted = {
            let mut r = effective.clone();
            let end = BASE + 3601;
            r.poll(&hardened, &time_at(end), end).unwrap();
            r
        };
        assert!(matches!(reverted.status, RequestStatus::Reverted { .. }));

        for request in [pending_r, effective, vetoed, cancelled, reverted] {
            let json = serde_json::to_string(&request).unwrap();
            let back: WeakeningRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(request, back);
        }
    }

    #[test]
    fn unknown_fields_on_a_request_are_rejected() {
        let request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        let mut value = serde_json::to_value(&request).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!(true));
        let result: Result<WeakeningRequest, _> = serde_json::from_value(value);
        assert!(result.is_err(), "unknown field should be rejected");
    }

    #[test]
    fn a_stale_schema_version_is_rejected() {
        let mut request = pending(
            Tier::Hardened,
            FilterChange::DisableSocialBlocking,
            None,
            BASE,
            BASE,
        );
        request.version = SchemaVersion(0);
        assert!(request.version.check().is_err());
    }

    #[test]
    fn unblock_requests_are_domain_free_by_construction() {
        // Landmine: UnblockDomain carries only the salted hash — the type
        // has no field a domain string could live in, so a serialized
        // request is relay-safe by construction. If someone adds a
        // `domain: String` field "for convenience," this JSON-shape
        // assertion breaks before the privacy floor does.
        let request = pending(
            Tier::Hardened,
            FilterChange::UnblockDomain {
                domain_hash: sample_hash(),
            },
            Some(3600),
            BASE,
            BASE,
        );
        let value = serde_json::to_value(&request).unwrap();
        let change = value.get("change").unwrap().as_object().unwrap();
        let keys: Vec<&str> = change.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["change", "domain_hash"],
            "an unblock request may carry the salted hash and nothing else"
        );
        assert_eq!(
            change.get("domain_hash").unwrap().as_str().unwrap(),
            sample_hash().to_hex()
        );
    }

    #[test]
    fn canonical_target_known_answers() {
        // Self-established vectors: cross-device approval verification
        // depends on requester and partner deriving the exact same target
        // string forever. Pure string-building — no CI pinning needed.
        let hash = sample_hash();
        let cases: Vec<(FilterChange, Option<u32>, String)> = vec![
            (
                FilterChange::DisableSocialBlocking,
                Some(3600),
                "category:social:off:d3600".into(),
            ),
            (
                FilterChange::DisableSocialBlocking,
                None,
                "category:social:off:permanent".into(),
            ),
            (
                FilterChange::PauseFiltering,
                Some(900),
                "filter:pause:d900".into(),
            ),
            (
                FilterChange::UnblockDomain { domain_hash: hash },
                None,
                format!("domain:{}:unblock:permanent", hash.to_hex()),
            ),
            (FilterChange::Uninstall, None, "uninstall:permanent".into()),
            (
                FilterChange::DisableQuicBlock,
                None,
                "quic:off:permanent".into(),
            ),
        ];
        for (change, duration, expected) in cases {
            assert_eq!(canonical_target(&change, duration), expected);
        }
    }

    #[test]
    fn canonical_targets_never_collide() {
        // Distinct (change, duration) pairs must produce distinct signed
        // targets, or one approval could authorize another action.
        let mut seen = std::collections::HashSet::new();
        for change in all_changes() {
            for duration in [None, Some(60), Some(3600)] {
                let target = canonical_target(&change, duration);
                assert!(
                    target.len() <= 255,
                    "targets must fit ApprovalStatement's field limit"
                );
                assert!(
                    seen.insert(target.clone()),
                    "canonical target collision: {target}"
                );
            }
        }
    }
}
