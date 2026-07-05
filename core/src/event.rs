use crate::ids::{DeviceId, HouseholdId, RequestId};
use crate::version::SchemaVersion;
use crate::weakening::{EffectiveVia, FilterChange};
use serde::{Deserialize, Serialize};

/// Events named across the M1 tickets that are already concretely scoped,
/// plus the weakening-lifecycle events defined when core-weakening landed
/// (that module owns the state machine's shape; these variants mirror its
/// [`crate::weakening::Transition`]s). There is no `WeakeningApproved`
/// separate from `WeakeningEffective` — an accepted approval *is* the
/// transition to effective, which `via` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// A managed control (NRPT, browser DoH policy, hosts tripwire, ...)
    /// was reverted after an unmanaged change. `control` names which one.
    TamperDetected {
        control: String,
    },
    /// An unmanaged edit to a managed config value, distinct from
    /// self-performed changes (svc-integrity).
    ConfigChanged {
        control: String,
    },
    /// A partner key or cooling-off value weaker than the pinned anchor was
    /// attempted (svc-config-anchor).
    AnchorMismatch,
    /// Missed heartbeats past the threshold (relay-heartbeat-silence).
    DeviceSilent,
    /// Heartbeats resumed after a `DeviceSilent`.
    DeviceResumed,
    /// The service was not running for `[from, to]`; cross-checked against
    /// the relay's last-seen heartbeat (svc-bootgap).
    ControlsAbsent {
        from: u64,
        to: u64,
    },
    /// The production canary found an open bypass route (svc-canary).
    FilterHoleDetected {
        path: String,
    },
    /// The filter engine is down and enforcement fell back to deny-by-default
    /// (svc-fail-closed).
    FailClosedEngaged,
    /// A mobile filter (Screen Time / VPN) was turned off (ios-deviceactivity,
    /// and-watchdog).
    FilterDisabled,
    /// On-device CV flagged content above threshold. Alert-only by design —
    /// this variant deliberately carries no image data or URL
    /// (cv-reporting: "no image egress").
    ScreenContentFlagged,
    /// A weakening request entered the pipeline (core-weakening). Carries
    /// the change and duration so the partner sees *what* is being
    /// weakened — never a domain: `FilterChange` can only represent a
    /// domain as its salted hash.
    WeakeningRequested {
        request: RequestId,
        change: FilterChange,
        duration_seconds: Option<u32>,
    },
    /// The weakening applied — `via` records whether the partner approved
    /// or the anchor-clocked cooling-off elapsed, which is exactly the
    /// distinction the accountability log exists to preserve.
    WeakeningEffective {
        request: RequestId,
        via: EffectiveVia,
    },
    WeakeningVetoed {
        request: RequestId,
    },
    WeakeningCancelled {
        request: RequestId,
    },
    /// A temporary weakening's window ended and the filter re-tightened.
    WeakeningReverted {
        request: RequestId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEvent {
    pub version: SchemaVersion,
    pub household_id: HouseholdId,
    pub device_id: DeviceId,
    /// Seconds since epoch; bookkeeping only, see [`crate::device::Device::registered_at`].
    pub occurred_at: u64,
    pub kind: EventKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: EventKind) -> NotificationEvent {
        NotificationEvent {
            version: SchemaVersion::CURRENT,
            household_id: HouseholdId([1u8; 16]),
            device_id: DeviceId([2u8; 16]),
            occurred_at: 1_700_000_000,
            kind,
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let samples = vec![
            EventKind::TamperDetected {
                control: "nrpt".into(),
            },
            EventKind::ConfigChanged {
                control: "cooling_off".into(),
            },
            EventKind::AnchorMismatch,
            EventKind::DeviceSilent,
            EventKind::DeviceResumed,
            EventKind::ControlsAbsent { from: 1, to: 2 },
            EventKind::FilterHoleDetected {
                path: "doh:1.1.1.1".into(),
            },
            EventKind::FailClosedEngaged,
            EventKind::FilterDisabled,
            EventKind::ScreenContentFlagged,
            EventKind::WeakeningRequested {
                request: RequestId([3u8; 16]),
                change: FilterChange::UnblockDomain {
                    domain_hash: crate::weakening::SaltedDomainHash([0xAB; 32]),
                },
                duration_seconds: Some(3600),
            },
            EventKind::WeakeningEffective {
                request: RequestId([3u8; 16]),
                via: EffectiveVia::PartnerApproval,
            },
            EventKind::WeakeningEffective {
                request: RequestId([3u8; 16]),
                via: EffectiveVia::CoolingOff,
            },
            EventKind::WeakeningVetoed {
                request: RequestId([3u8; 16]),
            },
            EventKind::WeakeningCancelled {
                request: RequestId([3u8; 16]),
            },
            EventKind::WeakeningReverted {
                request: RequestId([3u8; 16]),
            },
        ];
        for kind in samples {
            let event = sample(kind);
            let json = serde_json::to_string(&event).unwrap();
            let back: NotificationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, back);
        }
    }

    #[test]
    fn screen_content_flagged_carries_no_image_payload() {
        // Landmine: if a future edit adds an `image` or `url` field to this
        // variant to be "helpful," this test's JSON-shape assertion breaks.
        let event = sample(EventKind::ScreenContentFlagged);
        let value = serde_json::to_value(&event).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "version, kind, household_id, device_id, occurred_at only"
        );
    }

    #[test]
    fn unrecognized_kind_is_rejected() {
        let json = serde_json::json!({
            "version": 1,
            "household_id": HouseholdId([1u8; 16]).to_hex(),
            "device_id": DeviceId([2u8; 16]).to_hex(),
            "occurred_at": 1_700_000_000u64,
            "kind": { "kind": "made_up_event" },
        });
        let result: Result<NotificationEvent, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}
