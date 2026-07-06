//! Heartbeat tracking and DeviceSilent detection (relay-heartbeat-silence).
//! Silence is the primary backstop against a hostile admin who kills or
//! suspends the agent: the agent can be stopped, but only at the price of
//! the partner hearing about the stop.
//!
//! Pure state machine, same discipline as the registry: no clock of its
//! own — `record_heartbeat` and `sweep` take `now`, so every timing rule
//! here is deterministic under test, and "simulated kill/suspend/airplane
//! mode" is simply *not calling* `record_heartbeat` while `now` advances
//! (all three failure modes are indistinguishable to the relay, which is
//! exactly why silence is the right signal).
//!
//! Decisions:
//!
//! - **Registration seeds the tracker.** A device that enrolls and is
//!   immediately killed would otherwise never be swept (you can't miss
//!   heartbeats you never started sending). Enrollment is a liveness
//!   signal, so the clock starts there.
//! - **One `DeviceSilent` per outage, not one per sweep.** The `silent`
//!   flag makes repeated sweeps idempotent — the partner gets a signal,
//!   not a siren stuck on. `DeviceResumed` clears it, re-arming the next
//!   outage's alert.
//! - **The threshold is a code constant** (15 minutes), not relay config:
//!   svc-heartbeat owns the device-side interval contract, and until that
//!   ticket fixes the cadence there is nothing principled for an operator
//!   to tune it against. Constructor-injected for tests.
//! - **Where events go**: transitions are returned to the caller; the
//!   HTTP layer buffers them in memory (bounded) as a loudly-documented
//!   stand-in until relay-log (#31) persists events and the notification
//!   tickets (#35/#37) deliver them.

use cf_core::{DeviceId, EventKind, HouseholdId, NotificationEvent, SchemaVersion};
use std::collections::HashMap;

/// A device is silent once its last liveness signal is more than this
/// many seconds old. See the module docs for why this isn't config yet.
pub const DEFAULT_SILENCE_THRESHOLD_SECONDS: u64 = 15 * 60;

struct Beat {
    household_id: HouseholdId,
    last_seen: u64,
    silent: bool,
}

pub struct SilenceTracker {
    threshold_seconds: u64,
    beats: HashMap<DeviceId, Beat>,
}

impl SilenceTracker {
    pub fn new(threshold_seconds: u64) -> Self {
        Self {
            threshold_seconds,
            beats: HashMap::new(),
        }
    }

    /// Records a liveness signal (a signed heartbeat, or enrollment). If
    /// the device was silent, returns the `DeviceResumed` event that
    /// clears it.
    pub fn record_heartbeat(
        &mut self,
        household_id: HouseholdId,
        device_id: DeviceId,
        now: u64,
    ) -> Option<NotificationEvent> {
        let beat = self.beats.entry(device_id).or_insert(Beat {
            household_id,
            last_seen: now,
            silent: false,
        });
        beat.last_seen = now;
        beat.household_id = household_id;
        if beat.silent {
            beat.silent = false;
            return Some(event(
                household_id,
                device_id,
                now,
                EventKind::DeviceResumed,
            ));
        }
        None
    }

    /// Marks every tracked device whose last signal is older than the
    /// threshold as silent, returning one `DeviceSilent` per device that
    /// just crossed over. Idempotent: already-silent devices emit nothing
    /// until a heartbeat resumes them.
    pub fn sweep(&mut self, now: u64) -> Vec<NotificationEvent> {
        let mut events = Vec::new();
        for (device_id, beat) in &mut self.beats {
            if !beat.silent && now.saturating_sub(beat.last_seen) > self.threshold_seconds {
                beat.silent = true;
                events.push(event(
                    beat.household_id,
                    *device_id,
                    now,
                    EventKind::DeviceSilent,
                ));
            }
        }
        events
    }
}

fn event(
    household_id: HouseholdId,
    device_id: DeviceId,
    occurred_at: u64,
    kind: EventKind,
) -> NotificationEvent {
    NotificationEvent {
        version: SchemaVersion::CURRENT,
        household_id,
        device_id,
        occurred_at,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const THRESHOLD: u64 = 900;
    const HH: HouseholdId = HouseholdId([4u8; 16]);
    const DEV: DeviceId = DeviceId([2u8; 16]);

    fn tracker_with_beat() -> SilenceTracker {
        let mut t = SilenceTracker::new(THRESHOLD);
        assert!(t.record_heartbeat(HH, DEV, NOW).is_none());
        t
    }

    #[test]
    fn a_device_that_stops_heartbeating_goes_silent_after_the_threshold() {
        // The DoD's "simulated kill/suspend/airplane": all three look the
        // same from here — heartbeats just stop. The device beat at NOW
        // and is never heard from again.
        let mut t = tracker_with_beat();

        // At exactly the threshold: not yet silent (boundary pinned).
        assert!(t.sweep(NOW + THRESHOLD).is_empty());

        // One second past: DeviceSilent, for this household and device.
        let events = t.sweep(NOW + THRESHOLD + 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].household_id, HH);
        assert_eq!(events[0].device_id, DEV);
        assert_eq!(events[0].kind, EventKind::DeviceSilent);
    }

    #[test]
    fn an_ongoing_outage_emits_device_silent_exactly_once() {
        // A signal, not a siren stuck on: sweeps during the same outage
        // must not re-alert.
        let mut t = tracker_with_beat();
        assert_eq!(t.sweep(NOW + THRESHOLD + 1).len(), 1);
        assert!(t.sweep(NOW + THRESHOLD + 2).is_empty());
        assert!(t.sweep(NOW + 100 * THRESHOLD).is_empty());
    }

    #[test]
    fn a_resumed_heartbeat_clears_silence_and_rearms_the_alert() {
        let mut t = tracker_with_beat();
        t.sweep(NOW + THRESHOLD + 1);

        // Resume: exactly one DeviceResumed.
        let resumed = t
            .record_heartbeat(HH, DEV, NOW + THRESHOLD + 60)
            .expect("resume should emit DeviceResumed");
        assert_eq!(resumed.kind, EventKind::DeviceResumed);

        // A healthy follow-up heartbeat emits nothing.
        assert!(t.record_heartbeat(HH, DEV, NOW + THRESHOLD + 120).is_none());

        // And the next outage alerts again, from the new last-seen.
        let last = NOW + THRESHOLD + 120;
        assert!(t.sweep(last + THRESHOLD).is_empty());
        assert_eq!(t.sweep(last + THRESHOLD + 1).len(), 1);
    }

    #[test]
    fn tracking_is_per_device() {
        let dev_b = DeviceId([3u8; 16]);
        let mut t = tracker_with_beat();
        t.record_heartbeat(HH, dev_b, NOW);

        // Device B keeps beating; device A goes dark.
        t.record_heartbeat(HH, dev_b, NOW + THRESHOLD);
        let events = t.sweep(NOW + THRESHOLD + 1);
        assert_eq!(events.len(), 1, "only the dark device alerts");
        assert_eq!(events[0].device_id, DEV);

        // B eventually goes dark too, independently.
        let events = t.sweep(NOW + 2 * THRESHOLD + 2);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].device_id, dev_b);
    }

    #[test]
    fn a_healthy_heartbeat_cadence_never_alerts() {
        let mut t = SilenceTracker::new(THRESHOLD);
        for i in 0..10 {
            t.record_heartbeat(HH, DEV, NOW + i * (THRESHOLD / 2));
            assert!(t.sweep(NOW + i * (THRESHOLD / 2) + 1).is_empty());
        }
    }
}
