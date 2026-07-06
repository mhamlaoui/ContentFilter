//! Independent SMTP alert channel (relay-email-fallback). Critical events
//! must reach the partner even if the push path (relay-push, a later
//! ticket) is broken, disabled, or censored — so this channel shares
//! nothing with it: its own queue, its own transport, its own retry
//! state. "Independent of push" is structural here: the dispatcher
//! consumes events directly at the point they're detected, not via any
//! push machinery.
//!
//! # Pieces
//!
//! - [`Mailer`] — the transport seam. Production uses [`SmtpMailer`]
//!   (lettre over rustls); tests inject a recording mock. CI never
//!   speaks SMTP.
//! - [`EmailOutbox`] — pure retry state (clock injected): due entries
//!   are taken out, attempted *outside* any lock, and failures re-queued
//!   with exponential backoff until [`MAX_ATTEMPTS`], then dropped with
//!   a loud error — an alert channel that silently retries forever just
//!   delays the operator noticing it's broken.
//! - [`is_critical`] / [`CRITICAL_EVENT_TYPES`] — what gets emailed:
//!   relay-detected silence, relay-detected log anomalies (gaps/forks),
//!   and device-pushed chain events whose `event_type` matches the
//!   critical set (the string tags mirror `EventKind`'s serde names —
//!   that correspondence is the wire contract for device-originated
//!   alerts, since chained-event payloads are opaque to the relay).
//!
//! Email *content* is minimal by design: event kind, device id (hex),
//! timestamp. No URLs, no domains, no payload bytes — the privacy floor
//! applies to the email channel too.

use cf_core::{EventKind, NotificationEvent};
use std::collections::VecDeque;

/// Give up after this many failed attempts per email.
pub const MAX_ATTEMPTS: u32 = 8;

const RETRY_BASE_SECONDS: u64 = 30;
const RETRY_CAP_SECONDS: u64 = 3600;

/// Chain `event_type` strings that trigger an email. Mirrors the serde
/// tags of `EventKind`'s critical variants — devices emit these types
/// when they chain the corresponding events.
pub const CRITICAL_EVENT_TYPES: &[&str] = &[
    "tamper_detected",
    "anchor_mismatch",
    "controls_absent",
    "filter_hole_detected",
    "fail_closed_engaged",
    "filter_disabled",
];

/// Relay-detected criticals (from the silence tracker's own events).
pub fn is_critical(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::TamperDetected { .. }
            | EventKind::AnchorMismatch
            | EventKind::DeviceSilent
            | EventKind::ControlsAbsent { .. }
            | EventKind::FilterHoleDetected { .. }
            | EventKind::FailClosedEngaged
            | EventKind::FilterDisabled
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// The transport seam. Synchronous — the pump wraps sends in
/// `spawn_blocking`, and tests call it directly.
pub trait Mailer: Send + Sync {
    fn send(&self, email: &OutgoingEmail) -> Result<(), String>;
}

/// Formats a relay-detected event as an alert email.
pub fn email_for_event(to: &str, event: &NotificationEvent) -> OutgoingEmail {
    let kind = match &event.kind {
        EventKind::TamperDetected { control } => format!("tamper_detected ({control})"),
        EventKind::FilterHoleDetected { path } => format!("filter_hole_detected ({path})"),
        other => {
            // The serde tag, without inventing a second naming scheme.
            serde_json::to_value(other)
                .ok()
                .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(String::from))
                .unwrap_or_else(|| "unknown".into())
        }
    };
    OutgoingEmail {
        to: to.to_string(),
        subject: format!("[ContentFilter] {kind}"),
        body: format!(
            "Critical event: {kind}\nDevice: {}\nAt (unix): {}\n\n\
             This alert was sent over the independent email channel.",
            event.device_id.to_hex(),
            event.occurred_at
        ),
    }
}

/// Formats a relay-detected log anomaly (gap/fork) as an alert email.
/// These are relay-side detections with no `NotificationEvent` shape —
/// the chain rejection itself is the signal.
pub fn email_for_log_anomaly(to: &str, device_hex: &str, detail: &str, now: u64) -> OutgoingEmail {
    OutgoingEmail {
        to: to.to_string(),
        subject: "[ContentFilter] event-log anomaly".into(),
        body: format!(
            "The relay rejected an event append: {detail}\nDevice: {device_hex}\nAt (unix): {now}\n\n\
             A gap or fork in a device's event chain can indicate withheld \
             or rewritten history.\n\
             This alert was sent over the independent email channel."
        ),
    }
}

struct QueuedEmail {
    email: OutgoingEmail,
    attempts: u32,
    next_attempt_at: u64,
}

/// Pure retry state. `take_due` hands out what should be attempted now;
/// `requeue_failed` puts failures back with backoff. Attempting happens
/// between the two calls, outside any lock.
#[derive(Default)]
pub struct EmailOutbox {
    queue: VecDeque<QueuedEmail>,
}

impl EmailOutbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, email: OutgoingEmail, now: u64) {
        self.queue.push_back(QueuedEmail {
            email,
            attempts: 0,
            next_attempt_at: now,
        });
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Everything due at `now`, removed from the queue for attempting.
    /// Each email carries its prior attempt count so failures re-queue
    /// with the right backoff — the pump never tracks retry state itself.
    pub fn take_due(&mut self, now: u64) -> Vec<(OutgoingEmail, u32)> {
        let mut due = Vec::new();
        let mut keep = VecDeque::new();
        while let Some(entry) = self.queue.pop_front() {
            if entry.next_attempt_at <= now {
                due.push((entry.email, entry.attempts));
            } else {
                keep.push_back(entry);
            }
        }
        self.queue = keep;
        due
    }

    /// Returns failures to the queue with exponential backoff, dropping
    /// (loudly) anything past [`MAX_ATTEMPTS`].
    pub fn requeue_failed(&mut self, failed: Vec<(OutgoingEmail, u32)>, now: u64) {
        for (email, prior_attempts) in failed {
            let attempts = prior_attempts + 1;
            if attempts >= MAX_ATTEMPTS {
                tracing::error!(
                    to = %email.to,
                    subject = %email.subject,
                    "giving up on alert email after {MAX_ATTEMPTS} attempts"
                );
                continue;
            }
            let shift = attempts.min(31);
            let delay = (RETRY_BASE_SECONDS << shift).min(RETRY_CAP_SECONDS);
            self.queue.push_back(QueuedEmail {
                email,
                attempts,
                next_attempt_at: now + delay,
            });
        }
    }
}

/// Formats a critical device-pushed chain event (matched by
/// [`CRITICAL_EVENT_TYPES`]) as an alert email. The relay can't see into
/// the chained payload — the `event_type` string is the whole signal,
/// which is exactly enough for an alert.
pub fn email_for_chained_event(
    to: &str,
    device_hex: &str,
    event_type: &str,
    ts: u64,
) -> OutgoingEmail {
    OutgoingEmail {
        to: to.to_string(),
        subject: format!("[ContentFilter] {event_type}"),
        body: format!(
            "Critical event: {event_type}\nDevice: {device_hex}\nAt (unix): {ts}\n\n\
             This alert was sent over the independent email channel."
        ),
    }
}

/// Discards everything. For tests and TLS-bootstrap fixtures that need an
/// `AppServices` but exercise no email path — production always builds
/// [`SmtpMailer`] from required config.
pub struct NoopMailer;

impl Mailer for NoopMailer {
    fn send(&self, email: &OutgoingEmail) -> Result<(), String> {
        tracing::warn!(to = %email.to, "NoopMailer dropping alert email");
        Ok(())
    }
}

/// Production mailer: SMTP over rustls via lettre, blocking transport
/// (the pump runs it under `spawn_blocking`). Behind the default-on
/// `smtp` feature — see Cargo.toml for the Smart App Control story.
#[cfg(feature = "smtp")]
pub struct SmtpMailer {
    transport: lettre::SmtpTransport,
    from: String,
}

#[cfg(feature = "smtp")]
impl SmtpMailer {
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        from: &str,
    ) -> Result<Self, String> {
        let transport = lettre::SmtpTransport::relay(host)
            .map_err(|e| format!("smtp relay config: {e}"))?
            .port(port)
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                username.to_string(),
                password.to_string(),
            ))
            .build();
        Ok(Self {
            transport,
            from: from.to_string(),
        })
    }
}

#[cfg(feature = "smtp")]
impl Mailer for SmtpMailer {
    fn send(&self, email: &OutgoingEmail) -> Result<(), String> {
        use lettre::Transport;
        let message = lettre::Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| format!("from address: {e}"))?,
            )
            .to(email.to.parse().map_err(|e| format!("to address: {e}"))?)
            .subject(&email.subject)
            .body(email.body.clone())
            .map_err(|e| format!("build message: {e}"))?;
        self.transport
            .send(&message)
            .map(|_| ())
            .map_err(|e| format!("smtp send: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn email(n: u32) -> OutgoingEmail {
        OutgoingEmail {
            to: "partner@example.com".into(),
            subject: format!("s{n}"),
            body: "b".into(),
        }
    }

    #[test]
    fn due_emails_are_taken_and_future_ones_wait() {
        let mut outbox = EmailOutbox::new();
        outbox.enqueue(email(1), NOW);
        outbox.requeue_failed(vec![(email(2), 0)], NOW); // due at NOW + backoff

        let due = outbox.take_due(NOW);
        assert_eq!(due, vec![(email(1), 0)]);
        assert_eq!(outbox.len(), 1, "the backed-off entry waits");

        let due = outbox.take_due(NOW + RETRY_CAP_SECONDS);
        assert_eq!(due, vec![(email(2), 1)]);
    }

    #[test]
    fn delivery_is_retried_with_growing_backoff_until_it_succeeds() {
        // The DoD row, at the state-machine level: fail, wait, retry.
        let mut outbox = EmailOutbox::new();
        outbox.enqueue(email(1), NOW);

        // Attempt 1 fails.
        let due = outbox.take_due(NOW);
        assert_eq!(due.len(), 1);
        outbox.requeue_failed(due, NOW);

        // Not yet due immediately after.
        assert!(outbox.take_due(NOW + 1).is_empty());

        // Due again after the backoff; this attempt "succeeds" (not
        // requeued), leaving the outbox empty.
        let due = outbox.take_due(NOW + RETRY_CAP_SECONDS);
        assert_eq!(due.len(), 1);
        assert!(outbox.is_empty());
    }

    #[test]
    fn a_permanently_failing_email_is_dropped_after_the_cap() {
        let mut outbox = EmailOutbox::new();
        outbox.enqueue(email(1), NOW);
        let mut now = NOW;
        // Every attempt fails; the outbox's own carried attempt counts
        // drive the give-up.
        for _ in 0..=MAX_ATTEMPTS {
            now += RETRY_CAP_SECONDS + 1;
            let due = outbox.take_due(now);
            outbox.requeue_failed(due, now);
        }
        assert!(
            outbox.is_empty(),
            "an alert that can never send must not retry forever"
        );
    }

    #[test]
    fn critical_classification_matches_the_threat_rows() {
        use cf_core::EventKind;
        assert!(is_critical(&EventKind::DeviceSilent));
        assert!(is_critical(&EventKind::TamperDetected {
            control: "nrpt".into()
        }));
        assert!(is_critical(&EventKind::FilterDisabled));
        assert!(!is_critical(&EventKind::DeviceResumed));
        assert!(!is_critical(&EventKind::ScreenContentFlagged));
    }

    #[test]
    fn alert_emails_carry_no_payload_content() {
        // Privacy floor: kind, device hex, timestamp — nothing else.
        let event = NotificationEvent {
            version: cf_core::SchemaVersion::CURRENT,
            household_id: cf_core::HouseholdId([4u8; 16]),
            device_id: cf_core::DeviceId([2u8; 16]),
            occurred_at: NOW,
            kind: cf_core::EventKind::DeviceSilent,
        };
        let mail = email_for_event("partner@example.com", &event);
        assert!(mail.subject.contains("device_silent"));
        assert!(mail.body.contains(&cf_core::DeviceId([2u8; 16]).to_hex()));
        assert!(!mail.body.contains("http"), "no links");
    }
}
