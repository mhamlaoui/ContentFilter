# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Next ticket candidates: `relay-email-fallback` (#37; SMTP alert channel independent of push — design pre-work: an SmtpMailer trait seam with a real client behind it (lettre is the obvious crate — weigh it; cf-relay only), config for SMTP creds (another RelayConfig growth), retry via the existing Backoff idea, and wiring the pending_events buffer (silence/tamper/log-gap events) as the source — this is the ticket that finally DRAINS that buffer for critical events) or `svc-skeleton` (#39; Windows SCM — different risk profile, starts the e-service epic).
- [ ] `relay-push` (#36): unblocked but **human-gated** — needs APNs/FCM sandbox credentials.
- [ ] Still open: `core-uniffi-scaffold` (#27; **awaiting human answer**), `hard-doh-feed-ops` (#76), #21 fuzzing follow-up.

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human**; #19 blocked on #16; #20 design doc doesn't exist; #27 paused on human CI call; #36 needs APNs/FCM creds — **human**
- Standing: local `cargo test` broken (Smart App Control) — CI-only verification

## Session Handoff

**What was done (2026-07-06, per MEMO.md):** SEVEN tickets closed: #29, #30, #33, #32, #34, #31, #35 — the e-relay epic's entire protocol surface. Two real CI-caught bugs today (Backoff checked_shl earlier in #26's arc; sign path-and-query in #35).

**Where things stand:**
- e-relay remaining: push (#36, human-gated), email-fallback (#37), deploy (#38). Everything else done.
- The relay is now a functionally complete accountability hub: enrollment (anchor-authenticated create, pairing codes), signed+replay-guarded requests (path-and-query inside signatures), time attestation (seq=utc beacons), release-signed feed distribution (conditional GET), heartbeat→silence detection, per-device hash-chained event log (fork/gap/prune-keeps-head), and sealed/signed message routing (mailboxes, rate-limited by salted request hash).
- In-memory seams throughout; durability lands at #38. Config: bind_addr, tls_cert_path, tls_key_path, beacon_key_path, feeds_dir.
- The pending_events buffer (silence events) still has no consumer — #37 drains it for critical events; #36 would too.

**Next steps / resume point:**
- Read #37's issue first if picking it (DoD: tamper/silence/log-gap events email out even with push disabled; path independent of relay push; delivery retried). The mailer must be a seam (no real SMTP in CI — tests assert against a recording mock; a real lettre-backed impl compiles but is exercised only in deploy).
- Alternative: #39 svc-skeleton (Windows SCM; CI has windows-latest, service install/start/stop tests need care — read MEMO 2026-07-03 for the Smart App Control history first).

**Open questions for the human:**
- #36: provide APNs/FCM sandbox credentials when ready.
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
