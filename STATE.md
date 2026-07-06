# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Next ticket: `relay-approvals-transport` (#35; newly unblocked by #31) — route sealed/signed verdicts; relay carries ciphertext + signatures only, cannot decrypt (no private key) with test; approval delivered to target device; dropped message surfaces as a log gap. Design questions: wire shape for ApprovalMessage (cf-core deliberately left serde off — THIS ticket owns the encoding), sealed unblock payload routing (SealedPayload → partner), delivery = polling endpoint (fetch_approvals in RelayTransport already expects pull).
- [ ] Then: `relay-email-fallback` (#37; unblocked by #31 — needs SMTP thinking) or `svc-skeleton` (#39).
- [ ] Still open: `core-uniffi-scaffold` (#27; **awaiting human answer**), `hard-doh-feed-ops` (#76), #21 fuzzing follow-up.

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human**; #19 blocked on #16; #20 design doc doesn't exist; #27 paused on human CI call
- Relay durability: question moved to relay-deploy (#38) where it belongs — every relay component so far is a logic-complete in-memory seam (registry, log, silence, replay guard; feeds immutable-after-load)
- Standing: local `cargo test` broken (Smart App Control) — CI-only verification

## Session Handoff

**What was done (2026-07-06, per MEMO.md):** SIX tickets closed this session: #29 (relay-auth), #30 (registry/pairing), #33 (timeanchor beacons), #32 (feeds), #34 (heartbeat-silence), #31 (event log). The last four were all first-round-trip green. Plus #26's post-close redteam hardening.

**Where things stand:**
- e-relay remaining: approvals-transport (#35), push (#36), email-fallback (#37), deploy (#38). Everything else in the epic is done.
- The relay now: enrolls households/devices, authenticates + replay-guards signed requests, attests time, serves release-signed feeds, tracks heartbeats → DeviceSilent/DeviceResumed (bounded pending-events buffer awaiting #35/#37 delivery), and stores per-device hash chains with fork/gap detection + prune-keeps-head.
- Config surface: relay.toml requires bind_addr, tls_cert_path, tls_key_path, beacon_key_path, feeds_dir.

**Next steps / resume point:**
- `relay-approvals-transport` (#35): read the issue. Key pre-work notes: ApprovalMessage wire encoding is deliberately undefined in cf-core (this ticket owns it — see #26/#29 comments); delivery should be pull-based per RelayTransport::fetch_approvals(household, device); "relay cannot decrypt (no private key) test" wants a test proving the sealed payload opens only with the partner scalar the relay never holds (cf-core sealing tests are the pattern); "dropped message surfaces downstream as a log gap" ties verdict delivery to the event log — think about whether verdicts are ALSO chained events pushed by the partner device (elegant: reuses #31 wholesale) vs a separate mailbox with its own continuity story.

**Open questions for the human:**
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
- (Durability question retired from #31; will resurface at #38 with concrete needs.)
