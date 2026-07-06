# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — newly unblocked by #30: `relay-log` (#31), `relay-feeds` (#32), `relay-timeanchor` (#33), `relay-heartbeat-silence` (#34). All four have their cf-core halves already built (hashchain, FeedEnvelope + sign_feed, TimeBeacon). #32/#33 are small (serve signed feeds with conditional GET; emit signed beacons); #31 is the meaty one (append-only log with gap/fork detection + household isolation + prune-keeps-head).
- [ ] Also open: `core-uniffi-scaffold` (#27; **awaiting human answer** on Swift/Kotlin CI jobs), `svc-skeleton` (#39; Windows SCM risk profile)
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder

## Current Blockers

- #16 (f-secrets-keymgmt): offline key ceremony — **human action**
- #17 (f-threat-model-doc): human sign-off; two residuals added in `2a2c633`
- #19 (f-repro-builds): signing blocked on #16
- #20 (core-models): design doc referenced by DoD does not exist
- #27: paused on the human's CI-surface call
- Standing: local `cargo test` broken (Smart App Control) — CI-only verification

## Session Handoff

**What was done (2026-07-06, per MEMO.md):**
- `relay-auth` (#29) closed — `8e4b978` + `6179400`
- `relay-registry-pairing` (#30) closed — `22515f7` + `52bc1b6`, green run 28771055852. Anchor canonical encoding + self-attestation now exist in cf-core; registry + HTTP endpoints live; relay-auth wire format = four `x-cf-*` headers with method/path/body taken from the received request.
- Both low-effort review passes: no findings.

**Where things stand:**
- e-relay: bootstrap, auth, registry/pairing done — the relay can now enroll households and devices end to end. Remaining: log, feeds, timeanchor beacons, heartbeat/silence, then approvals-transport → push → email-fallback → deploy.
- e-core: only #27 remains (paused).
- The registry is in-memory behind a seam; durability decision deferred to relay-deploy, but relay-log (#31) may force it sooner — debate there.

**Next steps / resume point:**
- Default next: `relay-feeds` (#32) or `relay-timeanchor` (#33) as quick wins (cf-core primitives exist; endpoints follow the #30 patterns), then `relay-log` (#31) as the substantial one. Read each issue's DoD first.
- For #31: reuse `cf_core::hashchain::verify_chain`/`find_gaps` server-side; fork detection is THIS ticket's DoD row (deliberately not implemented in core-hashchain — see MEMO 2026-07-05).

**Open questions for the human:**
- #27 CI surface (UniFFI + Swift/Kotlin jobs) — yes/no?
- THREAT_MODEL sign-off (#17) incl. `2a2c633` residuals; key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
- Relay storage: in-memory registry is fine until relay-log; OK to pick sqlite (or similar) when #31 needs durability, or prefer a different store?
