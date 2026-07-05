# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-05 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — unblocked: `core-uniffi-scaffold` (#27; closes out e-core; needs UniFFI toolchain + Swift/Kotlin CI jobs — new CI surface), `relay-auth` (#29; blockers relay-bootstrap closed, core-crypto-approvals functionally done), `svc-skeleton` (#39; Windows SCM risk profile)
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder (property-test stand-in exists)

## Current Blockers

- #16 (f-secrets-keymgmt): needs actual offline key ceremony — **human action, air-gapped machine**
- #17 (f-threat-model-doc): needs human review/sign-off of trust model + residuals — **note: THREAT_MODEL.md gained two residual entries in `2a2c633` (core-weakening clock design); review those too**
- #19 (f-repro-builds): signing blocked on #16's key
- #20 (core-models): DoD box unclosable — referenced design doc does not exist
- Standing: local `cargo test` broken (Smart App Control) — all test verification via CI round-trips

## Session Handoff

**What was done this session (2026-07-05, per MEMO.md):**
- Hive Mind layer committed (`c19732d`)
- `core-weakening` (#25) **closed**: `2a2c633`, CI green first round-trip, all 6 DoD boxes checked
- Quick self-review of the weakening diff: no findings
- `core-relay-client` (#26) **closed**: `a6d3a8e` + `63e4c1d` + `7eb0d5a`, green run 28756805635, all 3 DoD boxes checked; 3 CI round-trips, 1 genuine bug (checked_shl top-bit drop in Backoff — see KNOWLEDGE.md)

**Where things stand:**
- e-core epic: only `core-uniffi-scaffold` (#27) remains, and it is now unblocked
- 5 issues open with partial progress (see Blockers)

**Next steps / resume point:**
- Three viable next tickets, different risk profiles: #27 (UniFFI + new CI jobs for Swift/Kotlin), #29 (relay-auth: nonce/timestamp replay guard, pure Rust + axum), #39 (svc-skeleton: Windows SCM). #29 is the least new-tooling; #27 closes the epic but expect CI-workflow churn for binding builds.
- Note for #29 if picked: it can reuse `relay_client::RegisterRequest`/`RegisterResponse` shapes from `2a2c633`'s follow-up (`a6d3a8e`) — the client defined them first; keep both sides in sync.

**Open questions for the human:**
- Sign off on THREAT_MODEL.md (#17)? Two residuals added in `2a2c633` need eyes too.
- Schedule offline key ceremony (#16)?
- Comfortable with Locked = ApprovalOnly for *every* weakening (#25 comment)? Flag now while it's one module.
- For #27: OK to add UniFFI + Swift/Kotlin build jobs to CI (new toolchain surface), or prefer relay-auth/svc-skeleton first?
