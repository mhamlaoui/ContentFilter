# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — unblocked: `relay-registry-pairing` (#30; continues the accountability spine, first real mutating endpoints — wires #29's `verify_mutating_request` and owns the auth wire framing), `core-uniffi-scaffold` (#27; **awaiting human answer** on adding UniFFI + Swift/Kotlin CI jobs), `svc-skeleton` (#39; Windows SCM risk profile)
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder (property-test stand-in exists)

## Current Blockers

- #16 (f-secrets-keymgmt): needs actual offline key ceremony — **human action, air-gapped machine**
- #17 (f-threat-model-doc): needs human review/sign-off — note: THREAT_MODEL.md gained two residual entries in `2a2c633`
- #19 (f-repro-builds): signing blocked on #16's key
- #20 (core-models): DoD box unclosable — referenced design doc does not exist
- #27 (core-uniffi-scaffold): technically unblocked, but paused on the human's call re: new CI toolchain surface
- Standing: local `cargo test` broken (Smart App Control) — all test verification via CI round-trips

## Session Handoff

**What was done (2026-07-05 evening → 2026-07-06, per MEMO.md):**
- `core-weakening` (#25) closed — `2a2c633`, first-round-trip green
- `core-relay-client` (#26) closed — `a6d3a8e`..`7eb0d5a` + post-close redteam hardening `7a5a497` (release key out of persisted state; truncation guards on signed encodings; FeedKind tag bytes pinned)
- `relay-auth` (#29) closed — `8e4b978` + `6179400`, green run 28769161796, all DoD boxes checked, no real bugs (2 round-trips, one being the KAT pin)

**Where things stand:**
- e-core: only `core-uniffi-scaffold` (#27) remains (paused on human input)
- e-relay: bootstrap + auth done; registry/pairing (#30) is the next spine link
- 5 long-running partial issues unchanged (see Blockers)

**Next steps / resume point:**
- Default next: `relay-registry-pairing` (#30). Read its issue first. It owns: household registry storage, signed trust-anchor authority (needs a canonical anchor encoding — coordinate with the "anchor signature not verified in relay_client::register" boundary noted on #26), pairing codes with expiry, and mounting #29's `verify_mutating_request` on the first mutating endpoints (it also owns the statement's HTTP wire framing).
- Storage decision will come up: relay currently has no database dependency. Debate in-memory-behind-a-trait vs sqlite now; check BACKLOG's relay-deploy ("data minimization") before adding anything heavy.

**Open questions for the human:**
- #27: OK to add UniFFI + Swift/Kotlin build jobs to CI, or keep riding the relay/service tracks first?
- Sign off THREAT_MODEL.md (#17), incl. the two `2a2c633` residuals? Schedule key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25 comment) — still comfortable?
