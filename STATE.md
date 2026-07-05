# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-05 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — unblocked: `core-relay-client` (#26; blockers core-models + core-hashchain both done) or `svc-skeleton` (#39; note: touches Windows SCM — different risk profile). #26 is the natural next: it finishes e-core's remaining chain and unblocks `core-uniffi-scaffold` (#27).
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder (property-test stand-in exists)

## Current Blockers

- #16 (f-secrets-keymgmt): needs actual offline key ceremony — **human action, air-gapped machine**
- #17 (f-threat-model-doc): needs human review/sign-off of trust model + residuals — **note: THREAT_MODEL.md gained two new residual entries in `2a2c633` (core-weakening clock design); review those too**
- #19 (f-repro-builds): signing blocked on #16's key
- #20 (core-models): DoD box unclosable — referenced design doc does not exist
- Standing: local `cargo test` broken (Smart App Control) — all test verification via CI round-trips

## Session Handoff

**What was done this session (2026-07-05, per MEMO.md):**
- Hive Mind layer files committed and pushed (`c19732d`), CI green
- `core-weakening` (#25) **closed**: commit `2a2c633`, CI green on both OSes on the first round-trip (run 28752690733), all 6 DoD boxes checked. Policy matrix defined in-repo (no design doc — flagged on the issue, pattern of #20/#21). THREAT_MODEL.md updated in the same commit.

**Where things stand:**
- e-core epic: only `core-relay-client` (#26) and `core-uniffi-scaffold` (#27, blocked by #26) remain
- Foundations + early Core/Relay epics done; 5 issues open with partial progress (see Blockers)

**Next steps / resume point:**
- Start `core-relay-client` (#26): read its GitHub issue Context/Deliverables/DoD first; it needs a mock relay in tests (offline queue + drain, signed-feed rejection). `svc-skeleton` (#39) is the alternative if #26 stalls.

**Open questions for the human:**
- Sign off on THREAT_MODEL.md (#17)? Two new residuals added in `2a2c633` need eyes too.
- Schedule offline key ceremony (#16)?
- Comfortable with the in-repo policy matrix decision on #25 (Locked = ApprovalOnly for *every* weakening)? It generalizes lock-uninstall-approval; flag now if that's too strict, while it's one module.
