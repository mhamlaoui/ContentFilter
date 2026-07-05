# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-05 · **By:** cowork · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket per BACKLOG.md wave order — unblocked: `core-weakening`, `core-relay-client`, `svc-skeleton` (note: svc-skeleton touches Windows SCM — different risk profile)
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder (property-test stand-in exists)

## Current Blockers

- #16 (f-secrets-keymgmt): needs actual offline key ceremony — **human action, air-gapped machine**
- #17 (f-threat-model-doc): needs human review/sign-off of trust model + residuals
- #19 (f-repro-builds): signing blocked on #16's key
- #20 (core-models): DoD box unclosable — referenced design doc does not exist
- Standing: local `cargo test` broken (Smart App Control) — all test verification via CI round-trips

## Session Handoff

**What was done last session (2026-07-05, per MEMO.md):**
- `relay-bootstrap` (#28) closed after 6 CI round-trips / 3 real bugs (axum-server incompatibility, rustls provider race, keep-alive graceful-shutdown hang)
- CLAUDE.md + MEMO.md authored; Hive Mind layer (RULES/KNOWLEDGE/STATE/.claudeignore) added by Cowork

**Where things stand:**
- Foundations + early Core/Relay epics done; 5 issues open with partial progress (see Blockers)

**Next steps / resume point:**
- Start one of the three unblocked Wave tickets; read its GitHub issue Context/Deliverables/DoD first

**Open questions for the human:**
- Sign off on THREAT_MODEL.md (#17)? Schedule offline key ceremony (#16)?
