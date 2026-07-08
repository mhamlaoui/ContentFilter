# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-08 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Continue the **e-service** epic. `svc-skeleton` (#39) landed this session, so its dependents are now unblocked:
  - `svc-config-anchor` — config load + server-anchor validation (also needs `relay-registry-pairing`, done). Security params come from the signed anchor, not local config; refuse a partner key / cooling-off weaker than the anchor; emit AnchorMismatch on swap, ConfigChanged on unmanaged edits; anchor pinned at install. Builds on `cf-core`'s anchor trust model (KNOWLEDGE 2026-07-06) — pinning is *this* ticket's job.
  - `svc-ipc` — named-pipe IPC server (HMAC, requests-only). DoD includes "IPC alone cannot apply a weakening without a partner signature" — preserve the Locked=ApprovalOnly invariant (KNOWLEDGE 2026-07-05).
  - `svc-resolver` — embedded filtering DNS resolver + ECH strip (also needs `relay-feeds`, done).
  - (later in the wave: `svc-egress-wfp`, `svc-approvals`, `svc-watchdog`, etc. — check BACKLOG wave order + each issue's Blocked-by.)
- [ ] `relay-deploy` (#38): last relay ticket besides push — durability (sqlite decision), real SMTP exercise, data-minimization audit, backups. Ops + persistence refactor behind existing seams.
- [ ] `relay-push` (#36): **human-gated** — needs APNs/FCM sandbox credentials. Push-token registration must get the same partner-key authorization scrutiny as contact email (KNOWLEDGE 2026-07-06, alert redirection).
- [ ] Still open: `core-uniffi-scaffold` (#27; **awaiting human answer** on Swift/Kotlin CI), `hard-doh-feed-ops` (#76), #21 fuzzing follow-up.

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human**; #19 blocked on #16; #20 design doc doesn't exist; #27 paused; #36 needs credentials — **human**.
- **No design doc** still bites e-service: `svc-skeleton`'s "ACLs match design §8.5" box is unchecked because §8.5 doesn't exist (implemented to the issue Deliverables shape instead). `svc-config-anchor` and others will hit the same nonexistent-doc DoD lines — keep flagging + leaving unchecked (pattern of #16/#20/#25).
- Standing: local `cargo test` broken (Smart App Control). `cargo build -p <crate>` / `clippy -p <crate>` (no --all-targets) work and — confirmed this session — DO compile Windows-only FFI non-test code (`cf-service`'s `scm.rs`), so SCM/WFP FFI has a real local build check; only test binaries are CI-only. `cf-relay` still needs `--no-default-features` locally (lettre icu build scripts).
- Session-env note: this session started in a permission mode that denied Write/Edit/gh; the user re-enabled edits partway through. If it recurs, surface it rather than retrying denied calls.

## Session Handoff

**What was done (2026-07-08, per MEMO.md):** `svc-skeleton` (#39) implemented and CI-green on both targets (runs 28971114311, 28971457047; commits `469b017` + `5fdfaa4`). Three of four DoD boxes checked; the §8.5 ACL box left unchecked (nonexistent doc). Issue #39 **not closed** (one box honestly unchecked).

**cf-service now:** a lib + bin. Cross-platform: `config` (required-field landmines + deny_unknown_fields), `logging` (size-based `RotatingLog` → tracing `MakeWriter`), `run_service_body` (idle-until-stop skeleton, no work loop yet). Windows-only: `scm` (install/uninstall/start/stop/run + `service_main`, LocalSystem) and `acl` (`harden_dir` → SYSTEM full / Admin read-only / Users none via icacls). `console` mode runs the body in the foreground. Config surface `service.toml`: `data_dir` + `[log]{max_size_bytes, keep_files, level=default "info"}`.

**Resume point:** pick `svc-config-anchor` next (natural successor; anchor-pinning-at-install slots right onto the skeleton's install path). Debate first: how the pinned anchor is stored/validated against local config, what AnchorMismatch/ConfigChanged detection looks like, and where "refuse weaker-than-anchor" lives (likely cf-core reused). Read cf-core's anchor trust model + the Locked=ApprovalOnly invariant before writing.

**Open questions for the human:**
- #36 APNs/FCM sandbox credentials, when ready.
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Is the svc-skeleton ACL policy (SYSTEM full / Admin read / Users none) the intended design §8.5? If so, whoever writes the doc can bless it and the box gets checked.
