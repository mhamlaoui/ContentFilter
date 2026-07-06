# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Next ticket: `svc-skeleton` (#39) — the e-service epic opener (Windows service host: SCM install/start/stop, LocalSystem, ACLs per a design section that doesn't exist [state that on the issue], rotating logs). **Different risk profile**: real SCM interaction; CI's windows-latest can install/start/stop services (admin runner), but tests need care — read MEMO 2026-07-03 for the Smart App Control history and the harness's netsh experience first. Ubuntu CI must skip the SCM tests (cfg(windows)).
- [ ] `relay-deploy` (#38): now the last relay ticket besides push; owns durability (sqlite decision), real SMTP exercise, data minimization audit, backups. Mostly ops + the persistence refactor behind the existing seams.
- [ ] `relay-push` (#36): **human-gated** — needs APNs/FCM sandbox credentials. Note from KNOWLEDGE: push-token registration must get the same partner-key authorization scrutiny as contact email (alert redirection).
- [ ] Still open: `core-uniffi-scaffold` (#27; **awaiting human answer** on Swift/Kotlin CI), `hard-doh-feed-ops` (#76), #21 fuzzing follow-up.

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human**; #19 blocked on #16; #20 design doc doesn't exist; #27 paused; #36 needs credentials — **human**
- Standing: local `cargo test` broken (Smart App Control). NEW: local `cargo build -p cf-relay` now needs `--no-default-features` (lettre's icu build scripts are SAC-blocked; default features remain correct for CI/releases — see KNOWLEDGE.md).

## Session Handoff

**What was done (2026-07-06, per MEMO.md):** EIGHT tickets closed: #29, #30, #33, #32, #34, #31, #35, #37. The relay epic is functionally complete except push (#36, credential-gated) and deploy (#38).

**The relay now:** enrolls households/devices (anchor-authenticated create, member-issued single-use pairing codes) · authenticates + replay-guards signed requests (path-AND-query inside signatures) · attests time (seq=utc beacons, online beacon key) · serves release-signed feeds (conditional GET) · tracks heartbeats → DeviceSilent/DeviceResumed · stores per-device hash chains (fork/gap detection, prune-keeps-head) · routes sealed requests + signed verdicts (mailboxes, rate-limited by salted request hash) · emails critical alerts over the independent channel (partner-key-authorized address, retries, default-on smtp feature).

**Config surface (relay.toml)**: bind_addr, tls_cert_path, tls_key_path, beacon_key_path, feeds_dir, [smtp]{host, port, username, password_path, from} — all required, each with a rejection landmine.

**Next steps / resume point:**
- `svc-skeleton` (#39): read the issue; debate the service-host crate choice (`windows-service` crate is the de-facto standard — read its actual API from the registry source per CLAUDE.md), how CI proves install/start/stop (windows-latest runners are admin; guard everything cfg(windows) + a Linux no-op), log rotation approach, and ACLs (no design section 8.5 exists — define in-repo, flag on the issue, pattern of #25/#30).

**Open questions for the human:**
- #36 APNs/FCM sandbox credentials, when ready.
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
