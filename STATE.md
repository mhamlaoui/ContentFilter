# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — unblocked: `relay-feeds` (#32; serve release-signed FeedEnvelopes + conditional GET; cf-core sign/verify half exists — decide how signed feed files reach the relay, likely a config-dir of envelope JSONs), `relay-heartbeat-silence` (#34; heartbeat tracking + DeviceSilent emission — needs an events/notification story, may want to precede or fold into #31 thinking), `relay-log` (#31; the substantial one — append-only chained log, gap/fork detection, household isolation, prune-keeps-head; will force the durability debate)
- [ ] Also open: `core-uniffi-scaffold` (#27; **awaiting human answer** on Swift/Kotlin CI jobs), `svc-skeleton` (#39; Windows SCM)
- [ ] #21 follow-up: real coverage-guided fuzzing of the canonical encoder

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human** (incl. `2a2c633` residuals); #19 blocked on #16; #20 design doc doesn't exist; #27 paused on human CI call
- Standing: local `cargo test` broken (Smart App Control) — CI-only verification

## Session Handoff

**What was done (2026-07-06, per MEMO.md):**
- `relay-auth` (#29) closed — `8e4b978` + `6179400`
- `relay-registry-pairing` (#30) closed — `22515f7` + `52bc1b6`
- `relay-timeanchor` (#33) closed — `a9e8e59`, first-round-trip green. Beacons: seq=utc (restart-safe, storage-free), online beacon key via `RelayConfig::beacon_key_path` (NOT the release key; pinning at install is the trust root), `GET /v1/time/beacon` + `/v1/time/key`.
- Config surface changed: `RelayConfig` now REQUIRES `beacon_key_path` (64-hex Ed25519 seed file). Any existing relay.toml needs the new field.

**Where things stand:**
- e-relay: bootstrap, auth, registry/pairing, timeanchor done. Remaining: feeds (#32), log (#31), heartbeat-silence (#34), then approvals-transport (#35) → push (#36) / email (#37) → deploy (#38).
- e-core: only #27 (paused). Registry still in-memory behind its seam.

**Next steps / resume point:**
- Default next: `relay-feeds` (#32). Open design question to settle first: how do release-signed FeedEnvelopes get INTO the relay (config dir of signed envelope files loaded at startup + reloaded on change? an authenticated admin upload endpoint is more machinery + new authz class). Leaning config-dir: feeds are produced offline (release key), ops copies them in; hard-doh-feed-ops (#76) later automates.
- Then #34 or #31; #31 forces the storage decision (human question pending below).

**Open questions for the human:**
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
- Relay durability for #31: OK with sqlite (or preferred alternative) when the log needs it?
