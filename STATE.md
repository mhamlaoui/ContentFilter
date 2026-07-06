# STATE.md — State Layer (Volatile, ContentFilter)

> Fully rewritable. Reflects NOW only — history lives in MEMO.md (with commit SHAs), reusable knowledge in KNOWLEDGE.md.
> Updated at the end of every session.

**Last updated:** 2026-07-06 · **By:** claude-code · **Branch:** main

---

## Active Todo List

- [ ] Pick next ticket — unblocked: `relay-heartbeat-silence` (#34; missed-heartbeat threshold → DeviceSilent, resume clears, per-device tracking — needs a heartbeat ingest endpoint + a place for emitted events to go, which previews #31's design) and `relay-log` (#31; the substantial one — append-only chained log, gap/fork detection, household isolation, prune-keeps-head; **forces the durability debate, human question pending**). Suggested order: #34 first (in-memory tracking is honest for it), then #31 with the storage answer in hand.
- [ ] Also open: `core-uniffi-scaffold` (#27; **awaiting human answer**), `svc-skeleton` (#39; Windows SCM), `hard-doh-feed-ops` (#76; newly unblocked, mostly ops tooling — needs relay deploy reality first)
- [ ] #21 follow-up: real coverage-guided fuzzing

## Current Blockers

- #16 offline key ceremony — **human**; #17 THREAT_MODEL sign-off — **human**; #19 blocked on #16; #20 design doc doesn't exist; #27 paused on human CI call; #31 storage choice — **human question below**
- Standing: local `cargo test` broken (Smart App Control) — CI-only verification

## Session Handoff

**What was done (2026-07-06, per MEMO.md):**
- `relay-auth` (#29), `relay-registry-pairing` (#30), `relay-timeanchor` (#33), `relay-feeds` (#32) all closed — four relay tickets in one day, the last two first-round-trip green.
- **Config surface grew twice**: `RelayConfig` now requires `beacon_key_path` (64-hex Ed25519 seed file) AND `feeds_dir` (dir of offline-signed FeedEnvelope JSONs; may be empty). Existing relay.toml files need both.
- `AppServices` bundle (beacon key + feed store) now feeds `app()`/`run_with_listener`.

**Where things stand:**
- e-relay remaining: log (#31), heartbeat-silence (#34), approvals-transport (#35), push (#36), email-fallback (#37), deploy (#38).
- The relay now: enrolls households/devices (anchor-authenticated create, member-issued single-use pairing codes), authenticates mutating requests (four-header statement wire format), attests time (seq=utc beacons), serves release-signed feeds (conditional GET).
- Registry + replay guard in-memory behind seams; feeds immutable-after-load.

**Next steps / resume point:**
- Default: `relay-heartbeat-silence` (#34). Read its issue first. Design questions to settle: heartbeat = signed relay-auth request (reuse verify_mutating_request) at what endpoint; threshold/window config; where DeviceSilent events GO before relay-log exists (in-memory event buffer behind a seam, drained by #31/#35/#37 later — or do #31 first if that feels backward).
- Then `relay-log` (#31) with the human's storage answer.

**Open questions for the human:**
- Relay durability for #31: sqlite OK, or preferred alternative?
- #27 UniFFI CI surface — yes/no?
- THREAT_MODEL sign-off (#17); key ceremony (#16)?
- Locked = ApprovalOnly for every weakening (#25) — still comfortable?
