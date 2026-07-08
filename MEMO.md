# Project memo

Running log of work done on ContentFilter. Append new entries at the
bottom of the relevant date; don't rewrite history. Each entry should
reference the actual commit SHA(s) and GitHub issue(s) so this stays
verifiable against the real history rather than becoming its own source of
truth.

---

## 2026-07-02 — Backlog automation

- `create_backlog.sh`, `BACKLOG.md`, `README.md` added (pre-existing,
  authored outside this log's tracking).
- Repo initialized; `git commit cc2f01a` — "Initial commit" (a one-line
  README placeholder from GitHub's own repo creation, later merged with the
  backlog-automation README).

## 2026-07-03 — Foundations epic

- **Fixed a real bug in `create_backlog.sh`** before it could run: a bare
  `return` in `create_one()`'s dry-run branch inherited the exit status of
  a false `&&` test, which killed the whole script under `set -e` after
  the very first item. Fixed with `return 0`.
- Ran the script for real against `mhamlaoui/ContentFilter`: 90 issues (13
  epics + 77 tasks), 17 labels, 4 milestones, 1 Project (v2) board.
  (`gh` CLI had to be installed via winget first; `project` OAuth scope
  granted interactively.)
- `f-repo-scaffold` (#14, closed): Cargo workspace scaffolded — `core`,
  `service`, `tray`, `guardian`, `relay`, `screen-cv`,
  `installer/custom-actions`. `cargo build`/`fmt`/`clippy` all pass.
  Commit `2dd0cea`.
  - Found along the way: the `installer/custom-actions` cdylib crate's test
    harness tripped Windows' legacy "Installer Detection" heuristic
    (renamed package from `cf-installer-custom-actions` to
    `cf-custom-actions`), then hit a Smart App Control block on the
    cdylib-derived test binary (see below) — disabled its test harness
    (`test = false`) since it had no tests yet anyway.
- `f-ci` (#15, closed): `.github/workflows/ci.yml` — Windows+Linux matrix,
  fmt/clippy/build/test gates, `Swatinem/rust-cache`. Commit `9179e9b`.
- `f-threat-model-doc` (#17, **open** — needs human sign-off):
  `THREAT_MODEL.md` — 30-row threat→control→test traceability table
  derived from every `security/invariant`-tagged ticket in `BACKLOG.md`,
  plus a trust-model section and explicit residuals. Commit `9179e9b`.
- `f-secrets-keymgmt` (#16, **open** — needs an actual offline key
  ceremony): `docs/KEY_CEREMONY.md`, `tools/fingerprint.sh`,
  `tools/check_no_private_keys.sh` (CI-verified to actually catch a planted
  fake key, not just pass on a clean tree), `keys/README.md`. Deliberately
  did **not** generate a real keypair — this sandboxed, network-connected
  machine is exactly what the offline-key invariant exists to exclude.
  Commit `9179e9b`.
- `f-test-harness` (#18, closed): `cf-test-harness` crate — hand-rolled toy
  DNS-over-UDP fixture (sinkhole/resolve) and real (temporary)
  firewall-rule egress helpers, standing in for `svc-resolver`/
  `svc-egress-wfp`. Commit `9179e9b`, with real bugs found and fixed via
  CI afterward:
  - `f3be98c` — Windows `netsh` rule used `localport` instead of
    `remoteport` (wrong field for an outbound rule; never actually
    blocked anything).
  - `193420e` — Windows routes same-host TCP through a fast path that
    bypasses outbound filtering even against a real (non-loopback)
    interface IP, not just 127.0.0.1. Switched the Windows assertion to
    verify the firewall rule's own state (`rule_blocks_port`) instead of a
    live connection; kept the live-connection assertion on Linux, where
    `iptables OUTPUT` doesn't have this problem.
  - `9b740d7`, `e783e8c` — diagnostic/fix cycle that led to the above.
- `f-repro-builds` (#19, **open** — signing needs #16's key first):
  `rust-toolchain.toml`, `.github/workflows/release.yml` (builds every tag
  twice from independent checkouts, fails if hashes differ),
  `tools/build_release.sh`, `tools/verify_release.sh`,
  `docs/REPRODUCIBLE_BUILDS.md`. Commit `9179e9b`, fixed once more
  (`5343e6a` — `draft-release` job needed `gh release create --repo`
  explicitly since it never checks out the repo).
  - **Key finding, hard-won**: `--remap-path-prefix` alone does not make
    Windows builds reproducible. Building at a fixed path still produced
    different hashes across runs — the MSVC linker embeds a fresh random
    GUID/timestamp into the PE and its PDB on every link, unrelated to
    source paths. `-C link-arg=/Brepro` fixed it; confirmed byte-identical
    hashes across three independent checkouts at three different paths.
  - Actually pushed a real test tag (`v0.0.1-test`), watched the release
    workflow build twice on both OSes and produce a draft release, then
    deleted the test tag and draft release afterward (pure validation, not
    a real release).

## 2026-07-04 — core-models, core-crypto-approvals

- **Environment discovery**: Windows Smart App Control blocks any
  freshly-compiled unsigned binary from being spawned as a process,
  including `cargo test`'s test binaries and any crate's `build.rs`
  script binary. This retroactively explained the earlier
  `installer/custom-actions` test-harness failure (the "cdylib trips a
  DLL-characteristics heuristic" theory from 2026-07-03 was wrong — same
  root cause both times). User chose to leave it enabled and verify via
  CI only; see `CLAUDE.md` for the resulting workflow.
- `core-models` (#20, **open** — no design doc to match against):
  `SchemaVersion` (strict equality check, not `<=`), hex-encoded
  `Ed25519PublicKey`/`X25519PublicKey`/`Signature`/`HouseholdId`/
  `DeviceId` newtypes (hand-rolled hex, zero non-serde dependencies),
  `Device`/`DeviceRole`, `Household`/`TrustAnchor`/`Tier`, `FilterState`,
  `NotificationEvent`/`EventKind`. Commit `f7a4140`, fixed once
  (`139854a` — an off-by-one in my own landmine test's field count).
  - Design calls made without a doc, flagged for review: `FilterState` has
    no `adult` field at all (always-on by design, not a togglable
    preference); `DeviceRole::Partner` carries `seal_key` as enum data
    rather than an `Option` on `Device`, so a monitored device can't
    accidentally have one; `NotificationEvent`'s `EventKind` deliberately
    excludes weakening-lifecycle events, left for `core-weakening` to
    define when it lands.
- `core-crypto-approvals` (#21, **open** — real fuzzing not implemented,
  only a lighter stand-in): hand-rolled canonical binary encoding
  (domain-separated `ContentFilter-Approval-v1\0` tag, fixed field order,
  length-prefixed variable fields — deliberately not serde/JSON, since
  canonicalization ambiguity in a signed encoding is a forgery vector),
  Ed25519 sign/verify via `ed25519-dalek` using `verify_strict` (not the
  more obvious `verify`, which isn't fully strict about signature
  malleability). Commits `3b9ad22`, `f236b2c` (KAT pinned from a real CI
  run — both OSes produced byte-identical canonical bytes and signature).
  - Added `RequestId` to `core-models`' id family rather than defining it
    locally, since `svc-approvals`/`svc-ipc` also reference request ids.
  - Two hand-rolled deterministic property tests (`SplitMix64`-seeded,
    ~1000+ generated statements) stand in for real coverage-guided fuzzing
    without adding a `proptest` dependency to `cf-core`.

## 2026-07-05 — core-crypto-sealing, core-timeanchor, core-hashchain, relay-bootstrap

- `core-crypto-sealing` (#22, closed): X25519 sealed-box via `crypto_box`
  (libsodium-compatible anonymous sealing), `salted_request_hash`
  (HMAC-SHA256) for dedup without revealing the sealed domain. Commits
  `43feaed`, `0bb028d` (fixed `SecretKey.as_bytes()` → `.to_bytes()` — the
  two key types have different APIs and I mixed them up), `35aa2b3` (KAT
  pinned).
  - First and only place this crate touches randomness: sealing needs a
    fresh ephemeral X25519 keypair per call, unlike Ed25519 signing
    (deterministic).
  - My first guess at `crypto_box`'s API (top-level `seal()`/`seal_open()`
    functions) was wrong; the real API is `PublicKey::seal()`/
    `SecretKey::unseal()` behind a `seal` cargo feature. Found by reading
    the downloaded crate source directly rather than guessing twice — see
    `CLAUDE.md`'s dependency policy.
  - `salted_request_hash` implements the primitive faithfully but
    documents rather than invents the protocol: the "doesn't reveal
    domain" property depends entirely on the salt never reaching the
    relay, and where that salt actually comes from is left for
    `relay-approvals-transport`.
- `core-timeanchor` (#24, closed): signed `(utc, seq)` beacons,
  `TimeAnchor`/`FloorStore` trait. Commits `273fa4e`, `0040831` (KAT
  pinned).
  - Resolved a real contradiction in the ticket's own deliverables before
    writing code: "effective_now = max(local, floor)" used for *both*
    expiry and activation checks would let a forward local-clock jump
    pre-activate a `not_before` gate. Fixed by treating the two checks
    asymmetrically — expiry uses `max(local, floor)`, activation
    (`has_reached`) uses the floor alone and doesn't even accept a
    local-time parameter, making the fix a type-level guarantee.
  - `FloorStore` is a trait (not a hardcoded file path) since `cf-core` has
    no I/O of its own — it's shared via UniFFI with iOS/Android.
- `core-hashchain` (#23, closed): `ChainedEvent`, `verify_chain` with a
  `DeviceKeyResolver` trait, `find_gaps`. Commits `5e8e75d`, `a2608ea`
  (fixed an unused-variable compile error caught by CI's
  `cargo build --all-targets`, the same local blind spot as sealing's
  `.as_bytes()` bug).
  - `ChainedEvent` deliberately doesn't reuse `NotificationEvent`'s
    `EventKind` — chain integrity is orthogonal to the application event
    taxonomy.
  - Fork detection intentionally **not** implemented — re-reading the
    backlog, that's `relay-log`'s DoD line, not this ticket's.
- `relay-bootstrap` (#28, closed): the hardest ticket so far. `cf-relay`
  lib+bin, axum HTTPS backbone with **no plaintext mode existing in the
  code at all** (not just off by default). Commits `c694efc`, `f8032e0`,
  `20aae18`, `8e48caa`, `e8b60aa` — six CI round-trips total, three
  distinct real bugs:
  1. **`axum-server` 0.6.0 is genuinely incompatible with current axum.**
     Its `bind_rustls().serve()` unconditionally calls hyper-util's
     `serve_connection_with_upgrades`, whose trait bounds axum's current
     body type doesn't satisfy. Ruled out simple version-skew first
     (pinned axum to 0.7.5, unified `tower` across the graph — same error
     either way) before concluding it's unfixable via pinning. Hand-rolled
     the TLS accept loop with `tokio-rustls` + `hyper-util` directly
     instead, which also let this crate pick rustls's pure-Rust `ring`
     backend explicitly over the default `aws-lc-rs` (a C library needing
     cmake — not worth it given how much `f-repro-builds` had to work out
     for pure-Rust reproducible builds).
  2. **rustls 0.23 crypto-provider ambiguity** once `reqwest` (dev-dep,
     tests only) unified in `aws-lc-rs` alongside this crate's `ring`
     choice. Fixed with an explicit, public
     `ensure_crypto_provider_installed()`, called both internally and at
     the top of every test (an async-spawned server's internal install
     could otherwise race a test's own reqwest client initialization).
  3. **The actual graceful-shutdown bug**: a `JoinSet`-based "wait for
     connection tasks to finish" approach hangs forever on an HTTP/1.1
     keep-alive connection, since that task doesn't finish just because
     the accept loop stops — it waits for a possible next request until
     the *client* closes it. Switched to
     `hyper_util::server::graceful::GracefulShutdown`
     (confirmed the API by reading hyper-util's own `server_graceful`
     example); had to bump the locked `hyper-util` from 0.1.3 (no graceful
     module at all) to 0.1.20.
  - Also fixed two of my own test bugs: a too-strict assertion that
    plaintext gets *zero* bytes back (it correctly gets a 7-byte TLS alert
    record instead — 5-byte record header + 2-byte alert body, an exact
    match), and a shutdown test that raced itself by sending the shutdown
    signal before the request future was ever polled.
- `CLAUDE.md`, `MEMO.md` added — instructions for future sessions and this
  running log.
- Hive Mind layer committed (`c19732d`): `RULES.md` (non-negotiables),
  `KNOWLEDGE.md` (append-only reusable knowledge), `STATE.md` (volatile
  session handoff), `.claudeignore`; CLAUDE.md gained the layer's
  description and startup sequence. Authored by Cowork the same day,
  committed by the following Claude Code session.
- `core-weakening` (#25, closed): `core/src/weakening.rs` — the weakening
  state machine. Commit `2a2c633`, CI green on both OSes on the **first**
  round-trip (a first for a test-heavy ticket here):
  https://github.com/mhamlaoui/ContentFilter/actions/runs/28752690733
  - Policy matrix defined in-repo (the "design section 7.3" it references
    doesn't exist — same handling as #20/#21): strengthen → Instant;
    weaken → DelayOrApproval (Hardened) / ApprovalOnly (Locked); all 22
    (change × tier) rows pinned by a table-driven test with a
    compile-time exhaustiveness guard.
  - Clock rules: `requested_at = max(local, floor)`; cooling-off
    completion is floor-only (`has_reached`), so no weakening becomes
    effective without post-request relay contact; expiry checks
    (approval windows, temporary weakenings) use `max(local, floor)`.
    Two honest residuals documented in THREAT_MODEL.md in the same
    commit (understating requested_at needs rollback + beacon starvation
    together; auto-revert can be delayed by the same combination).
  - Approvals **and** vetoes are Ed25519-verified inside the machine at
    the point of consequence (vetoes signed to prevent log
    misattribution); the signed target binds change + duration
    (`canonical_target`); domains are unrepresentable — `UnblockDomain`
    carries only `salted_request_hash` output, so requests/events are
    relay-safe by construction.
  - `EventKind` gained the weakening lifecycle variants event.rs had
    reserved (no separate `WeakeningApproved`; `WeakeningEffective.via`
    records cooling-off vs partner approval).
    `TimeAnchor::floor_utc()` made public for grant timestamps.
- `core-relay-client` (#26, closed): `core/src/relay_client.rs` — sans-I/O
  relay client over a synchronous `RelayTransport` trait (no HTTP dep in
  cf-core; the DoD's "mock relay" is a mock transport, everything above
  the seam is real). Commits `a6d3a8e`, `63e4c1d`, `7eb0d5a`; green run
  https://github.com/mhamlaoui/ContentFilter/actions/runs/28756805635 —
  three round-trips, one genuine CI-caught bug:
  - **`checked_shl` guards the shift amount, not value overflow** —
    `u32::MAX << 1` silently drops the top bit, so `Backoff` at the cap
    *shrank* its delay. Widened the arithmetic to u64.
  - Feed trust = pinned release key (`verify_strict`) + kind binding (a
    validly-signed DoH feed must not pass as a blocklist) + per-kind seq
    monotonicity (client-side downgrade protection). Feed schema version
    lives in the domain tag, following ApprovalStatement.
  - Outbox never silently drops: flush stops at the first failure and
    keeps the failed event plus everything behind it. Approvals received,
    not verified, in transit — the end-to-end test proves partner-sign →
    relay → receive → `weakening::apply_approval` → effective.
  - Registration checks the relay's echo (identity-key swap = hijacked
    enrollment). Anchor *signature* explicitly not verified here — no
    canonical anchor encoding exists yet; that's svc-config-anchor's job.
  - `ChainedEvent` gained serde (hex fields; canonical signed encoding
    untouched); reserialized chains still verify (test).
- Post-close redteam of #26 (`7a5a497`, green run 28757162626, first
  try): split `ClientState` (serde) from `RelayClient` (pinned release
  key, no serde impls) so a tampered state file structurally cannot swap
  feed trust; loud asserts on the truncating length casts in both signed
  canonical encodings (feed + hashchain — wrapped length prefixes are a
  canonicalization-ambiguity forgery vector); `FeedKind` tag bytes pinned
  by landmine.

## 2026-07-06 — relay-auth

- `relay-auth` (#29, closed): `core/src/request_auth.rs` (signed bytes,
  shared by every platform) + `relay/src/auth.rs` (stateful verdicts:
  registry lookup via the existing `DeviceKeyResolver` trait, timestamp
  window, per-device nonce store). Commits `8e4b978`, `6179400` (KAT
  pin); green run
  https://github.com/mhamlaoui/ContentFilter/actions/runs/28769161796 —
  two round-trips, no real bugs (first push failed only on the deliberate
  `PENDING_CI_RUN` KAT; tuple assert delivered both values in one run).
  - `AuthStatement` binds device_id + method/path + sha256(body) + ts +
    nonce; the relay compares its own routing context and recomputed body
    hash against the signed claims (endpoint-replay and body-swap both
    have negative tests). No `household_id` inside — the registry stays
    the single source of truth for membership.
  - Eviction invariant: a nonce is forgotten exactly when its signed ts
    goes stale, so a replay self-rejects on staleness from that moment —
    the window never reopens (boundary pinned by test). Future-dated ts
    beyond skew rejected (no banking one nonce for a far-future replay).
  - Check order (signature before nonce write) means unauthenticated
    traffic can't poison or grow the replay cache.
  - Axum middleware deliberately deferred to relay-registry-pairing
    (#30), which owns the wire framing and the first mutating endpoints.
- `relay-registry-pairing` (#30, closed): commits `22515f7`, `52bc1b6`
  (KAT pin); green run
  https://github.com/mhamlaoui/ContentFilter/actions/runs/28771055852 —
  two round-trips, only the deliberate KAT failure.
  - cf-core `household.rs` gained the anchor's canonical signable bytes +
    self-attestation (signed by the partner key it names — proves
    authorship of exactly these fields, nothing more; pinning stays with
    svc-config-anchor). `verify_signed_by()` for the rotation rule; tier
    bytes pinned.
  - `relay/src/registry.rs`: pure state machine (clock/RNG injected).
    Creation authenticated by the anchor itself + founding device
    registered atomically (resolves the relay-auth chicken-and-egg).
    Server-authoritative rule: replacement must verify against the
    *stored* anchor's key and strictly advance seq — a thief's fully
    self-consistent anchor is refused (test). Lost-key recovery + any
    rotation HTTP endpoint deliberately absent (sec-key-recovery's).
    Pairing codes: member-issued, single-use, 15-min TTL, atomic
    consume; failure reasons collapsed into one error. Registry
    implements `DeviceKeyResolver` → relay-auth reads registration
    directly.
  - `relay/src/http.rs`: endpoints + relay-auth wire format (four
    `x-cf-*` headers; method/path/body taken from the received request,
    so endpoint/body binding is constructive, not checked).
    `POST /v1/pair` speaks core-relay-client's
    RegisterRequest/RegisterResponse. End-to-end test: create → signed
    code issue → pair → joiner authenticates its own request → code
    dead; HTTP-level replay rejected. Deps: ring (already rustls's
    backend) for codes/ids; tower (dev) for Router::oneshot.
  - Process lesson: verify multi-line KAT hex literals against the CI
    value programmatically before pushing — an eyeballed split was off
    by three chars (caught locally, no round-trip wasted).
- `relay-timeanchor` (#33, closed): commit `a9e8e59`, green on the
  **first** round-trip
  (https://github.com/mhamlaoui/ContentFilter/actions/runs/28781741584).
  - `GET /v1/time/beacon`: freshly signed beacon with **seq = utc** —
    restart-safe monotonicity with zero storage; relay clock rollback
    stalls floors instead of corrupting them; never signing future time
    preserves `floor ≤ real-now` (core-weakening leans on it). Rejected:
    persisted counter (needs durability #31 hasn't forced; a reset
    counter would brick every client floor).
  - Beacon key = online operational key via
    `RelayConfig::beacon_key_path` (64-hex seed file, required — no
    beacon-less mode). NOT the release key (air-gapped keys can't attest
    time continuously; bounded blast radius). `GET /v1/time/key` is
    provisioning convenience; the trust root is install-time pinning.
  - End-to-end test ingests the served beacon through a real
    TimeAnchor/FloorStore; tampered beacon rejected without floor
    movement. `ed25519-dalek` promoted to a full cf-relay dependency;
    `AppState::Default` removed (an implicit beacon key in prod would be
    a key nobody pinned).
- `relay-feeds` (#32, closed): commit `df90951`, first-round-trip green
  (https://github.com/mhamlaoui/ContentFilter/actions/runs/28787720432).
  - The relay serves, never signs: offline-signed FeedEnvelope JSON
    files load from `RelayConfig::feeds_dir` (required; may be empty) at
    startup, highest seq per kind kept; `GET /v1/feeds/{kind}
    ?newer_than=N` → 200 / 304 / 404.
  - Rejected: relay-side signature verification (second pinned copy of
    the release key that can drift, zero security gain — clients verify
    regardless; publish-time validation is #76's) and an authenticated
    upload endpoint (new authz class duplicating scp + restart). Corrupt
    feed files fail startup loudly, naming the file.
  - DoD's client rows proven against served bytes via cf-core's real
    RelayClient (accept valid, reject tampered). `serde_json` promoted
    to full dependency; `AppServices` bundle introduced for
    run_with_listener.
- `relay-heartbeat-silence` (#34, closed): commit `75785ee`,
  first-round-trip green (run 28809090335). Pure `SilenceTracker`
  (clock injected; kill/suspend/airplane = heartbeats just stop);
  enrollment seeds liveness; one DeviceSilent per outage (idempotent
  sweeps), DeviceResumed clears + re-arms; `POST /v1/heartbeat` signed +
  replay-guarded; threshold = code constant (15 min) until svc-heartbeat
  fixes the cadence contract; events land in a bounded in-memory buffer
  (drop-oldest, warned) — stand-in until #31 persisted + #35/#37
  deliver; sweeper spawns in `app()`, not `router()`.
- `relay-log` (#31, closed): commit `33b4bd3`, first-round-trip green
  (run 28809587235). **Household log = set of per-device chains** (a
  shared chain can't exist under offline writers; per-device streams
  are the audit unit `verify_chain` walks). Server stricter than the
  verifier: contiguous seqs from 1 (outbox guarantees in-order
  delivery, so a server-side gap = lost/withheld history). Outcomes:
  Appended / Duplicate (bit-identical resend, idempotent — lost-ack
  retries) / Fork (same seq, different bytes) / SeqGap / BrokenLink /
  SeqPruned (no fork verdict once bytes are gone). Prune keeps
  head_hash/next_seq (continuity preserved, truncation visible via
  pruned_before). HTTP: signed push (author-only, membership-checked) +
  signed member log fetch; end-to-end test runs cf-core verify_chain
  over HTTP-fetched bytes. cf-core: `verify_event_signature` made pub.
  Named follow-up: client-side pruned-suffix verification needs a
  non-genesis-anchored verify_chain variant (whoever consumes the read
  API). Durability = relay-deploy (#38), same seam story as the
  registry.

---

## 2026-07-08 — svc-skeleton (e-service epic opener)

- `svc-skeleton` (#39, **not closed** — one DoD box honestly unchecked):
  `cf-service` is now a lib + bin instead of an empty stub. Commits
  `469b017` (skeleton) + `5fdfaa4` (ACL read-only correction). Both CI
  targets green first push each:
  runs/28971114311 and runs/28971457047.
  - **installs/starts/stops via SCM** (checked): `scm.rs` on
    `windows-service` 0.7. Installed image runs `cf-service run --config
    <abs>`; `service_main` registers a control handler and reports
    StartPending→Running→Stopped. `tests/scm_lifecycle.rs` drives the real
    built exe (`env!("CARGO_BIN_EXE_cf-service")`) create→Running→stop→
    delete, guarded by `scm::can_manage()` so it skips (not fails) when
    unelevated.
  - **runs as LocalSystem** (checked): `account_name: None` at install;
    test asserts `query_config().account_name == "LocalSystem"`.
  - **logs rotate at size limit** (checked): `logging.rs` hand-rolled
    size-based `RotatingLog` as a tracing `MakeWriter` (tracing-appender
    is time-only). Property tests: rotate-on-limit, no-byte-loss across
    generations, drop-past-keep_files, over-limit-single-record landmine,
    restart-seeds-size; plus an end-to-end tracing→JSON-lines test.
  - **ACLs match design section 8.5** (UNCHECKED): §8.5 doesn't exist
    (pattern of #16/#17/#19/#20/#21). Implemented `acl.rs` to the issue's
    Deliverables shape instead — SYSTEM full, Admin **read-only**
    (`(OI)(CI)RX`), Users/Everyone none, inheritance stripped — via
    `icacls` with well-known SIDs. First cut granted Admin Full;
    corrected in `5fdfaa4` because an admin-level monitored user must not
    silently rewrite the accountability record. Landmine test parses
    `icacls` output: SYSTEM `(F)`, Administrators not `(F)`, no broad
    principals.
  - CI passed on the **first push both times** (like core-weakening):
    non-test code build+clippy verified locally on this Windows host
    (`scm.rs` compiles here), pre-push audit of the CI-only test code,
    `--locked` checked after adding `serde_json` dev-dep.
  - Environment note: this session's permission mode initially denied
    Write/Edit/gh; user re-enabled edits mid-session.

---

## Open items with partial progress (as of 2026-07-05)

| Issue | Ticket | What's done | What's blocking full closure |
|---|---|---|---|
| #16 | f-secrets-keymgmt | Runbook, fingerprint tooling, CI guard | An actual offline key ceremony (human action, air-gapped machine) |
| #17 | f-threat-model-doc | THREAT_MODEL.md written | Human review/sign-off of the trust-model framing and residuals |
| #19 | f-repro-builds | Reproducibility proven and CI-gated; verify tooling built | Signing needs #16's key first |
| #20 | core-models | All types implemented, 21 tests | No design doc exists to check the "matches section 13.8/14" box against |
| #21 | core-crypto-approvals | Sign/verify/KAT/tamper tests all pass | "Fuzz the canonical encoder" — only a lighter property-test stand-in exists, not real coverage-guided fuzzing |

## Next unblocked tickets (per BACKLOG.md wave order)

- ~~`core-weakening`~~ — done (#25 closed, `2a2c633`)
- ~~`core-relay-client`~~ — done (#26 closed, `a6d3a8e`..`7eb0d5a`, hardened `7a5a497`)
- ~~`relay-auth`~~ — done (#29 closed, `8e4b978` + `6179400`)
- ~~`relay-registry-pairing`~~ — done (#30 closed, `22515f7` + `52bc1b6`)
- ~~`relay-timeanchor`~~ — done (#33 closed, `a9e8e59`)
- ~~`relay-feeds`~~ — done (#32 closed, `df90951`)
- ~~`relay-heartbeat-silence`~~ — done (#34 closed, `75785ee`)
- ~~`relay-log`~~ — done (#31 closed, `33b4bd3`; durability question
  moved to relay-deploy #38 where it belongs)
- ~~`relay-approvals-transport`~~ — done (#35 closed, `1702d25` +
  `00fe0b7`). Mailbox model (per-recipient seqs, pull w/ client floor);
  verdict wire encoding defined here; sealed bytes routed unchanged +
  relay-cannot-decrypt + full verdict spine proven end to end; mailbox
  is NOT the record — the chain is (drop test); rate-limit by salted
  request hash. CI-caught bug: sign path-AND-query, not path (query
  params now ride inside signatures).
- ~~`relay-email-fallback`~~ — done (#37 closed, `5601688` + `cfe80bd` +
  `9861b1c`). Partner-key-authorized contact email (role labels don't
  authorize alert redirection); dispatcher at point of detection
  (silence / log anomalies / critical chained event_types, all three
  tested incl. no-re-alert-on-duplicate); EmailOutbox pure retry state,
  sends outside the lock, loud give-up at 8 attempts; lettre behind a
  DEFAULT-ON `smtp` feature (SAC blocks icu build scripts locally —
  local dev uses --no-default-features; a no-feature binary refuses to
  start). RelayConfig gains required [smtp] table.
- `relay-push` (#36) — unblocked by #35, but needs APNs/FCM sandbox
  credentials — **human-gated external dependency**.
- `hard-doh-feed-ops` (#76) — unblocked by #32 (ops/tooling).
- `core-uniffi-scaffold` (#27; blocked by core-weakening + core-relay-client —
  both now done). Closes out the e-core epic; needs new CI surface
  (UniFFI codegen + Swift/Kotlin build jobs) — human input requested.
- `svc-skeleton` (#39; e-service epic; blocked by core-models only — done). Different
  risk profile from everything above: involves actually installing/starting/
  stopping a Windows service via SCM, not just application-level Rust.
