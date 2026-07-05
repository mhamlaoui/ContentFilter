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
- ~~`core-relay-client`~~ — done (#26 closed, `a6d3a8e`..`7eb0d5a`)
- `core-uniffi-scaffold` (#27; blocked by core-weakening + core-relay-client —
  both now done). Closes out the e-core epic.
- `relay-auth` (#29; blocked by relay-bootstrap (closed) + core-crypto-approvals
  (#21, open only for the fuzzing follow-up — functionally done, same basis on
  which core-weakening proceeded)).
- `svc-skeleton` (#39; e-service epic; blocked by core-models only — done). Different
  risk profile from everything above: involves actually installing/starting/
  stopping a Windows service via SCM, not just application-level Rust.
