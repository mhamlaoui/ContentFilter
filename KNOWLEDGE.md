# KNOWLEDGE.md — Knowledge Layer (Append-Only, ContentFilter)

> ⚠️ **APPEND-ONLY.** Never rewrite, reorder, or delete entries. New entries at the BOTTOM of the matching section.
> Format: `- [YYYY-MM-DD] [source: claude-code | cowork | human] <entry>`
>
> Division of labor with existing docs: **MEMO.md** stays the commit-referenced work log (what was done, when).
> This file holds *reusable* knowledge: decisions, gotchas, lessons. Don't duplicate MEMO entries here.

---

## Architectural Decisions

- [2026-07-05] [source: cowork] Hive Mind layer added around existing docs: RULES.md (invariants), this file (reusable knowledge), STATE.md (volatile). CLAUDE.md remains the operating guide; MEMO.md remains the work log.
- [2026-07-05] [source: human, via CLAUDE.md] `cf-core` is linked by every platform (Windows, relay, future UniFFI iOS/Android) — dependency additions there carry the highest bar.
- [2026-07-05] [source: human, via CLAUDE.md] There is NO design doc in this repo despite ticket DoD references to one. Say so explicitly (pattern: issues #16, #17, #19–21); never invent content to match a phantom doc.
- [2026-07-05] [source: claude-code] Weakening clock rules (core-weakening, #25): `requested_at = max(local, floor)`; cooling-off completion is floor-only (`has_reached`) so it structurally requires post-request relay contact; expiry checks use `max(local, floor)`. Direction picks the primitive: "has time passed?" → floor only; "is it over?" → max. Reuse this for any new timed control; residuals in THREAT_MODEL.md.
- [2026-07-05] [source: claude-code] Locked-tier policy (core-weakening): every weakening is ApprovalOnly — no timeout path exists, generalizing lock-uninstall-approval. svc-approvals and lock-* tickets must preserve this; the matrix tests in weakening.rs will break loudly if it drifts.
- [2026-07-05] [source: claude-code] Privacy pattern: make domains *unrepresentable* in relay-bound types rather than stripped by discipline — `UnblockDomain` carries only `sealing::salted_request_hash` output, and the approval's signed target binds change + duration via `canonical_target`. Follow for any new relay-visible type.
- [2026-07-05] [source: claude-code] Verdict verification (approve AND veto) lives inside cf-core at the point of consequence; vetoes are partner-signed to prevent accountability-log misattribution. Service layers must not add an unsigned path to Effective/Vetoed.
- [2026-07-05] [source: claude-code] cf-core network code is sans-I/O: `RelayTransport` is a synchronous trait seam (like FloorStore/DeviceKeyResolver); HTTP/async never enters cf-core. Platform crates implement transports; protocol logic (feed verification, outbox ordering, registration echo checks) stays in core where every platform shares it.
- [2026-07-05] [source: claude-code] Feed acceptance requires signature + kind + strict per-kind seq monotonicity — all three; every signed feed kind is a substitution candidate for every other without the kind check. Wire encodings for approvals are deliberately NOT defined in cf-core (no serde on ApprovalMessage) — relay-approvals-transport owns that; don't let a convenience derive become the de-facto format.
- [2026-07-05] [source: claude-code] Pinned trust roots (release key) never ride in persisted/serializable state — keep them constructor-only so a tampered state file can't swap trust (relay_client `ClientState` split). Landmine the persisted shape with an exact-keys assertion.
- [2026-07-06] [source: claude-code] Replay-guard eviction invariant (relay-auth): evict a nonce exactly when its *signed* timestamp goes stale (`ts + skew < now`) — a replay carries the same signed ts, so staleness rejects it from that instant and the window never reopens. Also reject future ts beyond skew (one nonce must not bank a far-future replay), and write the nonce store only after full verification (signature first) so unauthenticated traffic can't poison it.
- [2026-07-06] [source: claude-code] Signed-request statements bind method+path+sha256(body); the SERVER compares its own routing context and recomputed hash against the claims, never the claims against themselves. Anything the server "knows" independently must be cross-checked, not echoed.
- [2026-07-06] [source: claude-code] Anchor trust model (relay-registry-pairing): self-attestation (signed by the partner key the anchor names) proves authorship, not identity — pinning is svc-config-anchor's; the registry's rule is replacement-verifies-against-STORED-key + strict seq increase. A fully self-consistent thief anchor passes self-verification and must still be refused. Bootstrap chicken-and-egg (no device to sign the create request) resolved by letting the anchor's own signature authenticate creation, registering the founder atomically.
- [2026-07-06] [source: claude-code] Bearer-secret flows (pairing codes): CSPRNG-minted, single-use, short TTL, consumed atomically in one lock section; collapse all failure reasons into one error so probes learn nothing. Rejection paths must not consume the secret.
- [2026-07-06] [source: claude-code] Verify multi-line KAT hex literals against the CI-printed value PROGRAMMATICALLY before pushing (regex the literal out of the source, strip continuations, compare) — an eyeballed 4-line split was off by three characters. Cheap script, saves a whole CI round-trip.

## Framework Intel (Rust/Windows/CI gotchas)

- [2026-07-05] [source: human, via CLAUDE.md] Smart App Control blocks freshly-compiled unsigned binaries (incl. build.rs scripts) → `cargo test`/`--all-targets` unusable locally. Works: `cargo build -p <crate>`, `cargo clippy -p <crate>`, `cargo fmt --all -- --check`. Test code is CI-verified only.
- [2026-07-05] [source: human, via CLAUDE.md] `crypto_box` seal/unseal API differs from the common libsodium shape — read the downloaded crate source, not memory.
- [2026-07-05] [source: human, via CLAUDE.md] Checked-in Cargo.lock can pin stale versions (hyper-util locked at 0.1.3 had no `graceful` module; needed 0.1.20). Check `cargo tree -i <crate>` before declaring incompatibility.
- [2026-07-05] [source: human, via CLAUDE.md] MSVC linker embeds random GUID/timestamp per link — `/Brepro` link-arg required for byte-identical builds; `--remap-path-prefix` alone is not sufficient.
- [2026-07-05] [source: human, via MEMO.md] Windows "Installer Detection" heuristic trips on crate names containing "installer" — `cf-installer-custom-actions` renamed to `cf-custom-actions`.
- [2026-07-05] [source: human, via CLAUDE.md] CI KAT pattern: push `PENDING_CI_RUN` placeholder that panics printing the real value, then hardcode from CI output in a follow-up commit.
- [2026-07-05] [source: claude-code] `checked_shl` guards the shift *amount* (None only when shift ≥ bit width), NOT value overflow — `u32::MAX.checked_shl(1)` happily returns a value with the top bit dropped. For overflow-safe exponential growth, widen to u64 (or use `checked_mul`). Caught by CI in cf-core's Backoff.
- [2026-07-05] [source: claude-code] KAT pinning with multiple expected values: assert them as one tuple, not sequentially — a sequential first-assert panic hides the later actual values and costs an extra CI round-trip (happened on the feed KAT).

## Learnings

- [2026-07-05] [source: human, via CLAUDE.md] Backticks inside double-quoted `gh --body "..."` arguments execute as command substitution and silently eat words (happened twice) → always `--body-file` with a scratch file.
- [2026-07-05] [source: human, via MEMO.md] Bare `return` in a bash function under `set -e` inherits a false `&&` test's exit status and kills the script — use `return 0` explicitly.
- [2026-07-05] [source: human, via CLAUDE.md] CI round-trips find real bugs local reasoning can't (relay-bootstrap: 6 round-trips, 3 genuine bugs). Push early instead of over-reasoning about untestable code.
- [2026-07-05] [source: claude-code] core-weakening passed CI on the first round-trip (test-heavy ticket, ~28 tests). What differed from relay-bootstrap: pure logic over already-CI-proven primitives, plus a pre-push audit of test code for the known local blind spots (imports actually used, PartialEq/Debug on asserted types, serde internal-tag nuances like deny_unknown_fields not applying to tagged enums, const-constructibility). The audit is cheap — do it every time, but still don't skip the push.
