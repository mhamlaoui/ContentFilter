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

## Framework Intel (Rust/Windows/CI gotchas)

- [2026-07-05] [source: human, via CLAUDE.md] Smart App Control blocks freshly-compiled unsigned binaries (incl. build.rs scripts) → `cargo test`/`--all-targets` unusable locally. Works: `cargo build -p <crate>`, `cargo clippy -p <crate>`, `cargo fmt --all -- --check`. Test code is CI-verified only.
- [2026-07-05] [source: human, via CLAUDE.md] `crypto_box` seal/unseal API differs from the common libsodium shape — read the downloaded crate source, not memory.
- [2026-07-05] [source: human, via CLAUDE.md] Checked-in Cargo.lock can pin stale versions (hyper-util locked at 0.1.3 had no `graceful` module; needed 0.1.20). Check `cargo tree -i <crate>` before declaring incompatibility.
- [2026-07-05] [source: human, via CLAUDE.md] MSVC linker embeds random GUID/timestamp per link — `/Brepro` link-arg required for byte-identical builds; `--remap-path-prefix` alone is not sufficient.
- [2026-07-05] [source: human, via MEMO.md] Windows "Installer Detection" heuristic trips on crate names containing "installer" — `cf-installer-custom-actions` renamed to `cf-custom-actions`.
- [2026-07-05] [source: human, via CLAUDE.md] CI KAT pattern: push `PENDING_CI_RUN` placeholder that panics printing the real value, then hardcode from CI output in a follow-up commit.

## Learnings

- [2026-07-05] [source: human, via CLAUDE.md] Backticks inside double-quoted `gh --body "..."` arguments execute as command substitution and silently eat words (happened twice) → always `--body-file` with a scratch file.
- [2026-07-05] [source: human, via MEMO.md] Bare `return` in a bash function under `set -e` inherits a false `&&` test's exit status and kills the script — use `return 0` explicitly.
- [2026-07-05] [source: human, via CLAUDE.md] CI round-trips find real bugs local reasoning can't (relay-bootstrap: 6 round-trips, 3 genuine bugs). Push early instead of over-reasoning about untestable code.
- [2026-07-05] [source: claude-code] core-weakening passed CI on the first round-trip (test-heavy ticket, ~28 tests). What differed from relay-bootstrap: pure logic over already-CI-proven primitives, plus a pre-push audit of test code for the known local blind spots (imports actually used, PartialEq/Debug on asserted types, serde internal-tag nuances like deny_unknown_fields not applying to tagged enums, const-constructibility). The audit is cheap — do it every time, but still don't skip the push.
