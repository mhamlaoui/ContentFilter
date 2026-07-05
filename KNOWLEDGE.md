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
