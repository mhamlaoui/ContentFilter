# Working on ContentFilter

Read this before picking up any ticket. It's the accumulated "don't
rediscover this the hard way" knowledge from building the Foundations and
early Core/Relay epics.

## What this project is

Self-imposed accountability software (like Covenant Eyes / Accountable2You),
**not stalkerware**. The design bakes in anti-stalkerware properties on
purpose: no silent install (`inst-consent-ui` requires interactive local
consent), no silent presence (`tray-monitored-badge` is non-dismissible).
Keep that framing in mind when making judgment calls — e.g. it's why
`FilterState` has no `adult` field (always-on, not a togglable preference)
and why enrollment requires real consent, not just a config flag.

Read `README.md`, `BACKLOG.md`, and `THREAT_MODEL.md` first. **There is no
design doc anywhere in this repo.** Several ticket DoD lines reference
"design doc section N" — that doc doesn't exist. Don't invent content and
pretend it matches a doc; say so explicitly (see how issues #16, #17, #19,
#20, #21 handle this) and leave the affected DoD box unchecked.

## Picking up a ticket

1. `BACKLOG.md`'s wave order is the recommended sequence — everything in a
   wave depends only on earlier waves. Check the GitHub issue for the exact
   Context/Deliverables/DoD before starting.
2. **Debate the design before writing code**, especially anything
   security-relevant. Write out the alternatives you're rejecting and why —
   see the last few commit messages and issue comments for the tone/depth
   expected (e.g. `core-timeanchor`'s effective_now vs. has_reached
   asymmetry, `core-crypto-sealing`'s salt-secrecy caveat).
3. Implement, then **redteam your own work**: what breaks it, what's the
   adversarial input, what did you assume without checking. Write tests
   named for the property they prove, not the code path. Include "landmine"
   tests — adversarial cases that fail loudly if a protection is later
   quietly removed (unknown-field smuggling, schema-version downgrade,
   truncated keys, tamper detection, etc.).
4. Verify for real (see the CI section below), then update the GitHub issue:
   check only the DoD boxes that are **honestly true**, leave the rest
   unchecked with a comment explaining the gap. Don't close an issue with
   unchecked boxes unless the remaining work is genuinely out of scope for
   that ticket (say so). This project's own README says "an issue is only
   closeable when its boxes are checked" — take that literally.

## Critical: local test builds are broken on this machine

**Windows Smart App Control is enabled and blocks any freshly-compiled,
unsigned binary from being spawned as a new process.** This includes:

- Any crate's `build.rs` script binary (e.g. `serde_json`'s build script) —
  blocks `cargo test` / `cargo build --all-targets` for **any** crate with
  such a dependency, even a dev-dependency.
- Test harness binaries themselves.

What still works locally: `cargo build -p <crate>` (no `--all-targets`) and
`cargo clippy -p <crate>` (same restriction) — these don't compile
`#[cfg(test)]` code at all, so they **do not catch bugs in test code**.
`cargo fmt --all -- --check` always works (no compilation involved).

**Practical consequence:** you cannot verify test code compiles, let alone
passes, on this machine. Every ticket that touches test code should expect
multiple CI round-trips: push, watch the run, read the failure, fix, repeat.
This is normal here, not a sign something is wrong. `relay-bootstrap` took
6 round-trips and surfaced three genuine bugs that local tooling could
never have caught. Don't skip pushing to "save a round trip" by reasoning
harder about test code instead of running it.

The user has explicitly chosen to leave Smart App Control enabled and
accept CI-only verification over weakening it. Don't suggest disabling it
again unless asked.

### CI workflow

```
git add -A && git commit -m "..." && git push origin main
gh run list --repo mhamlaoui/contentfilter --limit 2
gh run watch <run-id> --repo mhamlaoui/contentfilter --exit-status
# on failure:
gh run view <run-id> --repo mhamlaoui/contentfilter --log-failed
```

Both `windows-latest` and `ubuntu-latest` must pass. When a test needs a
fixed value only the real run can produce (a KAT signature, a computed
hash), push with a `PENDING_CI_RUN` placeholder that panics and prints the
actual value, then hardcode it from the failure output in a follow-up
commit — see any `known_answer_vector` test for the pattern.

## GitHub issue hygiene

- Use `gh issue comment/edit --body-file <path>`, **never**
  `--body "$(cat <<'EOF' ... EOF)"` inline with backticks in the text —
  backticks inside a double-quoted shell argument execute as command
  substitution and silently eat words. This has happened twice. Write the
  comment to a scratch file first, then `--body-file`.
- Reference the actual commit SHAs and CI run URLs in issue comments — this
  repo's history is the source of truth, and future readers (including
  future you) will want to jump straight to the relevant run.

## Git identity

Repo-local `user.name`/`user.email` are already configured
(`mhamlaoui` / `im.hamlaoui@gmail.com`). **Do not add a
`Co-Authored-By: Claude` trailer to commits** — the user explicitly asked
for commits to not show Claude as a co-author on this repo.

## Dependency policy

- **Never hand-roll cryptography or randomness.** `ed25519-dalek`,
  `crypto_box`, `hmac`/`sha2` are all deliberate, justified choices for
  exactly this reason. Hex encoding, by contrast, is hand-rolled in
  `core/src/hex.rs` on purpose — it's data formatting, not a security
  primitive, so hand-rolling it is fine and keeps `cf-core`'s dependency
  footprint small.
- `cf-core` is linked by every platform (Windows, relay, iOS/Android via
  future UniFFI bindings). Weigh new dependencies there more heavily than
  in `cf-relay` or other platform-specific crates.
- When a dependency's API is uncertain, **read the actual downloaded source**
  in `~/.cargo/registry/src/index.crates.io-.../<crate>-<version>/` before
  writing code against it, rather than trusting memory. This has caught
  real mistakes: `crypto_box`'s actual seal/unseal API differs from the
  more common `libsodium` shape, `hyper-util`'s graceful-shutdown API
  needed reading its own example, and a locked dependency version can be
  stale (checked-in `Cargo.lock` doesn't always have the version a feature
  needs — `hyper-util` was locked at 0.1.3 with no `graceful` module at all
  until bumped to 0.1.20).
- If a crate's latest version turns out incompatible with something else in
  the graph, verify it's not a simple version-skew issue (check with
  `cargo tree -i <crate>`) before concluding it's unfixable and routing
  around it — but also don't chase phantom version pins forever if the
  actual error is an inherent API mismatch (see `relay-bootstrap`'s
  axum-server writeup in issue #28 for both sides of this judgment call).

## Reproducible builds

`rust-toolchain.toml` pins the exact toolchain. For byte-identical release
builds, `--remap-path-prefix` alone is **not suffient** on Windows —
`-C link-arg=/Brepro` is required too (MSVC's linker embeds a fresh random
GUID/timestamp per link otherwise). See `docs/REPRODUCIBLE_BUILDS.md` and
`tools/build_release.sh` for the full recipe; don't rediscover this.

## Secrets

Never commit private key material. `tools/check_no_private_keys.sh` runs in
CI as a guard, but it's a backstop, not the actual control — the actual
control is that release/anchor private keys are generated offline per
`docs/KEY_CEREMONY.md` and never touch a machine that runs this repo's code.


## Hive Mind layer (added 2026-07-05)

This repo now has three companion files shared between Claude Code and Cowork:

- `RULES.md` — non-negotiables distilled from this file + THREAT_MODEL.md. Read it silently before writing or refactoring any code; if a request conflicts with it, flag the conflict instead of proceeding.
- `KNOWLEDGE.md` — **append-only** reusable knowledge (decisions, gotchas, lessons). Never rewrite or reorder entries; append with date + source. MEMO.md remains the commit-referenced work log — log *what happened* there, log *what to remember* in KNOWLEDGE.md.
- `STATE.md` — volatile session state (todos, blockers, handoff). **Rewrite it at the end of every session** so the next session resumes with zero re-explanation. An outdated STATE.md is a bug.

Startup sequence: RULES.md → STATE.md → relevant KNOWLEDGE.md sections → this file's ticket workflow.
