# RULES.md — Identity Layer (ContentFilter)

> Non-negotiables extracted from CLAUDE.md, THREAT_MODEL.md, and hard-won experience.
> **Claude Code** owns the codebase. **Cowork** owns strategy/docs/non-code tasks. Both obey this file.

## Product Identity

1. This is **self-imposed accountability software, not stalkerware**. Anti-stalkerware properties are design invariants: no silent install (interactive local consent required), no silent presence (non-dismissible tray badge), no togglable `adult` filter field. Any change eroding these is rejected regardless of who asks.

## Security — Non-Negotiables

1. **Never hand-roll cryptography or randomness.** `ed25519-dalek`, `crypto_box`, `hmac`/`sha2` are the deliberate choices. (Hand-rolled hex in `core/src/hex.rs` is fine — formatting, not a primitive.)
2. **Never commit private key material.** `tools/check_no_private_keys.sh` is a backstop, not the control — real keys are generated offline per `docs/KEY_CEREMONY.md` and never touch this machine.
3. Security-relevant code gets a design debate BEFORE implementation (write out rejected alternatives), then a self-redteam after. Include "landmine" tests that fail loudly if a protection is quietly removed.

## Process — Non-Negotiables

1. DoD checkboxes on GitHub issues are checked only when **honestly true**; gaps get an explaining comment. An issue closes only when its boxes are checked or remaining work is explicitly out of scope.
2. Local test builds are broken (Smart App Control): verification happens in CI only. Push and watch runs; multiple round-trips are normal. Never "reason harder" instead of running CI. Never suggest disabling Smart App Control.
3. `gh issue comment/edit` uses `--body-file` only — never inline bodies with backticks.
4. Commits: repo-local identity (`mhamlaoui`), **no `Co-Authored-By: Claude` trailer**.
5. Dependencies added to `cf-core` are weighed more heavily than anywhere else (linked by every platform). Read the actual downloaded crate source when an API is uncertain.
6. Reproducible releases need `--remap-path-prefix` **and** `-C link-arg=/Brepro` on Windows — see `docs/REPRODUCIBLE_BUILDS.md`.
7. MEMO.md entries and issue comments reference real commit SHAs and CI run URLs — the repo history is the source of truth.
