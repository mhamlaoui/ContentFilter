# Reproducible builds

Every tagged release is built twice, from two independent checkouts, by
`.github/workflows/release.yml`, and the release job fails outright if the
resulting binaries don't hash-match byte-for-byte. This is a CI gate, not
just a claim in this document — see the `reproducible-build` job.

## What makes it reproducible

Three things, all required:

1. **A pinned toolchain.** `rust-toolchain.toml` pins an exact Rust version.
   Different compiler versions are not expected to produce identical output.
2. **`--remap-path-prefix`.** Normalizes the absolute checkout path embedded
   in debug info to a fixed placeholder (`/build`), so it doesn't matter
   whether you checked out to `/home/runner/work/...` or `C:\Users\you\...`.
3. **A linker flag that kills the embedded build GUID.** This is the
   non-obvious one. On Windows, the MSVC linker embeds a fresh random GUID
   and timestamp into the PE and its PDB on *every* link, purely to pair a
   binary with its debug symbols — this is unrelated to source paths and
   `--remap-path-prefix` cannot touch it. The fix is `-C link-arg=/Brepro`,
   a real MSVC linker flag for exactly this. Confirmed empirically: without
   it, two byte-identical source trees built at the very same path still
   produced different binaries; with it, two independent checkouts at
   different paths produced identical hashes. On Linux, the equivalent
   concern is `ld`'s build-id note; `-C link-arg=-Wl,--build-id=sha1` makes
   it content-derived instead of random.

`CARGO_INCREMENTAL=0` is also set — incremental compilation caches are a
plausible additional source of nondeterminism and there's no reason to risk
it for a release build.

The exact recipe lives in `tools/build_release.sh` (used identically by CI
and available for you to run locally) rather than duplicated here — read
that script for the literal flags.

## Reproducing a release yourself

```sh
git clone https://github.com/mhamlaoui/ContentFilter --branch <tag> repro-1
git clone https://github.com/mhamlaoui/ContentFilter --branch <tag> repro-2
(cd repro-1 && tools/build_release.sh) | tail -n +2 > repro-1.sha256
(cd repro-2 && tools/build_release.sh) | tail -n +2 > repro-2.sha256
diff repro-1.sha256 repro-2.sha256 && echo "reproducible"
```

Or more simply: run `tools/build_release.sh` once locally, drop the leading
`SHA256SUMS:` line, and diff the rest against the `SHA256SUMS` file attached
to the GitHub release for the same tag — that's comparing your build
against CI's, which is the more meaningful check for a third party.

## Verifying a published release

```sh
tools/verify_release.sh path/to/downloaded/release/assets/
```

Checks every file's checksum against `SHA256SUMS`. If `SHA256SUMS.sig` and
a pinned `keys/release-key.pub.pem` are both present, also verifies the
Ed25519 signature over `SHA256SUMS` — see `docs/KEY_CEREMONY.md` for why
that signature only exists on releases a maintainer has manually,
offline-signed, and why CI can never produce it itself.

An unsigned draft release (the state every tagged push produces
automatically) can only be checksum-verified, not signature-verified. That
is intentional, not a bug: matching checksums prove CI's two builds agreed
with each other, not that a maintainer endorsed the release.
