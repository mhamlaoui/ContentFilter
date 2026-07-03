#!/usr/bin/env bash
# Reproducible release build. Run this from a checkout of the tag you want
# to build; run it twice from two different checkout paths (or once here
# and compare against a CI-published SHA256SUMS) to confirm reproducibility
# yourself. See docs/REPRODUCIBLE_BUILDS.md.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
if [ "$(uname -s | cut -c1-5)" = "MINGW" ] || [ "$(uname -s | cut -c1-4)" = "MSYS" ] || [ -n "${WINDIR:-}" ]; then
  abs_path="$(pwd -W)"
  export RUSTFLAGS="-C link-arg=/Brepro --remap-path-prefix=${abs_path}=/build"
else
  abs_path="$(pwd)"
  export RUSTFLAGS="-C link-arg=-Wl,--build-id=sha1 --remap-path-prefix=${abs_path}=/build"
fi

cargo build --workspace --release --locked

echo
echo "SHA256SUMS:"
(
  cd target/release
  find . -maxdepth 1 -type f \( -name 'cf-*' -o -name 'cf_*' \) \
    ! -name '*.d' ! -name '*.pdb' ! -name '*.exp' ! -name '*.lib' ! -name '*.rlib' \
    | sort | xargs sha256sum
)
