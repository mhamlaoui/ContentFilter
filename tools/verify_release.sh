#!/usr/bin/env bash
# Third-party release verification. See docs/REPRODUCIBLE_BUILDS.md.
#
# USAGE: tools/verify_release.sh <release-assets-dir>
#
# Expects <dir> to contain SHA256SUMS, SHA256SUMS.sig, and the release
# binaries, as published on a GitHub release once a maintainer has
# offline-signed it (see docs/KEY_CEREMONY.md — unsigned draft releases
# have no SHA256SUMS.sig yet and can only be checksum-verified, not
# signature-verified).
set -euo pipefail
cd "$(dirname "$0")/.."

dir="${1:?usage: $0 <release-assets-dir>}"
pubkey="keys/release-key.pub.pem"

[ -f "$dir/SHA256SUMS" ] || { echo "missing $dir/SHA256SUMS" >&2; exit 1; }

echo "== checksums =="
( cd "$dir" && sha256sum -c SHA256SUMS )

if [ ! -f "$pubkey" ]; then
  echo
  echo "no release key pinned yet ($pubkey missing) — cannot verify the signature." >&2
  echo "checksums matched, but that alone does not prove the release wasn't tampered with in transit." >&2
  exit 1
fi

if [ ! -f "$dir/SHA256SUMS.sig" ]; then
  echo
  echo "$dir/SHA256SUMS.sig missing — this looks like an unsigned draft release." >&2
  echo "checksums matched, but an unsigned release has no cryptographic authenticity guarantee." >&2
  exit 1
fi

echo
echo "== signature =="
openssl pkeyutl -verify -rawin \
  -in "$dir/SHA256SUMS" \
  -sigfile "$dir/SHA256SUMS.sig" \
  -pubin -inkey "$pubkey"
echo "SHA256SUMS signature verified against $pubkey"
