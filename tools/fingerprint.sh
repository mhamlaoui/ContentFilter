#!/usr/bin/env bash
# Print the sha256 fingerprint of an Ed25519 public key, in the same format
# expected in keys/release-key.fingerprint. See docs/KEY_CEREMONY.md.
#
# USAGE: tools/fingerprint.sh path/to/release-key.pub.pem
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <ed25519-public-key.pem>" >&2; exit 2; }
[ -f "$1" ] || { echo "no such file: $1" >&2; exit 2; }

# An Ed25519 SubjectPublicKeyInfo DER is 44 bytes: a fixed 12-byte
# algorithm-identifier prefix followed by the raw 32-byte public key.
openssl pkey -pubin -in "$1" -outform DER | tail -c 32 | sha256sum | cut -d' ' -f1
