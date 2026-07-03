# keys/

Holds only **public** material for the release key described in
[`docs/KEY_CEREMONY.md`](../docs/KEY_CEREMONY.md):

- `release-key.pub.pem` — the Ed25519 public key (not yet generated).
- `release-key.fingerprint` — its sha256 fingerprint, from
  `tools/fingerprint.sh` (not yet generated).
- `release-key.history` — prior fingerprints from past rotations, once any
  rotation has happened.

Nothing in this directory should ever be a private key. That invariant is
checked in CI by `tools/check_no_private_keys.sh`.
