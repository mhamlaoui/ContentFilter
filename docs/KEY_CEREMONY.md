# Release key ceremony and rotation runbook

## What this key is (and isn't)

The **release key** is an Ed25519 keypair. Its public half is pinned in every
client and used to verify:

- the blocklist and DoH-endpoint feeds (`relay-feeds`),
- release checksums/manifests (`f-repro-builds`).

It is **not** the Authenticode/EV code-signing certificate used to sign
Windows binaries and the MSI (`inst-signing`), and not the WDK driver's
EV-signed certificate (`lock-wfp-driver`). Those are commercial,
CA-issued X.509 certificates with their own custody chain (typically an HSM
or cloud HSM offered by the signing authority) and are out of scope for this
document. Do not reuse one keypair for both purposes.

It is also not a per-household trust anchor or partner approval key — those
are generated per-installation by `inst-custom-actions` and are a different
key entirely.

## Current status

**No release key has been generated yet.** This repository intentionally
contains no `keys/release-key.pub` or fingerprint file. Generating one is a
manual, offline action — not something a CI job or an agent should do,
because the entire point of the control is that the private key is never
on a machine that has ever touched the network.

## Generation ceremony

1. Boot a machine that has **never been and will never be connected to a
   network** (a spare laptop with wifi/bluetooth physically disabled, or a
   live USB with no network drivers, is sufficient). Two people present
   (dual control) is strongly recommended.
2. Generate the keypair with a tool you can audit, e.g.:
   ```sh
   openssl genpkey -algorithm ed25519 -out release-key.pem
   openssl pkey -in release-key.pem -pubout -out release-key.pub.pem
   ```
3. Compute the fingerprint of the raw 32-byte public key (not the PEM
   wrapper) as `sha256(pubkey_bytes)`, hex-encoded. `tools/fingerprint.sh`
   in this repo does this from a PEM file so the format is consistent
   between the ceremony machine and CI verification.
4. Move **only** `release-key.pub.pem` and the computed fingerprint off the
   offline machine (USB drive, visually verified to contain no other files).
5. On a normal machine, commit:
   - `keys/release-key.pub.pem`
   - `keys/release-key.fingerprint` (the hex string from step 3)
6. The private key (`release-key.pem`) never leaves the offline machine.
   Store it in a safe / HSM / smart card, per your organization's custody
   policy. Document where, physically, without putting that location in
   this repo.
7. Open a PR with only the two public files above. Reviewers verify the
   fingerprint file matches `tools/fingerprint.sh keys/release-key.pub.pem`
   run against the public key in the same PR — they cannot verify the
   private key was generated offline, which is why dual control in step 1
   matters more than any check CI can run.

## Rotation

Rotating the release key is itself a security-relevant event — a coerced or
compromised holder could otherwise swap it silently. Mirror the partner-key
rotation invariant from `sec-key-recovery`:

1. A rotation requires either a signature from the **old** release key over
   the new public key and fingerprint, or a fixed cooling-off period with
   multi-channel notification (repo announcement + release notes + any
   registered client-update channel) if the old key is lost/compromised.
2. Never delete the old fingerprint from history — append a
   `keys/release-key.history` entry recording the old fingerprint, the
   rotation date, and the reason, so clients and third parties can audit the
   chain of custody.
3. A silent swap (new key appears with no signature from the old key and no
   cooling-off/announcement) should be treated as a compromise indicator by
   anyone verifying releases.

## No private key in repo or CI logs

Enforced by `tools/check_no_private_keys.sh`, wired into CI (`f-ci`): it
scans the working tree for PEM private-key headers and common private-key
file extensions and fails the build if any are found. This is a backstop,
not a substitute for the offline ceremony above.
