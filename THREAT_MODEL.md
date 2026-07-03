# Threat model & invariants

This is a living document. Every row in the traceability table maps a defended
threat to the control that defends it and the ticket/test that proves the
control works. When a ticket in `BACKLOG.md` changes a security-relevant
behavior, update this file in the same PR.

## Scope and trust model

Content Filter is **self-imposed accountability software**: the monitored
device's owner consents to install it and names an accountability partner.
The adversary this system defends against is primarily **the monitored user
in a weak moment** — not a secret abuser monitoring a non-consenting victim.
That framing drives two hard requirements that run through every ticket below:

- **No silent install.** Enrollment requires interactive local consent and
  local admin (`inst-consent-ui`). This is what keeps the tool out of
  stalkerware territory: it cannot be dropped on someone else's device without
  their knowledge.
- **No silent presence.** A non-dismissible "monitored" badge is visible
  whenever the tool is active (`tray-monitored-badge`).

### Actors

| Actor | Capability | Trusted for |
|---|---|---|
| Monitored user | Full local admin on their own device (Hardened tier) | Nothing security-critical — they are the threat model |
| Accountability partner | Holds the Ed25519 approval key and the X25519 unblock-seal key | Approving/vetoing weakening actions; cannot be impersonated without their private key |
| Relay operator | Runs the cloud relay | Routing ciphertext/signatures and detecting silence — **not** trusted to read content, mint approvals, or decrypt requests |
| Network-level attacker | On-path or off-path, may run a DoH resolver, VPN, or rotating-front service | Nothing; every bypass route is a ticket in the enforcement-hardening epic |

### Two tiers, two guarantees

- **Hardened** (default): enforcement is strong, but a sufficiently determined
  local admin can eventually disable it. The backstop is **detection and
  accountability**, not perfect prevention — tampering, silence, and config
  drift are alerted to the partner even when they can't be stopped outright.
- **Locked** (opt-in, `e-locked`): trades convenience for harder technical
  prevention (kernel driver, iOS supervision, Android Device Owner,
  approval-gated uninstall). Still not unbreakable against a local attacker
  with physical access and OS reinstall rights — that residual is explicit,
  not hidden.

## Threat → control → test traceability

| # | Threat | Control(s) | Ticket(s) | Proof / test |
|---|---|---|---|---|
| 1 | Forged partner approval | Ed25519 signature over a canonical statement | `core-crypto-approvals` | Verify-key holder cannot forge (negative test); KATs |
| 2 | Relay reads unblock-request content (URL/reason) | X25519 sealed-box, sealed to partner only | `core-crypto-sealing` | Party without private key cannot decrypt; request hash doesn't reveal domain |
| 3 | Relay silently drops or reorders events (censorship) | Hash-chained, per-device-signed event log with gap/fork detection | `core-hashchain`, `relay-log` | Insert/reorder/remove breaks verification; gap detection returns missing seqs; fork detected |
| 4 | Local clock rollback to revive an expired approval | Signed, monotonic time-anchor floor; `effective_now = max(local, floor)` | `core-timeanchor`, `relay-timeanchor` | Rollback below floor cannot revive expired approval; forward jump can't pre-activate |
| 5 | Weakening applied without delay or partner sign-off | Weakening state machine: cooling-off clocked by the signed anchor, partner-approval shortcut, auto-revert | `core-weakening`, `svc-approvals` | Table-driven tests per policy-matrix row; cooling-off uses anchor not local clock |
| 6 | Replayed or forged relay request | Per-device signed requests, nonce + timestamp window | `relay-auth` | Replayed nonce rejected; stale timestamp rejected; unknown device rejected |
| 7 | Partner key or trust anchor swapped without consent | Server-authoritative signed anchor; rotation requires old key or full cooling-off + multi-channel alert | `relay-registry-pairing`, `sec-key-recovery` | Anchor is server-authoritative (test); silent partner-key swap is impossible (test) |
| 8 | Local config/anchor tampering | Anchor pinned at install; refuses weaker-than-anchor values; `AnchorMismatch`/`ConfigChanged` events | `svc-config-anchor`, `svc-integrity` | Refuses partner-key/cooling-off downgrade; unmanaged change emits diff |
| 9 | IPC used to apply a weakening without a signature | Named-pipe IPC is request-only; cannot itself approve | `svc-ipc` | IPC alone cannot apply a weakening without partner signature (test) |
| 10 | DNS resolver bypass (foreign resolver, ECH hiding SNI) | On-device resolver as chokepoint; ECH config stripped; NRPT forces local resolver and re-asserts | `svc-resolver`, `svc-nrpt` | Blocked name sinkholed; `ech=` stripped (capture test); manual DNS change reverted + `TamperDetected` |
| 11 | Messaging apps collaterally blocked by social-category rules | Allowlist precedence: messaging beats social on fused domains | `svc-categories` | `messenger.com` allowed while `facebook.com` blocked |
| 12 | Egress around the resolver (raw DoH/DoT, VPN, Tor) | User-mode WFP egress lock on :53/:853, DoH-endpoint IPs, VPN/Tor endpoints | `svc-egress-wfp`, `relay-feeds` | Outbound blocked except allowlist; feed signature required |
| 13 | QUIC (UDP/443) hides ClientHello SNI | Block UDP/443, forcing TCP fallback | `svc-quic-block` | Browsers fall back to TCP; SNI visible in capture |
| 14 | Browser-level DoH re-enabled | Policy-locked DoH in Chrome/Edge/Firefox, monitored | `svc-browser-doh` | Reverted + `TamperDetected` if changed |
| 15 | Hosts-file edit as a naive bypass | Capped tripwire subset, monitored | `svc-hosts-tripwire` | Edit/delete detected, re-applied, `TamperDetected` |
| 16 | Agent killed or suspended (hostile admin) | Signed heartbeats; relay-side silence timer | `svc-heartbeat`, `relay-heartbeat-silence` | Force-kill/suspend/airplane-mode leads to `DeviceSilent` within window |
| 17 | Tampering while the service wasn't running (Safe Mode, USB boot, offline edit) | Boot-gap detection cross-checked against relay's last heartbeat | `svc-bootgap` | Simulated downtime emits `ControlsAbsent{from,to}` on next start |
| 18 | A bypass route opens in production without anyone noticing | Multi-path canary probing DNS/DoH/direct-IP/VPN on an interval | `svc-canary`, `hard-bypass-matrix` | Opened path emits `FilterHoleDetected{path}`; matrix is a CI gate |
| 19 | Casual kill of the service or the watchdog | Paired mutual-restart watchdog; simultaneous suspend covered by relay silence | `svc-watchdog-guardian` | Killing either restarts and alerts; simultaneous case documented as relay-silence's job |
| 20 | Critical alert suppressed by disabling one channel | `PartnerNotifier` fans out critical events over relay **and** independent SMTP | `svc-notifier`, `relay-email-fallback` | Tamper/silence/log-gap events email out even with push disabled |
| 21 | Filter engine down fails open | Fail-closed: deny unresolved hosts while keeping relay/filter reachable; unconfirmed temp-unblocks revert | `svc-fail-closed` | `FailClosedEngaged` emitted; offline temp-unblock past window reverts |
| 22 | Silent/unattended install onto someone else's device | Interactive local consent + local admin required at enrollment | `inst-consent-ui` | Silent/unattended enroll is refused (test) |
| 23 | Tampered or unsigned release binaries | Authenticode signing + reproducible, checksummed builds | `inst-signing`, `f-repro-builds` | Two independent builds of a tag hash-identical; signatures verify |
| 24 | Mobile approval forged without the hardware key | Secure Enclave (iOS) / StrongBox-Keystore (Android) signing; non-exportable | `ios-partner-mode`, `and-partner-mode` | Forgery impossible without the private key (design test) |
| 25 | Mobile filter silently disabled | DeviceActivity / WorkManager re-assertion; `FilterDisabled` → `DeviceSilent` | `ios-deviceactivity`, `and-watchdog` | Disabling Screen Time / VPN emits the event chain |
| 26 | Screen-content CV frames or flags leave the device | On-device-only inference; alert-only default; no raw thumbnail by default | `cv-inference`, `cv-reporting` | Network egress test = zero for raw frames; opt-in gating enforced |
| 27 | SNI-level evasion via rotating fronts / DoH under TLS (Locked tier) | Kernel WFP callout inspecting ClientHello SNI | `lock-wfp-driver` | Blocks DoH hostnames and rotating fronts; fails closed |
| 28 | Locked-tier filter disabled via OS settings | iOS supervision / Android Device Owner lock global filter + VPN/DNS config | `lock-ios-supervision`, `lock-android-deviceowner` | Non-disableable on a supervised/owned device (test) |
| 29 | Uninstall used to escape Locked tier | Uninstall blocked without a valid partner approval | `lock-uninstall-approval` | Blocked without approval on all Locked platforms; clean removal with approval |
| 30 | Privacy-floor violation (browsing history, URL logs, DPI, off-device screenshots) | Data-flow audit; relay stores only minimal fields; sealed unblock end-to-end | `sec-privacy-review`, `relay-deploy` | Audit + DPIA published |

## Explicit residuals (not defended, by design)

- **Hardened tier is not tamper-proof.** A local admin with enough
  persistence (e.g., reinstalling the OS, or defeating the watchdog and the
  relay-silence backstop simultaneously within one heartbeat window) can
  disable enforcement. The guarantee is that this is **detected and reported
  to the partner**, not silently prevented. Locked tier narrows this gap; it
  does not close it against physical access + OS reinstall.
- **Two simultaneous suspends (service + guardian) at once** are not
  independently caught by the watchdog pair — this case is covered only by
  relay-side heartbeat silence, which has a detection window (not instant).
- **The relay is not a trust anchor.** It is assumed hostile-but-honest-enough
  to deliver most messages; censorship shows up as a hash-chain gap, not as
  silent, undetectable loss.
- **Screen-content CV is opt-in and alert-only by default**; it is not a
  general surveillance layer and is out of scope for the Hardened/Locked
  network-enforcement guarantees above.

## Keeping this doc live

- Every ticket tagged `security/invariant` in `BACKLOG.md` must have a row
  here (or an explicit residual entry) before it closes.
- `sec-threat-validation` (M3) re-derives this table from closed tickets and
  their tests, and is the release gate confirming nothing drifted.
