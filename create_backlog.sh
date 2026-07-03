#!/usr/bin/env bash
# =============================================================================
# Content Filter — GitHub backlog generator
# Creates a GitHub Project (v2) + labels + milestones + issues with
# dependencies (blocked-by) and per-issue validation criteria, in the
# existing repository.
#
# SAFE BY DESIGN:
#   * --dry-run prints the entire plan and creates nothing.
#   * Idempotent: an issue whose exact title already exists is skipped.
#   * Preflight checks gh auth + repo access before any write.
#   * Nothing is deleted, ever.
#
# USAGE:
#   ./create_backlog.sh --dry-run                # review the whole plan
#   ./create_backlog.sh                          # create everything (asks once)
#   REPO_OWNER=my-org ./create_backlog.sh        # if repo is under an org
#   ./create_backlog.sh --yes                    # skip the confirmation prompt
#   ./create_backlog.sh --no-project             # skip Project v2 creation
#
# REQUIREMENTS: gh (GitHub CLI) authenticated (`gh auth login`), bash 4+.
#   For epic sub-issues + Project fields, a recent gh (>= 2.55) is best;
#   those steps are best-effort and never fail the run.
# =============================================================================
set -euo pipefail

# ---- configuration ----------------------------------------------------------
REPO_NAME="${REPO_NAME:-contentfilter}"
REPO_OWNER="${REPO_OWNER:-}"                 # empty => authenticated user login
PROJECT_TITLE="${PROJECT_TITLE:-Content Filter — Delivery}"
DRY_RUN=0
ASSUME_YES=0
MAKE_PROJECT=1

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    --no-project) MAKE_PROJECT=0 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
say()  { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$c_dim" "$*" "$c_off"; }
ok()   { printf '%s✓%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '%s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }

# ---- preflight --------------------------------------------------------------
command -v gh >/dev/null 2>&1 || die "GitHub CLI 'gh' not found. Install it and run 'gh auth login'."
if [ "$DRY_RUN" -eq 0 ]; then
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run 'gh auth login'."
fi
if [ -z "$REPO_OWNER" ]; then
  if [ "$DRY_RUN" -eq 0 ]; then
    REPO_OWNER="$(gh api user --jq .login)"
  else
    REPO_OWNER="<your-login>"
  fi
fi
REPO="$REPO_OWNER/$REPO_NAME"
if [ "$DRY_RUN" -eq 0 ]; then
  gh repo view "$REPO" >/dev/null 2>&1 || die "Cannot access repo '$REPO'. Set REPO_OWNER if it lives under an org."
fi
info "Repo:    $REPO"
info "Project: $PROJECT_TITLE"
[ "$DRY_RUN" -eq 1 ] && warn "DRY RUN — nothing will be created."

# ---- data structures --------------------------------------------------------
declare -a SLUG TYPE EPIC MS LABELS DEPS TITLE CTX DELIV VALID
declare -A NUM URL NODE
IDX=0
# ITEM slug type epic ms labels deps title ctx deliv valid
ITEM() {
  SLUG[$IDX]="$1"; TYPE[$IDX]="$2"; EPIC[$IDX]="$3"; MS[$IDX]="$4"
  LABELS[$IDX]="$5"; DEPS[$IDX]="$6"; TITLE[$IDX]="$7"; CTX[$IDX]="$8"
  DELIV[$IDX]="$9"; VALID[$IDX]="${10}"
  IDX=$((IDX+1))
}

# ---- label + milestone catalog ---------------------------------------------
# name|color|description
LABELCAT='
type/epic|6f42c1|Epic: a tracking issue with child tasks
type/task|0e8a16|Implementation task
area/core|1d76db|Shared Rust core (crypto, state)
area/relay|5319e7|Relay backend
area/service|b60205|Windows filter service
area/tray|d93f0b|Windows tray app
area/installer|fbca04|Windows installer / packaging
area/mobile|0052cc|Mobile shared + apps
area/ios|006b75|iOS app
area/android|3d9970|Android app
area/enforcement|e11d48|Network enforcement / bypass closing
area/screen-cv|c2185b|Optional screen-content CV
area/security|000000|Security, threat model, release gates
area/foundations|c5def5|Repo, CI, build, keys
priority/critical|b60205|Must-have for the release it targets
security/invariant|d4c5f9|Protects a non-negotiable invariant
blocked|e99695|Has open blockers
'
# key|title|description
MILESTONECAT='
M0|Phase 0 — Foundations|Workspace, CI, reproducible builds, key management, threat-model baseline
M1|Phase 1 — Accountability Core|Hardened Windows + relay + partner mobile app (the cryptographic accountability spine)
M2|Phase 2 — Locked Tier & Screen-CV|Opt-in hard lockdown (driver/supervision/device-owner) and optional desktop screen-CV
M3|Phase 3 — Hardening & Release|Threat-model validation, key recovery, pen test, privacy audit, beta, docs
'

ensure_labels() {
  say ""; info "Labels:"
  printf '%s\n' "$LABELCAT" | while IFS='|' read -r name color desc; do
    [ -z "$name" ] && continue
    if [ "$DRY_RUN" -eq 1 ]; then say "  would ensure label: $name"; continue; fi
    if gh label list --repo "$REPO" --limit 200 --json name --jq '.[].name' | grep -qx "$name"; then
      gh label edit "$name" --repo "$REPO" --color "$color" --description "$desc" >/dev/null 2>&1 || true
    else
      gh label create "$name" --repo "$REPO" --color "$color" --description "$desc" >/dev/null 2>&1 || true
    fi
    ok "label $name"
  done
}

declare -A MSNUM
ensure_milestones() {
  say ""; info "Milestones:"
  printf '%s\n' "$MILESTONECAT" | while IFS='|' read -r key title desc; do
    [ -z "$key" ] && continue
    [ "$DRY_RUN" -eq 1 ] && { say "  would ensure milestone: $title"; continue; }
    existing="$(gh api "repos/$REPO/milestones?state=all&per_page=100" --jq ".[] | select(.title==\"$title\") | .number" 2>/dev/null | head -n1)"
    if [ -z "$existing" ]; then
      gh api "repos/$REPO/milestones" -f title="$title" -f description="$desc" >/dev/null 2>&1 \
        && ok "milestone $title" || warn "could not create milestone $title"
    else
      ok "milestone $title (exists)"
    fi
  done
}
# resolve a milestone key to its title (issues take the title via --milestone)
ms_title() {
  case "$1" in
    M0) echo "Phase 0 — Foundations" ;;
    M1) echo "Phase 1 — Accountability Core" ;;
    M2) echo "Phase 2 — Locked Tier & Screen-CV" ;;
    M3) echo "Phase 3 — Hardening & Release" ;;
    *)  echo "" ;;
  esac
}

# ---- body rendering ---------------------------------------------------------
# turn "a | b | c" into markdown bullet lines
bullets() {
  local kind="$1" text="$2" line
  local IFS='|'
  for line in $text; do
    line="$(printf '%s' "$line" | sed -e 's/^ *//' -e 's/ *$//')"
    [ -z "$line" ] && continue
    if [ "$kind" = "check" ]; then printf -- '- [ ] %s\n' "$line"; else printf -- '- %s\n' "$line"; fi
  done
}

render_body() {  # $1 index
  local i="$1" dep depnum epicnum body
  body="## Context"$'\n'"${CTX[$i]}"$'\n\n'
  body+="## Deliverables"$'\n'"$(bullets plain "${DELIV[$i]}")"$'\n\n'
  body+="## Validation / Definition of Done"$'\n'"$(bullets check "${VALID[$i]}")"$'\n\n'
  body+="## Dependencies"$'\n'
  if [ -n "${EPIC[$i]}" ]; then
    epicnum="${NUM[${EPIC[$i]}]:-}"
    [ -n "$epicnum" ] && body+="Epic: #${epicnum}"$'\n'
  fi
  if [ -n "${DEPS[$i]}" ]; then
    local reflist=""
    for dep in ${DEPS[$i]}; do
      depnum="${NUM[$dep]:-}"
      if [ -n "$depnum" ]; then reflist+=" #${depnum}"; else reflist+=" ${dep}(?)"; fi
    done
    body+="⛔ Blocked by:${reflist}"$'\n'
  else
    body+="_No blockers — ready to start._"$'\n'
  fi
  printf '%s' "$body"
}

# ---- issue creation ---------------------------------------------------------
find_existing() {  # $1 title -> prints number or empty
  gh issue list --repo "$REPO" --state all --search "\"$1\" in:title" --json number,title \
    --jq ".[] | select(.title==\"$1\") | .number" 2>/dev/null | head -n1
}

create_one() {  # $1 index
  local i="$1" title="${TITLE[$i]}" labels="${LABELS[$i]}" mtitle body num url flags
  mtitle="$(ms_title "${MS[$i]}")"
  body="$(render_body "$i")"
  if [ "$DRY_RUN" -eq 1 ]; then
    NUM[${SLUG[$i]}]="DRY-$((i+1))"
    printf '\n%s[%s]%s %s\n' "$c_ylw" "${TYPE[$i]}" "$c_off" "$title"
    printf '   labels: %s | milestone: %s\n' "$labels" "$mtitle"
    [ -n "${DEPS[$i]}" ] && printf '   blocked by: %s\n' "${DEPS[$i]}"
    return 0
  fi
  num="$(find_existing "$title" || true)"
  if [ -n "$num" ]; then
    NUM[${SLUG[$i]}]="$num"
    url="$(gh issue view "$num" --repo "$REPO" --json url --jq .url)"
    URL[${SLUG[$i]}]="$url"
    NODE[${SLUG[$i]}]="$(gh issue view "$num" --repo "$REPO" --json id --jq .id 2>/dev/null || echo '')"
    warn "exists #$num — $title"
    return
  fi
  # build label flags
  flags=()
  local IFS=','
  for l in $labels; do flags+=(--label "$l"); done
  unset IFS
  [ -n "$mtitle" ] && flags+=(--milestone "$mtitle")
  if ! url="$(gh issue create --repo "$REPO" --title "$title" --body "$body" "${flags[@]}" 2>&1)"; then
    warn "failed to create: $title"; printf '   %s\n' "$url" | head -n2 >&2
    NUM[${SLUG[$i]}]="ERR"; return 0
  fi
  num="$(printf '%s' "$url" | grep -oE '[0-9]+$' | tail -n1)"
  NUM[${SLUG[$i]}]="$num"; URL[${SLUG[$i]}]="$url"
  NODE[${SLUG[$i]}]="$(gh issue view "$num" --repo "$REPO" --json id --jq .id 2>/dev/null || echo '')"
  ok "#$num — $title"
}

# GitHub native sub-issue link (epic -> child); best-effort, never fatal
link_subissue() {  # $1 parent-node  $2 child-node
  [ -z "$1" ] || [ -z "$2" ] && return 0
  gh api graphql -f query='
    mutation($p:ID!,$c:ID!){ addSubIssue(input:{issueId:$p, subIssueId:$c}){ clientMutationId } }' \
    -f p="$1" -f c="$2" >/dev/null 2>&1 || true
}

run_create() {
  # pass 1: epics (so tasks can reference epic numbers)
  say ""; info "Creating epics…"
  for i in "${!SLUG[@]}"; do [ "${TYPE[$i]}" = "epic" ] && create_one "$i"; done
  # pass 2: tasks in topological order (array is pre-sorted so blockers precede)
  say ""; info "Creating tasks…"
  for i in "${!SLUG[@]}"; do [ "${TYPE[$i]}" = "task" ] && create_one "$i"; done
  [ "$DRY_RUN" -eq 1 ] && return
  # pass 3: link epic children as native sub-issues (best-effort)
  say ""; info "Linking epic → child sub-issues (best-effort)…"
  for i in "${!SLUG[@]}"; do
    [ "${TYPE[$i]}" = "task" ] || continue
    [ -n "${EPIC[$i]}" ] || continue
    link_subissue "${NODE[${EPIC[$i]}]:-}" "${NODE[${SLUG[$i]}]:-}"
  done
  ok "sub-issue linking attempted"
}

# =============================================================================
# BACKLOG DATA  —  ITEM slug type epic ms labels deps title ctx deliv valid
# Tasks are listed in TOPOLOGICAL order: every blocker appears before the
# issues it blocks, so #-references resolve at creation time.
# =============================================================================

# ---- EPICS (created first) --------------------------------------------------
ITEM e-foundations epic "" M0 "type/epic,area/foundations" "" \
 "EPIC: Project foundations & CI/CD" \
 "Workspace, pipelines, reproducible builds and key management that everything else depends on." \
 "Cargo workspace | GitHub Actions CI | Reproducible + signed releases | Release-key management | Threat-model baseline | Enforcement test harness" \
 "All child issues closed | CI green on main | A tagged build is byte-reproducible and signed"

ITEM e-core epic "" M1 "type/epic,area/core,priority/critical" "e-foundations" \
 "EPIC: Shared Rust core (crypto, approvals, state)" \
 "The single implementation of the security-critical logic shared by Windows, relay, iOS and Android via UniFFI." \
 "Models | Ed25519 approvals | X25519 sealing | Hash-chain log | Time anchors | Weakening state machine | Relay client | UniFFI bindings" \
 "All child issues closed | 100% of crypto paths unit- and vector-tested | Forgery/rollback negative tests pass"

ITEM e-relay epic "" M1 "type/epic,area/relay,priority/critical" "e-core" \
 "EPIC: Relay backend" \
 "Thin cloud relay: registry, signed feeds, hash-chained log, push, time anchors, approval transport. Mints/decrypts nothing." \
 "axum service | Device auth | Pairing/anchor | Event log | Feeds | Time anchors | Heartbeat/silence | Approval transport | Push | Email fallback | Deploy" \
 "All child issues closed | Relay-cannot-decrypt and cannot-forge tests pass | Silence detection verified"

ITEM e-service epic "" M1 "type/epic,area/service,priority/critical" "e-core" \
 "EPIC: Windows filter service (enforcement)" \
 "LocalSystem service: embedded resolver, NRPT, WFP egress lock, ECH/QUIC handling, watchdog, canary, IPC, approvals." \
 "Skeleton+ACLs | Config anchor | Resolver+ECH | NRPT | WFP egress | QUIC block | Browser DoH | Hosts tripwire | Heartbeat | Boot-gap | Canary | Integrity | IPC | Approvals | Watchdog | Notifier | Fail-closed | Categories" \
 "All child issues closed | Bypass matrix green | No approval applied without partner signature"

ITEM e-tray epic "" M1 "type/epic,area/tray" "e-service" \
 "EPIC: Windows tray app" \
 "User-session UI: status, request flows into the weakening state machine, approval entry, persistent monitored badge." \
 "Skeleton+IPC | Request flows | Approval entry | Monitored badge" \
 "All child issues closed | Requests never bypass cooling-off/approval | Monitored badge non-dismissible"

ITEM e-installer epic "" M1 "type/epic,area/installer" "e-service e-tray" \
 "EPIC: Windows installer & packaging" \
 "WiX MSI, custom actions (key gen, anchor pinning, DPAPI), consent/enrollment UI, Authenticode signing." \
 "WiX package | Custom actions | Consent/enrollment UI | Signing" \
 "All child issues closed | Clean install/upgrade/uninstall | Enrollment requires interactive local consent"

ITEM e-mobile epic "" M1 "type/epic,area/mobile" "e-core" \
 "EPIC: Mobile shared core (UniFFI)" \
 "Swift and Kotlin bindings over the Rust core so mobile never re-implements crypto." \
 "Swift package | Kotlin AAR" \
 "All child issues closed | Approve/verify callable from both platforms in CI"

ITEM e-ios epic "" M1 "type/epic,area/ios" "e-mobile e-relay" \
 "EPIC: iOS app" \
 "SwiftUI companion + filter: FamilyControls (Hardened), Secure-Enclave approvals, relay + push." \
 "App shell | FamilyControls filter | DeviceActivity extension | Partner mode | Apple entitlement" \
 "All child issues closed | Filter-off/silence alerts fire | Approvals signed in Secure Enclave"

ITEM e-android epic "" M1 "type/epic,area/android" "e-mobile e-relay" \
 "EPIC: Android app" \
 "Compose companion + filter: foreground VpnService DNS/SNI + ECH/QUIC, StrongBox approvals, relay + FCM." \
 "App shell | VpnService filter | Watchdog | Partner mode" \
 "All child issues closed | Filter-off/silence alerts fire | Approvals signed in hardware keystore"

ITEM e-enforcement epic "" M1 "type/epic,area/enforcement,priority/critical" "e-service" \
 "EPIC: Enforcement hardening (ECH/QUIC/DoH)" \
 "Cross-cutting: prove every bypass route is closed and keep the DoH-endpoint feed fresh." \
 "Bypass test matrix | DoH-feed ops pipeline" \
 "All child issues closed | Automated matrix asserts block+alert on every route"

ITEM e-screencv epic "" M2 "type/epic,area/screen-cv" "e-service" \
 "EPIC: Screen-content CV (optional, desktop)" \
 "On-device, opt-in, alert-only detection layer. Never ships raw frames off device." \
 "ROI capture | On-device ONNX inference | Alert-only reporting" \
 "All child issues closed | Zero image egress verified | Alert-only default enforced"

ITEM e-locked epic "" M2 "type/epic,area/enforcement" "e-service e-ios e-android" \
 "EPIC: Locked tier (driver / supervision / device owner)" \
 "Opt-in hard lockdown: WFP callout driver, iOS supervision, Android Device Owner, approval-gated uninstall." \
 "WFP SNI driver | iOS supervision | Android Device Owner | Approval-gated uninstall" \
 "All child issues closed | Uninstall blocked without partner approval on all Locked platforms"

ITEM e-security epic "" M3 "type/epic,area/security,priority/critical" "e-enforcement" \
 "EPIC: Security validation & release" \
 "Traceable threat-model validation, partner-key recovery, pen test, privacy audit, beta, docs." \
 "Threat validation | Key recovery | Privacy audit | Pen test | Beta | Docs" \
 "All child issues closed | Threat->test matrix all green | External pen test passed"

# ---- FOUNDATIONS (M0) -------------------------------------------------------
ITEM f-repo-scaffold task e-foundations M0 "type/task,area/foundations" "" \
 "Scaffold Cargo workspace and module layout" \
 "Create the workspace and empty crates per the project structure so all later work has a home." \
 "Workspace Cargo.toml with members: core, service, tray, guardian, relay, screen-cv, installer/custom-actions | Stub crates compile | rustfmt.toml + clippy config | CODEOWNERS + issue/PR templates" \
 "cargo build compiles the whole workspace | cargo fmt --check passes | cargo clippy -D warnings passes | directory tree matches the design doc section 16"

ITEM f-ci task e-foundations M0 "type/task,area/foundations" "f-repo-scaffold" \
 "Set up CI (build, test, clippy, fmt)" \
 "Automated checks on every PR across Windows and Linux runners." \
 "GitHub Actions workflow | Windows + Linux matrix | cache | required status checks" \
 "PR triggers CI | clippy warning fails the build | main stays green | test results visible on PR"

ITEM f-secrets-keymgmt task e-foundations M0 "type/task,area/foundations,security/invariant" "f-repo-scaffold" \
 "Establish release-key management and pinning" \
 "The project release key signs blocklists, feeds and binaries; its fingerprint is pinned in clients." \
 "Offline/HSM release keypair | Documented key ceremony | Public fingerprint committed | Rotation runbook" \
 "Signing uses an offline key | fingerprint is reproducible and committed | rotation runbook reviewed | no private key in repo or CI logs"

ITEM f-threat-model-doc task e-foundations M0 "type/task,area/security" "f-repo-scaffold" \
 "Commit living threat-model and invariants doc" \
 "A repo-tracked doc mapping each threat to a control or test, kept in sync with the design." \
 "THREAT_MODEL.md | invariant list | threat->ticket/test traceability table | linked from README" \
 "every defended threat maps to a ticket or test | residuals explicitly listed | reviewed and signed off"

ITEM f-test-harness task e-foundations M0 "type/task,area/foundations" "f-ci" \
 "Build enforcement integration-test harness" \
 "A sandbox that can assert DNS/egress outcomes so enforcement tickets have a way to prove blocking." \
 "Network namespace / VM fixture | helpers to assert resolve/deny | sample DNS + egress test | CI wiring" \
 "harness asserts a domain is sinkholed and an egress port is denied | sample test green in CI | documented Windows runner path"

ITEM f-repro-builds task e-foundations M0 "type/task,area/foundations,security/invariant" "f-ci" \
 "Reproducible builds and signed release pipeline" \
 "The open-source trust story requires that shipped binaries provably match source." \
 "Pinned toolchain + deterministic flags | release workflow | checksums + signatures published | verify script" \
 "two independent builds of a tag produce identical hashes | release publishes signed artifacts + checksums | documented third-party verification steps"

# ---- CORE (M1) --------------------------------------------------------------
ITEM core-models task e-core M1 "type/task,area/core" "f-repo-scaffold" \
 "Core data models and serialization" \
 "Shared types used everywhere: FilterState, Household, Device, TrustAnchor, NotificationEvent." \
 "Rust structs/enums | serde impls | schema versioning | doc comments" \
 "serde round-trips for every type | schema matches design section 13.8 and 14 | version field present and checked"

ITEM core-crypto-approvals task e-core M1 "type/task,area/core,security/invariant,priority/critical" "core-models" \
 "Ed25519 approval sign/verify + canonical statement" \
 "Approvals are asymmetric signatures over a canonical statement; this is the invariant that makes accountability unforgeable." \
 "Canonical encoder for {action,target,request_id,not_before,not_after,nonce,household_id} | sign (partner) | verify (devices) | KATs" \
 "valid signature verifies | tampered payload fails | wrong key fails | known-answer vectors pass | NEGATIVE: holder of only the verify key cannot forge (test) | fuzz the canonical encoder"

ITEM core-crypto-sealing task e-core M1 "type/task,area/core,security/invariant" "core-models" \
 "X25519 sealed-box for unblock request payloads" \
 "Unblock request domain/reason are sealed to the partner so the relay never sees a URL." \
 "seal(to partner box pubkey) | open(partner) | salted request hash for dedup | KATs" \
 "seal/open round-trips | a party without the private key cannot decrypt (test) | tamper -> auth failure | request hash does not reveal domain"

ITEM core-hashchain task e-core M1 "type/task,area/core,security/invariant" "core-crypto-approvals" \
 "Hash-chained, signed event log" \
 "Per-household hash chain with per-device signatures so relay censorship leaves a detectable hole." \
 "event {seq,prev_hash,device_id,type,ts,payload,sig} | build + verify | gap/fork detection | seq monotonicity" \
 "chain verifies end to end | removing/reordering/inserting an event breaks verification (tests) | gap detection returns the missing seqs | per-device signature enforced"

ITEM core-timeanchor task e-core M1 "type/task,area/core,security/invariant" "core-crypto-approvals" \
 "Signed time anchors and effective-now logic" \
 "Defeats clock rollback: validity is clamped to a monotonic, relay-signed time floor." \
 "signed (utc,seq) beacon verify | persistent monotonic floor | effective_now = max(local,floor) | not_before handling" \
 "rollback below floor cannot revive an expired approval (test) | forward jump cannot pre-activate (not_before) | unsigned/tampered anchor rejected | floor persists across restart"

ITEM core-weakening task e-core M1 "type/task,area/core,security/invariant,priority/critical" "core-timeanchor core-crypto-approvals" \
 "Weakening state machine (cooling-off + approval)" \
 "Strengthening is instant; weakening is delayed and/or approved. The mechanism that defends the weak moment." \
 "states PENDING/EFFECT/VETOED/CANCELLED/REVERTED | policy matrix from design section 7.3 | anchor-clocked timers | approval shortcut | auto-revert" \
 "table-driven tests for every policy-matrix row | cooling-off uses the signed anchor not the local clock | partner approval shortcuts the wait | veto and cancel work | temporary unblock auto-reverts | strengthening is instant"

ITEM core-relay-client task e-core M1 "type/task,area/core" "core-models core-hashchain" \
 "Relay client library" \
 "Register, pull signed feeds, push signed events, receive approvals, with offline resilience." \
 "register | pull+verify blocklist/DoH feeds | push signed events | receive approvals | retry/backoff + offline queue" \
 "against a mock relay: register, push event, pull feed with signature verified, receive approval | rejects unsigned/invalid feed | queues while offline and drains on reconnect"

ITEM core-uniffi-scaffold task e-core M1 "type/task,area/core,area/mobile" "core-weakening core-relay-client" \
 "UniFFI export scaffolding" \
 "Expose the core to Swift and Kotlin so mobile shares one crypto implementation." \
 "UDL/proc-macro exports | Swift + Kotlin binding generation | CI build of both | smoke API (approve/verify)" \
 "generated Swift and Kotlin bindings compile in CI | a round-trip approve/verify call works from both host stubs | ABI documented"

# ---- RELAY (M1) -------------------------------------------------------------
ITEM relay-bootstrap task e-relay M1 "type/task,area/relay" "core-models" \
 "Relay service skeleton (axum + TLS + config)" \
 "The HTTP/WebSocket backbone with TLS and structured logging." \
 "axum/tokio bootstrap | config loader | TLS termination | health endpoint | structured logs | graceful shutdown" \
 "service starts and health returns 200 | TLS enforced (no plaintext) | logs structured | shuts down gracefully"

ITEM relay-auth task e-relay M1 "type/task,area/relay,security/invariant" "relay-bootstrap core-crypto-approvals" \
 "Per-device key auth + replay guard" \
 "Every mutating request is signed by a registered device; nonce+timestamp stop replay." \
 "device-signed request verification | nonce sliding window | timestamp window | unknown-device rejection" \
 "valid device-signed request accepted | replayed nonce rejected | stale timestamp rejected | unknown device rejected"

ITEM relay-registry-pairing task e-relay M1 "type/task,area/relay,security/invariant,priority/critical" "relay-auth" \
 "Household registry, trust anchor, pairing codes" \
 "Stores the signed trust anchor (partner keys, cooling-off floor) authoritatively and issues pairing codes." \
 "household model | signed anchor storage | pairing-code issue/redeem | device pubkey registration" \
 "create household stores a signed anchor | join with a code registers the device pubkey | anchor served signed | expired/invalid codes rejected | anchor is server-authoritative (test)"

ITEM relay-log task e-relay M1 "type/task,area/relay,security/invariant" "relay-registry-pairing core-hashchain" \
 "Append-only hash-chained event log" \
 "Server side of the transparency log with gap/fork detection and retention that preserves the head." \
 "append with chain verification | per-household isolation | gap/fork detection | retention prune keeps head hash" \
 "appends verify against the chain | out-of-order/missing seq flagged | fork detected | households isolated | prune keeps continuity head"

ITEM relay-feeds task e-relay M1 "type/task,area/relay" "relay-registry-pairing" \
 "Signed blocklist + DoH-endpoint feed distribution" \
 "Versioned, release-key-signed feeds so a MITM cannot push an empty list." \
 "signed blocklist | signed DoH-endpoint feed | versioning + ETag | client verification path" \
 "feeds served with a valid release-key signature | version increments | client rejects a bad signature | conditional GET works"

ITEM relay-timeanchor task e-relay M1 "type/task,area/relay,security/invariant" "relay-registry-pairing core-timeanchor" \
 "Emit signed time-anchor beacons" \
 "Periodic signed (utc,seq) beacons that clients persist as a monotonic time floor." \
 "beacon emitter | signature | monotonic seq | delivery to devices" \
 "beacon is signed and monotonic | devices persist the floor | a tampered beacon is rejected"

ITEM relay-heartbeat-silence task e-relay M1 "type/task,area/relay,security/invariant,priority/critical" "relay-registry-pairing" \
 "Heartbeat tracking + DeviceSilent detection" \
 "Silence is the primary backstop against a hostile admin who kills or suspends the agent." \
 "heartbeat ingest | per-device last-seen | silence timer -> DeviceSilent | recovery clears" \
 "missed heartbeats beyond threshold emit DeviceSilent | resumed heartbeat clears it | simulated kill/suspend/airplane triggers the alert | per-device tracking"

ITEM relay-approvals-transport task e-relay M1 "type/task,area/relay,security/invariant,priority/critical" "relay-log" \
 "Route sealed/signed approvals and requests" \
 "The relay carries ciphertext and signatures only; it can neither mint approvals nor read requests." \
 "route sealed request to partner | route signed approval to device | audit event | rate limit by request hash" \
 "ciphertext routed unchanged | relay cannot decrypt (no private key) test | approval delivered to the target device | a dropped message surfaces downstream as a log gap"

ITEM relay-push task e-relay M1 "type/task,area/relay" "relay-approvals-transport" \
 "APNs + FCM push fan-out" \
 "Background push to phones (impossible without APNs/FCM)." \
 "APNs client | FCM client | token registration/rotation | retry/backoff" \
 "push delivered to sandbox APNs and FCM targets | token rotation handled | failures retried and logged"

ITEM relay-email-fallback task e-relay M1 "type/task,area/relay,security/invariant" "relay-log" \
 "Independent SMTP alert channel" \
 "A channel independent of relay push so relay censorship cannot suppress critical alerts." \
 "SMTP sender | critical-event routing | independence from push path | deliverability retries" \
 "tamper/silence/log-gap events email out even with push disabled | path is independent of the relay push service | delivery retried"

ITEM relay-deploy task e-relay M1 "type/task,area/relay" "relay-push relay-email-fallback" \
 "Relay deployment + data minimization" \
 "Reproducible deploy storing only the minimum, with backups and retention." \
 "container + IaC | TLS certs | retention job | backup/restore | secrets management" \
 "reproducible deploy | audit confirms only minimal fields stored | retention job runs | restore from backup verified"

# ---- SERVICE (M1) -----------------------------------------------------------
ITEM svc-skeleton task e-service M1 "type/task,area/service" "core-models" \
 "Windows service skeleton (SCM, ACLs, logging)" \
 "LocalSystem service host with correct filesystem ACLs and rotating logs." \
 "windows_service SCM entry | config load | rotating file logger | PROGRAMDATA ACLs (SYSTEM full, Admin read, Users none)" \
 "installs/starts/stops via SCM | runs as LocalSystem | ACLs match design section 8.5 | logs rotate at size limit"

ITEM svc-config-anchor task e-service M1 "type/task,area/service,security/invariant,priority/critical" "svc-skeleton relay-registry-pairing" \
 "Config load + server-anchor validation" \
 "Security-critical params come from the signed anchor, not local config; tampering is detected." \
 "fetch+pin signed anchor | reject weaker-than-anchor values | ConfigChanged diff vs last-known-good | AnchorMismatch event" \
 "refuses a partner key or cooling-off weaker than the anchor | emits AnchorMismatch on swap attempt | emits ConfigChanged for unmanaged edits | anchor pinned at install"

ITEM svc-ipc task e-service M1 "type/task,area/service,security/invariant" "svc-skeleton" \
 "Named-pipe IPC server (HMAC, requests-only)" \
 "Authenticated local IPC that can request actions but can never itself approve a weakening." \
 "pipe server | HMAC over type+payload+nonce+ts | replay window | SYSTEM-owned ACL | request dispatch" \
 "valid HMAC request dispatched | replay/stale rejected | pipe ACL correct | IPC alone cannot apply a weakening without a partner signature (test)"

ITEM svc-resolver task e-service M1 "type/task,area/service,area/enforcement,priority/critical" "svc-skeleton relay-feeds" \
 "Embedded filtering DNS resolver + ECH strip" \
 "On-device resolver is the chokepoint; strips ECH configs so SNI stays inspectable." \
 "local resolver | sinkhole blocked names | strip ech= from HTTPS/SVCB (type 65) | upstream to trusted resolver" \
 "blocked name returns NXDOMAIN/sinkhole | allowed names resolve | ech= stripped from responses (capture test) | queries stay on device (no third-party egress)"

ITEM svc-nrpt task e-service M1 "type/task,area/service,area/enforcement" "svc-resolver" \
 "Force system resolver via NRPT + re-assert" \
 "NRPT is the OS-sanctioned way to force the local resolver; the monitor re-asserts it." \
 "NRPT rule to local resolver | interface DNS set | monitor + re-assert | tamper event" \
 "NRPT points to the local resolver | a manual DNS change is reverted within one monitor tick and emits TamperDetected | survives reboot"

ITEM svc-categories task e-service M1 "type/task,area/service" "svc-resolver" \
 "Category manifests + messaging-wins-ties" \
 "Adult always on, social optional, YouTube sub-toggle, messaging never blocked." \
 "adult/social/messaging manifests | youtube sub-toggle | allowlist precedence | enable=instant, disable=weakening" \
 "adult always active | social toggles | youtube independent | messaging allowlist beats social on fused domains (messenger.com allowed while facebook.com blocked) | disabling social routes through the weakening state machine"

ITEM svc-egress-wfp task e-service M1 "type/task,area/service,area/enforcement,security/invariant,priority/critical" "svc-resolver relay-feeds" \
 "User-mode WFP egress lock" \
 "Deny the routes around the chokepoint without a kernel driver." \
 "WFP filters at ALE_AUTH_CONNECT | deny :53/:853 to non-approved | deny DoH-endpoint IP feed | deny VPN/Tor endpoints" \
 "outbound :53/:853 to non-approved resolvers blocked | DoH endpoint IPs blocked | VPN/Tor endpoints blocked or alerted | no kernel driver required"

ITEM svc-quic-block task e-service M1 "type/task,area/service,area/enforcement" "svc-egress-wfp" \
 "Block UDP/443 (QUIC) to force TCP fallback" \
 "Removing QUIC restores an inspectable TCP ClientHello." \
 "WFP deny outbound UDP/443 with allowlist | toggle wired as a weakening action" \
 "UDP/443 outbound denied except allowlist | browsers fall back to TCP | SNI becomes visible in capture | disabling the block is a cooling-off + notify action"

ITEM svc-browser-doh task e-service M1 "type/task,area/service,area/enforcement" "svc-skeleton" \
 "Browser DoH policy lockdown + monitor" \
 "Policy-lock encrypted DNS in Chrome/Edge/Firefox and re-assert if changed." \
 "Chrome/Edge DnsOverHttpsMode=off | Firefox policies.json locked | monitor + re-assert" \
 "policies set and greyed out in-browser | reverted and TamperDetected if changed | covers all installed supported browsers"

ITEM svc-hosts-tripwire task e-service M1 "type/task,area/service,area/enforcement" "svc-skeleton" \
 "Hosts tripwire (capped) + tamper detection" \
 "A small top-domain tripwire, not the full blocklist, to catch the naive editor." \
 "~1-2k managed section | monitor | re-apply on change" \
 "tripwire present and capped | edit/delete detected, re-applied, TamperDetected emitted | no DNS-client perf regression from size"

ITEM svc-heartbeat task e-service M1 "type/task,area/service,security/invariant,priority/critical" "svc-config-anchor relay-heartbeat-silence" \
 "Signed heartbeat emitter + liveness ticks" \
 "First-class PC heartbeats so the relay can detect a killed/suspended agent." \
 "signed heartbeat (TPM device key) at interval | persisted liveness tick | relay reporting" \
 "heartbeats signed with the device key at the configured interval | relay marks the device active | force-kill leads to DeviceSilent within the window"

ITEM svc-bootgap task e-service M1 "type/task,area/service,security/invariant" "svc-heartbeat" \
 "Boot-gap / ControlsAbsent detection" \
 "Detect tampering done while the service was not running (Safe Mode, USB boot, offline edits)." \
 "liveness-tick store | downtime computation on start | cross-check relay last-heartbeat | missing-filter check" \
 "simulated downtime emits ControlsAbsent{from,to} on next start | cross-checks relay last-heartbeat | absent WFP filters flagged"

ITEM svc-canary task e-service M1 "type/task,area/service,area/enforcement,priority/critical" "svc-egress-wfp svc-resolver" \
 "Multi-path production canary" \
 "Continuously prove the block holds across every path that matters." \
 "probe system DNS | probe rotating public DoH providers | direct-IP | active VPN adapter | FilterHoleDetected on success" \
 "all paths blocked -> green heartbeat | a deliberately opened path -> FilterHoleDetected{path} | the DoH provider set rotates | runs on interval"

ITEM svc-integrity task e-service M1 "type/task,area/service,security/invariant" "svc-config-anchor" \
 "Last-known-good config/control diffing" \
 "The service knows what it applied and flags anything it did not." \
 "signed last-known-good store | live-vs-known diff | suppress self-performed changes" \
 "any unmanaged change to a managed control emits an event with a diff | self-performed changes are suppressed | store is integrity-protected"

ITEM svc-approvals task e-service M1 "type/task,area/service,security/invariant,priority/critical" "svc-ipc core-weakening svc-config-anchor" \
 "Verify approvals + drive weakening state machine" \
 "Wire Ed25519 verification and the cooling-off machine into the service." \
 "verify approval vs anchored partner key | drive core-weakening | single-use request_id | emit events" \
 "a valid partner approval applies the action | forged/rollback/expired approvals rejected | cooling-off enforced by the anchor clock | veto/cancel/auto-revert all work"

ITEM svc-watchdog-guardian task e-service M1 "type/task,area/service" "svc-skeleton" \
 "Paired watchdog (service + guardian)" \
 "Mutual restart for crashes and casual kills; silence covers the hostile case." \
 "guardian process | mutual heartbeat | restart + alert | service recovery config" \
 "killing the service -> guardian restarts it and alerts | killing the guardian -> service restarts it and alerts | simultaneous suspend is documented as covered by relay silence (test)"

ITEM svc-notifier task e-service M1 "type/task,area/service,security/invariant" "core-relay-client relay-approvals-transport relay-email-fallback" \
 "PartnerNotifier (relay + SMTP)" \
 "One trait, two channels; critical events go out both; unblock payloads are sealed." \
 "PartnerNotifier trait | RelayNotifier | SmtpNotifier | dual-channel for critical events | seal unblock payloads" \
 "events reach the relay | critical events are dual-channel | retry/backoff | sealed unblock payloads are never sent to the relay in cleartext (test)"

ITEM svc-fail-closed task e-service M1 "type/task,area/service,area/enforcement,security/invariant" "svc-resolver svc-egress-wfp" \
 "Fail-closed policy" \
 "When the engine is down, default to deny, while keeping recovery paths reachable." \
 "deny on resolver/engine down | keep relay+filter reachable | revert unconfirmed temporary unblocks | FailClosedEngaged event" \
 "resolver down -> HTTP(S) to unresolved hosts denied while relay/filter still reachable | an offline temporary unblock past its window reverts to blocked | FailClosedEngaged emitted"

# ---- TRAY (M1) --------------------------------------------------------------
ITEM tray-skeleton task e-tray M1 "type/task,area/tray" "svc-ipc" \
 "Tray app skeleton + IPC client" \
 "The user-session UI that talks to the service over the signed pipe." \
 "tray icon + event loop | IPC client with HMAC signing | status view (Active/Paused/Pending)" \
 "connects to the pipe | signs requests | reflects service status live"

ITEM tray-request-flows task e-tray M1 "type/task,area/tray,security/invariant" "tray-skeleton svc-approvals" \
 "Unblock/uninstall/pause request flows" \
 "Requests enter the weakening state machine and show the cooling-off timer." \
 "request UIs | seal unblock payload to partner | show anchor-clocked timer | reflect states" \
 "a request creates WeakeningRequested | the cooling-off timer is anchor-clocked (not local) | approved/vetoed/effective states reflected | payload sealed to the partner"

ITEM tray-approval-entry task e-tray M1 "type/task,area/tray" "tray-request-flows" \
 "Approval entry + notification history" \
 "Enter/scan a partner approval and review the accountability log locally." \
 "approval paste/scan | validation feedback | event history view" \
 "a valid approval applies the action | an invalid one is rejected with a reason | history lists recent events"

ITEM tray-monitored-badge task e-tray M1 "type/task,area/tray,security/invariant" "tray-skeleton" \
 "Persistent monitored indicator" \
 "A non-dismissible badge enforcing the self-imposed-accountability framing." \
 "always-on badge when enrolled | non-dismissible | reflects filter active/inactive" \
 "badge is visible whenever enrolled | it cannot be permanently dismissed | it reflects filter state"

# ---- INSTALLER (M1) ---------------------------------------------------------
ITEM inst-wix-package task e-installer M1 "type/task,area/installer" "svc-skeleton tray-skeleton" \
 "WiX v4 package (service, tray, ACLs)" \
 "The MSI that installs the service, tray and guardian with correct ACLs." \
 "WiX project | ServiceInstall/Control | tray Run key | directory ACL custom actions | upgrade logic" \
 "MSI installs service+tray+guardian to Program Files | ACLs applied | uninstall removes cleanly | major-upgrade works"

ITEM inst-custom-actions task e-installer M1 "type/task,area/installer,security/invariant" "inst-wix-package svc-config-anchor" \
 "Installer custom actions (keys, anchor, DPAPI)" \
 "Rust CA DLL that provisions keys and pins the trust anchor at install." \
 "gen IPC key | DPAPI-encrypt SMTP | gen device identity key in TPM | pin signed anchor | remove enforcement on uninstall" \
 "install provisions keys (TPM-backed where present), pins the anchor, encrypts SMTP | uninstall removes managed enforcement | actions are idempotent"

ITEM inst-consent-ui task e-installer M1 "type/task,area/installer,security/invariant" "inst-custom-actions relay-registry-pairing" \
 "Installer consent + enrollment UI" \
 "Interactive local consent and pairing so the tool cannot be silently installed on someone else." \
 "wizard: partner email/SMTP, tier, consent | pairing to household | monitored-consent capture" \
 "enrollment requires interactive local consent and local admin | pairs to a household | tier selectable | a silent/unattended enroll is refused (test)"

ITEM inst-signing task e-installer M1 "type/task,area/installer,security/invariant" "inst-wix-package f-repro-builds" \
 "Authenticode signing of binaries + MSI" \
 "Signed, timestamped release artifacts consistent with the reproducible-build story." \
 "sign service/tray/guardian exes | sign MSI | timestamp | wire into release pipeline" \
 "MSI and exes are signed and timestamped | signatures verify | unsigned dev builds are clearly flagged"

# ---- MOBILE SHARED (M1) -----------------------------------------------------
ITEM mob-uniffi-ios task e-mobile M1 "type/task,area/mobile,area/ios" "core-uniffi-scaffold" \
 "Swift bindings package (SPM) from core" \
 "A Swift package wrapping the Rust core so iOS never re-implements crypto." \
 "SPM package | xcframework build | approve/verify + relay client exposed | macOS CI" \
 "Swift package builds | approve/verify and relay client are callable | CI builds it on macOS"

ITEM mob-uniffi-android task e-mobile M1 "type/task,area/mobile,area/android" "core-uniffi-scaffold" \
 "Kotlin bindings (AAR) from core" \
 "An AAR wrapping the Rust core for Android." \
 "AAR build | JNI load | approve/verify + relay client exposed | CI" \
 "AAR builds | native lib loads via JNI | approve/verify callable | CI builds it"

# ---- iOS (M1) ---------------------------------------------------------------
ITEM ios-entitlement task e-ios M1 "type/task,area/ios" "" \
 "Obtain Apple FamilyControls entitlement" \
 "A schedule dependency, not code: Family Controls (Managed Settings) needs Apple approval. Start early." \
 "entitlement request | justification | provisioning profiles updated | risk tracked" \
 "entitlement granted by Apple | provisioning profiles updated | dependency tracked on the release plan"

ITEM ios-app-shell task e-ios M1 "type/task,area/ios" "mob-uniffi-ios relay-registry-pairing" \
 "iOS app shell + relay client + Keychain key" \
 "SwiftUI shell that registers the device with a Secure-Enclave identity key." \
 "SwiftUI shell | device identity key in Secure Enclave/Keychain | relay register | dashboard | pull signed blocklist" \
 "registers the device with a hardware-backed key | pulls and verifies the blocklist | dashboard shows filter state | a TestFlight build runs"

ITEM ios-familycontrols task e-ios M1 "type/task,area/ios,area/enforcement" "ios-app-shell" \
 "FamilyControls filter engine (Hardened)" \
 "Screen Time / Managed Settings shields for the configured categories." \
 "FamilyControls auth | ManagedSettingsStore shields | DNS profile | category mapping" \
 "with the entitlement, configured categories are blocked in Safari and apps | DNS profile applied | requires Screen Time authorization | limits documented (revocable without supervision)"

ITEM ios-deviceactivity task e-ios M1 "type/task,area/ios,security/invariant" "ios-familycontrols relay-heartbeat-silence" \
 "DeviceActivityMonitor extension (re-assert + heartbeat)" \
 "Re-assert shields and report state; disabling Screen Time surfaces as an alert." \
 "extension | re-assert shields on change | heartbeat to relay | FilterDisabled reporting" \
 "shields re-assert after a change | heartbeat reaches the relay | disabling Screen Time emits FilterDisabled and eventually DeviceSilent"

ITEM ios-partner-mode task e-ios M1 "type/task,area/ios,security/invariant,priority/critical" "ios-app-shell relay-approvals-transport relay-push" \
 "iOS partner mode (Secure-Enclave approvals)" \
 "One-tap approve/veto signed by a non-exportable Enclave key; can decrypt sealed unblocks." \
 "approve/veto signing in Secure Enclave | sealed-unblock decryption | APNs handling | request UI" \
 "one-tap approve signs with the Enclave key | can open a sealed unblock (box key) | push received | forgery is impossible without the private key (design test)"

# ---- ANDROID (M1) -----------------------------------------------------------
ITEM and-app-shell task e-android M1 "type/task,area/android" "mob-uniffi-android relay-registry-pairing" \
 "Android app shell + relay client + Keystore key" \
 "Compose shell that registers the device with a StrongBox/TEE identity key." \
 "Compose shell | device key in StrongBox/TEE | relay register | dashboard | pull signed blocklist" \
 "registers with a hardware-backed key | pulls and verifies the blocklist | dashboard shows state | an internal build runs"

ITEM and-vpnservice task e-android M1 "type/task,area/android,area/enforcement,priority/critical" "and-app-shell" \
 "Foreground VpnService DNS/SNI filter + ECH/QUIC" \
 "On-device filtering with ECH strip and UDP/443 drop, always-on capable." \
 "foreground VpnService | DNS/SNI matcher | strip ECH | drop UDP/443 | always-on VPN option" \
 "configured categories blocked via on-device DNS | ECH stripped | UDP/443 dropped | always-on option works | battery within budget"

ITEM and-watchdog task e-android M1 "type/task,area/android,security/invariant" "and-vpnservice relay-heartbeat-silence" \
 "Android watchdog (heartbeat + off-detection)" \
 "WorkManager heartbeat and detection of filter-off/app-kill." \
 "WorkManager heartbeat | VPN/off detection | reboot re-arm | FilterDisabled reporting" \
 "heartbeat reaches the relay | turning the VPN off emits FilterDisabled | killing the app leads to DeviceSilent | re-arms after reboot"

ITEM and-partner-mode task e-android M1 "type/task,area/android,security/invariant,priority/critical" "and-app-shell relay-approvals-transport relay-push" \
 "Android partner mode (Keystore approvals)" \
 "One-tap approve/veto signed by a hardware Keystore key; decrypts sealed unblocks." \
 "approve/veto signing in Keystore | sealed-unblock decryption | FCM handling | request UI" \
 "approve signs with the hardware key | can open a sealed unblock | FCM received | forgery impossible without the private key"

# ---- ENFORCEMENT HARDENING (M1) --------------------------------------------
ITEM hard-doh-feed-ops task e-enforcement M1 "type/task,area/enforcement" "relay-feeds" \
 "DoH-endpoint feed maintenance pipeline" \
 "Keep the DoH denylist fresh and signed; it rots weekly." \
 "scheduled feed build | signing | staleness alarm | canary integration" \
 "feed auto-updates on schedule and is signed | the canary picks up new providers | a stale feed raises an alarm"

ITEM hard-bypass-matrix task e-enforcement M1 "type/task,area/enforcement,security/invariant,priority/critical" "svc-canary svc-quic-block svc-browser-doh and-vpnservice ios-deviceactivity" \
 "Automated bypass test matrix" \
 "Every documented escape route gets an automated test asserting block + alert." \
 "tests for DoH, DoT, foreign DNS, VPN, Tor, ECH, QUIC, hosts, direct-IP | CI gate | report artifact" \
 "each route has a test asserting it is blocked and alerted | the matrix is a CI gate | a coverage report is published"

# ---- SCREEN-CV (M2) ---------------------------------------------------------
ITEM cv-capture task e-screencv M2 "type/task,area/screen-cv,security/invariant" "svc-notifier" \
 "ROI screen capture + visible indicator" \
 "Capture the focused window in the interactive session, with a persistent indicator." \
 "session-side helper | focused-window ROI capture | persistent capture indicator | watchdog-protected" \
 "captures the focused-window ROI (not the whole desktop) | a visible indicator is always shown while active | runs in the interactive session (not Session 0)"

ITEM cv-inference task e-screencv M2 "type/task,area/screen-cv,security/invariant" "cv-capture" \
 "On-device two-stage ONNX inference" \
 "Fast+heavy staged NSFW inference entirely on device." \
 "ort/DirectML runtime | fast then heavy stage | confidence scores | eval benchmark" \
 "raw frames never leave the device (network egress test = zero) | staged pipeline runs | confidence scores emitted | accuracy benchmarked on an eval set"

ITEM cv-reporting task e-screencv M2 "type/task,area/screen-cv,security/invariant" "cv-inference" \
 "Threshold -> ScreenContentFlagged (alert-only default)" \
 "Turn scores into a partner signal that is alert-only by default and never raw." \
 "threshold logic | ScreenContentFlagged event | opt-in gating | optional blurred thumbnail" \
 "alert-only by default | no image egress | opt-in gating enforced | blurred thumbnail optional and never raw by default"

# ---- LOCKED TIER (M2) -------------------------------------------------------
ITEM lock-wfp-driver task e-locked M2 "type/task,area/enforcement" "svc-egress-wfp" \
 "WFP callout driver (C/C++ WDK) SNI inspection" \
 "Kernel callout for SNI-level DoH/front blocking; the one place we keep C/C++ and EV signing." \
 "WDK callout driver | ClientHello SNI inspection | DoH-hostname + front denylist | EV-signed test build | fail-closed" \
 "driver inspects ClientHello SNI | blocks DoH hostnames and rotating fronts | an EV-signed build loads | fails closed | performance acceptable"

ITEM lock-ios-supervision task e-locked M2 "type/task,area/ios" "ios-familycontrols" \
 "iOS supervised profile (global filter, locked settings)" \
 "Supervision is the only path to a non-disableable iOS filter." \
 "supervised .mobileconfig | NEFilterDataProvider global filter | lock DNS/VPN | disallow app removal | lock Screen Time" \
 "on a supervised device the global filter is non-disableable | VPN creation disabled | app removal disallowed | Screen Time locked | flow documented"

ITEM lock-android-deviceowner task e-locked M2 "type/task,area/android" "and-vpnservice" \
 "Android Device Owner provisioning" \
 "Device Owner is the real Android lockdown; requires a reset device." \
 "DPC | QR/afw provisioning | always-on VPN lockdown | DISALLOW_CONFIG_VPN/PRIVATE_DNS | pin private DNS | DISALLOW_UNINSTALL" \
 "on a reset device, provisioning applies always-on VPN lockdown | VPN/private-DNS config disallowed | uninstall blocked | flow documented"

ITEM lock-uninstall-approval task e-locked M2 "type/task,area/enforcement,security/invariant" "lock-ios-supervision lock-android-deviceowner svc-approvals" \
 "Approval-gated uninstall (Locked)" \
 "In Locked, uninstall is blocked without a partner approval, by prior consent." \
 "block uninstall paths | require Ed25519 approval | clean removal on approval | events" \
 "uninstall blocked without a valid partner approval on all Locked platforms | with approval, removal is clean and emits events"

# ---- SECURITY & RELEASE (M3) ------------------------------------------------
ITEM sec-threat-validation task e-security M3 "type/task,area/security,security/invariant,priority/critical" "hard-bypass-matrix svc-approvals relay-approvals-transport" \
 "Validate every defended threat with a test" \
 "A traceability matrix proving each design section 15 defended item has a passing control/test." \
 "threat->test matrix | fill coverage gaps | document residuals | sign-off" \
 "every defended threat maps to a passing test | residuals explicitly documented | security sign-off recorded"

ITEM sec-key-recovery task e-security M3 "type/task,area/security,security/invariant,priority/critical" "svc-approvals relay-registry-pairing ios-partner-mode and-partner-mode" \
 "Partner key rotation and recovery flow" \
 "The new attack surface: rotating the partner key must be delayed and dual-notified so it cannot be silently swapped." \
 "rotation via old key OR full-delay+multi-channel alert | recovery runbook | anchor update path" \
 "rotation requires the old key or a full cooling-off plus multi-channel alert | a silent partner-key swap is impossible (test) | recovery runbook validated"

ITEM sec-privacy-review task e-security M3 "type/task,area/security,security/invariant" "relay-deploy cv-reporting svc-notifier" \
 "Privacy-floor audit" \
 "Confirm no browsing history, no URL logging, no DPI, no screenshots off device, minimal relay storage." \
 "data-flow audit | relay storage review | sealed-unblock verification | DPIA document" \
 "audit confirms the privacy invariants | relay stores only minimal fields | sealed unblock verified end to end | DPIA published"

ITEM sec-pentest task e-security M3 "type/task,area/security" "sec-threat-validation" \
 "Third-party pen test / red-team" \
 "External validation focused on the accountability guarantees and enforcement." \
 "engage vendor | scope to accountability + enforcement | remediate | retest" \
 "external report delivered | critical findings remediated | retest passes | report archived"

ITEM rel-docs task e-security M3 "type/task,area/security,area/foundations" "f-threat-model-doc" \
 "User/partner docs + OSS repo hygiene" \
 "Onboarding docs and the open-source hygiene the trust story implies." \
 "install/pairing guides | SECURITY.md | CONTRIBUTING | LICENSE | reproducible-build verify steps" \
 "install and pairing guides exist | SECURITY.md disclosure policy present | reproducible-build verification documented | LICENSE chosen"

ITEM rel-beta task e-security M3 "type/task,area/security,priority/critical" "inst-signing ios-partner-mode and-partner-mode relay-deploy" \
 "Phase-1 closed beta" \
 "End-to-end validation of the Hardened Windows + relay + partner app spine with real users." \
 "beta cohort | end-to-end pairing | field validation of approvals+alerts | telemetry budget" \
 "beta cohort onboarded | pairing works end to end | approvals and alerts verified in the field | crash/telemetry within budget"

# =============================================================================
# PROJECT (v2)  —  create a board and add every issue (best-effort)
# =============================================================================
PROJECT_NUMBER=""
create_project() {
  [ "$MAKE_PROJECT" -eq 1 ] || { info "Skipping Project (--no-project)."; return; }
  say ""; info "Project board:"
  if [ "$DRY_RUN" -eq 1 ]; then say "  would create Project v2: $PROJECT_TITLE (owner $REPO_OWNER)"; return; fi
  # gh has a built-in jq engine (--jq/-q); no external jq needed. Needs the 'project' scope:
  #   gh auth refresh -s project,read:project
  PROJECT_NUMBER="$(gh project list --owner "$REPO_OWNER" --format json \
     --jq ".projects[] | select(.title==\"$PROJECT_TITLE\") | .number" 2>/dev/null | head -n1 || true)"
  if [ -z "$PROJECT_NUMBER" ]; then
    PROJECT_NUMBER="$(gh project create --owner "$REPO_OWNER" --title "$PROJECT_TITLE" \
       --format json --jq '.number' 2>/dev/null || true)"
  fi
  if [ -n "$PROJECT_NUMBER" ]; then ok "Project #$PROJECT_NUMBER"; else warn "could not create/find the project — is the 'project' scope granted? (continuing without it)"; fi
}

add_to_project() {
  [ "$MAKE_PROJECT" -eq 1 ] && [ -n "$PROJECT_NUMBER" ] || return 0
  say ""; info "Adding issues to Project #$PROJECT_NUMBER…"
  local s
  for s in "${!URL[@]}"; do
    gh project item-add "$PROJECT_NUMBER" --owner "$REPO_OWNER" --url "${URL[$s]}" >/dev/null 2>&1 || true
  done
  ok "issues added to project (best-effort)"
}

# =============================================================================
# RUN
# =============================================================================
TOTAL="${#SLUG[@]}"
EPICS=0; TASKS=0
for i in "${!TYPE[@]}"; do [ "${TYPE[$i]}" = "epic" ] && EPICS=$((EPICS+1)) || TASKS=$((TASKS+1)); done
say ""
info "Plan: $TOTAL issues ($EPICS epics, $TASKS tasks) across 4 milestones."

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  printf 'Create these in %s? [y/N] ' "$REPO"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "Aborted." ;; esac
fi

ensure_labels
ensure_milestones
create_project
run_create
add_to_project

say ""
ok "Done. $TOTAL issues processed for $REPO."
[ "$DRY_RUN" -eq 1 ] && info "(dry run — re-run without --dry-run to apply)"
if [ "$DRY_RUN" -eq 0 ]; then
  say ""
  say "Next: open the project board and set the first sprint from the M0/M1 'no-blocker' issues:"
  say "  - f-repo-scaffold, core-models, relay-bootstrap have no blockers and unlock the critical path."
fi
