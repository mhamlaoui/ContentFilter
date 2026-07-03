# Content Filter — GitHub backlog automation

Three files:

| File | What it is |
|------|------------|
| `create_backlog.sh` | Idempotent Bash script that creates the GitHub **Project**, labels, milestones, and **90 issues** (13 epics + 77 tasks) with dependencies and validation criteria, in your existing repo. |
| `BACKLOG.md` | Human-readable plan: every ticket, its blockers, its Definition of Done, a build-order (dependency waves), and a Mermaid epic graph. Read this first. |
| `README.md` | You are here. |

The script targets the **existing** `contentfilter` repository — it does **not** create a repo. It creates a new **Project (v2)** board and files the issues into it.

---

## Prerequisites

1. **GitHub CLI** installed and authenticated:
   ```bash
   gh --version
   gh auth login          # if not already logged in
   ```
2. **Project scope** (only needed for the Project board; issues work without it):
   ```bash
   gh auth refresh -s project,read:project
   ```
3. **Bash 4+** (macOS ships 3.2 — use `brew install bash` or run under WSL/Linux; associative arrays are required).

---

## Run it

**Always dry-run first** — this prints the entire plan and creates nothing:

```bash
chmod +x create_backlog.sh
./create_backlog.sh --dry-run
```

Then create for real (it asks for one confirmation):

```bash
./create_backlog.sh
```

### Options / environment

| Flag / Env | Effect |
|------------|--------|
| `--dry-run` | Print the plan, create nothing. |
| `--yes` / `-y` | Skip the confirmation prompt. |
| `--no-project` | Create issues/labels/milestones but skip the Project board. |
| `REPO_OWNER=my-org` | Set if `contentfilter` lives under an **organization** (defaults to your user login). |
| `REPO_NAME=other` | Target a different repo name (default `contentfilter`). |
| `PROJECT_TITLE="…"` | Override the Project title. |

Example for an org-owned repo, no prompt:

```bash
REPO_OWNER=my-org ./create_backlog.sh --yes
```

---

## What it creates

- **Labels** — `type/epic`, `type/task`, `area/*` (core, relay, service, tray, installer, mobile, ios, android, enforcement, screen-cv, security, foundations), `priority/critical`, `security/invariant`, `blocked`.
- **Milestones** — `Phase 0 — Foundations`, `Phase 1 — Accountability Core`, `Phase 2 — Locked Tier & Screen-CV`, `Phase 3 — Hardening & Release`.
- **A Project (v2)** — every issue added to it (best-effort).
- **90 issues** — each with **Context**, **Deliverables**, **Validation / Definition of Done** (checkbox list), and a **Dependencies** section (`Epic: #…`, `Blocked by: #…`).

Epics are created first so tasks can reference them. Tasks are created in **topological order**, so each `Blocked by: #N` reference already exists when the dependent issue is filed. Where supported, epics are also linked to their children as native **sub-issues**.

---

## How ordering, dependencies, and validation are modeled

- **Order** — the script emits issues in dependency-topological order; `BACKLOG.md` additionally groups them into **waves** (Wave 0 has no blockers; Wave N depends only on earlier waves). That is your recommended execution order.
- **Which blocks who** — encoded as `Blocked by: #N` in each issue body (and native sub-issue links for epics). If A is *blocked by* B, then B *blocks* A. Add the `blocked` label workflow or GitHub's native issue-dependencies UI on top if you want automatic gating.
- **Validation per ticket** — every issue has a **Definition of Done** as a checkbox list. An issue is only closeable when its boxes are checked; security-critical tickets (`security/invariant`) include explicit negative tests (e.g. "a holder of only the verify key cannot forge").

---

## Safety

- **Idempotent** — an issue whose exact title already exists is skipped, so re-running won't duplicate.
- **No deletions, ever** — the script only creates/ensures.
- **Preflight** — checks `gh` auth and repo access before any write; aborts cleanly otherwise.
- Review everything in `BACKLOG.md` or via `--dry-run` before you commit.

---

## After it runs

Start the first sprint from the Wave-0 / no-blocker issues:
`f-repo-scaffold`, and (schedule-only, start early) `ios-entitlement`. Then `core-models`
and `relay-bootstrap` open the critical path. Build the **relay + shared core early** —
they gate every accountability property in the design.
