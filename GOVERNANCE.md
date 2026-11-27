# GOVERNANCE.md — Operating Policy & Repo Map for CompliProof

> Companion to `CONSTITUTION.md` (the *why* — philosophy and clean-code policy, which
> this file enforces operationally) and `AGENTS.md` (the agent charter + ledger).
> Read all three before acting. This file may be updated by any agent **as a logged
> governance change**; the CONSTITUTION itself is owner-only.

## 1. Repository map

| Path | Purpose (one line) |
|---|---|
| `src/compliproof/` | The product: reconciliation engine, local server, CLI, report writers, and the tamper-evident audit ledger. |
| `dashboard/home.html` | The single-page dashboard served by the local server. |
| `docker/` | `Dockerfile` and `nginx.conf` for the container image CI builds and health-checks. |
| `scripts/` | Operator and verification scripts: `check_doc_consistency.py`, `scale_stress.py`, `backup_restore_drill.py`, `migration_rehearsal.py`, `role_smoke.py`, `remediate.py`. |
| `tests/` | The pytest suite, including `test_doc_consistency.py`, which enforces the status-truth policy in section 3. |
| `evidence/` | Captured evidence packs, one directory per dated run. Logs and artifacts, never claims. |
| `synthetic_data/` | Generated synthetic inputs, manifests and chaos scenarios. Never customer data. |
| `tooling/security/` | `scan_history_secrets.py`, the full-history secret scanner CI runs. |
| `docs/archive/` | Historical execution logs and superseded plans (section 4). |
| `.github/workflows/ci.yml` | The verification gate: test, install, docker, security, docs-consistency, history-scan, root-document gate. |
| `.github/workflows/docs-sync.yml` | Release-triggered status-block sync; it opens a pull request and never commits to the branch. |
| `index.html` | The landing page. It mirrors `README.md`; it never forks it. |
| `_docs_profile.json` | This repository's docs-sync configuration. |

**Branch policy.** The default branch is `audit/shipment-candidate`, not `main`. CI runs on
every branch, and a green run is a verification result — never a release or shipment decision.

## 2. Documentation policy (what belongs where)

**Root holds only the requested set** — nothing else:

| File | State | Purpose |
|---|---|---|
| `README.md` | required | The single source of truth: what this is, how to run it, and the current status. Carries the Helix Solutions logo. |
| `AGENTS.md` | required | Agent charter + sign-in/out ledger. |
| `CONSTITUTION.md` | required | The owner's engineering philosophy and clean-code policy, the same text as in every other repository in the portfolio. |
| `GOVERNANCE.md` | required | This file: repo map, documentation policy, status-truth policy, archiving rules. |
| `CHANGELOG.md` | standard | Dated user-visible changes. |
| `LICENSE` / `LICENSE.md` | standard | MIT. |
| `SECURITY.md` | standard | Security policy and private reporting route. |
| `SHIPMENT_READINESS.md` | status | The live shipment-status record. Read as a live document by `scripts/check_doc_consistency.py`, so it stays at the root. |
| `AUDIT_REPORT.md` | status | The live audit findings. Read as a live document by `scripts/check_doc_consistency.py`, so it stays at the root. |
| `REMEDIATION_PLAN.md` | status | The live P0 remediation and evidence plan, linked from `README.md`. It tracks open findings; it is not a historical report. |

**Everything else lives in `docs/`** — reports, audit logs, execution plans, research
notes, ADRs, runbooks, anything dated or one-off. No stray `.md`/`.txt` at the root.
If a document at the root is not in the table above, move it to `docs/` (or
`docs/archive/` if it is historical) and record the move in the `AGENTS.md` ledger.

`requirements.lock.txt` and `requirements.in` are package manifests, not documents: pip
resolves them relative to the working directory, so `docs/` is not an option.

## 3. Status truth policy

`README.md`'s "Current status" section is the single source of truth for project status.
`scripts/check_doc_consistency.py` enforces it: version, Python floor, dependency pins and
status wording must agree across `pyproject.toml`, the package, the Dockerfile, CI and the
live documents. Dated execution logs are historical records and may describe an earlier state.

A green CI run proves the checks passed on that commit. It does not close a P0 finding, and
it is not a compliance determination or a customer-deployment approval. Seven P0 release
findings remain open pending owner-signed closure; the register lives in the `company-os`
repository, outside this one.

## 4. Archiving rule

- Archive (move to `docs/archive/`), never delete: historical reports, superseded plans,
  dated audits, and one-off execution logs.
- Delete outright only regenerable artifacts: caches, build output, coverage files.
- Fix the links inside a moved document and the links pointing at it in the same landing,
  so the archive never breaks a reader's path.
- Record every move in the `AGENTS.md` ledger with date and time.

## 5. Engineering philosophy & clean-code policy (operational summary)

The full text is `CONSTITUTION.md`. The operational reminders, enforced here:

- **Fail closed.** Missing input, an unverified hash or an unauthenticated caller is a
  refusal, never a default.
- **Evidence before claims.** Every published number carries a command, a date and an artifact.
- **No duplicates, no temp files, one file one job, every file explains itself.**
- **Secrets never enter the tree.**
- **Simple English** in code, docs and UI.
- **One brand mark:** the Helix Solutions logo, everywhere.

## 6. Definition of done

It works; it has a test or a documented manual check; the `AGENTS.md` ledger has an entry;
the docs reflect the new reality; no temporary file was left behind; and every published
number can be re-run to reproduce itself.
