<div align="center">

# CompliProof

<!-- badges:start -->

![licence](https://img.shields.io/badge/licence-MIT-blue)
![local verification](https://img.shields.io/badge/local%20verification-102%20passed-brightgreen)
![shipment status](https://img.shields.io/badge/shipment-locally%20ready-yellow)

*Local verification measured 2026-11-05 on `audit/shipment-candidate`; hosted GitHub Actions has not run on this candidate. Seven P0 findings remain open — owner-signed closure evidence has not been recorded.*

<!-- badges:end -->

**CompliProof reconciles two CSV exports by a key, presents the result, and generates HTML, PDF, and CSV reports with a local evidence pack and hash-chained audit events.**

![Status](https://img.shields.io/badge/status-pre--production-yellow)
![Licence](https://img.shields.io/badge/licence-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-3776ab)

</div>

## GitHub shipment status (2026-11-06)

The intended public repository is [Hatemshalaby15071979/CompliProof](https://github.com/Hatemshalaby15071979/CompliProof). This checkout has been pushed to `audit/shipment-candidate`; hosted GitHub Actions verification has not yet been observed on the pushed SHA. Local CI-equivalent checks pass: **102 tests passed, 31 skipped** (conditional scenario/scale cases, not failures), bandit no findings, `pip-audit` clean on the hash-locked runtime set, hash install passes in a clean venv, wheel builds (`compliproof-0.1.0-py3-none-any.whl`), Docker builds and the loopback smoke returns `{"ok": true}`. See [`SHIPMENT_READINESS.md`](SHIPMENT_READINESS.md) for exact check outcomes and remaining hosted-only verification.

## One-line identity

CompliProof is a local reconciliation and reporting engine: it reconciles two CSV exports by `id`, presents matched / A-only / B-only sections, and generates HTML / PDF / CSV reports with a local evidence pack and hash-chained audit events. It targets one customer-hosted installation with multiple users; it is not a multi-tenant SaaS service.

> [!IMPORTANT]
> **Positioning.** Pre-production candidate — not confirmed production-ready or audit-grade. Local implementation and regression tests do not close the governing release gates or authorize customer-data use. The authoritative register remains [`../company-os/stage-0/P0_REGISTER.yaml`](../company-os/stage-0/P0_REGISTER.yaml): **seven P0 findings are still open** because owner-signed closure evidence has not been recorded. There is no approved customer deployment, no production dataset, and no external product claim.

> [!NOTE]
> **Operating principle.** CompliProof records a durable intent before reading inputs, rejects duplicate or empty keys, and sorts result sections for repeatable output. The evidence-pack manifest includes approval and can detect field drift against its local hash. The report file's SHA-256 is recorded in the local audit ledger and checked before it is served. Uploaded CSV files are temporary and removed after reconciliation. A local hash chain is not an external trust anchor — keep the workspace on an encrypted volume, restrict service-account access, and align backups with the 30-day retention policy.

## What it does

CompliProof reconciles two systems' exports (`system_a.csv`, `system_b.csv`) by their shared `id` key, produces the union of keys (A-only, B-only, common), and renders HTML / PDF / CSV reports. Every report route requires authentication and authorisation; content types are correct, no unhandled exceptions are surfaced, CORS is explicit, and cookies carry Secure / HttpOnly / SameSite flags.

## How it fits Helix Codex

CompliProof is part of the Helix Codex / Helix Prime body of work — the same author and the same design philosophy (explainable, auditable, no generative model in the evidence path). It is an **independent repository with no shared codebase or runtime infrastructure** with Helix Prime, live-support-assistant, Signoff, or CreateLee; portfolio membership, not technical integration.

CreateLee supplies valid `system_a.csv` / `system_b.csv` pairs so `compliproof reconcile` can be exercised and a reconciliation report produced — that demonstrates the product works, not that the product is production-ready. **0 of the 7 P0 gates are closed by CSV exports.**

## Architecture

- `src/compliproof/` — CLI (`audit verify`, `reconcile`), server, report, auth, reconcile modules.
- `workspace/` — local runtime data (gitignored); results under `$COMPLIPROOF_WORKSPACE/results/` with mode `0700` / file mode `0600`.
- `docker/` — non-root Dockerfile, digest-pinned base image, secure cookies, no built-in TLS (front with a trusted TLS-terminating reverse proxy).
- `requirements.in` / `requirements.lock.txt` — direct dependencies and SHA-256-pinned resolved runtime set.
- `evidence/` — dated production-readiness evidence bundles (checksummed).

## Production status & verification

> [!WARNING]
> This is a pre-production candidate. **Validated on synthetic fixtures; safety-first by design; intended for local reconciliation and reporting, not a compliance determination.** The backup exercise used an unencrypted one-line synthetic archive; migration checking used a fixture rather than a real upgrade/rollback; interrupted reconciliation was recorded but not resumed. See [`PRODUCTION_READINESS_EXECUTION_2026-11-05.md`](./PRODUCTION_READINESS_EXECUTION_2026-11-05.md) and the checksummed [`evidence bundle`](./evidence/production-readiness-2026-11-05/).

| Area | Result | Source |
| --- | --- | --- |
| Tests | **102 passed, 31 skipped** (conditional scenario/scale cases) | `python3 -m pytest tests -q` |
| Bandit | **No findings** | `bandit -r src -q` |
| Dependency audit | **No known vulnerabilities found** | `pip-audit -r requirements.lock.txt` |
| Hash install | **Passed** in clean venv | `pip install --require-hashes -r requirements.lock.txt` |
| Wheel build | `compliproof-0.1.0-py3-none-any.whl` (59,672 bytes) | `python3 -m build --wheel --no-isolation ...` |
| Docker build | **Built** (repaired after hash-lock fix) | `docker build -f docker/Dockerfile ...` |
| Docker smoke | `{"ok": true}` on `GET /api/healthz` | loopback-only run, container removed |
| Synthetic scale | **100,000 rows** reconciled in 4.590 s, audit chain verifying | local run, 2026-11-05 |

**Important remaining release gaps:** evidence trust (local hashes/HMACs, not asymmetric signature or independent verifier; no external anchor or key lifecycle), operations (only limited synthetic backup/restore and migration fixture checks; encrypted backup lifecycle, real upgrade/rollback, monitoring, incident response unverified), authentication operations (account recovery, credential rotation, encrypted TOTP key operations, multi-process session coordination not implemented), deployment/supply chain (local gates do not prove a hosted GitHub Actions run; hosted CI has not run), reconciliation scope (supported file limits and resumption after interrupted processing open), and data protection (filesystem encryption, backup expiry, and deletion from external backups are the operator's responsibility).

See [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) for the dated assessment and [`REMEDIATION_PLAN.md`](./REMEDIATION_PLAN.md) for the closeout checklist.

## Reproducible dependencies

`requirements.in` lists direct runtime dependencies. `requirements.lock.txt` pins the resolved runtime set and includes SHA-256 hashes for supported platform artifacts. Update it with:

```bash
uv pip compile --generate-hashes --universal requirements.in --output-file requirements.lock.txt
python -m pip install -r requirements.lock.txt
python -m pip install --no-deps .
```

## Local development

Python 3.10+ is declared; the checked-in CI currently targets Python 3.11. Install from this directory, then provision an account. Privileged roles require an authenticator app.

```bash
python3 -m pip install .
export COMPLIPROOF_WORKSPACE="$PWD/workspace"
compliproof users add owner --email owner@example.test --role owner
compliproof-server
```

The account command prompts for a password and, for owner/approver, verifies TOTP enrollment before saving the account. Open `http://127.0.0.1:8200/`. Registration is disabled by default. The optional `--allow-registration` bootstrap is loopback-only and creates viewer accounts; do not enable it for a network-facing service.

For development directly from the source tree:

```bash
PYTHONPATH=src python -m compliproof.cli audit verify
PYTHONPATH=src python -m compliproof.cli reconcile a.csv b.csv id
PYTHONPATH=src python -m compliproof.server
```

## Data handling and roles

- The HTTP request limit is 5 MiB. CSV upload files are written to a private temporary directory and removed after reconciliation.
- Full row-level results are stored under `$COMPLIPROOF_WORKSPACE/results/` with directory mode `0700` and file mode `0600`. A local audit event records the result hash. Stored row-level results are deleted after 30 days; the server checks hourly, CLI saves prune expired records, and CLI loads remove the requested expired record. HTML files explicitly exported by the CLI are outside this managed retention.
- Roles: `owner` manages finance/pipeline and audit; `approver` can operate and read audit; `operator` can reconcile and manage tasks; `auditor` is read/audit-only; `viewer` is read-only.
- All application/data API routes require a session; login and the optional loopback-only registration endpoint are exceptions. The dashboard shell itself is public and shows a login form. `/api/healthz` returns only `{"ok": true}` for health probes.

## Container

The image runs as a non-root user, binds inside the container, and sets secure cookies. The service has no built-in TLS. Put it behind a trusted TLS-terminating reverse proxy; do not expose the container port directly. Non-loopback server bindings require `COMPLIPROOF_SECURE_COOKIES=1`.

```bash
python -m pip install -r requirements.lock.txt
python -m pip install --no-deps .
docker build -f docker/Dockerfile -t compliproof:local .
docker volume create compliproof-local-data
docker run --rm --name compliproof-local \
  -p 127.0.0.1:8200:8200 \
  -v compliproof-local-data:/app/workspace \
  compliproof:local
```

This is a local container smoke path, not a customer deployment or operations runbook.

## Tests and local packaging

```bash
COMPLIPROOF_WORKSPACE=/tmp/compliproof-tests python3 -m pytest tests -q
ruff check src/compliproof/auth.py src/compliproof/server.py src/compliproof/cli.py \
  src/compliproof/reconcile.py src/compliproof/report.py \
  tests/test_security.py tests/test_server_auth.py tests/test_report.py tests/test_cli_workspace.py
python3 -m pip wheel . --no-deps --no-build-isolation -w /tmp/compliproof-wheel
```

The tests use temporary workspaces and ledgers. Do not point test runs at a customer workspace. The GitHub workflow additionally builds/installs a wheel, runs scans, and builds the container; those hosted checks are not represented as passed until a real CI run exists. The repository-wide Ruff scan currently has existing findings in other untouched files; the changed Python paths above are clean.

## Claims and governance

Customer-facing claims remain blocked by the claims register. The product is not certified, independently audited, or represented as a compliance determination. Synthetic fixtures and local tests are simulation evidence only. See [`../company-os/stage-0/CLAIMS_REGISTRY.yaml`](../company-os/stage-0/CLAIMS_REGISTRY.yaml) and [`../company-os/stage-0/TRUTH_FREEZE_WORK_ORDER.md`](../company-os/stage-0/TRUTH_FREEZE_WORK_ORDER.md).

## License

The root `LICENSE` and package metadata declare MIT. Dependency-license provenance and third-party source lineage still require review; the license declaration is not that review.
