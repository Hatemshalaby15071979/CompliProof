# CompliProof P0 remediation execution — 2026-10-31

## Decision and evidence labels

**Readiness: NOT READY for production or customer-data use.** The governing register remains
**7 open / 0 closed**. This report records engineering work and local checks; it is not an Owner
sign-off, independent review, customer evidence, or production approval. The updated register is
[`../company-os/stage-0/P0_REGISTER.yaml`](../company-os/stage-0/P0_REGISTER.yaml).

All HTTP, account, reconciliation, report, backup, restore, browser, and scale exercises in this
report used synthetic data. The fixtures `SYN-001` / `SYN-002`, `synthetic-alpha` /
`synthetic-beta`, and the `synthetic-viewer` / `synthetic-operator` accounts are simulated. No
customer dataset or service was used. See
[`evidence/p0-remediation-2026-10-31/`](evidence/p0-remediation-2026-10-31/) for captured logs,
wheel, manifest, hashes, scanner output, and supplemental browser/scale results.

## Changes made

- `src/compliproof/reconcile.py`: records and fsyncs a reconciliation intent before opening either
  input; links the completion event to that intent; rejects blank and duplicate keys rather than
  overwriting rows; sorts result sections; calculates the match rate against the larger input.
- `src/compliproof/audit.py`: verifies the existing complete chain before appending. A corrupt
  chain now fails closed instead of being extended.
- `src/compliproof/evidence.py`: declares the exact local digest manifest, including approval, and
  adds a verifier that detects changes to covered fields. This is still an unkeyed local digest,
  not a digital signature.
- `src/compliproof/server.py`: persists login throttling in a mode-restricted SQLite file. It
  stores SHA-256 digests of IP/username keys, uses an immediate write transaction across workers,
  and retains the five-attempt/15-minute limit across process restarts.
- `tests/`: adds coverage for pre-action intent and linkage, duplicate/blank keys, injected
  interruption behavior, seal tampering, fail-closed audit appends, persistent login lockout,
  task-scoped reproducible reports, report audit hashes for HTML/PDF/CSV, and exact CLI/server HTML
  parity.
- `.github/workflows/ci.yml`: sets `SOURCE_DATE_EPOCH` from the checked-out commit timestamp before
  wheel builds. The workflow YAML parses locally; GitHub Actions has not been run.

## P0 disposition

| P0 | Local engineering result | Why the registered finding remains open |
|---|---|---|
| P0-1 Packaging/deployment | `python -m build`, clean virtualenv install, both CLI help commands, and Docker build/start passed. Two local wheel builds with the same `SOURCE_DATE_EPOCH` produced byte-identical wheels. The final image ran as UID/GID 999 and passed its health probe. | No hosted CI run exists. The Docker base is still a floating `python:3.11-slim` tag. An in-place downgrade to the older `compliproof:sellable-final-20261031` image could not authenticate a bcrypt account created by the newer code (`401 invalid credentials`). Restore of the synthetic backup with the current candidate passed; restore/rollback from a true pre-upgrade snapshot, migration rehearsal, TLS proxy, operator procedures, and Owner signature remain outstanding. |
| P0-2 Evidence integrity | Approval is in the seal manifest; local verification detects approval, artifact, summary, and timestamp changes. Stored answer-key tamper tests fail verification as required. | The evidence-pack digest is not a signature. The HMAC key is local, with no rotation/revocation lifecycle. Independent review is required by closure evidence and was not supplied. |
| P0-3 Audit ledger | Reconciliation intent is durable before input processing and completion links to it. Append rejects a broken chain. Concurrency, local anchor comparison, independent chain-verifier, and production-ledger isolation tests pass. Inventory found one `audit_events.jsonl` at `workspace/audit_events.jsonl`, with 26 events; 3 contain the substring `test`, which is insufficient to determine provenance. No rows were deleted. | Pre-action intent has only been wired for reconciliation, not every consequential action. Anchors were local only; no verified external TSA receipt exists. No independent external verifier/reviewer or Owner signature was obtained. |
| P0-4 Reporting/reconciliation | A perfect synthetic 2-vs-2 match rendered 100.0% in the served report. HTML/PDF/CSV included full task data; CSV parsed with `csv.DictReader` and retained source values. Report generation is task-scoped, repeatable, and audited. A regression compares CLI and served HTML bytes exactly for the same stored task. An injected read interruption left a valid, pending intent and no false completion. A bounded 20,000-row-per-input synthetic run completed in 0.938 s with 24.99 MiB traced peak memory. | The 20,000-row run is not a production capacity guarantee; larger-file limits and end-to-end recovery/resume remain untested. The complete registered golden matrix and Owner signature are not present. |
| P0-5 Report access | Route/auth/role/CSRF/cookie tests pass. The HTTP drill confirmed authenticated reports and logout revocation. Bandit and Ruff scans passed on the current source. Browser smoke covered sign-in, role-restricted panels, and logout revocation. | No supported TLS proxy deployment or external security review was run. Full browser-level route acceptance and Owner signature remain open. |
| P0-6 Authentication | bcrypt, privileged-role TOTP, hashed 12-hour sessions, RBAC, CSRF, and persistent throttling are implemented. Five failed synthetic attempts followed by a container restart still returned HTTP 429. | TOTP secrets remain unencrypted in the private workspace. Account recovery/offboarding, credential/key operations, and multi-process session coordination remain incomplete. External security review and Owner signature are absent. |
| P0-7 Dashboard/routes | Login/logout controls and simulated-data labeling are in the dashboard. HTTP route inventory and login/logout tests pass; non-public application routes require authentication, with health and login as intended public endpoints. Integrated-browser smoke verified the login page, synthetic viewer sign-in, simulated-data banner, owner-only finance/pipeline restrictions, logout, and post-logout HTTP 401. | The browser run covered the viewer flow only, not every role or customer deployment. Owner signature remains absent. |

No P0 status was changed to `closed`, and no Owner approval was entered.

## Verification commands and results

Run from the CompliProof repository root (`[LOCAL_PATH]/[REDACTED_VOLUME]/Career/CompliProof`).

### Regression and static checks

```bash
COMPLIPROOF_WORKSPACE=/tmp/compliproof-p0-continue-final-20261031 \
PYTHONPATH=src python3 -m pytest tests -q
```

Result after the continuation regression: **85 passed in 18.14s**. Captured output:
`evidence/p0-remediation-2026-10-31/pytest.log`.

Continuation regression:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/test_reconcile.py::test_interrupted_reconciliation_leaves_only_a_pending_intent -q
```

Result: **1 passed**. The test injects an input-read failure after the durable intent and verifies
the chain remains valid without recording a false completion; it is included in the 85-test full
suite above.

```bash
ruff check src/compliproof/auth.py src/compliproof/server.py \
  src/compliproof/reconcile.py src/compliproof/evidence.py src/compliproof/audit.py \
  tests/test_server_auth.py tests/test_reconcile.py tests/test_evidence.py \
  tests/test_report.py tests/test_audit_p0_3.py
```

Result: **All checks passed**. Captured output: `evidence/p0-remediation-2026-10-31/ruff.log`.

```bash
bandit -r src -f json -o evidence/p0-remediation-2026-10-31/bandit.json
```

Bandit **1.9.4**: 0 findings. The initial scan flagged the literal `bcrypt$` storage prefix as a
possible hard-coded password; the source now documents the marker and suppresses that false
positive, and the rescan is clean. The JSON result is saved with the logs. A dependency audit was
not rerun in this execution; the earlier same-day result is in
[`../docs/production_readiness/evidence/sellable-release-2026-10-31/pip-audit.json`](../docs/production_readiness/evidence/sellable-release-2026-10-31/pip-audit.json).

### Reproducible wheel and clean install

The repository's checked-out commit timestamp was `1793438580`. The same environment and timestamp
were used for two independent local builds:

```bash
SOURCE_DATE_EPOCH=1793438580 python -m build --wheel --no-isolation --outdir /tmp/compliproof-repro-a
SOURCE_DATE_EPOCH=1793438580 python -m build --wheel --no-isolation --outdir /tmp/compliproof-repro-b
```

Both produced SHA-256
`87d767d91e7e534a1c351f4edd3777c89fc71d3c4e75897f14327e018e70b741`; archive member contents
also matched. Without `SOURCE_DATE_EPOCH`, two builds had differed only in ZIP timestamps for
generated metadata. The CI workflow now sets the epoch from the commit timestamp. The retained
wheel contains 11 `compliproof/*.py` modules and dashboard data; its manifest and digest are in the
evidence directory.

The retained wheel was installed into a fresh `/tmp` virtual environment with the pinned runtime
dependencies from `requirements.lock.txt`. `compliproof --help` and `compliproof-server --help`
both exited 0. Logs: `clean-install.log`, `compliproof-help.log`, and
`compliproof-server-help.log`.

### Container and synthetic HTTP drill

```bash
docker build -f docker/Dockerfile -t compliproof:p0-drill-20261031 .
docker run -d --name compliproof-p0-app-20261031 \
  -p 127.0.0.1:18200:8200 \
  -v compliproof-p0-data-20261031:/app/workspace \
  compliproof:p0-drill-20261031
```

Build result: image ID `sha256:549868f799dfcd4dec1077d95ceb1641cfc8e7dd83e67256adc77e740049deaf`.
The container ran as UID/GID `999:999`, reached `healthy`, and was published only on host
loopback. It has no built-in TLS. Captured build and HTTP output are
`docker-build.log` and `http-drill.log`.

The synthetic HTTP drill passed secure-cookie login, unauthenticated status denial (401),
CSRF-protected reconciliation, 100.0% HTML, authenticated PDF and CSV downloads, CSV source-value
parsing, and logout revocation. The lockout drill recorded five 401 responses, restarted the
container, and then recorded 429 for that same synthetic account; see `lockout-restart.log`.

The integrated-browser smoke used an isolated temporary workspace and a synthetic viewer. It
verified the sign-in form, successful login, simulated-data banner, finance/pipeline restrictions,
logout, and HTTP 401 from `/api/auth/me` after logout. The captured summary is
[`dashboard-browser-smoke.txt`](evidence/p0-remediation-2026-10-31/dashboard-browser-smoke.txt).
This is not role-by-role browser acceptance.

A separate bounded synthetic scale run reconciled 20,000 rows per input in 0.938 seconds with
24.99 MiB peak traced Python allocations; the chain verified successfully. Its output is
[`scale-20k.log`](evidence/p0-remediation-2026-10-31/scale-20k.log). This does not establish a
production file-size limit or capacity guarantee.

### Backup and restore

The source workspace was backed up to
`/tmp/compliproof-p0-backup-20261031/compliproof-workspace.tar.gz` and restored into a separate
named volume. Archive SHA-256:
`fdca39da9bf10d122aa2578635f66847bef550a6e568648c5683ddd4c6321942`. The final candidate booted
against the restored volume; the synthetic operator could log in and download persisted HTML, PDF,
and CSV reports (`restore-check.log`). The independent local ledger verifier reported 18 valid
events in that restored snapshot. This demonstrates a local synthetic restore only; it does not
test encrypted backup storage, retention, external backup copies, migration, or restore-point
objectives. The temporary archive contained synthetic account/session records and was removed
after the restore drill; its digest and restore logs are retained, but the credential-bearing
runtime archive is not committed or kept in the project tree.

An in-place attempt to run the older image against the newer bcrypt account record returned
`401 {"error": "invalid credentials"}`. The older image only supports its legacy salted-SHA256
hash format. A rollback procedure must restore a compatible pre-upgrade backup; that scenario was
not rehearsed. There is no relational database migration system in this candidate, so no schema
migration command was applicable or claimed as passed.

## Required Owner / external actions

1. Review and sign closure evidence for each P0 only after the remaining criteria above are met.
2. Run the checked-in CI workflow in GitHub Actions. No remote was configured and nothing was
   pushed.
3. Arrange independent evidence review and a verifiable external audit-chain anchor receipt.
4. Decide and document the supported TLS proxy, encrypted-volume/backup policy, TOTP key
   protection, recovery/offboarding, session coordination, and downgrade/restore procedure.
5. Complete role-by-role dashboard acceptance in the intended customer deployment; the local
   viewer browser smoke does not cover every role.
6. Define and test supported large-file limits and interruption/recovery procedures with synthetic
   data, then update this report and register without changing status unless acceptance criteria
   and signed evidence actually exist.

Until those items are complete, CompliProof remains **NOT READY for production or customer-data
use**.
