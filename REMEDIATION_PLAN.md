# CompliProof — release remediation and evidence plan

**Status date:** 2026-10-31
**Deployment target:** one customer-hosted installation, multiple users, one customer per
installation
**Authority:** [`../company-os/stage-0/P0_REGISTER.yaml`](../company-os/stage-0/P0_REGISTER.yaml)

## Governing rule

The registered rule is unchanged: a P0 closes only after its registered acceptance test passes
and the Owner signs the closure evidence. This plan tracks implementation separately from formal
closure. Do not mark a P0 closed because a local test passes, and do not claim customer or
production readiness while the release gate remains open.

The local candidate is a useful base for synthetic, simulated design-partner drills. AI-generated
review and synthetic chaos tests can provide repeatable engineering evidence when their method,
inputs, and limitations are recorded. They are simulations, not a human independent audit and
not customer-market evidence. Do not label them otherwise.

## Candidate implementation status

| Area | Implemented in the local candidate | Still required for registered closure |
|---|---|---|
| P0-1 Packaging/deployment | Correct package discovery, pinned runtime dependencies, wheel/CLI/container paths | Fresh clean install/build evidence, CI evidence, digest/hash reproducibility, backup/restore, migration/rollback, operator runbook, Owner signature |
| P0-2 Evidence integrity | Existing local seals and tamper tests; reconciliation result-file digest is linked to the local ledger | Asymmetric signature/key lifecycle, independent verifier evidence, complete seal-manifest tests, Owner signature |
| P0-3 Audit | Shared workspace ledger, thread/process locking in the ledger, local verification and anchor mechanisms | Verified external anchor receipt, canonical-ledger inventory, full registered pre-action and independent-verifier evidence, Owner signature |
| P0-4 Reports/reconciliation | Persisted full results, task-scoped HTML/PDF/CSV route data, 30-day result retention, CSV formula escaping | Complete golden acceptance matrix, CLI/server parity evidence, duplicate/missing-key and large-file behavior, interruption/recovery, Owner signature |
| P0-5 Report access | Session authentication, role checks, CSRF for mutations, report-format route tests | Full route/security scan, supported TLS proxy deployment, Owner signature |
| P0-6 Authentication | bcrypt, privileged-role TOTP, hashed 12-hour sessions, RBAC, CSRF, local rate limit | Persistent throttling, encrypted TOTP secret/key operations, account recovery/offboarding, multi-process coordination, complete registered evidence, Owner signature |
| P0-7 Dashboard/routes | Login/logout, role-aware controls, authenticated application routes, minimal health endpoint | Browser-level acceptance, customer deployment verification, complete registered evidence, Owner signature |

These are not formal P0 closures. The authoritative register currently remains at **7 open / 0
closed**.

## Required verification sequence

Run from the repository root with a disposable test workspace:

```bash
COMPLIPROOF_WORKSPACE=/tmp/compliproof-tests python3 -m pytest tests -q
ruff check src/compliproof/auth.py src/compliproof/server.py src/compliproof/cli.py \
  src/compliproof/reconcile.py src/compliproof/report.py \
  tests/test_security.py tests/test_server_auth.py tests/test_report.py tests/test_cli_workspace.py
python3 -m pip wheel . --no-deps --no-build-isolation -w /tmp/compliproof-wheel
```

Then install the wheel in a fresh virtual environment, run both installed CLI entry points, build
the Docker image without relying only on cached project layers, start it as non-root, and verify
`/api/healthz` plus the authenticated login/report flows through the intended TLS proxy. Preserve
the command output as local evidence. Hosted workflow status must be reported only after an actual
hosted run; this project can remain local with no remote, but local checks are not a CI run.

Do not run tests against customer workspaces. Reconciliation results contain row values and are
retained locally for 30 days; use synthetic fixtures for readiness simulations.

## Operational closeout before a customer deployment

1. Select and document TLS termination, trust boundaries, proxy headers, network exposure, and
   service-account permissions. The app does not provide TLS itself.
2. Use an encrypted persistent volume. Define backup access, backup retention, restore point
   objectives, and deletion of expired copies in backup systems.
3. Execute backup/restore, upgrade/migration, rollback, and service-restart drills using synthetic
   customer-shaped data; record artifacts and measured recovery times.
4. Define monitoring, log handling, incident notification, credential recovery/rotation, account
   suspension, and operator ownership.
5. Test the 30-day deletion behavior, including the server worker and any external backups. The
   CLI-exported HTML report is outside the managed result retention.
6. Run browser acceptance for owner, approver, operator, auditor, and viewer; verify denied
   actions and authenticated report downloads in the intended proxy configuration.
7. Review the current P0 register and claims register. Record Owner decisions and evidence without
   rewriting a simulated result as independent review or external certification.

## Local repository closeout

The requested delivery is a local Git repository only. Verify `git remote -v` is empty, stage only
CompliProof source/tests/docs/deployment files, inspect staged paths and secret-scan output, then
make a local commit. Do not add a remote or push. A commit records source state; it does not
authorize a release.

## Readiness decision

Until the registered acceptance criteria and Owner-signed closure evidence are complete, the
decision remains **NOT READY for production/customer-data use**. Continue with synthetic fixtures
and clearly labeled AI-assisted simulation. The owner may revise governance requirements through
the governing decision process, but documentation must preserve what was actually tested and by
whom.
