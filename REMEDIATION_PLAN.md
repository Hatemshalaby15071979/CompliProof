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
| P0-1 Packaging/deployment | Local wheel build, clean-venv install and CLI smoke passed; final Docker image built and ran non-root; synthetic backup restored and served by the final image | GitHub Actions run, versioned operator runbook, migration rehearsal, supported TLS proxy deployment, rollback to a pre-upgrade snapshot, Owner signature |
| P0-2 Evidence integrity | Approval is in the explicit seal manifest; local verification detects approval, artifact, and metadata changes; answer-key tamper tests pass | Asymmetric signatures/key lifecycle, external independent review, trust model for the local HMAC key, Owner signature |
| P0-3 Audit | Reconciliation intent is durable before file reads; completion links to intent; append verifies the chain; concurrent append, local anchor, and test-isolation checks pass | Pre-action events for every consequential operation, verified external timestamp/anchor receipt, independent review, Owner signature |
| P0-4 Reports/reconciliation | Stable sorted report rows, explicit duplicate/empty-key rejection, 100% synthetic perfect match, task-only report events, audited HTML/PDF/CSV, byte-identical CLI/server HTML regression; injected input interruption leaves a valid pending intent; 20,000 synthetic rows per input completed in 0.938 s | Production capacity/file-size limits, interruption recovery/resume matrix, remaining complete golden matrix, Owner signature |
| P0-5 Report access | Authenticated report routes, role checks, CSRF, cookie/header tests, current Bandit and Ruff scans pass; basic browser login/logout smoke passes | Full browser-level route acceptance, TLS proxy deployment verification, external security review, Owner signature |
| P0-6 Authentication | bcrypt, privileged-role TOTP, hashed 12-hour sessions, RBAC, CSRF, persistent hashed-key login throttling; lockout survived a local container restart | Encrypted TOTP key operations, account recovery/offboarding, multi-process session coordination, external security review, Owner signature |
| P0-7 Dashboard/routes | Login/logout controls and simulated-data labeling are present; HTTP login/logout and route inventory tests pass; integrated browser smoke passed for a synthetic viewer, restricted finance/pipeline panels, and logout revocation | Browser acceptance for every role and customer deployment verification, Owner signature |

These are not formal P0 closures. The authoritative register remains at **7 open / 0 closed**.
Exact commands, results, synthetic-data labels, and negative recovery findings are in
[`P0_REMEDIATION_EXECUTION_2026-10-31.md`](./P0_REMEDIATION_EXECUTION_2026-10-31.md) and the
attached evidence directory.

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
