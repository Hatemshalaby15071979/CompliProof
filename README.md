<div align="center">

# CompliProof

<!-- badges:start -->

![licence](https://img.shields.io/badge/licence-MIT-blue)
![local verification](https://img.shields.io/badge/local%20verification-passing-brightgreen)
![CI](https://github.com/Hatemshalaby15071979/CompliProof/actions/workflows/ci.yml/badge.svg)

*Local verification and hosted GitHub Actions are green on the default branch. Seven P0 findings remain open — owner-signed closure evidence has not been recorded.*

<!-- badges:end -->

</div>

## What is this?

CompliProof compares two CSV exports — say, from two different systems — matches the rows by a shared ID, and shows you clearly what matches, what only exists on one side, and what differs. It then produces a report (HTML, PDF, or CSV) and keeps a tamper-evident local audit trail of everything it did.

Think of it as a careful reconciliation assistant: every result comes with evidence you can check later.

## Current status — read this first

**This is a pre-production candidate, verified locally and in CI. It is not production-ready, not audit-grade, and not approved for customer data.**

<!-- docs-sync:start -->
**CompliProof 0.1.0 — pre-production candidate, verified locally and in CI.** The full test suite passes (conditional scenario/scale cases are skipped). Seven P0 release gates remain open (owner-signed closure not recorded).
<!-- docs-sync:end -->

What has actually been checked (locally, 2026-11-05, and in hosted CI on every branch):

| Check | Result |
| --- | --- |
| Tests | Full suite passes; 31 conditional scenario/scale cases skipped, not failed |
| Security scan | No findings |
| Dependency audit | No known vulnerabilities |
| Install from locked deps | Passes in a clean environment |
| Package build | Wheel builds |
| Docker | Builds; health check returns `{"ok": true}` |
| Scale test | 100,000 rows reconciled in about 4.6 seconds |

What is still open:

- Hosted GitHub Actions is green on the default branch; the checks above are now CI-backed, not local-only.
- Seven P0 release findings remain open, waiting for owner-signed closure. The register lives in the company-os repo.
- It is not a compliance determination, and there is no approved customer deployment.

Full details, if you want them: [SHIPMENT_READINESS.md](SHIPMENT_READINESS.md) · [AUDIT_REPORT.md](AUDIT_REPORT.md) · [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md)

This "Current status" section is the single source of truth for project status. Dated execution logs elsewhere in the repository are historical records and may describe an earlier state.

## How to run it

```bash
python3 -m pip install .
export COMPLIPROOF_WORKSPACE="$PWD/workspace"
compliproof users add owner --email owner@example.test --role owner
compliproof-server
```

The user command asks for a password (owners also need an authenticator app). Then open `http://127.0.0.1:8200/`. Registration is off by default.

Just want the reconciliation, no server?

```bash
compliproof reconcile system_a.csv system_b.csv id
```

## A few design choices, briefly

- It records what it intends to do *before* reading your files, and rejects duplicate or empty keys — so runs are repeatable and auditable.
- Uploaded files are deleted after each run; results are stored with restrictive file permissions and cleaned up after 30 days.
- Every report's hash is written to the local audit ledger and checked before the report is served.
- One honest caveat: a local hash chain is not an external trust anchor. Keep the workspace on an encrypted volume and align backups with your retention policy.

## Dependencies

Direct dependencies live in `requirements.in`; `requirements.lock.txt` pins exact versions with SHA-256 hashes so installs are reproducible.

## License

MIT. Dependency-license provenance still needs a proper review — the MIT declaration is not that review.
