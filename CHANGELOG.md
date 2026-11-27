# Changelog

All notable changes to CompliProof are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

This file is new as of 2026-11-27; before it existed, changes were recorded only in the
git log and in the dated execution logs now under `docs/archive/`.

## 2026-11-27

### Added

- `AGENTS.md` — agent charter and the sign-in/sign-out ledger.
- `CONSTITUTION.md` — the owner's engineering philosophy and clean-code policy, the same
  text as in every other repository in the portfolio.
- `GOVERNANCE.md` — repo map, documentation policy, status-truth policy and archiving rules.
- `scripts/check_root_docs.py` — the root-document hygiene gate from `GOVERNANCE.md`
  section 2, checked in both directions, with a self-test that proves it fails closed.
- A `governance` job in `.github/workflows/ci.yml`, included in the release gate.

### Changed

- Historical execution logs moved to `docs/archive/`:
  `AUTONOMOUS_PRODUCTION_READINESS_PLAN_2026-10-31.md`,
  `P0_REMEDIATION_EXECUTION_2026-10-31.md`,
  `PRODUCTION_READINESS_EXECUTION_2026-11-04.md`,
  `PRODUCTION_READINESS_EXECUTION_2026-11-05.md`. Their internal relative links were fixed,
  and `REMEDIATION_PLAN.md` now points at the archived execution log.
- `SHIPMENT_READINESS.md`, `AUDIT_REPORT.md` and `REMEDIATION_PLAN.md` stay at the root and
  are named as live status documents: `scripts/check_doc_consistency.py` reads the first two
  from the root, and `README.md` links the third.

### Unchanged, and deliberately so

- The product code, the test suite, the CI jobs that existed before, and every published
  status number. Nothing in this landing claims a P0 is closed.
