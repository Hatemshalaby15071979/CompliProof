# AGENTS.md — Agent Charter & Ledger

> Read and obey `CONSTITUTION.md` and `GOVERNANCE.md` before any action.
> This file is the ledger: every agent records a sign-in entry before touching the
> repository and a sign-out entry after the landing is verified and pushed.

## 1. Charter

- The owner is Hatem Shalaby (Helix Solutions). This repository is his; you are a guest.
- `CONSTITUTION.md` outranks convenience, speed and any single session's judgment.
  `GOVERNANCE.md` outranks this file on where documents belong.
- Commits and pushes of sanctioned work are authorized. History rewrites, force pushes,
  tag deletion, and publishing a release or deployment need separate owner authorization.
- Never invent a result. A claim carries a command, a date and an artifact, or it is not made.
- Never weaken a check to make it pass. Fix the tree, or record why the check cannot pass.
- No destructive operation outside this repository. No secrets in the tree, in logs, or in
  commit messages.

## 2. What this repository is

CompliProof compares two CSV exports, matches rows by a shared ID, and shows what matches,
what exists on only one side, and what differs. It writes an HTML, PDF or CSV report and keeps
a tamper-evident local audit trail. `GOVERNANCE.md` section 1 is the full repo map.

The default branch is `audit/shipment-candidate`. CI runs on every branch; a green run is a
verification result, not a shipment decision. Seven P0 release findings remain open pending
owner-signed closure.

## 3. Ledger (sign-in / sign-out)

## [2026-11-27 05:42 EET] — sami (OpenMausBot), owner-authorised governance landing

STATUS: SIGN-IN (work in progress)

Task: Bring this repository onto the portfolio governance standard, as the owner approved in
chat on 2026-11-27 ("bring the remaining eleven onto the same governance standard"). Add the
missing root documents, archive the dated execution logs, land the shared root-document gate,
and wire it into CI.

Touched: Will add `AGENTS.md`, `CHANGELOG.md`, `CONSTITUTION.md`, `GOVERNANCE.md` and
`scripts/check_root_docs.py`; will move four dated execution logs into `docs/archive/` and fix
their links plus the live plan's link to them; will add a `governance` job to
`.github/workflows/ci.yml` and include it in the release gate. `SHIPMENT_READINESS.md`,
`AUDIT_REPORT.md` and `REMEDIATION_PLAN.md` stay at the root, because the doc-consistency
check reads the first two and the README links the third.

Why: The repository had a status-truth check but no written policy for it to follow, no
charter, no constitution, no changelog and no root-document rule.

Verification: Planned — `python3 scripts/check_root_docs.py`, `--self-test`,
`python3 scripts/check_doc_consistency.py`, then the full pytest suite and CI on the landing.

Left undone: Nothing at sign-in.

Sensitive: `git push origin audit/shipment-candidate` (owner's instruction in chat,
2026-11-27). No force push, no history rewrite. No secrets.

## [2026-11-27 05:43 EET] — sami (OpenMausBot), owner-authorised governance landing

STATUS: SIGN-OUT (landing complete)

Task: Bring this repository onto the portfolio governance standard, as the owner approved in
chat on 2026-11-27. Done.

Touched: `AGENTS.md`, `CHANGELOG.md`, `CONSTITUTION.md`, `GOVERNANCE.md`,
`scripts/check_root_docs.py` (all new); `docs/archive/` (four dated execution logs moved in,
their relative links fixed); `REMEDIATION_PLAN.md` (one link now points at the archived log);
`.github/workflows/ci.yml` (one `governance` job, added to the release gate's `needs`).

Why: The repository had a status-truth check but no written policy for it to follow, no
charter, no constitution, no changelog and no root-document rule. `SHIPMENT_READINESS.md`,
`AUDIT_REPORT.md` and `REMEDIATION_PLAN.md` were kept at the root and named in the table
because the doc-consistency check reads the first two from the root and the README links the
third — moving them would have broken a live check to satisfy a rule they do not break.

Verification: `python3 scripts/check_root_docs.py` -> "OK -- CompliProof/ holds only the
GOVERNANCE.md section 2 set" (10 table rows, 10 allowed root documents; `requirements.lock.txt`
acknowledged as a package manifest, not a document). `--self-test` -> 7/7 cases behaved.
`python3 scripts/check_doc_consistency.py` -> "Documentation consistency checks passed".
Full suite in a clean dependency install (`pip install --require-hashes -r
requirements.lock.txt`) -> 133 passed, 31 skipped, matching the README's stated 31 conditional
scenario/scale skips.

Left undone: Nothing failing. The published status numbers and the seven open P0 findings are
untouched; a green CI run is not a shipment decision.

Sensitive: `git push origin audit/shipment-candidate` (owner's instruction in chat,
2026-11-27). No force push, no history rewrite. No secrets.
