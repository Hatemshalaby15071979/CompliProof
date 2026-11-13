# CompliProof local production-readiness execution — 2026-11-05

## Decision

**NOT READY for production or customer-data use.** The authoritative register remains **7 open / 0 closed**. No governance rule or status was changed. Work was local and synthetic; no customer data, external network/service, hosted CI, deployment, commit, or push was used. The existing dirty worktree was preserved; this execution added only its report and evidence.

## Checks performed

| Check | Result | Scope / limit |
|---|---|---|
| Complete tests | `102 passed, 31 skipped in 21.71s` | `evidence/production-readiness-2026-11-05/pytest.log`; skips remain unverified cases. |
| Recovery + synthetic scenario tests | `44 passed, 31 skipped in 2.48s` | Includes interruption/pending-intent recovery and synthetic reconciliation/report scenarios; not a customer workflow. |
| Scale | `rows=100000 elapsed=4.590s peak=106.68MiB match_rate=100.0%`; `chain_ok= True` | Two generated synthetic CSVs on this local host; no capacity/SLO claim. |
| Five-role smoke | `owner`, `approver`, `operator`, `auditor`, `viewer`: all `OK`; `ALL ROLES PASSED` | Scripted local HTTP/auth smoke; not full browser or deployment acceptance. |
| Backup/restore | `archive_sha256 ccf0b5507c373ecd54abf8622a28cb763f20e0a374da2879f399e40df76d9d79`; `restore_ok`; `DRILL PASSED` | Current script archives a one-line synthetic JSON file with gzip. It is not encrypted and does not exercise a live production workspace or backup key lifecycle. |
| Migration | `tasks load: []`; `MIGRATION REHEARSAL PASSED` | Checks one `tasks.v1` fixture only; no real upgrade/downgrade or rollback. |
| Static/runtime | Ruff clean; compileall clean; `pip check`: `No broken requirements found.` | Local environment only. |
| Package | Built wheel, installed offline with `--no-deps --no-index` into an isolated target; CLI help passed. SHA-256 `877826845d91df722687c40eb517b2e3abca6bb0cdfa48520280a9513fe4ba09`. | Dependencies were not separately installed into that target; full clean dependency install/matrix remains open. |
| Container/scanners | Cached `compliproof:plan-check` image ID `sha256:25151f304109ec3d85c4eaae5b2249afbb497f3c30f11d53142319ee977c73f1`, created 2026-10-31; `pip-audit`, Bandit, Trivy unavailable. | Cached image predates this candidate; no current-candidate build/run or new vulnerability scan. No network used. |

## Tenant and product-scope boundary

The synthetic scenario tests exercise reconciliation/report behavior using deterministic fixture data associated with the two synthetic tenant profiles. The product describes itself as a local prototype, not a multi-tenant SaaS service. These tests do **not** prove cross-tenant authorization/isolation in an application serving multiple tenants. Full browser/role-by-role acceptance, supported TLS deployment, TOTP-at-rest/recovery lifecycle, and a real multi-process session-coordination proof remain open.

Recovery evidence proves an interrupted action can leave a pending audit intent and that a restarted `AuditLog` can append a linked result and verify the chain. It does not implement or prove resumption of partially processed reconciliation input.

## Unclosed gates

- **P0-1:** Hosted CI, clean install matrix, current-candidate Docker build/health, real backup/restore and migration/rollback acceptance remain unverified.
- **P0-2:** Local hash/digest evidence is not an independently validated signature/key lifecycle.
- **P0-3:** Consequential-action intent/result coverage is incomplete; no independent external timestamp receipt.
- **P0-4:** Interrupted reconciliation is recorded but not resumed; input limits and full golden acceptance remain open.
- **P0-5/P0-7:** Full browser acceptance and supported TLS deployment remain open.
- **P0-6:** TOTP-at-rest encryption, account recovery/offboarding, and multi-process session coordination remain open.
- Independent review and Owner closure signatures remain outstanding.

No P0 was closed. Commands, raw outputs, and SHA-256 values are in `evidence/production-readiness-2026-11-05/`; see `SHA256SUMS`. The authoritative register was left unchanged.

## Continuation — shipment-audit recheck — 2026-11-05

- `ruff check .`: passed after removing an unused import and narrowing a bare exception to `OSError` in `synthetic_data/generate_synthetic.py`.
- `python3 -m compileall -q src scripts`: passed.
- `python3 -m pip check`: no broken requirements.
- `PYTHONPATH=src python3 -m pytest tests -q`: **102 passed, 31 skipped** (20.99s). Loopback HTTP tests required execution outside the restricted sandbox; the sandbox-only run failed at socket creation, not in application assertions.
- `python3 -m pip_audit --version`: unavailable (`No module named pip_audit`); dependency vulnerability scan remains unverified.
- Current candidate image built successfully with `docker build -f docker/Dockerfile -t compliproof:shipment-audit .` (image ID `d596fd3f288d`). A local HTTP smoke returned `{"ok": true}`; container UID was `999`, and the container was removed afterward. A separate `--network=none` build could not fetch build dependencies; this is a build-time network requirement, not an offline runtime test.

No P0 was closed. Hosted CI, clean install matrix, vulnerability scan (`pip-audit` unavailable), TLS deployment, independent evidence verification, owner closure signatures and operational acceptance remain release gates. The authoritative register remains unchanged and the release decision is **NOT READY**.

## History-secret scan — local precommit baseline

> **Superseded 2026-11-13 (finding HI-11).** The two scan records below are
> kept as history but are no longer the published result. They covered 3 and
> then 5 commits of a history that now contains 30, and the "all hard-category
> counts were zero" wording hid the review-category matches (1
> password-assignment, 42 email addresses) that the same reports contained.
> The current fail-closed scan — 30/30 commits, 17,609 added lines, 0 hard
> matches, 92 email matches all in reserved domains, 1 synthetic
> password-assignment, all exempted by exact registry entry — is documented in
> `SHIPMENT_READINESS.md` and enforced by the `history-scan` CI job.

Used the fail-closed history scanner from the Live Support security tooling against the pre-candidate `HEAD`: `node ../live-support-assistant/tooling/security/scan-history-secrets.mjs HEAD --json evidence/production-readiness-2026-11-05/history-secret-scan-precommit.json`. It inspected 3/3 commits and 12,136 changed lines; all hard-category counts were zero. The 16 email-pattern review detections were synthetic `example.com` / `example.test` values. The report is checksummed in `SHA256SUMS`.

## Final candidate history scan — 2026-11-05

After committing the candidate, the same scanner inspected 5/5 commits and 14,300 changed lines. All hard-category counts were zero. The single password-assignment review hit is the fixed local-only synthetic test password in `scripts/role_smoke.py`; email-pattern hits are `callcenter.local`, `example.com`, and `example.test`. No live credential was identified. The redacted report is `evidence/production-readiness-2026-11-05/history-secret-scan-final.json`, checksummed in `SHA256SUMS`. The documentation-only commit is rescanned on the final candidate tip before push. This scan does not close the P0 release blockers above.
