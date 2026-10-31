# CompliProof engineering readiness assessment

**Assessment date:** 2026-10-31
**Scope:** local repository, customer-hosted single-instance/multi-user target
**Assessment type:** engineering verification by the implementing agent; not an independent audit,
legal opinion, certification, or production authorization
**Authoritative release register:** [`../company-os/stage-0/P0_REGISTER.yaml`](../company-os/stage-0/P0_REGISTER.yaml)

## Executive status

**CompliProof is not confirmed production-ready and must not yet be represented as ready for
customer data.** The current local candidate materially hardens authentication, route permissions,
report reconstruction, storage permissions, and retention. That work does not close registered
release gates by itself.

At the time of this assessment the authoritative register records **7 open P0s and 0 closed**.
Its rule requires a passing registered acceptance test **and Owner-signed closure evidence**.
No P0 closure evidence or customer deployment approval is included in this repository. Do not
silently close or waive those findings.

The target is one customer-operated installation, with multiple user accounts and real customer
data after approval. This is not a multi-tenant SaaS design. Tests use synthetic/local fixtures;
they do not prove behavior with a real customer's environment or dataset.

## Current implementation verified in this candidate

- Wheel/package metadata declares the actual `compliproof` package and runtime dependencies.
- Passwords use bcrypt; owner and approver roles require TOTP at account creation and login.
- Sessions use random bearer tokens with SHA-256 hashes persisted in a mode-`0600` file, 12-hour
  expiry, CSRF tokens, and thread synchronization.
- RBAC distinguishes owner, approver, operator, auditor, and viewer. Data routes require a
  session; finance/pipeline and audit reads are role-limited.
- The dashboard has login/logout, restricts controls by role, and no longer sends a client-chosen
  audit actor identity.
- Non-loopback server binding refuses to start unless secure cookies are configured. The container
  sets that option and runs non-root; TLS must terminate at a trusted reverse proxy.
- Request bodies are JSON objects capped at 5 MiB. Malformed task/finance/pipeline stores fail
  closed instead of being presented as empty/successful data.
- HTTP-uploaded CSVs are held in a private temporary directory and removed after reconciliation.
  Result rows are stored in a mode-`0700` directory as mode-`0600` files for up to 30 days.
  A local audit event binds each stored result to its SHA-256; a report read checks the local
  ledger and result digest before serving the report.
- HTML, PDF, and CSV report routes require authentication. CLI and server use the same result
  store. CSV cells beginning with spreadsheet formula characters are escaped.
- Invalid or corrupt persisted results are not silently treated as valid report data.

These are local code and test results. They are not a claim that the controls have been independently
reviewed or tested in a customer deployment.

## Remaining release blockers

### P0-1 — Packaging and deployment

The local candidate can be built and exercised, but the registered gate also requires clean
installation, non-root container evidence, and CI. The hosted GitHub workflow has not been run
in this local-only workflow. Runtime pins are not hash-locked, the base image is not digest-pinned,
and backup/restore, migration, rollback, persistent-volume ownership, and operator procedures
remain unproven.

### P0-2 — Evidence integrity

The result file is bound to the local audit chain, and the evidence pack uses local hashes/HMACs.
There is no established asymmetric signature/key lifecycle or independent verifier. A sufficiently
privileged local attacker can rewrite both local state and an unanchored ledger. The software does
not establish an externally verifiable compliance conclusion.

### P0-3 — Audit ledger

The current ledger implementation provides local hash-chain, locking, and anchor-related
mechanisms, but a verified external timestamp receipt, canonical deployment evidence, and the
registered independent-verification criteria are not supplied here. Local integrity checks do not
prove immutability against a host administrator.

### P0-4 — Reporting and reconciliation

The server and CLI now persist full row-level results so reports can be regenerated; those results
expire after 30 days. Focused tests cover served HTML/PDF/CSV, result-file tampering, retention,
and formula escaping. The registered gate still needs its complete golden acceptance evidence,
including CLI/server parity and reconciliation edge cases such as duplicate/missing keys, large
files, and interruption/recovery.

### P0-5 — Server reporting

The report routes now use authentication, role checks, CSRF on mutations, security headers, and
route tests. The health endpoint is deliberately public and returns only a boolean; login and
optional loopback-only registration are also unauthenticated by design. Secure cookies require
the production proxy configuration. The complete registered route/security scan has not been
independently signed off.

### P0-6 — Authentication

The local implementation now has bcrypt, TOTP for privileged roles, hashed sessions, expiry,
CSRF, and role checks. Login throttling is in-memory and per process, not persistent across
restarts or multiple server processes. TOTP secrets are stored in the private workspace rather
than encrypted with a managed key. Password reset/recovery, account suspension/offboarding,
role lifecycle, and multi-process session coordination are not implemented.

### P0-7 — Dashboard and route surface

The dashboard login and role-aware controls are implemented and tested through HTTP-level
regressions. A minimal public health endpoint and the static login shell remain intentionally
reachable. Browser-level acceptance, proxy/TLS deployment, and the complete registered security
evidence are not established by the HTTP tests.

## Data-protection boundary

Row-level reconciliation results contain customer-provided values. The application stores them
locally for report generation for 30 days, then removes them when the retention worker runs
(hourly while the server is running; expired requested records are also removed on read). CLI
saves prune expired records. Separately exported HTML files are outside this managed retention.

Mode `0700`/`0600` is an access-control measure, **not encryption at rest**. A customer operator
must provide encrypted storage, service-account isolation, suitable backup access/expiry, and
secure deletion policy before any customer data is used. Data already copied into backups is not
automatically deleted by this retention worker.

## Verification record

Commands completed against this candidate:

| Check | Result |
|---|---|
| `COMPLIPROOF_WORKSPACE=/tmp/compliproof-final-tests-a9f5 python3 -m pytest tests -q` | **75 passed** |
| Ruff on changed Python source/tests | **Clean** |
| Repository-wide `ruff check .` | **16 findings remain** in pre-existing, untouched files (`scripts/remediate.py`, `src/compliproof/audit.py`, `email.py`, `gate.py`, `tests/test_audit.py`, `tests/test_audit_p0_3.py`) |
| Wheel build via `python3 -m pip wheel . --no-deps --no-build-isolation` | **Succeeded**; wheel SHA-256 `b2728e19b36bbd579a2aa278953a7273e99992a37c1f5c84f5131dfa5d736a4e` |
| Clean Python 3.14 virtualenv install from `requirements.lock.txt`, both CLI `--help` commands, installed dashboard asset | **Passed** |
| Clean venv `pip check` | **No broken requirements** |
| Docker build with `--no-cache --pull=false` | **Succeeded**; the base image was not pulled or digest-pinned |
| Container smoke | **Passed**: health endpoint and login page responded; configured user is `compliproof` |
| Browser check | **Passed**: temporary operator could log in/out; finance/pipeline were restricted in the dashboard |
| CI secret-pattern scan on `src`, `tests`, and `dashboard` | **No configured patterns found** |
| Bandit and pip-audit | **Not run**; executables were unavailable |
| Hosted GitHub CI | **Not run**; no remote is configured |

These are local engineering checks, not P0 closure evidence. The test interpreter was Python 3.14;
the declared minimum Python 3.10 and full supported-version matrix were not exercised. A green
local test suite does not close a P0 without its registered evidence and Owner sign-off.

## Release decision

**Decision: NOT READY for production or customer-data use.** Continue local development and
synthetic design-partner simulations only. Do not claim independent audit, certification,
compliance determination, or production readiness. Revisit this decision only after each registered
P0 has reproducible evidence, operational drills are complete, and the required Owner decisions
are recorded.
