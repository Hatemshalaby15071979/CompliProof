# CompliProof GitHub shipment readiness

**Assessment date:** 2026-11-06 (re-verified; prior assessment 2026-11-05)
**Local branch:** `audit/shipment-candidate`
**Base HEAD before this audit's commit:** `ee8a1ca` (see `git log` for the
shipment commit SHA; this file is committed together with the fixes below)
**GitHub destination:** <https://github.com/Hatemshalaby15071979/CompliProof>

This record covers source control, documentation, automated verification,
package construction, a local synthetic container smoke test, and an SBOM. It
does not assert production readiness, external audit completion, or successful
hosted GitHub Actions. No push, tag, release, or publication was made.

## Initial state (2026-11-06)

- Checkout `cloned_repos/CompliProof`, branch `audit/shipment-candidate`,
  HEAD `ee8a1ca`, remote `origin` = destination above.
- Uncommitted prior shipment edits (preserved and reviewed, not discarded):
  hash-regenerated `requirements.lock.txt` (320 SHA-256 entries),
  `requirements.in`, explicit `pyproject.toml` runtime dependencies
  (`pillow`, `charset-normalizer` previously transitive only), CI
  `--require-hashes` installs, README reproducible-dependency docs, and an
  untracked prior `SHIPMENT_READINESS.md`.

## Findings and fixes

1. **Dockerfile could not build with the hash lock (blocker, fixed).**
   `pip install setuptools==... wheel==... -r requirements.lock.txt` makes pip
   auto-enable `--require-hashes` (because the lock contains hashes) and then
   fails on the unhashed build tools. Build tools are now installed in a
   separate invocation, followed by
   `pip install --require-hashes -r requirements.lock.txt`.
2. **CI triggers/permissions (fixed).** Pushes and PRs previously targeted
   only `main`, so this audit branch would never run CI. Now all branches
   trigger, with least-privilege `permissions: contents: read`. Third-party
   actions remain tag-pinned; the Docker base image is digest-pinned as
   before (digest not re-verified from this environment).
3. **Security policy (added).** No root `SECURITY.md` existed. Added one that
   honestly states no monitored reporting contact exists yet; no address was
   invented.

## Local verification (2026-11-06, re-run in this session)

| Check | Command | Outcome |
| --- | --- | --- |
| Tests | `python3 -m pytest tests -q` | **102 passed, 31 skipped** (conditional scenario/scale cases, not failures) |
| Bandit | `bandit -r src -q` | Passed, no findings |
| Dependency audit | `pip-audit -r requirements.lock.txt` | **No known vulnerabilities found** |
| Hash install | `pip install --require-hashes -r requirements.lock.txt` in clean venv | Passed |
| Wheel build | `python3 -m build --wheel --no-isolation --outdir /tmp/opencode/cp-dist` | `compliproof-0.1.0-py3-none-any.whl` (59,672 bytes) |
| Docker build | `docker build -f docker/Dockerfile -t compliproof:shipment-audit .` | **Built** (failed before the fix above) |
| Docker smoke | loopback-only run, `GET /api/healthz` | `{"ok": true}`; container removed |
| SBOM | prior CycloneDX run (2026-11-05) | Generated, contained project + `reportlab`, `pillow`, `charset-normalizer`; not regenerated this session (CI regenerates it) |

`pip-audit`/`bandit`/`build` were installed into the operator's user site
(`--user --break-system-packages`), not into the repository.

## Secret-history scan

> **Superseded 2026-11-13 (finding HI-11).** The scan recorded below covered
> only 5 commits of a history that already contained 29, and reported
> `hardCounts` of zero while the same report listed one password-assignment
> and 42 email matches. Those counts were review categories, not hard
> categories, but the summary wording hid them. The current, fail-closed scan
> is described after this historical record.

Historical record (2026-11-06, superseded):

- Scope: full reachable history (`git log --all -p`, 7 commits) plus
  `git grep` over tracked files, for private-key blocks, AWS/GitHub/API-key
  shapes, and live secret prefixes.
- Result: **no hits**. Prior recorded scans (`git log` evidence commits
  `21717ee`/`75e8dbf`) reviewed 143 blobs with two manually confirmed
  non-credential matches (a dashboard field identifier and a documented
  synthetic smoke-test credential). Pattern scans cannot prove no secret ever
  existed; no values are printed here.
- Tracked-file audit: `workspace/` (local runtime data), `.env*`, `*.db`,
  `*.pem`/`*.key`, `dist/`, `build/`, and `/helix-prime/` + `/helix-education/`
  are gitignored and untracked. Tracked `evidence/*.log` files are recorded
  run logs, not credentials (grep-verified).

Current scan (2026-11-13, fail-closed, required CI gate):

- Command: `python3 tooling/security/scan_history_secrets.py --json scan.json`
  over `git log --all -p -m` — every reachable commit on every ref, merge
  diffs expanded.
- Scope measured 2026-11-13 on the remediation branch: 35/35 commits,
  18,436 added lines inspected. Counts grow with history; the CI artifact is
  the authoritative report for each run.
- Real counts at that snapshot: 1 hard-category match (a fake AWS-shaped
  fixture in the scanner's own test, exempted by exact line hash), 94
  email-address matches (all in reserved `example.com`, `example.test` or
  synthetic `callcenter.local` domains) and 2 occurrences of the fixed
  synthetic test credential in `scripts/role_smoke.py`. Unresolved matches: 0.
- Every review-category match is either exempted by a documented rule or the
  gate fails. Exceptions are exact (SHA-256 of the value or line, never the
  value) and live in `tooling/security/history-scan-exceptions.json`; removing
  one makes the scan fail closed.
- The scan runs as the `history-scan` job in `.github/workflows/ci.yml`, and
  the release gate requires it. The full JSON report is uploaded as a CI
  artifact on every run; it is not committed, because it is regenerated
  evidence rather than source.

## Provenance and signature status (2026-11-13, finding HI-07)

- No signature exists in this repository or its history: there is no `.sig`,
  `.pem`, `.key`, certificate, or keypair, and no human-supplied key has been
  provided.
- Evidence packs and answer keys are **hash-consistent, not signed**. A pack
  carries a plain local SHA-256 digest; an answer key carries an HMAC-SHA256
  digest under a 32-byte integrity key that the tool generates itself when the
  key file is absent. Anyone who can read that key file can recompute the
  digest, so it does not authenticate an author, an approver, or a reviewer.
  The code names this an `integrity_key`, never a signing key.
- This readiness record, the execution logs, and the status claims in them
  were written by the same engineering session that made the changes. They are
  self-assessed. No independent reviewer has signed them, and no closure
  evidence is signed. No signature claim is made here and none may be added
  until a human supplies a key and a key lifecycle exists.
- The authoritative current status is the "Current status" section of
  `README.md`; the dated execution logs in this repository are historical.

## Remaining limitations (not waived)

- Hosted GitHub Actions is verified green on `audit/shipment-candidate`
  (CI run 42834746842, 2026-11-10). Branch protection, repository visibility,
  and remote state outside that run were **not verified** from this clone.
- Actions are tag-pinned, not SHA-pinned.
- Pre-production gates remain open: authentication recovery/credential
  rotation, independent security review, customer data and operating
  controls, and production deployment acceptance. Local checks use synthetic
  data only and establish reproducible behavior on synthetic inputs.

**Status: pushed to GitHub, with hosted CI green on `audit/shipment-candidate`;
not production-ready.** The hosted-only verification and product gates above
remain open. Nothing was published, released, or deployed.
