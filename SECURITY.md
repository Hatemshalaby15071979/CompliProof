# Security Policy

CompliProof is a pre-production compliance-evidence prototype. It is not
production-ready, has not passed an external security review, and must not be
used with real customer data. See [`README.md`](README.md) and
[`SHIPMENT_READINESS.md`](SHIPMENT_READINESS.md) for the stated scope and
limitations.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.0   | Yes — pre-production candidate only; authentication recovery, credential rotation, and independent review remain open |

## Reporting a vulnerability

**Reporting contact: to be filled in by the owner.** There is no monitored
security mailbox or private reporting channel in this repository yet; do not
send vulnerability reports to any address guessed from this file.

Until the owner publishes a contact, please:

1. Do not open a public issue containing exploit details.
2. Do not include real client data, credentials, or personal data in any report.
3. The owner will add a private reporting channel (e.g. GitHub Private
   Vulnerability Reporting) before any public release; re-check this file then.

Local-only mitigations already in the tree: hash-pinned runtime dependencies
(`requirements.lock.txt`), digest-pinned Docker base image, non-root container
user, loopback-only local binding by default, and synthetic data only in
tests and evidence bundles.
