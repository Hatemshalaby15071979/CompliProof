"""CompliProof — prototype reconciliation and evidence-pack tool.

This is a local prototype, not a platform and not audit-grade. The CSV
reconciliation happy path works; integrity, packaging, authentication, and
audit guarantees have open P0 defects.

Core modules:
- audit: local hash-chained event ledger (lineage unverified)
- evidence: prototype scoring and evidence packs (lineage unverified)
- gate: prototype confidence gate (not wired)
- reconcile: CSV-to-CSV reconciliation happy path
- report: local HTML/PDF report generator
- cli: local command-line interface
- server: standard-library HTTP dashboard prototype

Version: 0.1.0
"""
__version__ = "0.1.0"
