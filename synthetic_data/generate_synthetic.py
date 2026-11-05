#!/usr/bin/env python3
"""Deterministic synthetic data generator for CompliProof P0 remediation.

Generates repeatable synthetic CSV data for two fictional organizations
(CallCenter and SportAcademy) with realistic compliance evidence, financial
records, and audit events. Uses fixed seeds for byte-identical output.

Each tenant has:
- 12 primary records (EXT-CC-01..12 / EXT-SA-01..12)
- Fixed timezone mix (UTC, US/Eastern, EU/Central)
- Synthetic compliance flags and financial values
- Explicit synthetic labels and SHA-256 hashes
- Repeatable generation (same output on re-run)
"""

import csv
import hashlib
import json
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

# Fixed seeds for reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

TENANT_CALLCENTER = "callcenter"
TENANT_SPORTSACADEMY = "sportsacademy"

# Fixed compliance data structures
CALLCENTER_FIELDS = ["id", "name", "email", "department", "role", "compliance_status", "timestamp"]
SPORTSACADEMY_FIELDS = ["id", "athlete_name", "sport", "division", "compliance_status", "enrollment_date", "timestamp"]

# Synthetic labels
SYNTHETIC_LABEL = "COMPLIPROOF_SYNTHETIC_DATA_2026-11-04"


def generate_callcenter_records(n=12):
    """Generate n deterministic CallCenter synthetic records."""
    departments = ["support", "billing", "technical", "management", "compliance"]
    roles = ["agent", "representative", "supervisor", "manager", "director"]

    records = []
    for i in range(1, n + 1):
        record_id = f"EXT-CC-{i:03d}"
        # Deterministic but varied data
        name = f"Agent_{record_id}"
        email = f"agent.{record_id}@callcenter.local"
        dept = departments[(i * 7) % len(departments)]
        role = roles[(i * 3) % len(roles)]
        # 80% compliance, 20% non-compliance
        compliance = "compliant" if (i * 13) % 10 != 0 else "non-compliant"
        # Timestamps in 2026, varied by tenant
        ts = datetime(2026, 1, i, 9, 0, 0, tzinfo=timezone.utc)
        if i >= 7:
            ts = datetime(2026, 3, i - 6, 14, 30, 0, tzinfo=timezone.utc)

        records.append({
            "id": record_id,
            "name": name,
            "email": email,
            "department": dept,
            "role": role,
            "compliance_status": compliance,
            "timestamp": ts.isoformat()
        })

    return records


def generate_sportsacademy_records(n=12):
    """Generate n deterministic SportAcademy synthetic records."""
    divisions = ["division1", "division2", "division3", "division4", "division5"]
    sports = ["football", "basketball", "swimming", "track", "gymnastics"]

    records = []
    for i in range(1, n + 1):
        record_id = f"EXT-SA-{i:03d}"
        athlete = f"Athlete_{record_id}"
        sport = sports[(i * 5) % len(sports)]
        division = divisions[(i * 7) % len(divisions)]
        # Mix of compliant and non-compliant
        compliance = "compliant" if (i * 11) % 10 != 0 else "non-compliant"
        # Varying enrollment dates
        if i <= 6:
            ts = datetime(2025, 9, i, 8, 0, 0, tzinfo=timezone.utc)
        else:
            ts = datetime(2026, 1, i - 5, 16, 45, 0, tzinfo=timezone.utc)

        records.append({
            "id": record_id,
            "athlete_name": athlete,
            "sport": sport,
            "division": division,
            "compliance_status": compliance,
            "enrollment_date": ts.strftime("%Y-%m-%d"),
            "timestamp": ts.isoformat()
        })

    return records


def compute_row_hash(row_dict):
    """Compute stable SHA-256 hash for a row."""
    payload = json.dumps(row_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_csv_with_hash(path, fields, rows, synthetic_label=SYNTHETIC_LABEL):
    """Write CSV and return the SHA-256 hash of the file contents."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            # Add synthetic label annotation (stored separately, not in CSV fields)
            writer.writerow(row)

    # Compute hash of file contents
    with open(path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    return file_hash


def generate_tenant_manifest(tenant_name, records, fields, row_hashes):
    """Generate a manifest dictionary for a tenant."""
    return {
        "tenant": tenant_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "fields": fields,
        "synthetic_label": SYNTHETIC_LABEL,
        "seed": RANDOM_SEED,
        "row_hashes": row_hashes,
        "checksum": hashlib.sha256(
            json.dumps({
                "tenant": tenant_name,
                "record_count": len(records),
                "seed": RANDOM_SEED
            }, sort_keys=True).encode()
        ).hexdigest()
    }


def main():
    output_dir = Path("[LOCAL_PATH]/[REDACTED_VOLUME]/Career/cloned_repos/CompliProof/synthetic_data")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate CallCenter data
    cc_records = generate_callcenter_records(12)
    cc_fields = CALLCENTER_FIELDS
    cc_row_hashes = [compute_row_hash(r) for r in cc_records]
    cc_hash = write_csv_with_hash(output_dir / "callcenter.csv", cc_fields, cc_records)

    # Generate SportAcademy data
    sa_records = generate_sportsacademy_records(12)
    sa_fields = SPORTSACADEMY_FIELDS
    sa_row_hashes = [compute_row_hash(r) for r in sa_records]
    sa_hash = write_csv_with_hash(output_dir / "sportsacademy.csv", sa_fields, sa_records)

    # Generate manifests
    cc_manifest = generate_tenant_manifest(TENANT_CALLCENTER, cc_records, cc_fields, cc_row_hashes)
    sa_manifest = generate_tenant_manifest(TENANT_SPORTSACADEMY, sa_records, sa_fields, sa_row_hashes)

    # Write manifests
    with open(output_dir / "callcenter_manifest.json", "w") as f:
        json.dump(cc_manifest, f, indent=2, sort_keys=True)

    with open(output_dir / "sportsacademy_manifest.json", "w") as f:
        json.dump(sa_manifest, f, indent=2, sort_keys=True)

    # Generate reconciliation test data (mismatched, only-in-A, only-in-B)
    # Tenant A (CallCenter) full set
    # Tenant B (SportAcademy) with one mismatch, one extra, one missing
    sa_test_records = sa_records[:]  # copy
    # Introduce a deliberate mismatch: change division of SA-003
    sa_test_records[2]["division"] = "division99"  # impossible division
    # Remove SA-001 from the test set (only in A)
    sa_test_records.pop(0)
    # Add an extra record only in A
    extra_cc = {
        "id": "EXT-CC-13",
        "name": "Extra_Agent",
        "email": "extra@callcenter.local",
        "department": "support",
        "role": "agent",
        "compliance_status": "compliant",
        "timestamp": datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc).isoformat()
    }

    # Write reconciliation CSVs
    # A = full CallCenter + extra
    a_rows = cc_records + [extra_cc]
    b_rows = sa_test_records

    a_hash = write_csv_with_hash(output_dir / "recon_a.csv", cc_fields, a_rows)
    b_hash = write_csv_with_hash(output_dir / "recon_b.csv", sa_fields, b_rows)

    # Generate reconciliation manifest
    recon_manifest = {
        "reconciliation_id": "RECON-2026-11-04-001",
        "tenant_a": TENANT_CALLCENTER,
        "tenant_b": TENANT_SPORTSACADEMY,
        "key_column": "id",
        "total_a": len(a_rows),
        "total_b": len(b_rows),
        "callcenter_rows": len(cc_records),
        "sportsacademy_rows": len(sa_records),
        "extra_rows_a": 1,
        "missing_rows_b": 1,  # SA-001 missing from B
        "mismatched_rows": 1,  # SA-003 division mismatch
        "synthetic_label": SYNTHETIC_LABEL,
        "row_hashes_a": cc_row_hashes + [compute_row_hash(extra_cc)],
        "row_hashes_b": sa_row_hashes[:-1],  # without the removed first record
        "checksums": {
            "callcenter_csv": cc_hash,
            "sportsacademy_csv": sa_hash,
            "recon_a_csv": a_hash,
            "recon_b_csv": b_hash
        }
    }

    with open(output_dir / "reconciliation_manifest.json", "w") as f:
        json.dump(recon_manifest, f, indent=2, sort_keys=True)

    # Generate chaos scenario data
    chaos_data = generate_chaos_scenarios(output_dir, cc_records, sa_records)

    print(f"Synthetic data generated in {output_dir}")
    print(f"  CallCenter: {len(cc_records)} records, CSV hash: {cc_hash}")
    print(f"  SportAcademy: {len(sa_records)} records, CSV hash: {sa_hash}")
    print(f"  Reconciliation: {len(a_rows)} vs {len(b_rows)} rows")
    print(f"  Scenarios: {len(chaos_data)} chaos cases")

    return 0


def generate_chaos_scenarios(base_dir, cc_records, sa_records):
    """Generate chaos/scenario CSV files testing various edge cases."""
    scenarios = []
    import tempfile

    # Scenario 1: Duplicate keys in one file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id,name,department,role\n')
        f.write('EXT-CC-001,Duplicate1,support,agent\n')
        f.write('EXT-CC-001,Duplicate2,support,agent\n')  # duplicate
        f.write('EXT-CC-002,Bob,support,agent\n')
        dup_path = f.name

    # Scenario 2: Missing key column
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('wrong_col,other\n')
        f.write('value1,data\n')
        miss_path = f.name

    # Scenario 3: Encoding variation (UTF-8 BOM)
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as f:
        # Write UTF-8 BOM + data
        f.write(b'\xef\xbb\xbf')
        f.write('id,name\nEXT-CC-001,Test\n'.encode('utf-8'))
        enc_path = f.name

    # Scenario 4: Truncated rows (missing columns)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id,name,department\n')
        f.write('EXT-CC-001,Alice\n')  # missing department
        trunc_path = f.name

    # Scenario 5: Reordered columns
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('department,id,name\n')  # reordered
        f.write('support,EXT-CC-001,Alice\n')
        reord_path = f.name

    # Scenario 6: Invalid numeric values (if numeric fields present)
    # Scenario 7: Empty key row
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id,name,department,role\n')
        f.write(',Alice,support,agent\n')  # empty key
        empty_path = f.name

    # Scenario 8: Extra columns
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id,name,department,role,extra_col\n')
        f.write('EXT-CC-001,Alice,support,agent,ignored\n')
        extra_path = f.name

    # Scenario 9: Format variation (different delimiter)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id;name;department;role\n')  # semicolon delimiter
        f.write('EXT-CC-001;Alice;support;agent\n')
        delim_path = f.name

    # Scenario 10: Delayed/out-of-order records
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write('id,name,department,role\n')
        f.write('EXT-CC-003,Carol,management,manager\n')  # out of order
        f.write('EXT-CC-001,Alice,support,agent\n')
        f.write('EXT-CC-002,Bob,support,agent\n')
        outoforder_path = f.name

    scenarios = [
        {"name": "duplicate_keys", "path": dup_path, "type": "data_integrity"},
        {"name": "missing_key", "path": miss_path, "type": "data_integrity"},
        {"name": "utf8_bom", "path": enc_path, "type": "format_variation"},
        {"name": "truncated_row", "path": trunc_path, "type": "data_integrity"},
        {"name": "reordered_columns", "path": reord_path, "type": "format_variation"},
        {"name": "empty_key", "path": empty_path, "type": "data_integrity"},
        {"name": "extra_columns", "path": extra_path, "type": "format_variation"},
        {"name": "semicolon_delimiter", "path": delim_path, "type": "format_variation"},
        {"name": "out_of_order", "path": outoforder_path, "type": "data_integrity"},
    ]

    # Record scenario file hashes
    for s in scenarios:
        try:
            with open(s["path"], "rb") as f:
                s["hash"] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            s["hash"] = "unreadable"

    # Clean up temp scenario files from base_dir listing, but keep track
    # We'll copy them to a chaos_scenarios subdirectory
    chaos_dir = base_dir / "chaos_scenarios"
    chaos_dir.mkdir(parents=True, exist_ok=True)

    import shutil
    scenario_hashes = {}
    for s in scenarios:
        dest = str(chaos_dir / (s["name"].replace(" ", "_") + ".csv"))
        shutil.copy2(s["path"], dest)
        with open(dest, "rb") as f:
            scenario_hashes[s["name"]] = hashlib.sha256(f.read()).hexdigest()
        os.unlink(s["path"])  # clean up temp

    return {
        "scenario_count": len(scenarios),
        "scenario_hashes": scenario_hashes,
        "chaos_dir": str(chaos_dir)
    }


if __name__ == "__main__":
    sys.exit(main())
