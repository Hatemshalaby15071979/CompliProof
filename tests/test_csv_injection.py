"""CSV export must neutralise spreadsheet formula injection (HI-08).

Every exported cell is sanitised by ``compliproof.report._csv_safe`` before it
reaches the CSV writer, so a value that begins with ``=``, ``+``, ``-``, ``@``,
TAB or CR can never be evaluated as a formula by Excel/LibreOffice/Sheets.
"""
import csv
import io
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.audit import AuditLog
from compliproof.report import ReportGenerator

DANGEROUS_PREFIXES = ["=", "+", "-", "@", "\t", "\r"]


def _result(cell: str = "safe", key: str = "k1", key_column: str = "id") -> dict:
    row = {"id": "k1", "value": cell}
    return {
        "task_id": "csv-injection",
        "correlation_id": "csv-injection",
        "source_a": "a.csv",
        "source_b": "b.csv",
        "key_column": key_column,
        "total_a": 1,
        "total_b": 1,
        "matched": 1,
        "only_in_a": 0,
        "only_in_b": 0,
        "mismatched": 0,
        "matched_rows": [{"key": key, "row_a": row, "row_b": row, "row_hash": "h"}],
        "only_in_a_rows": [],
        "only_in_b_rows": [],
        "mismatched_rows": [],
        "evidence_pack": {},
    }


def _export(result: dict) -> list[list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        gen = ReportGenerator(AuditLog(Path(tmp) / "audit.jsonl"))
        text = gen.to_csv(result)
    return list(csv.reader(io.StringIO(text)))


def _cells(rows: list[list[str]]) -> list[str]:
    header = rows[0]
    return [
        value
        for record in rows[1:]
        if len(record) == len(header)
        for value in record
    ]


@pytest.mark.parametrize("prefix", DANGEROUS_PREFIXES)
def test_source_cell_with_dangerous_prefix_is_escaped(prefix):
    payload = f"{prefix}cmd|' /C calc'!A0"
    cells = _cells(_export(_result(cell=payload)))
    assert f"'{payload}" in cells
    assert payload not in cells


@pytest.mark.parametrize("prefix", DANGEROUS_PREFIXES)
def test_row_key_with_dangerous_prefix_is_escaped(prefix):
    payload = f"{prefix}1+1"
    cells = _cells(_export(_result(key=payload)))
    assert f"'{payload}" in cells
    assert payload not in cells


@pytest.mark.parametrize("prefix", DANGEROUS_PREFIXES)
def test_summary_key_column_with_dangerous_prefix_is_escaped(prefix):
    payload = f"{prefix}1+1"
    cells = _cells(_export(_result(key_column=payload)))
    assert f"'{payload}" in cells
    assert payload not in cells


def test_leading_whitespace_before_formula_is_escaped():
    payload = "  =1+1"
    assert f"'{payload}" in _cells(_export(_result(cell=payload)))


def test_ordinary_values_are_unchanged():
    cells = _cells(_export(_result(cell="hello", key="k1")))
    assert "hello" in cells
    assert "k1" in cells
