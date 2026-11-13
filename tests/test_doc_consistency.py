"""Version, Python and status claims must have one source of truth (ME-07)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_doc_consistency  # noqa: E402

FILES = {
    "pyproject.toml": """[project]
name = "compliproof"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["reportlab==5.0.1", "pillow==13.0.0"]
""",
    "src/compliproof/__init__.py": '__version__ = "0.1.0"\n',
    "README.md": (
        "# CompliProof\n\nCompliProof 0.1.0\n\n"
        "This section is the single source of truth for project status.\n"
    ),
    "docker/Dockerfile": "FROM python:3.11-slim\n",
    ".github/workflows/ci.yml": 'python-version: ["3.11", "3.12", "3.13"]\n',
    "requirements.in": "reportlab==5.0.1\npillow==13.0.0\n",
    "SHIPMENT_READINESS.md": "No signature exists.\n",
    "AUDIT_REPORT.md": "The minimum is Python 3.11.\n",
    "SECURITY.md": "Report privately.\n",
}


def _tree(tmp_path: Path, overrides: dict[str, str] | None = None) -> Path:
    for name, content in {**FILES, **(overrides or {})}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def test_consistent_tree_has_no_problems(tmp_path):
    assert check_doc_consistency.check_repo(_tree(tmp_path)) == []


def test_dockerfile_python_drift_is_detected(tmp_path):
    root = _tree(tmp_path, {"docker/Dockerfile": "FROM python:3.10-slim\n"})
    assert any("Dockerfile python 3.10" in p for p in check_doc_consistency.check_repo(root))


def test_stale_python_claim_in_readme_is_detected(tmp_path):
    root = _tree(
        tmp_path,
        {
            "README.md": (
                "CompliProof 0.1.0\n\nPython 3.10 is the minimum.\n\n"
                "single source of truth for project status\n"
            )
        },
    )
    assert any("Python 3.10" in p for p in check_doc_consistency.check_repo(root))


def test_dependency_drift_is_detected(tmp_path):
    root = _tree(tmp_path, {"requirements.in": "reportlab==5.0.0\npillow==13.0.0\n"})
    assert any("differ" in p for p in check_doc_consistency.check_repo(root))


def test_hardcoded_test_count_is_detected(tmp_path):
    root = _tree(
        tmp_path,
        {
            "README.md": (
                "CompliProof 0.1.0\n\n102 automated tests pass.\n\n"
                "single source of truth for project status\n"
            )
        },
    )
    assert any("test count" in p for p in check_doc_consistency.check_repo(root))


def test_signature_claim_is_detected(tmp_path):
    root = _tree(tmp_path, {"SHIPMENT_READINESS.md": "Packs are digitally signed.\n"})
    assert any("signature claim" in p for p in check_doc_consistency.check_repo(root))
