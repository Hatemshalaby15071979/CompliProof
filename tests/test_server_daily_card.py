"""Tests for fail-closed daily-card workspace reads."""
import os
import subprocess
import sys
from pathlib import Path


def test_daily_card_rejects_malformed_finance_summary(tmp_path):
    finance_dir = tmp_path / "finance"
    finance_dir.mkdir()
    (finance_dir / "finance.json").write_text("{invalid json}", encoding="utf-8")

    project = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env["COMPLIPROOF_WORKSPACE"] = str(tmp_path)
    env["PYTHONPATH"] = str(project / "src")
    script = """
import compliproof.server as server
try:
    server._daily_card()
except ValueError as error:
    assert str(error) == "Finance summary is unavailable or invalid"
else:
    raise SystemExit("malformed finance summary was treated as a successful result")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=project,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
