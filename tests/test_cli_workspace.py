import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof import cli


def test_reconcile_cli_uses_configured_workspace(tmp_path, monkeypatch, capsys):
    source_a = tmp_path / "source-a.csv"
    source_b = tmp_path / "source-b.csv"
    source_a.write_text("id,amount\nrow-1,10\n", encoding="utf-8")
    source_b.write_text("id,amount\nrow-1,10\n", encoding="utf-8")
    workspace = tmp_path / "runtime"
    monkeypatch.setenv("COMPLIPROOF_WORKSPACE", str(workspace))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compliproof",
            "reconcile",
            str(source_a),
            str(source_b),
            "id",
            "--task-id",
            "synthetic-cli-smoke",
        ],
    )

    assert cli.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["matched"] == 1
    assert (workspace / "audit_events.jsonl").is_file()
    assert list((workspace / "results").glob("*.json"))


def test_cli_report_uses_persisted_rows(tmp_path, monkeypatch, capsys):
    source_a = tmp_path / "source-a.csv"
    source_b = tmp_path / "source-b.csv"
    source_a.write_text("id,amount\nrow-1,10\n", encoding="utf-8")
    source_b.write_text("id,amount\nrow-1,10\n", encoding="utf-8")
    workspace = tmp_path / "runtime"
    monkeypatch.setenv("COMPLIPROOF_WORKSPACE", str(workspace))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compliproof",
            "reconcile",
            str(source_a),
            str(source_b),
            "id",
            "--task-id",
            "cli-report",
        ],
    )
    assert cli.main() == 0
    capsys.readouterr()

    output = tmp_path / "report.html"
    monkeypatch.setattr(
        sys, "argv", ["compliproof", "report", "cli-report", "--output", str(output)]
    )
    assert cli.main() == 0
    capsys.readouterr()
    html = output.read_text(encoding="utf-8")
    assert "row-1" in html
    assert "10" in html
