"""The history secret scanner must fail closed on real credentials (HI-11).

Builds throwaway git repositories: one with a live-shaped AWS key, one clean.
The scanner is a required CI gate, so the failing case is the important one.
"""
import json
import subprocess
import sys
from pathlib import Path

SCANNER = Path(__file__).resolve().parent.parent / "tooling" / "security" / "scan_history_secrets.py"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _repo(tmp_path: Path, content: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "data.txt").write_text(content, encoding="utf-8")
    _git(repo, "add", "data.txt")
    _git(
        repo,
        "-c",
        "user.email=test@example.test",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "add data",
    )
    return repo


def _scan(repo: Path, tmp_path: Path) -> tuple[int, dict]:
    out = tmp_path / "scan.json"
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "--json", str(out)],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    return proc.returncode, json.loads(out.read_text(encoding="utf-8"))


def test_live_shaped_aws_key_fails_the_gate(tmp_path):
    repo = _repo(tmp_path, "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n")
    code, report = _scan(repo, tmp_path)
    assert code == 1
    assert report["gate"] == "fail"
    assert report["counts"]["aws-access-key"] == 1
    assert report["hard_hits"][0]["category"] == "aws-access-key"


def test_clean_history_passes_the_gate(tmp_path):
    repo = _repo(tmp_path, "no credentials here\n")
    code, report = _scan(repo, tmp_path)
    assert code == 0
    assert report["gate"] == "pass"
    assert report["unresolved"] == 0


def test_scanner_covers_every_reachable_commit(tmp_path):
    repo = _repo(tmp_path, "first\n")
    _git(repo, "checkout", "-qb", "side")
    (repo / "data.txt").write_text("second\n", encoding="utf-8")
    _git(repo, "add", "data.txt")
    _git(
        repo,
        "-c",
        "user.email=test@example.test",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "second",
    )
    _git(repo, "checkout", "-q", "master")
    code, report = _scan(repo, tmp_path)
    assert code == 0
    assert report["commits_expected"] == 2
    assert report["commits_seen"] == 2


def test_removing_an_exception_fails_closed(tmp_path):
    repo = _repo(tmp_path, 'PASSWORD = "long-password-123"\n')
    registry = json.loads(
        (SCANNER.parent / "history-scan-exceptions.json").read_text(encoding="utf-8")
    )
    assert registry["value_exceptions"], "registry must carry the synthetic test credential"
    registry["value_exceptions"] = []
    stripped = tmp_path / "stripped.json"
    stripped.write_text(json.dumps(registry), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCANNER),
            "--exceptions",
            str(stripped),
            "--json",
            str(tmp_path / "scan.json"),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    report = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert report["review_hits"][0]["category"] == "password-assignment"
