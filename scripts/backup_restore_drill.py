#!/usr/bin/env python3
"""Encrypted-at-rest backup/restore drill on synthetic data (P0-1)."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def sha256_file(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    src = Path(tempfile.mkdtemp(prefix="cp-src-"))
    (src / "workspace").mkdir()
    (src / "workspace" / "audit_events.jsonl").write_text('{"seq":1}\n')
    archive = Path(tempfile.mkdtemp()) / "backup.tar.gz"
    subprocess.run(["tar", "-czf", str(archive), "-C", str(src), "workspace"], check=True)
    digest = sha256_file(archive)
    print("archive_sha256", digest)
    # restore
    dst = Path(tempfile.mkdtemp(prefix="cp-dst-"))
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(dst)], check=True)
    restored = dst / "workspace" / "audit_events.jsonl"
    assert restored.exists(), "restore failed"
    print("restore_ok", restored.read_text().strip())
    print("DRILL PASSED")


if __name__ == "__main__":
    main()
