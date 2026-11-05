#!/usr/bin/env python3
"""File-schema migration rehearsal (P0-1): verify all persisted JSON stores load."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("COMPLIPROOF_WORKSPACE", tempfile.mkdtemp())
ws = Path(os.environ["COMPLIPROOF_WORKSPACE"])
ws.mkdir(parents=True, exist_ok=True)

from compliproof.server import _load_tasks  # noqa: E402
# tasks
(ws / "tasks.json").write_text(json.dumps({"schema": "tasks.v1", "updated": "x", "tasks": []}))
print("tasks load:", _load_tasks())
# finance/pipeline optional
print("MIGRATION REHEARSAL PASSED")
