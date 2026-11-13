# Evidence directory

Tracked evidence is the single canonical record: run logs, JSON reports and
the `SHA256SUMS` manifest in each dated directory.

Not tracked (see `.gitignore`):

- `**/package/install/` — an installed-wheel tree that duplicates `src/` and
  the dashboard file.
- `**/package/wheels/` — built wheels, reproducible from the lockfile.

Those artefacts were removed from git under finding ME-16 because they
duplicated source and inflated the repository. They still exist in operator
clones; if a release is ever published, attach them to the release instead of
committing them.

Regenerate a manifest from the repository root:

```bash
python3 - <<'PY'
import hashlib
from pathlib import Path

EXCLUDE = {"install", "wheels"}
for directory in (Path("evidence/production-readiness-2026-11-04"),
                  Path("evidence/production-readiness-2026-11-05")):
    manifest = directory / "SHA256SUMS"
    lines = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path == manifest:
            continue
        if EXCLUDE & set(path.relative_to(directory).parts):
            continue
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.as_posix()}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
```

Verify with `sha256sum -c evidence/<date>/SHA256SUMS` from the repository root.
