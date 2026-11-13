#!/usr/bin/env python3
"""Check that version, Python and status claims agree across the repository.

Single sources of truth:

* version      -> ``pyproject.toml`` ``[project].version``
* Python floor -> ``pyproject.toml`` ``requires-python``
* status       -> the "Current status" section of ``README.md``

Everything else (``__init__.__version__``, README text, Dockerfile, CI matrix,
``requirements.in``) must agree with those. Dated execution logs are historical
records and are not checked, except that live docs may not hardcode a test
count that will drift.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

LIVE_DOCS = ("README.md", "SHIPMENT_READINESS.md", "AUDIT_REPORT.md", "SECURITY.md")
FORBIDDEN_SIGNATURE_CLAIMS = re.compile(
    r"(?i)\b(digitally signed|cryptographically signed|signed evidence pack|signature-verified)\b"
)
HARDCODED_TEST_COUNT = re.compile(r"(?i)\b\d{2,4}\s+(?:automated\s+)?tests?\s+pass")
STATUS_SOURCE_DECLARATION = "single source of truth for project status"


def _dependency_set(lines: list[str]) -> set[str]:
    deps = set()
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, version = line.partition("==")
        deps.add(f"{name.strip().lower().replace('_', '-')}=={version.strip()}")
    return deps


def _python_versions(ci_text: str) -> list[str]:
    versions: list[str] = []
    for match in re.finditer(r"python-version:\s*(\[[^\]]*\]|\"[^\"]+\")", ci_text):
        value = match.group(1).strip()
        if value.startswith("["):
            versions.extend(re.findall(r"[\"']([0-9]+\.[0-9]+)[\"']", value))
        else:
            versions.append(value.strip("\"'"))
    return versions


def check_repo(root: Path) -> list[str]:
    problems: list[str] = []
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    version = project["version"]
    requires = project["requires-python"]
    floor = re.search(r">=\s*([0-9]+\.[0-9]+)", requires)
    if not floor:
        return [f"requires-python must use a >=X.Y floor, found {requires!r}"]
    python_floor = floor.group(1)

    init_text = (root / "src" / "compliproof" / "__init__.py").read_text(encoding="utf-8")
    declared = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if not declared or declared.group(1) != version:
        problems.append(
            f"src/compliproof/__init__.py __version__ "
            f"{declared.group(1) if declared else 'missing'} != pyproject {version}"
        )

    readme = (root / "README.md").read_text(encoding="utf-8")
    if f"CompliProof {version}" not in readme:
        problems.append(f"README.md does not name version {version}")
    if STATUS_SOURCE_DECLARATION not in readme:
        problems.append(f"README.md must declare itself the {STATUS_SOURCE_DECLARATION!r}")

    dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
    base = re.search(r"^FROM\s+python:([0-9]+\.[0-9]+)", dockerfile, re.MULTILINE)
    if not base:
        problems.append("docker/Dockerfile has no python:X.Y base image")
    elif base.group(1) != python_floor:
        problems.append(f"docker/Dockerfile python {base.group(1)} != requires-python {python_floor}")

    ci_versions = _python_versions((root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    if not ci_versions:
        problems.append("CI workflow declares no python-version")
    else:
        if min(ci_versions, key=lambda v: tuple(map(int, v.split(".")))) != python_floor:
            problems.append(f"CI minimum python {min(ci_versions)} != requires-python {python_floor}")
        for candidate in ci_versions:
            if tuple(map(int, candidate.split("."))) < tuple(map(int, python_floor.split("."))):
                problems.append(f"CI tests python {candidate} below the {python_floor} floor")

    pyproject_deps = _dependency_set(project.get("dependencies", []))
    requirements = _dependency_set(
        (root / "requirements.in").read_text(encoding="utf-8").splitlines()
    )
    if pyproject_deps != requirements:
        problems.append(
            "requirements.in and pyproject dependencies differ: "
            f"only in pyproject {sorted(pyproject_deps - requirements)}, "
            f"only in requirements.in {sorted(requirements - pyproject_deps)}"
        )

    floor_minor = int(python_floor.split(".")[1])
    for name in LIVE_DOCS:
        path = root / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"Python\s+3\.(\d+)", text):
            if int(match.group(1)) < floor_minor:
                problems.append(f"{name} claims Python 3.{match.group(1)} below the {python_floor} floor")
        if FORBIDDEN_SIGNATURE_CLAIMS.search(text):
            problems.append(f"{name} contains a signature claim; evidence is hash-consistent only")
        if HARDCODED_TEST_COUNT.search(text):
            problems.append(f"{name} hardcodes a test count that will drift; let CI report it")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    problems = check_repo(root)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print("Documentation consistency checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
