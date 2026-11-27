#!/usr/bin/env python3
"""Root-document hygiene gate: GOVERNANCE.md section 2, enforced both ways.

One house rule, one text, in every repository:

    Root holds only the requested set -- nothing else. (...) No stray `.md`/`.txt`
    at the root. If a document at the root is not in the table above, move it to
    `docs/` (or `docs/archive/` if it is historical) and record the move in the
    `AGENTS.md` ledger.

Why the gate exists
-------------------
Assay's ``scripts/check-scaffold.py`` gained this assertion on 2026-11-27, after the
2026-11-26 governance pass archived three reports and the root set *still* looked
satisfied. A one-way check ("the documents I know about are present") cannot enforce
a "nothing else at the root" rule: it stays green while extra documents pile up. The
rule needs both directions, so this gate asserts:

  1. present -- every root document named in this repository's own GOVERNANCE.md
     section 2 table exists at the root;
  2. absent  -- no ``.md``/``.txt`` sits at the root that the table does not name.

The allowed set is parsed out of GOVERNANCE.md instead of being hard-coded here, so
the policy document stays the single source of truth and this gate follows it. Edit
the table, not this file.

Non-document ``.txt``
---------------------
``requirements*.txt`` and ``constraints*.txt`` at the root are package manifests,
not documents: they carry no narrative and pip resolves them relative to the working
directory, so ``docs/`` is not an option. They are printed as acknowledged
non-documents and are not strays.

Usage
-----
    python3 <this script>              # check the repository this script lives in
    python3 <this script> <repo_root>  # check another checkout
    python3 <this script> --self-test  # prove the gate fails closed, in a temp tree

Exit 0 = clean. Exit 1 = at least one named problem. A gate that cannot run -- no
GOVERNANCE.md, an unparsable section 2 table -- fails closed with exit 1.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

DOC_SUFFIXES = {".md", ".txt"}
NON_DOCUMENT_TXT = re.compile(r"(requirements|constraints)[-._A-Za-z0-9]*\.txt", re.IGNORECASE)
SECTION_2 = re.compile(r"^##[ \t]*2\b[^\n]*$", re.MULTILINE)
ANY_H2 = re.compile(r"^##[ \t]", re.MULTILINE)
BACKTICKED = re.compile(r"`([^`]+)`")


def find_repo_root(start: Path) -> Path | None:
    """The nearest ancestor holding GOVERNANCE.md, or None if there is none."""
    for candidate in [start, *start.parents]:
        if (candidate / "GOVERNANCE.md").is_file():
            return candidate
    return None


def section_2_text(governance: str) -> str:
    """The body of the section 2 heading, up to the next '## ' heading."""
    match = SECTION_2.search(governance)
    if match is None:
        return ""
    rest = governance[match.end() :]
    following = ANY_H2.search(rest)
    return rest[: following.start()] if following else rest


def parse_root_table(section: str) -> list[tuple[list[str], str]]:
    """Every row of the section 2 table, as ([document names], state).

    A cell may offer alternatives -- ``| `LICENSE` / `LICENSE.md` |`` -- so a row is
    a list of names of which one must exist. Names containing a slash are skipped:
    the table describes the root, not paths below it.
    """
    rows: list[tuple[list[str], str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 2:
            continue
        names = [name.strip() for name in BACKTICKED.findall(cells[0]) if "/" not in name.strip()]
        if not names:
            continue
        rows.append((names, cells[1].lower() or "unspecified"))
    return rows


def check(root: Path) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for one checkout."""
    problems: list[str] = []
    notes: list[str] = []

    governance = root / "GOVERNANCE.md"
    if not governance.is_file():
        return ["missing GOVERNANCE.md at the root: there is no policy to enforce"], notes

    table = parse_root_table(
        section_2_text(governance.read_text(encoding="utf-8", errors="replace"))
    )
    if not table:
        return [
            "GOVERNANCE.md section 2 carries no parsable root-document table, so the gate "
            "cannot tell what belongs at the root and fails closed"
        ], notes

    allowed_docs: set[str] = set()
    for names, state in table:
        if not any((root / name).is_file() for name in names):
            problems.append(
                f"missing root document: {' or '.join(names)} "
                f"({state}, GOVERNANCE.md section 2)"
            )
        for name in names:
            if Path(name).suffix.lower() in DOC_SUFFIXES:
                allowed_docs.add(name.lower())

    # The policy file is self-evidently allowed: this gate exists only because it
    # could read GOVERNANCE.md, so flagging it as a stray would be circular.
    allowed_docs.add("governance.md")

    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() not in DOC_SUFFIXES:
            continue
        if path.name.lower() in allowed_docs:
            continue
        if path.suffix.lower() == ".txt" and NON_DOCUMENT_TXT.fullmatch(path.name):
            notes.append(f"acknowledged non-document (package manifest): {path.name}")
            continue
        problems.append(
            f"stray root document: {path.name} -- move it to docs/ or docs/archive/ "
            f"(GOVERNANCE.md section 2)"
        )

    notes.append(
        f"{len(table)} table row(s), {len(allowed_docs)} allowed root document(s), "
        f"parsed from GOVERNANCE.md section 2"
    )
    return problems, notes


SELF_TEST_GOVERNANCE = """\
# GOVERNANCE

## 1. Repo map

| Path | What it is |
|---|---|
| `src/` | the code |

## 2. Documentation policy (what belongs where)

**Root holds only the requested set** -- nothing else:

| File | State | Purpose |
|---|---|---|
| `README.md` | required | Source of truth. |
| `AGENTS.md` | required | Agent charter + ledger. |
| `GOVERNANCE.md` | required | This file. |
| `LICENSE` / `LICENSE.md` | standard | MIT. |

**Everything else lives in `docs/`.** No stray `.md`/`.txt` at the root.

## 3. Sync policy
"""


def _case(
    name: str,
    tree: dict[str, str],
    expect_failures: int,
    governance: str = SELF_TEST_GOVERNANCE,
) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs").mkdir()
        (root / "GOVERNANCE.md").write_text(governance, encoding="utf-8")
        for relative, body in tree.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        problems, _ = check(root)
        ok = len(problems) == expect_failures
        mark = "ok" if ok else "FAIL"
        detail = f"{len(problems)} problem(s), expected {expect_failures}"
        print(f"  {mark}: {name} -- {detail}")
        for problem in problems:
            print(f"        {problem}")
        return ok


def self_test() -> int:
    """Prove each direction of the gate moves, on a throwaway tree.

    A check that can only pass is not a gate. Each case plants one condition and
    states how many problems it must produce.
    """
    clean = {"README.md": "x", "AGENTS.md": "x", "LICENSE": "x"}
    print("check_root_docs: self-test -- the gate must fail closed")
    results = [
        _case("documented root set", clean, 0),
        _case("planted stray .md", {**clean, "STRAY-NOTE.md": "x"}, 1),
        _case("planted stray .txt", {**clean, "NOTES.txt": "x"}, 1),
        _case("required document missing", {"AGENTS.md": "x", "LICENSE": "x"}, 1),
        _case("package manifest at root", {**clean, "requirements.txt": "x"}, 0),
        _case("stray under docs/", {**clean, "docs/note.md": "x"}, 0),
        _case("unparsable section 2", clean, 1, governance="# GOVERNANCE\n\nNo table here.\n"),
    ]
    if all(results):
        print(f"check_root_docs: self-test OK -- {len(results)}/{len(results)} cases behaved")
        return 0
    print(f"check_root_docs: self-test FAILED -- {results.count(False)}/{len(results)} cases wrong")
    return 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    positional = [argument for argument in argv if not argument.startswith("-")]
    if positional:
        root = Path(positional[0]).resolve()
    else:
        found = find_repo_root(Path(__file__).resolve().parent)
        if found is None:
            print(
                "check_root_docs: no GOVERNANCE.md above this script, so there is no "
                "policy to enforce; run it with an explicit repository path",
                file=sys.stderr,
            )
            return 1
        root = found

    problems, notes = check(root)
    for note in notes:
        print(f"note: {note}")
    if problems:
        print(f"check_root_docs: FAIL -- {len(problems)} problem(s) in {root}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"check_root_docs: OK -- {root.name}/ holds only the GOVERNANCE.md section 2 set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
