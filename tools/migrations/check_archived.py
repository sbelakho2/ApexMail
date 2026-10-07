#!/usr/bin/env python3
"""Pin the archival status of tools/migrations (coverage audit U-11).

Fails when a live test/migration runner surface references the archived tree.
SQL `--` comments and prose (docs) may cite it as history and are ignored —
the F01 lesson was test code BOOTSTRAPPING it, so this checks executable
surfaces: ci/, scripts/, services/ (excluding this directory), tests/,
deploy/, docker-compose*.yml, Makefile, .github/.

Usage: python3 tools/migrations/check_archived.py
Exit: 0 = no live runner reads the archive; 1 = reference found; 2 = bad usage.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "tools" / "migrations"

SURFACES = [
    ROOT / "ci",
    ROOT / "scripts",
    ROOT / "services",
    ROOT / "tests",
    ROOT / "deploy",
    ROOT / ".github",
]
FILES = sorted(ROOT.glob("docker-compose*.yml")) + [ROOT / "Makefile"]

TOKEN = re.compile(r"tools[/\\]migrations|TOOL_MIGRATIONS")

CODE_SUFFIXES = {
    ".rs", ".py", ".sh", ".bash", ".toml", ".yml", ".yaml", ".json",
    ".conf", ".mk", ".sql", ".js", ".mjs", ".ts", ".tsx", ".go", ".rb",
}
SKIP_PARTS = {".git", "node_modules", "target", ".venv", "__pycache__"}


def iter_files() -> list[Path]:
    out: list[Path] = []
    for surface in SURFACES + FILES:
        if not surface.exists():
            continue
        if surface.is_file():
            out.append(surface)
        else:
            for path in sorted(surface.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix not in CODE_SUFFIXES:
                    continue
                if SKIP_PARTS & set(path.parts):
                    continue
                if path.resolve().is_relative_to(ARCHIVE):
                    continue
                out.append(path)
    return out


def strip_comments(path: Path, text: str) -> str:
    """Remove comment-only prose so legitimate historical citations pass."""
    if path.suffix == ".sql":
        return "\n".join(line.split("--", 1)[0] for line in text.splitlines())
    if path.suffix == ".rs":
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        return "\n".join(line.split("//", 1)[0] for line in text.splitlines())
    if path.suffix in {".py", ".sh", ".bash", ".toml", ".yml", ".yaml", ".mk"}:
        return "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return text


def main() -> int:
    hits: list[str] = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = strip_comments(path, text)
        for number, line in enumerate(text.splitlines(), 1):
            if TOKEN.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")

    if hits:
        print(
            "FAIL: live runner surface references the archived tools/migrations tree "
            "(F01 regression — runners must use services/mail-server/migrations):",
            file=sys.stderr,
        )
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print(
        "archived-tree pin passed: no live runner surface reads tools/migrations "
        f"({len(iter_files())} files scanned)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print("usage: check_archived.py", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
