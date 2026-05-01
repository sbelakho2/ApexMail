#!/usr/bin/env python3
"""Guardrail for Rust unwrap/expect usage in mail-server crates."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "services" / "mail-server" / "crates"
MAX_PANIC_PATHS = int(os.environ.get("MAX_RUST_PANIC_PATHS", "1700"))
PANIC_RE = re.compile(r"\.(unwrap|expect)\s*\(")


def rust_sources() -> list[Path]:
    return sorted(path for path in CRATES.rglob("*.rs") if "/target/" not in path.as_posix())


def count_panic_paths() -> tuple[int, list[str]]:
    count = 0
    examples: list[str] = []
    for path in rust_sources():
        relative = path.relative_to(ROOT)
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if PANIC_RE.search(line):
                count += 1
                if len(examples) < 10:
                    examples.append(f"{relative}:{line_number}: {line.strip()}")
    return count, examples


def main() -> int:
    count, examples = count_panic_paths()
    if count > MAX_PANIC_PATHS:
        print(
            f"Rust unwrap/expect count is {count}, above guardrail {MAX_PANIC_PATHS}.",
            file=sys.stderr,
        )
        for example in examples:
            print(example, file=sys.stderr)
        return 1

    print(f"Rust unwrap/expect guardrail passed ({count}/{MAX_PANIC_PATHS})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
