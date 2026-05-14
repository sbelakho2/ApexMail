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
TEST_FILE_RE = re.compile(r"(^|/)tests?(/|$)")


def is_test_file(path: Path) -> bool:
    relative = path.relative_to(CRATES).as_posix()
    if TEST_FILE_RE.search(relative):
        return True
    # Common benchmark and test helper locations.
    if "/benches/" in relative or relative.endswith("_test.rs"):
        return True
    return False


def rust_sources() -> list[Path]:
    return sorted(
        path
        for path in CRATES.rglob("*.rs")
        if "/target/" not in path.as_posix() and not is_test_file(path)
    )


def count_braces_delta(
    line: str,
    in_double: bool = False,
    in_raw: bool = False,
) -> tuple[int, bool, bool]:
    """
    Best-effort brace counting that ignores quoted braces.
    Returns (delta, new_in_double, new_in_raw).
    Tracks in_double and in_raw across lines for multi-line string and
    raw string literals (r#"...", r##"..."##, etc.).
    NOTE: Rust lifetimes (e.g. 'static, 'a) use ' followed by identifier chars;
    we must NOT treat them as character literal delimiters.
    """
    in_single = False
    escaped = False
    delta = 0
    i = 0
    while i < len(line):
        ch = line[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double and not in_raw:
            # Distinguish Rust lifetimes ('static, 'a) from char literals ('x', '\n').
            # Lifetimes: ' followed by one or more identifier chars (no closing ').
            # Char literals: 'X' (exactly one char + closing ') or '\X' (escape).
            if i + 1 < len(line):
                nxt = line[i + 1]
                if nxt.isalnum() or nxt == '_':
                    # Check whether the pattern is 'X' (char literal) or longer (lifetime).
                    # If the char after next is also id-char or we're at end, it's a lifetime.
                    if i + 2 < len(line) and line[i + 2] == "'":
                        # Pattern 'X' — treat as char literal only if no more id-chars follow.
                        # In Rust, 'X' where X is alphanumeric is always a char literal.
                        # But 'a alone is a lifetime. Since there's a closing ', it's a char.
                        in_single = not in_single
                    # else: lifetime — do NOT toggle in_single
                else:
                    # Not followed by identifier char — could be char literal like '{' or ')'
                    in_single = not in_single
            else:
                in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            if in_raw:
                # Inside a raw string r#"...": a " followed by # closes the raw string.
                # (The # is the closing delimiter marker.)
                if i + 1 < len(line) and line[i + 1] == "#":
                    in_raw = False
                    in_double = not in_double  # Toggle for the closing "
                    i += 2  # Consume the #
                    continue
                # Otherwise: an embedded " inside the raw string content — ignore it.
                i += 1
                continue
            else:
                # Check if this " starts a raw string literal.
                # Raw strings: r"..." or r#"...", r##"..."##, etc.
                # Check if this " starts a raw string literal.
                # Raw strings: r"..." or r#"..."#, r##"..."##, etc.
                # Look backwards: r + optional #s + "
                j = i - 1  # Start just before the "
                hash_count = 0
                while j >= 0 and line[j] == "#":
                    hash_count += 1
                    j -= 1
                if j >= 0 and line[j] == "r":
                    # Found r followed by hash_count #s followed by "
                    # Verify it's not part of an identifier like `err"` or `bar#"`
                    k = j - 1
                    if k < 0 or not (line[k].isalnum() or line[k] == "_"):
                        in_raw = True
                        # Do NOT toggle in_double — raw string content is literal.
                        i += 1
                        continue
                # Normal string literal — toggle in_double.
                in_double = not in_double
            i += 1
            continue
        if in_single or in_double or in_raw:
            i += 1
            continue
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1
    return delta, in_double, in_raw


def count_panic_paths() -> tuple[int, list[str]]:
    count = 0
    examples: list[str] = []
    for path in rust_sources():
        relative = path.relative_to(ROOT)
        skip_block = False
        skip_depth = 0
        pending_test_attr = False
        in_double = False  # Track multi-line string literals (e.g. r#"..."#)
        in_raw = False     # Track multi-line raw string literals
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip doc-comment lines (/// and //!) — doc examples are not production code.
            trimmed = line.lstrip()
            if trimmed.startswith("///") or trimmed.startswith("//!"):
                continue

            if stripped.startswith("#[cfg(test"):
                pending_test_attr = True
                continue
            if stripped.startswith("#[test") or stripped.startswith("#[tokio::test"):
                pending_test_attr = True
                continue

            if pending_test_attr and (
                stripped.startswith("mod ")
                or stripped.startswith("fn ")
                or stripped.startswith("async fn ")
                or stripped.startswith("pub fn ")
                or stripped.startswith("pub async fn ")
            ):
                pending_test_attr = False
                delta, in_double, in_raw = count_braces_delta(line, in_double, in_raw)
                if not skip_block:
                    skip_block = True
                    skip_depth = max(1, delta)
                else:
                    # Already inside a skip_block (e.g. mod tests { }).
                    # Don't reset depth — just account for this line's braces.
                    skip_depth += delta
                    if skip_depth < 0:
                        skip_depth = 0
                continue

            if skip_block:
                delta, in_double, in_raw = count_braces_delta(line, in_double, in_raw)
                skip_depth += delta
                if skip_depth <= 0:
                    skip_block = False
                    skip_depth = 0
                    in_double = False  # Reset state on skip_block exit
                    in_raw = False
                continue

            if PANIC_RE.search(line):
                count += 1
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
