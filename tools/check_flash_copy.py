#!/usr/bin/env python3
"""Gate C — flash-copy canon gate.

Executable copy: every user-facing flash string (redirect_success /
redirect_error / FlashMessage::{success,error,info}) is checked against the
house copy canon, so copy drift (the P2 finding: mixed casing, unpunctuated
banners, leaked error internals) cannot land silently.

Canon (per literal, production code only — files are split at the first
`#[cfg(test)]`):
  * trimmed non-empty;
  * starts with a capital letter;
  * ends with a period (a literal carrying `{…}` interpolation may end with
    an ellipsis `…`/`...` — the interpolated sentence still has to close);
  * `!` is never the only terminal punctuation;
  * banned substrings: `panic`, `unwrap(`, `Error: `, `.to_string()`
    (implementation vocabulary must never reach a browser);
  * the `redirect_error(&error.to_string())` call-site shape is flagged
    separately as leaked-error-display.

Allowlist: tools/ui_copy_allowlist.txt — one exemption per line,

    path:line[:rule] # justification

`path` is repo-relative (exact match), `rule` optionally narrows the
exemption to a single rule id. Blank lines and `# comments` are ignored.
Every violation prints file:line + the string; any non-allowlisted violation
exits 1.

Usage: python3 tools/check_flash_copy.py [root …]
       (default root: services/mail-server/crates)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_flash_extract import all_flash_sites  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = Path(__file__).resolve().parent / "ui_copy_allowlist.txt"

failures: list[str] = []

# (rule id, predicate) — order is the print order per site.
BANNED_SUBSTRINGS = {
    "banned:panic": "panic",
    "banned:unwrap": "unwrap(",
    "banned:error-colon": "Error: ",
    "banned:to-string": ".to_string()",
}

_ELLIPSIS_END = re.compile(r"(\u2026|\.\.\.)\s*$")
_FIRST_CHAR = re.compile(r"\S")


def violations_for(site) -> list[str]:
    rules: list[str] = []
    text = site.text
    stripped = text.strip()
    if not stripped:
        return ["empty-copy"]
    first = _FIRST_CHAR.search(stripped)
    if first is None or not (first.group(0).isupper() or first.group(0).isdigit()):
        rules.append("not-capitalized")
    if stripped.endswith("!"):
        # `!` as the only terminal punctuation — the canon closes with a
        # period (calm voice); report it INSTEAD of a bare missing-period.
        rules.append("terminal-exclamation")
    elif not stripped.endswith("."):
        if not (stripped.endswith("\u2026") or stripped.endswith("...")) or "{" not in stripped:
            rules.append("missing-period")
    for rule, needle in BANNED_SUBSTRINGS.items():
        if needle in stripped:
            rules.append(rule)
    return rules


def load_allowlist(path: Path) -> tuple[dict, dict]:
    """({(path,line): set(rules-or-all)}, examples) — exact path:line keys."""
    exact: dict[tuple[str, int], set[str]] = {}
    if not path.is_file():
        return exact, []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split(":")
        if len(parts) < 2:
            print(f"allowlist: unparseable entry skipped: {line}")
            continue
        fpath = ":".join(parts[:-1])
        try:
            lineno = int(parts[-1])
        except ValueError:
            # path:line:rule form
            fpath, lineno_s, rule = parts[0], parts[1], ":".join(parts[2:])
            try:
                lineno = int(lineno_s)
            except ValueError:
                print(f"allowlist: unparseable entry skipped: {line}")
                continue
            exact.setdefault((fpath, lineno), set()).add(rule)
            continue
        exact.setdefault((fpath, lineno), set()).add("*")
    return exact, []


def main(argv: list[str]) -> int:
    roots = [Path(p) for p in argv[1:]] or None
    sites, leaked = all_flash_sites(roots)
    allow_exact, _examples = load_allowlist(ALLOWLIST)

    print(f"flash call sites scanned: {len(sites)} "
          f"(+{len(leaked)} leaked-error-display candidates)")

    violations: list[tuple[str, int, str, str]] = []  # (path, line, rule, text)
    for site in sites:
        for rule in violations_for(site):
            violations.append((site.path, site.line, rule, site.text))
    for site in leaked:
        violations.append((site.path, site.line, "leaked-error-display", site.snippet))

    active = []
    for path, line, rule, text in violations:
        exempt_rules = allow_exact.get((path, line))
        if exempt_rules is not None and ("*" in exempt_rules or rule in exempt_rules):
            continue
        active.append((path, line, rule, text))

    for path, line, rule, text in sorted(active):
        print(f"FAIL {rule} {path}:{line} — {text!r}")
        failures.append(f"{rule} {path}:{line}")

    print()
    if failures:
        print(f"FLASH COPY FAILURES: {len(failures)} "
              f"({len(violations)} raw, {len(violations) - len(active)} allowlisted)")
        for name in failures[:50]:
            print(f"  - {name}")
        if len(failures) > 50:
            print(f"  … and {len(failures) - 50} more")
        sys.exit(1)
    print("flash copy: all green")


if __name__ == "__main__":
    main(sys.argv)
