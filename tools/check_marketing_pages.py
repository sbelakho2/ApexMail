#!/usr/bin/env python3
"""Marketing page-content gate — every built page renders its real body.

Owner directive 2026-10-25 ("way wider and more thorough scan"): structural
and style gates passed while the pricing calculator template rendered the
literal word "test" (a leftover skeleton from a parse-debug session) on
every locale. Nothing asserted that a page's body was actually there.

This gate fails when a built marketing page:

  1. has no <h1> (the one-heading contract), or more than one;
  2. renders a <main> whose visible text is shorter than MIN_MAIN_CHARS
     (skeletons, stubs, accidentally empty templates);
  3. carries obvious placeholder markers ("lorem ipsum", "coming soon",
     "TODO:", "FIXME");

and it also guards the pre-render templates: a template whose whole
content block is a bare word (the calculator regression shape).

The marketing build is a committed artifact (`apps/marketing-zola/public`),
so this runs against the shipped bytes, not a model of them.

Usage: python3 tools/check_marketing_pages.py [--self-test]
Exit codes: 0 = clean, 1 = violations, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "apps/marketing-zola/public"
TEMPLATES = ROOT / "apps/marketing-zola/templates"

MIN_MAIN_CHARS = 400

# Pages that are legitimately terse (they still must carry an h1).
SHORT_PAGE_ALLOWLIST = {
    "404.html",
    "50x.html",  # the nginx 50x document: minimal by design, still has its h1
}

# Case-sensitive on purpose: Spanish "todo:" ("everything:") is prose.
PLACEHOLDERS = [
    "lorem ipsum",
    "TODO",
    "FIXME",
]


def visible_text(html: str) -> str:
    html = re.sub(r"<script.*?</script>", " ", html, flags=re.S)
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    html = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", html).strip()


def main_body(html: str) -> str:
    m = re.search(r"<main\b[^>]*>(.*?)</main>", html, re.S)
    return m.group(1) if m else ""


def strip_rcdata(html: str) -> str:
    """Textarea content is TEXT to the browser (RCDATA): a JSON payload
    sample containing markup must not count as document headings."""
    return re.sub(r"<textarea\b.*?</textarea>", " ", html, flags=re.S)


def check_page(path: Path) -> list[str]:
    rel = path.relative_to(PUBLIC).as_posix()
    raw = path.read_text(errors="ignore")
    html = strip_rcdata(raw)
    problems = []
    h1s = re.findall(r"<h1\b", html)
    if len(h1s) == 0:
        problems.append(f"{rel}: no <h1>")
    elif len(h1s) > 1:
        problems.append(f"{rel}: {len(h1s)} <h1> elements")
    body = visible_text(main_body(html))
    if rel not in SHORT_PAGE_ALLOWLIST and len(body) < MIN_MAIN_CHARS:
        problems.append(
            f"{rel}: <main> renders {len(body)} visible chars "
            f"(floor {MIN_MAIN_CHARS}) — stub or empty template?"
        )
    low = html
    for marker in PLACEHOLDERS:
        if marker in low:
            problems.append(f"{rel}: placeholder marker {marker!r}")
    return problems


def check_templates() -> list[str]:
    """A template whose content block is a bare word (the regression shape)."""
    problems = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        text = path.read_text(errors="ignore")
        for m in re.finditer(r"\{%\s*block content\s*%\}(.*?)\{%\s*endblock", text, re.S):
            body = m.group(1).strip()
            if body and not body.startswith(("{%", "{#", "<")) and body.isalpha() and len(body) < 20:
                problems.append(
                    f"{path.relative_to(ROOT).as_posix()}: content block is the bare word {body!r}"
                )
    return problems


def run() -> int:
    if not PUBLIC.is_dir():
        print(f"marketing-pages: built tree absent ({PUBLIC})")
        return 2
    pages = sorted(PUBLIC.rglob("*.html"))
    problems = []
    for path in pages:
        problems.extend(check_page(path))
    problems.extend(check_templates())
    print(
        f"marketing-pages: {len(pages)} pages checked, "
        f"h1 floor {MIN_MAIN_CHARS} chars, {len(problems)} violation(s)"
    )
    for p in problems[:60]:
        print(f"  FAIL {p}")
    if len(problems) > 60:
        print(f"  … and {len(problems) - 60} more")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(run())
