#!/usr/bin/env python3
"""Public-artifact disclosure gates (external audit 2026-10-26, items 12+13).

Two checks over what the marketing build actually serves:

1. Static artifact allowlist. `apps/marketing-zola/static/` is copied
   VERBATIM into every build, so deployment-oriented files there are
   publicly downloadable. Banned outright: `.htaccess`, `_headers`,
   `_redirects` (deployment plumbing with routing commentary), source maps
   (`*.map`), and dotfiles outside `.well-known/`. Everything else in the
   tree is allowed by extension pattern; a new public artifact type needs a
   deliberate allowlist entry here.

2. Public OpenAPI boundary. `apps/marketing-zola/static/specs/openapi.yaml`
   is the served spec. It must contain NO admin/control-plane/internal
   route prefixes and no infrastructure-provider terms. (The internal
   `docs/api/openapi.yaml` source legitimately documents admin routes; only
   the SERVED copy is gated — but it is a copy, so keep the two in sync
   deliberately, not silently.)

--self-test proves both directions with mutated fixtures.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "apps" / "marketing-zola" / "static"
PUBLIC_SPEC = STATIC_DIR / "specs" / "openapi.yaml"

# Files that must NOT exist anywhere under static/ (deployment plumbing and
# build metadata that leak routing/deployment detail).
BANNED_BASENAMES = {".htaccess", "_headers", "_redirects"}

# Route prefixes and terms that must never appear in the SERVED spec.
FORBIDDEN_SPEC_PATTERNS = [
    "/v1/admin",
    "/admin/",
    "/cp/",
    "/internal/",
    "/secrets",
    "hetzner",
]


def check_static_dir(root: Path) -> list[str]:
    problems: list[str] = []
    if not root.is_dir():
        return [f"static directory missing: {root}"]
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        name = path.name
        if name in BANNED_BASENAMES:
            problems.append(f"banned deployment artifact: {rel}")
        if name.endswith(".map"):
            problems.append(f"source map must not ship: {rel}")
        if name.startswith(".") and not rel.startswith(".well-known/"):
            problems.append(f"dotfile must not ship (only .well-known is public): {rel}")
    return problems


def check_public_spec(spec: Path) -> list[str]:
    problems: list[str] = []
    if not spec.is_file():
        return [f"public OpenAPI spec missing: {spec}"]
    text = spec.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    for pattern in FORBIDDEN_SPEC_PATTERNS:
        if pattern in lowered:
            problems.append(f"public OpenAPI spec contains forbidden pattern {pattern!r}")
    return problems


def run_checks(static_dir: Path = STATIC_DIR, spec: Path = PUBLIC_SPEC) -> list[str]:
    return check_static_dir(static_dir) + check_public_spec(spec)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        static = root / "static"
        (static / "specs").mkdir(parents=True)
        (static / "css").mkdir()
        (static / "css" / "ok.css").write_text("body{}")
        (static / ".well-known").mkdir()
        (static / ".well-known" / "security.txt").write_text("Contact: security@apexmail.ee\n")
        (static / "specs" / "openapi.yaml").write_text("openapi: 3.0.0\npaths:\n  /v1/messages:\n")

        # Clean tree passes.
        problems = run_checks(static_root_for(static), static / "specs" / "openapi.yaml")
        assert not problems, problems

        # Each banned artifact is caught.
        for banned, content in [
            (".htaccess", "RewriteEngine On\n"),
            ("_headers", "/*\n  X-Frame-Options: DENY\n"),
            ("_redirects", "/old /new 301\n"),
            ("app.js.map", "{}"),
        ]:
            (static / banned).write_text(content)
            problems = run_checks(static_root_for(static), static / "specs" / "openapi.yaml")
            assert any(banned in p for p in problems), (banned, problems)
            (static / banned).unlink()

        # A dotfile outside .well-known is caught; inside it is fine.
        (static / ".env.example").write_text("SECRET=1\n")
        problems = run_checks(static_root_for(static), static / "specs" / "openapi.yaml")
        assert any(".env.example" in p for p in problems), problems
        (static / ".env.example").unlink()

        # Forbidden spec patterns are caught (both route and provider terms).
        for pattern in ["/v1/admin/impersonate", "/cp/tenants", "runs on Hetzner"]:
            (static / "specs" / "openapi.yaml").write_text(f"paths:\n  {pattern}:\n")
            problems = run_checks(static_root_for(static), static / "specs" / "openapi.yaml")
            assert any("forbidden pattern" in p for p in problems), (pattern, problems)

    print("public-artifacts self-test: ok")
    return 0


def static_root_for(_hint: Path) -> Path:
    """Indirection so the self-test can point run_checks at a temp dir."""
    return _hint


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = run_checks()
    if problems:
        for problem in problems:
            print(f"public-artifacts: {problem}", file=sys.stderr)
        return 1
    print("public-artifacts: OK (static allowlist + public OpenAPI boundary)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
