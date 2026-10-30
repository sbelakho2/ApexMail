#!/usr/bin/env python3
"""Public-artifact disclosure gates (external audit 2026-10-26, items 12+13).

Three checks over what the marketing build actually serves:

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

3. Hosting-location boundary (audit WEB-9). No hosting country, city,
   data-centre, facility code or infrastructure-provider name may appear on
   ANY public surface, in all four site languages: the templates, the
   content sources, `data/i18n.json` and the built `public/` output. The
   location is a contractual fact disclosed in the customer DPA annex and
   the internal registers, never on the website.

--self-test proves all three directions with mutated fixtures, including a
seeded "Finland" that the hosting-location scan must reject.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MARKETING_ROOT = REPO_ROOT / "apps" / "marketing-zola"
STATIC_DIR = MARKETING_ROOT / "static"
PUBLIC_SPEC = STATIC_DIR / "specs" / "openapi.yaml"

# Every public surface the hosting-location scan covers. `public/` is the
# build output; the rest are the sources that produce it, so a dirty source
# fails before a build can ship it.
PUBLIC_SURFACES = [
    MARKETING_ROOT / "templates",
    MARKETING_ROOT / "content",
    MARKETING_ROOT / "data" / "i18n.json",
    MARKETING_ROOT / "static",
    MARKETING_ROOT / "public",
]

# Text artifacts worth scanning. Images/fonts are binary and carry no copy.
TEXT_SUFFIXES = {
    ".html",
    ".htm",
    ".css",
    ".js",
    ".json",
    ".md",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".svg",
    ".webmanifest",
}

# The owner directive: the hosting country/city, the data-centre provider and
# its facility codes are withheld from every public surface, in every language
# the site publishes (English, German, French, Spanish). The patterns are
# case-insensitive, word-boundary anchored, and language-inclusive:
#   Finland / Finnish / Finnland / finnisch / Finlande / finlandais /
#   Finlandia / finlandés / finlandesa.
HOSTING_LOCATION_PATTERNS = [
    ("hosting country (en)", re.compile(r"(?i)\bfinland\w*\b")),
    ("hosting country (de)", re.compile(r"(?i)\bfinnland\w*\b")),
    ("hosting country (fr)", re.compile(r"(?i)\bfinlande\b")),
    ("hosting country (es)", re.compile(r"(?i)\bfinlandia\b")),
    (
        "hosting demonym",
        re.compile(r"(?i)\b(?:finnish|finnisch\w*|finlandais\w*|finland[eé]s\w*)\b"),
    ),
    ("hosting city", re.compile(r"(?i)\bhelsinki\b")),
    ("infrastructure provider", re.compile(r"(?i)\bhetzner\b")),
    ("provider facility code", re.compile(r"(?i)\b(?:hel1|fsn1|nbg1)\b")),
    (
        "provider facility city",
        re.compile(r"(?i)\b(?:falkenstein|nuremberg|ashburn|hillsboro)\b"),
    ),
]

# The legal/contractual exception manifest (external audit 2026-10-26, item
# 9): a disclosure permitted ONLY because law/contract requires it must be
# listed with its exact allowed surface; unlisted disclosures are forbidden.
EXCEPTIONS_MANIFEST = REPO_ROOT / "docs" / "operations" / "disclosure-exceptions.json"

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


def check_exceptions_manifest(manifest: Path = EXCEPTIONS_MANIFEST) -> list[str]:
    import json

    problems: list[str] = []
    if not manifest.is_file():
        return [f"disclosure-exceptions manifest missing: {manifest}"]
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except ValueError as error:
        return [f"disclosure-exceptions manifest is not valid JSON: {error}"]
    if data.get("version") != 1:
        problems.append("manifest version must be 1")
    if not str(data.get("policy", "")).strip():
        problems.append("manifest must state the policy sentence")
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list) or not exceptions:
        return problems + ["manifest must list at least one exception"]
    seen_ids: set[str] = set()
    required = {"id", "fact", "basis", "allowed_surface", "prohibited_surfaces"}
    for entry in exceptions:
        if not isinstance(entry, dict):
            problems.append(f"exception entry is not an object: {entry!r}")
            continue
        missing = required - entry.keys()
        if missing:
            problems.append(f"exception {entry.get('id', '?')} misses keys: {sorted(missing)}")
        eid = entry.get("id", "")
        if eid in seen_ids:
            problems.append(f"duplicate exception id: {eid}")
        seen_ids.add(eid)
        allowed = str(entry.get("allowed_surface", ""))
        if not allowed.strip():
            problems.append(f"exception {eid} must name an exact allowed surface")
        prohibited = entry.get("prohibited_surfaces")
        if not isinstance(prohibited, list) or not prohibited:
            problems.append(f"exception {eid} must enumerate prohibited surfaces")
        # The manifest itself must never spell the provider name: an
        # exception document describing a withheld identity cannot contain it.
        if "hetzner" in json.dumps(entry).lower():
            problems.append(f"exception {eid} spells the withheld provider name")
    return problems


def check_public_hosting_locations(surfaces: list[Path] | None = None) -> list[str]:
    """Audit WEB-9: no hosting country/city/facility/provider name on any
    public surface, in any published language.

    Scans the template and content sources, `data/i18n.json`, the static tree
    and the BUILT `public/` output. Anything the scan finds is a disclosure
    of the hosting location; the fact belongs in the customer DPA annex and
    the internal registers, not on the website.
    """
    surfaces = PUBLIC_SURFACES if surfaces is None else surfaces
    problems: list[str] = []
    for surface in surfaces:
        if not surface.exists():
            continue
        candidates = [surface] if surface.is_file() else sorted(surface.rglob("*"))
        for path in candidates:
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                for label, pattern in HOSTING_LOCATION_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        problems.append(
                            f"{path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}:"
                            f"{number}: hosting-location disclosure ({label}): {match.group(0)!r}"
                        )
    return problems


def run_checks(
    static_dir: Path = STATIC_DIR,
    spec: Path = PUBLIC_SPEC,
    exceptions: Path = EXCEPTIONS_MANIFEST,
    hosting_surfaces: list[Path] | None = None,
) -> list[str]:
    return (
        check_static_dir(static_dir)
        + check_public_spec(spec)
        + check_exceptions_manifest(exceptions)
        + check_public_hosting_locations(hosting_surfaces)
    )


def self_test_hosting_locations() -> None:
    """Prove the hosting-location scan fails on every seeded variant and
    passes a clean tree, in all four published languages."""
    with tempfile.TemporaryDirectory() as tmp:
        marketing = Path(tmp) / "marketing-zola"
        templates = marketing / "templates"
        content = marketing / "content"
        data = marketing / "data"
        public = marketing / "public"
        for directory in (templates, content, data, public):
            directory.mkdir(parents=True, exist_ok=True)
        (templates / "hero.html").write_text("EU infrastructure, EEA storage.\n", encoding="utf-8")
        (content / "index.md").write_text("EU data centres. No third-country transfer.\n", encoding="utf-8")
        (data / "i18n.json").write_text('{"latency_row_de": "ApexMail EU service"}\n', encoding="utf-8")
        (public / "index.html").write_text("<p>EU infrastructure</p>\n", encoding="utf-8")
        surfaces = [templates, content, data / "i18n.json", public]

        assert not check_public_hosting_locations(surfaces), "clean public tree must pass"

        seeded = [
            ("Finland", "en"),
            ("Finnish data centres", "en demonym"),
            ("Finnland", "de"),
            ("finnisch", "de demonym"),
            ("Finlande", "fr"),
            ("finlandais", "fr demonym"),
            ("Finlandia", "es"),
            ("finlandés", "es demonym"),
            ("Helsinki", "city"),
            ("Hetzner", "provider"),
            ("hel1", "facility code"),
            ("fsn1", "facility code"),
        ]
        for term, label in seeded:
            (templates / "hero.html").write_text(f"Hosted in {term}.\n", encoding="utf-8")
            problems = check_public_hosting_locations(surfaces)
            assert problems, f"seeded {label!r} term {term!r} was NOT rejected"
            (templates / "hero.html").write_text("EU infrastructure.\n", encoding="utf-8")

        # The BUILT output is scanned too: a term that only appears after the
        # build cannot hide there.
        (public / "index.html").write_text("<p>Hetzner (Finland)</p>\n", encoding="utf-8")
        problems = check_public_hosting_locations(surfaces)
        assert any("public/index.html" in p for p in problems), problems
        (public / "index.html").write_text("<p>EU infrastructure</p>\n", encoding="utf-8")


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
        problems = run_checks(
            static_root_for(static), static / "specs" / "openapi.yaml", hosting_surfaces=[]
        )
        assert not problems, problems

        # Each banned artifact is caught.
        for banned, content in [
            (".htaccess", "RewriteEngine On\n"),
            ("_headers", "/*\n  X-Frame-Options: DENY\n"),
            ("_redirects", "/old /new 301\n"),
            ("app.js.map", "{}"),
        ]:
            (static / banned).write_text(content)
            problems = run_checks(
                static_root_for(static), static / "specs" / "openapi.yaml", hosting_surfaces=[]
            )
            assert any(banned in p for p in problems), (banned, problems)
            (static / banned).unlink()

        # A dotfile outside .well-known is caught; inside it is fine.
        (static / ".env.example").write_text("SECRET=1\n")
        problems = run_checks(
            static_root_for(static), static / "specs" / "openapi.yaml", hosting_surfaces=[]
        )
        assert any(".env.example" in p for p in problems), problems
        (static / ".env.example").unlink()

        # Forbidden spec patterns are caught (both route and provider terms).
        for pattern in ["/v1/admin/impersonate", "/cp/tenants", "runs on Hetzner"]:
            (static / "specs" / "openapi.yaml").write_text(f"paths:\n  {pattern}:\n")
            problems = run_checks(
                static_root_for(static), static / "specs" / "openapi.yaml", hosting_surfaces=[]
            )
            assert any("forbidden pattern" in p for p in problems), (pattern, problems)
        (static / "specs" / "openapi.yaml").write_text("openapi: 3.0.0\npaths:\n  /v1/messages:\n")

        # Exception manifest schema: clean passes; each broken shape fails.
        good_manifest = {
            "version": 1,
            "policy": "Internal by default.",
            "exceptions": [
                {
                    "id": "sample",
                    "fact": "x",
                    "basis": "law requires it",
                    "allowed_surface": "signed DPA annex",
                    "prohibited_surfaces": ["website"],
                }
            ],
        }
        import json as _json

        manifest_path = root / "exceptions.json"
        manifest_path.write_text(_json.dumps(good_manifest))
        assert not check_exceptions_manifest(manifest_path), "clean manifest must pass"
        for mutate, expected in [
            (lambda m: m.update(version=2), "version"),
            (lambda m: m.update(exceptions=[]), "at least one"),
            (
                lambda m: m["exceptions"][0].pop("allowed_surface"),
                "allowed_surface",
            ),
            (
                lambda m: m["exceptions"][0].update(prohibited_surfaces=[]),
                "enumerate prohibited",
            ),
            (
                lambda m: m["exceptions"][0].update(fact="runs on Hetzner"),
                "provider name",
            ),
        ]:
            broken = _json.loads(_json.dumps(good_manifest))
            mutate(broken)
            manifest_path.write_text(_json.dumps(broken))
            problems = check_exceptions_manifest(manifest_path)
            assert any(expected in p for p in problems), (expected, problems)
        manifest_path.unlink()

    self_test_hosting_locations()

    print("public-artifacts self-test: ok (allowlist + spec boundary + hosting-location boundary)")
    return 0


def static_root_for(_hint: Path) -> Path:
    """Indirection so the self-test can point run_checks at a temp dir."""
    return _hint


def main(argv: list[str]) -> int:
    if "--hosting-locations-self-test" in argv:
        self_test_hosting_locations()
        print("public-artifacts hosting-location self-test: ok")
        return 0
    if "--hosting-locations" in argv:
        problems = check_public_hosting_locations()
        if problems:
            for problem in problems:
                print(f"public-hosting-locations: {problem}", file=sys.stderr)
            return 1
        print("public-hosting-locations: OK (no hosting location on any public surface)")
        return 0
    if "--self-test" in argv:
        return self_test()
    problems = run_checks()
    if problems:
        for problem in problems:
            print(f"public-artifacts: {problem}", file=sys.stderr)
        return 1
    print(
        "public-artifacts: OK (static allowlist + public OpenAPI boundary + "
        "hosting-location boundary)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
