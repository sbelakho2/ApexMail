#!/usr/bin/env python3
"""Marketing serving gate — built pages, public artifacts, and asset routes.

The Zola build output (`apps/marketing-zola/public/**`) is the single source
of truth for the marketing site, but it is *served* by the api-server:

  * ui-foundation's `marketing_static_document` whitelist (explicit
    `include_str!` arms — a built page with no arm is a live 404), and
  * api-server's `marketing_assets` router for the root artifacts
    (CSS/fonts/images, robots/sitemap/manifest/icon, `/.well-known/*`,
    the PGP keys).

Both lists were hand-maintained and drifted from the build output
(dogfood 2026-10-08):

  * 63 built locale pages (/de|/es|/fr pricing, pricing/calculator,
    compare/*, solutions/*, contact/*, enterprise, inbox-placement,
    anti-spam, secure-email-for-regulated-saas) had no whitelist arm and
    404'd live;
  * `css/styles.css` shipped mode 0600 (a umask-077 tailwind build), which
    the non-root api-server (uid 10001) cannot read — `/css/styles.css`
    404'd and EVERY marketing page rendered unstyled;
  * `/.well-known/security.txt` (RFC 9116, the file's own `Canonical:`) and
    its `Encryption:` targets `/pgp-key.asc` / `/pgp-key.txt` existed in the
    build output but had no route.

This gate fails on any recurrence. It reads the real files (no hardcoded
expectations) and `--self-test` proves every arm can fail.

Usage: python3 tools/check_marketing_serving.py [--self-test] [--root DIR]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Root-artifact contract: every file the built pages or the security policy
# reference at the site root must exist, be served, and be readable by the
# non-root runtime user.
REQUIRED_ARTIFACTS = [
    "index.html",
    "manifest.json",
    "icon.svg",
    "robots.txt",
    "sitemap.xml",
    "pgp-key.asc",
    "pgp-key.txt",
    ".well-known/security.txt",
    "css/styles.css",
    "css/no-js.css",
]

# Asset paths the api-server must route explicitly (the well-known prefix is
# served by a nest, but security.txt predates its own route).
REQUIRED_ASSET_ROUTES = [
    "/.well-known/security.txt",
    "/pgp-key.asc",
    "/pgp-key.txt",
]

ARM_RE = re.compile(r'^        "(/[^"]*)" => Some\(include_str!\(', re.M)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check_built_pages_are_whitelisted(root: Path, errors: list[str]) -> int:
    router = root / "services/mail-server/crates/ui-foundation/src/axum_router.rs"
    source = read(router)
    arms = {m.group(1) for m in ARM_RE.finditer(source)}
    if not arms:
        errors.append(f"{router}: no whitelist arms found — did the include style change?")
        return 0

    public = root / "apps/marketing-zola/public"
    pages: list[str] = []
    for index in sorted(public.rglob("index.html")):
        rel = index.parent.relative_to(public)
        pages.append("/" if str(rel) == "." else f"/{rel}")
    if len(pages) < 100:
        errors.append(
            f"{public}: expected 100+ built pages (is the site built?), found {len(pages)}"
        )
        return len(pages)

    for page in pages:
        if page not in arms:
            errors.append(
                f"built page {page} has no marketing_static_document arm — it will 404 live"
            )
    return len(pages)


def check_artifacts_readable(root: Path, errors: list[str]) -> None:
    public = root / "apps/marketing-zola/public"
    for rel in REQUIRED_ARTIFACTS:
        path = public / rel
        if not path.is_file():
            errors.append(f"required marketing artifact missing: {path}")
            continue
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH) == 0:
            errors.append(
                f"{path} is mode {stat.S_IMODE(mode):03o}: the api-server image runs as "
                f"uid 10001 and cannot read it — the live /{rel} 404s"
            )


def check_asset_routes(root: Path, errors: list[str]) -> None:
    app = root / "services/mail-server/crates/api-server/src/app.rs"
    source = read(app)
    for route in REQUIRED_ASSET_ROUTES:
        # Must be an actual route registration, not merely the path string
        # appearing in a cache-tier matcher or a test list.
        if not re.search(r"route_service\(\s*\"" + re.escape(route) + r"\"", source):
            errors.append(f"api-server markets asset router does not route {route}")
    dockerfile = root / "services/mail-server/Dockerfile"
    if "chmod -R a+rX /app/apps/marketing-zola/public" not in read(dockerfile):
        errors.append(
            f"{dockerfile}: image build must normalize the static export's read bits "
            "(a umask-077 build otherwise ships a root-only stylesheet)"
        )


def check_consent_policy_link_is_localized(root: Path, errors: list[str]) -> None:
    partial = root / "apps/marketing-zola/templates/partials/cookie-consent.html"
    source = read(partial)
    if not re.search(r'href="\{\{ lp \}\}', source):
        errors.append(
            f"{partial}: cookie-policy link must be locale-prefixed with {{{{ lp }}}} "
            "(the de/fr/es banner otherwise links the English /cookies/)"
        )


# Versioned asset references in built HTML: Zola's get_url(cachebust=true)
# emits `?h=<hash>` on the stylesheet/font URLs. The observed serving defect
# (2026-10-08 review §1) was a versioned stylesheet URL 404ing while the bare
# path returned 200 — i.e. the versioned form every page actually requests
# resolved to nothing. This check resolves every referenced asset path
# (query stripped, as a server must) against the built export.
VERSIONED_ASSET_RE = re.compile(
    r'(?:href|src)="([^"?#]+\.(?:css|woff2|ttf|png|svg|js)(?![a-zA-Z0-9]))(?:\?h=([0-9a-f]+))?"'
)


def check_versioned_asset_references(root: Path, errors: list[str]) -> int:
    public = root / "apps/marketing-zola/public"
    versioned = 0
    bare = 0
    missing: set[str] = set()
    pages = sorted(public.rglob("index.html"))
    for index in pages:
        text = read(index)
        for match in VERSIONED_ASSET_RE.finditer(text):
            path, digest = match.group(1), match.group(2)
            if path.startswith("http://") or path.startswith("https://"):
                path = urlsplit(path).path
            if digest:
                versioned += 1
            else:
                bare += 1
            if path.startswith("//"):
                continue
            target = public / path.lstrip("/")
            if not target.is_file():
                missing.add(path)
    if missing:
        errors.append(
            "built pages reference asset paths with no file in the export "
            f"(versioned URLs would 404, as observed 2026-10-08): {sorted(missing)[:5]}"
        )
    if versioned == 0:
        errors.append(
            f"{public}: no cachebusted (?h=) asset URLs found in {len(pages)} built pages — "
            "did get_url(cachebust=true) get dropped from base.html?"
        )
    return versioned


def check_asset_router_is_query_agnostic(root: Path, errors: list[str]) -> None:
    """The api-server's asset router must match on the PATH, never on the
    versioned query string: a route registered with `?h=` in it 404s every
    real request (query strings are not part of the route path)."""
    app = root / "services/mail-server/crates/api-server/src/app.rs"
    source = read(app)
    block = source.split("let marketing_assets", 1)
    if len(block) < 2:
        errors.append(f"{app}: marketing_assets router not found")
        return
    block = block[1].split("let public", 1)[0]
    if 'nest_service("/css", ServeDir::new(' not in block:
        errors.append(f"{app}: /css must be served via ServeDir (path-based, query-agnostic)")
    if '?h=' in block or "?v=" in block:
        errors.append(
            f"{app}: asset route registration contains a cache-bust query string — "
            "routes match paths only, so the versioned URL would 404"
        )


# Root-relative asset references in built HTML (quoted or zola-minified
# unquoted, absolute or relative). Every one of these must resolve on the
# api-server path, not only inside the static export: /giallo.css and
# /specs/openapi.yaml were referenced by built pages but had no route.
REFERENCED_ASSET_RE = re.compile(
    r'(?:href|src)="?((?:https?://[^"/]+)?/[^"\'\s>?#]+?\.'
    r'(?:css|js|png|jpg|jpeg|gif|ico|svg|webp|woff2?|ttf|otf|xml|yaml|yml|json|txt|asc)'
    r'(?![a-zA-Z0-9]))'
    r'(?:\?[^"\'\s>]*)?"?'
)
ROUTE_RE = re.compile(r'route_service\(\s*"([^"]+)"')
NEST_RE = re.compile(r'nest_service\(\s*"([^"]+)"')


def check_referenced_root_assets_are_routed(root: Path, errors: list[str]) -> int:
    app = root / "services/mail-server/crates/api-server/src/app.rs"
    source = read(app)
    routes = set(ROUTE_RE.findall(source))
    nests = set(NEST_RE.findall(source))
    public = root / "apps/marketing-zola/public"
    referenced: dict[str, int] = {}
    for index in public.rglob("index.html"):
        for match in REFERENCED_ASSET_RE.finditer(read(index)):
            path = urlsplit(match.group(1)).path
            referenced[path] = referenced.get(path, 0) + 1
    unrouted = []
    for path in sorted(referenced):
        if path in routes:
            continue
        parent = path.rsplit("/", 1)[0]
        if any(parent == nest or parent.startswith(nest.rstrip("/") + "/") for nest in nests):
            continue
        unrouted.append(path)
    if unrouted:
        errors.append(
            "root-relative assets referenced by built pages have no api-server route "
            f"(they 404 on the marketing host): {unrouted[:6]}"
        )
    return len(referenced)


def check_pricing_display_strings(root: Path, errors: list[str]) -> None:
    """data/pricing.json is the commercial UI authority: its display strings
    must be derived from its numeric fields, and annual pricing must mean ten
    monthly payments (~16.7% saving), never a 10% discount."""
    data_path = root / "apps/marketing-zola/data/pricing.json"
    try:
        data: dict[str, Any] = json.loads(read(data_path))
    except json.JSONDecodeError as error:
        errors.append(f"{data_path}: invalid JSON ({error})")
        return
    for plan in data.get("plans", []):
        plan_id = plan.get("id", "?")
        monthly = plan.get("monthly_price")
        volume = plan.get("included_volume")
        if isinstance(monthly, (int, float)):
            expected = f"€{monthly:,}"
            if plan.get("monthly_price_display") != expected:
                errors.append(
                    f"{data_path}: {plan_id}.monthly_price_display {plan.get('monthly_price_display')!r} "
                    f"!= derived {expected!r}"
                )
        if isinstance(volume, int) and volume >= 0:
            expected_volume = f"{volume:,}"
            if plan.get("included_volume_display") != expected_volume:
                errors.append(
                    f"{data_path}: {plan_id}.included_volume_display {plan.get('included_volume_display')!r} "
                    f"!= derived {expected_volume!r}"
                )
        if "retention_days" not in plan:
            errors.append(f"{data_path}: {plan_id} has no retention_days (plan retention is a public claim)")
        annual_month = plan.get("annual_price_per_month")
        if isinstance(monthly, (int, float)) and isinstance(annual_month, (int, float)):
            months = data.get("annual_billing_months", 10)
            expected_annual = monthly * months / 12
            if abs(annual_month - expected_annual) > 0.01:
                errors.append(
                    f"{data_path}: {plan_id}.annual_price_per_month {annual_month} != "
                    f"monthly*{months}/12 ({expected_annual:.4f})"
                )
    allowance = data.get("free_launch_allowance", {})
    if allowance.get("emails_display") != f"{allowance.get('emails'):,}":
        errors.append(f"{data_path}: free_launch_allowance.emails_display must match emails")
    if not allowance.get("window_days"):
        errors.append(f"{data_path}: free_launch_allowance must state its one-time window")
    if data.get("annual_billing_months") != 10:
        errors.append(f"{data_path}: annual_billing_months must be 10 (ten monthly payments ⇒ ≈16.7% saving)")


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    pages = check_built_pages_are_whitelisted(root, errors)
    check_artifacts_readable(root, errors)
    check_asset_routes(root, errors)
    check_consent_policy_link_is_localized(root, errors)
    check_versioned_asset_references(root, errors)
    check_asset_router_is_query_agnostic(root, errors)
    check_referenced_root_assets_are_routed(root, errors)
    check_pricing_display_strings(root, errors)
    print(f"checked {pages} built pages under {root}")
    return errors


def self_test(root: Path) -> int:
    """Prove every check can fail: mutate copies and assert the mutation is caught."""
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)

        def clone() -> Path:
            dst = tmp_root / "root"
            if dst.exists():
                shutil.rmtree(dst)
            dst.mkdir(parents=True)
            for rel in [
                "services/mail-server/crates/ui-foundation/src",
                "services/mail-server/crates/api-server/src",
                "services/mail-server/Dockerfile",
                "apps/marketing-zola/templates/partials",
                "apps/marketing-zola/data",
                "apps/marketing-zola/public",
            ]:
                src = root / rel
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if src.is_dir():
                    shutil.copytree(src, target, symlinks=True)
                else:
                    shutil.copy2(src, target)
            return dst

        # Baseline: the real tree must pass.
        base_errors = run_checks(clone())
        if base_errors:
            print("self-test baseline unexpectedly failed:", base_errors, file=sys.stderr)
            failures += 1

        # 1. A built page with no whitelist arm is caught.
        mutant = clone()
        router = mutant / "services/mail-server/crates/ui-foundation/src/axum_router.rs"
        src = read(router)
        src = src.replace(
            '        "/de/pricing" => Some(include_str!(concat!(\n'
            '            env!("APX_MARKETING_PUBLIC_DIR"),\n'
            '            "/de/pricing/index.html"\n'
            '        ),)),\n',
            "",
        )
        router.write_text(src)
        errs = run_checks(mutant)
        if not any("/de/pricing has no marketing_static_document arm" in e for e in errs):
            print("self-test: un-whitelisted page NOT caught", errs, file=sys.stderr)
            failures += 1

        # 2. A non-world-readable artifact is caught.
        mutant = clone()
        css = mutant / "apps/marketing-zola/public/css/styles.css"
        css.chmod(0o600)
        errs = run_checks(mutant)
        if not any("css/styles.css is mode 600" in e for e in errs):
            print("self-test: 0600 stylesheet NOT caught", errs, file=sys.stderr)
            failures += 1

        # 3. A missing asset route is caught.
        mutant = clone()
        app = mutant / "services/mail-server/crates/api-server/src/app.rs"
        src = read(app).replace('"/.well-known/security.txt"', '"/.well-known/security-DISABLED.txt"', 1)
        app.write_text(src)
        errs = run_checks(mutant)
        if not any("does not route /.well-known/security.txt" in e for e in errs):
            print("self-test: unrouted security.txt NOT caught", errs, file=sys.stderr)
            failures += 1

        # 4. A locale-less consent policy link is caught.
        mutant = clone()
        partial = mutant / "apps/marketing-zola/templates/partials/cookie-consent.html"
        src = read(partial).replace('href="{{ lp }}{{ config.extra.cookie_consent_policy_path',
                                    'href="{{ config.extra.cookie_consent_policy_path')
        partial.write_text(src)
        errs = run_checks(mutant)
        if not any("must be locale-prefixed" in e for e in errs):
            print("self-test: locale-less consent link NOT caught", errs, file=sys.stderr)
            failures += 1

        # 5. A versioned asset URL whose file is missing is caught (the
        #    2026-10-08 review §1 serving defect: versioned 404, bare 200).
        mutant = clone()
        (mutant / "apps/marketing-zola/public/css/styles.css").rename(
            mutant / "apps/marketing-zola/public/css/styles-MOVED.css"
        )
        errs = run_checks(mutant)
        if not any("versioned URLs would 404" in e for e in errs):
            print("self-test: unresolvable versioned asset NOT caught", errs, file=sys.stderr)
            failures += 1

        # 6. An asset route registered with a cachebust query string is caught.
        mutant = clone()
        app = mutant / "services/mail-server/crates/api-server/src/app.rs"
        src = read(app).replace(
            '.nest_service("/css", ServeDir::new(format!("{marketing_public}/css")))',
            '.route_service("/css/styles.css?h=deadbeef", ServeFile::new(format!("{marketing_public}/css/styles.css")))',
            1,
        )
        app.write_text(src)
        errs = run_checks(mutant)
        if not any("must be served via ServeDir" in e for e in errs):
            print("self-test: query-string asset route NOT caught", errs, file=sys.stderr)
            failures += 1

        # 7. A pricing display string that contradicts its numeric field is caught.
        mutant = clone()
        pricing = mutant / "apps/marketing-zola/data/pricing.json"
        src = read(pricing).replace('"included_volume_display": "3,000"', '"included_volume_display": "30,000"', 1)
        pricing.write_text(src)
        errs = run_checks(mutant)
        if not any("!= derived" in e for e in errs):
            print("self-test: contradicted pricing display NOT caught", errs, file=sys.stderr)
            failures += 1

        # 8. A 10%-discount-style annual number is caught.
        mutant = clone()
        pricing = mutant / "apps/marketing-zola/data/pricing.json"
        src = read(pricing).replace('"annual_price_per_month": 24.1666666667',
                                    '"annual_price_per_month": 26.1', 1)
        pricing.write_text(src)
        errs = run_checks(mutant)
        if not any("annual_price_per_month" in e for e in errs):
            print("self-test: wrong annual price NOT caught", errs, file=sys.stderr)
            failures += 1

        # 9. A referenced root asset with no handler route is caught (the
        #    /giallo.css + /specs/openapi.yaml 404s).
        mutant = clone()
        app = mutant / "services/mail-server/crates/api-server/src/app.rs"
        src = read(app)
        src = re.sub(
            r'\s*\.route_service\(\s*"/giallo\.css",\s*ServeFile::new\([^)]*\)\,?\s*\)',
            "",
            src,
        )
        app.write_text(src)
        errs = run_checks(mutant)
        if not any("/giallo.css" in e and "no api-server route" in e for e in errs):
            print("self-test: unrouted referenced asset NOT caught", errs, file=sys.stderr)
            failures += 1

    if failures:
        print(f"SELF-TEST FAILED: {failures} check(s) cannot fail", file=sys.stderr)
        return 1
    print("self-test: all nine checks can fail (mutants caught)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()
    root = Path(args.root)

    if args.self_test:
        return self_test(root)

    errors = run_checks(root)
    if errors:
        print("marketing serving gate FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("marketing serving gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
