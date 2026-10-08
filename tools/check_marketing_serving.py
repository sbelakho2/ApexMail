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
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

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


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    pages = check_built_pages_are_whitelisted(root, errors)
    check_artifacts_readable(root, errors)
    check_asset_routes(root, errors)
    check_consent_policy_link_is_localized(root, errors)
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

    if failures:
        print(f"SELF-TEST FAILED: {failures} check(s) cannot fail", file=sys.stderr)
        return 1
    print("self-test: all four checks can fail (mutants caught)")
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
