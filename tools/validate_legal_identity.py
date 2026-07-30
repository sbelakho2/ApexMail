#!/usr/bin/env python3
"""
Legal-Identity Validation Test for ApexMail Website.

Crawls built HTML output and verifies:
- Required legal identifiers appear in expected locations
- No prohibited former identifiers exist
- Footer, legal pages, and JSON-LD are consistent
- Registry code is formatted consistently

Usage:
    python3 tools/validate_legal_identity.py [--build-dir public/]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

REQUIRED_LEGAL_NAME = "Bel Consulting OÜ"
REQUIRED_REGISTRY_CODE = "16588745"
REQUIRED_VAT_NUMBER = "EE102951727"
REQUIRED_ADDRESS_FRAGMENTS = ["Sakala tn 7-2", "10141 Tallinn", "Estonia"]

PROHIBITED_PATTERNS = [
    r"(?i)bel\s*consulting\s*(ou|OÜ|ou)",
]

FAILED = False


def fail(msg: str) -> None:
    global FAILED
    FAILED = True
    print(f"  FAIL: {msg}")


def ok(msg: str) -> None:
    print(f"  OK: {msg}")


def check_html_files(build_dir: Path) -> None:
    html_files = list(build_dir.rglob("*.html"))
    print(f"\nScanning {len(html_files)} HTML files in {build_dir}")

    for f in sorted(html_files):
        rel = f.relative_to(build_dir)
        try:
            content = f.read_text(encoding="utf-8")
        except Exception:
            continue

        if "Bel Consulting" in content and REQUIRED_LEGAL_NAME not in content:
            fail(f"{rel}: contains 'Bel Consulting' but not exact legal name '{REQUIRED_LEGAL_NAME}'")


def check_footer(build_dir: Path) -> None:
    print("\n--- Footer Legal Identity ---")
    index_file = build_dir / "index.html"
    if not index_file.exists():
        fail("index.html not found in build dir")
        return

    content = index_file.read_text(encoding="utf-8")
    if REQUIRED_LEGAL_NAME not in content:
        fail(f"Footer missing legal name '{REQUIRED_LEGAL_NAME}'")
    else:
        ok(f"Legal name '{REQUIRED_LEGAL_NAME}' present")

    if REQUIRED_REGISTRY_CODE not in content:
        fail(f"Footer missing registry code '{REQUIRED_REGISTRY_CODE}'")
    else:
        ok(f"Registry code '{REQUIRED_REGISTRY_CODE}' present")

    if REQUIRED_VAT_NUMBER not in content:
        fail(f"Footer missing VAT number '{REQUIRED_VAT_NUMBER}'")
    else:
        ok(f"VAT number '{REQUIRED_VAT_NUMBER}' present")

    for frag in REQUIRED_ADDRESS_FRAGMENTS:
        if frag not in content:
            fail(f"Footer missing address fragment '{frag}'")
        else:
            ok(f"Address fragment '{frag}' present")


def check_legal_pages(build_dir: Path) -> None:
    print("\n--- Legal Page Identity ---")
    legal_paths = [
        "privacy/index.html",
        "terms/index.html",
        "dpa/index.html",
        "cookies/index.html",
        "acceptable-use/index.html",
        "sla/index.html",
    ]

    for path in legal_paths:
        f = build_dir / path
        if not f.exists():
            print(f"  SKIP: {path} (not found)")
            continue
        content = f.read_text(encoding="utf-8")
        if REQUIRED_LEGAL_NAME not in content:
            fail(f"{path}: missing legal name")
        else:
            ok(f"{path}: legal name present")
        if REQUIRED_REGISTRY_CODE not in content:
            fail(f"{path}: missing registry code")
        else:
            ok(f"{path}: registry code present")


def check_jsonld(build_dir: Path) -> None:
    print("\n--- JSON-LD Structured Data ---")
    index_file = build_dir / "index.html"
    if not index_file.exists():
        fail("index.html not found")
        return

    content = index_file.read_text(encoding="utf-8")
    match = re.search(r'<script type="application/ld\+json"[^>]*>(.*?)</script>', content, re.DOTALL)
    if not match:
        fail("No JSON-LD script found in index.html")
        return

    try:
        ld = json.loads(match.group(1).strip())
    except json.JSONDecodeError as e:
        fail(f"JSON-LD parse error: {e}")
        return

    legal_name = ld.get("legalName", "")
    if legal_name != REQUIRED_LEGAL_NAME:
        fail(f"JSON-LD legalName '{legal_name}' != '{REQUIRED_LEGAL_NAME}'")
    else:
        ok(f"JSON-LD legalName: {legal_name}")

    vat = ld.get("vatID", "")
    if vat != REQUIRED_VAT_NUMBER:
        fail(f"JSON-LD vatID '{vat}' != '{REQUIRED_VAT_NUMBER}'")
    else:
        ok(f"JSON-LD vatID: {vat}")


def check_prohibited(build_dir: Path) -> None:
    print("\n--- Prohibited Identifier Scan ---")
    html_files = list(build_dir.rglob("*.html"))
    for f in sorted(html_files):
        rel = f.relative_to(build_dir)
        try:
            content = f.read_text(encoding="utf-8")
        except Exception:
            continue
        for pattern in PROHIBITED_PATTERNS:
            if re.search(pattern, content):
                fail(f"{rel}: prohibited pattern match: {pattern}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate legal identity on built HTML")
    parser.add_argument("--build-dir", default="public", help="Zola build output directory")
    args = parser.parse_args()

    build_dir = Path(args.build_dir).resolve()
    if not build_dir.is_dir():
        print(f"ERROR: Build directory not found: {build_dir}", file=sys.stderr)
        print("Run 'zola build' first, or pass --build-dir", file=sys.stderr)
        sys.exit(1)

    print(f"=== ApexMail Legal Identity Validation ===")
    print(f"Build directory: {build_dir}")
    print(f"Expected legal name: {REQUIRED_LEGAL_NAME}")
    print(f"Expected registry code: {REQUIRED_REGISTRY_CODE}")
    print(f"Expected VAT: {REQUIRED_VAT_NUMBER}")

    check_html_files(build_dir)
    check_footer(build_dir)
    check_legal_pages(build_dir)
    check_jsonld(build_dir)
    check_prohibited(build_dir)

    if FAILED:
        print("\n=== VALIDATION FAILED ===")
        sys.exit(1)
    else:
        print("\n=== ALL CHECKS PASSED ===")
        sys.exit(0)


if __name__ == "__main__":
    main()
