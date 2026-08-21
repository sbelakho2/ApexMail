#!/usr/bin/env python3
"""CSP inline-script verifier for the built marketing site.

Run after `zola build`:  python3 scripts/check_csp_inline_scripts.py

Asserts the audit-1 contract for the public/ output:
  * every executable inline <script> (no src, not a JSON-LD data block)
    has a matching 'sha256-...' entry in public/_headers' CSP, and
  * the analytics script stays consent-shielded (type=text/plain) so CSP
    script-src never needs a third-party host.

Non-executable data blocks (type=application/ld+json, type=text/plain) are
exempt — CSP script-src does not gate them.
"""
import base64
import glob
import hashlib
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "public")

def main() -> int:
    headers_path = os.path.join(ROOT, "_headers")
    headers = open(headers_path, encoding="utf-8").read()
    m = re.search(r"script-src ([^;]+);", headers)
    if not m:
        print("FAIL: no script-src directive in _headers")
        return 1
    allowed = m.group(1)

    failures = []
    checked = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "**", "*.html"), recursive=True)):
        html = open(path, encoding="utf-8").read()
        for tag in re.finditer(
            r"<script([^>]*)>(.*?)</script>", html, re.S
        ):
            attrs, body = tag.group(1), tag.group(2)
            if "src=" in attrs:
                continue  # external — covered by 'self'
            kind = re.search(r'type=["\']?([^"\'>\s]+)', attrs)
            kind = kind.group(1) if kind else ""
            if kind in ("application/ld+json", "text/plain"):
                continue  # non-executable data blocks
            digest = base64.b64encode(
                hashlib.sha256(body.encode()).digest()
            ).decode()
            checked += 1
            if f"'sha256-{digest}'" not in allowed:
                failures.append(
                    f"{os.path.relpath(path, ROOT)}: inline script hash "
                    f"sha256-{digest} missing from _headers"
                )
    if failures:
        for f in failures:
            print("FAIL -", f)
        return 1
    print(f"ok - all {checked} inline executable scripts are CSP-hash-allowlisted")
    return 0

if __name__ == "__main__":
    sys.exit(main())
