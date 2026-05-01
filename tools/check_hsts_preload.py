#!/usr/bin/env python3
"""Validate that a public HTTPS endpoint is HSTS-preload ready."""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

MIN_MAX_AGE = 31_536_000


def parse_directives(header: str) -> dict[str, str | None]:
    directives: dict[str, str | None] = {}
    for part in header.split(";"):
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            directives[key.strip().lower()] = value.strip()
        else:
            directives[item.lower()] = None
    return directives


def validate_header(header: str) -> list[str]:
    directives = parse_directives(header)
    errors: list[str] = []

    try:
        max_age = int(directives.get("max-age") or "0")
    except ValueError:
        max_age = 0
    if max_age < MIN_MAX_AGE:
        errors.append(f"max-age must be at least {MIN_MAX_AGE}")
    if "includesubdomains" not in directives:
        errors.append("includeSubDomains directive is required")
    if "preload" not in directives:
        errors.append("preload directive is required")
    return errors


def fetch_header(url: str, timeout: int) -> str | None:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "apexmail-hsts-preload-check/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.headers.get("Strict-Transport-Security")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="HTTPS URL to validate")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    if not args.url.startswith("https://"):
        print("URL must use https://", file=sys.stderr)
        return 2

    try:
        header = fetch_header(args.url, args.timeout)
    except urllib.error.URLError as error:
        print(f"failed to fetch {args.url}: {error}", file=sys.stderr)
        return 2

    if not header:
        print("Strict-Transport-Security header is missing", file=sys.stderr)
        return 1

    errors = validate_header(header)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"HSTS preload header is valid: {header}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
