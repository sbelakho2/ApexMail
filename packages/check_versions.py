#!/usr/bin/env python3
"""Check that every SDK's version constant equals its CHANGELOG's latest entry.

Audit SM15 F4 follow-up: the five first-party SDKs once shipped changelogs
advertising a release their code constants never carried (and vice versa),
which made User-Agents unreliable for support. packages/README.md states the
invariant ("Each SDK's version constant ... must equal the head entry of its
CHANGELOG.md"); this script enforces it mechanically so CI can gate on it.

"Head entry" = the highest semver release heading in the CHANGELOG (the
files are not consistently ordered newest-first, so the maximum is the only
order-independent definition).

Usage: python3 packages/check_versions.py

Exits 0 when all five SDKs are consistent, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXPECT_LOCKSTEP = True  # all five SDKs must carry the same version

SEMVER = r"\d+\.\d+\.\d+"


def changelog_latest(path: Path) -> str | None:
    """Highest `## [x.y.z]` release heading in a changelog."""
    heads = re.findall(rf"^## \[({SEMVER})\]", path.read_text(), re.MULTILINE)
    if not heads:
        return None
    def key(v: str) -> tuple[int, int, int]:
        a, b, c = (int(p) for p in v.split("."))
        return (a, b, c)
    return max(heads, key=key)


def first_match(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text, re.MULTILINE)
    return m.group(1) if m else None


def check() -> list[str]:
    errors: list[str] = []
    versions: dict[str, str] = {}

    def probe(sdk: str, label: str, value: str | None) -> str | None:
        if value is None:
            errors.append(f"{sdk}: cannot locate {label}")
            return None
        return value

    go = ROOT / "sdk-go"
    py = ROOT / "sdk-python"
    rb = ROOT / "sdk-ruby"
    jv = ROOT / "sdk-java"
    php = ROOT / "sdk-php"

    # go
    vals = [
        probe("go", "sdkVersion constant",
              first_match((go / "apexmail.go").read_text(), r'sdkVersion\s*=\s*"([^"]+)"')),
        changelog_latest(go / "CHANGELOG.md") or probe("go", "changelog release heading", None),
    ]
    # python
    vals += [
        probe("python", "pyproject version",
              first_match((py / "pyproject.toml").read_text(), r'^version\s*=\s*"([^"]+)"')),
        probe("python", "__version__",
              first_match((py / "src/apexmail/__init__.py").read_text(), r'^__version__\s*=\s*"([^"]+)"')),
        probe("python", "User-Agent constant",
              first_match((py / "src/apexmail/client.py").read_text(), r'"User-Agent":\s*"apexmail-python/([^"]+)"')),
        changelog_latest(py / "CHANGELOG.md") or probe("python", "changelog release heading", None),
    ]
    # ruby
    vals += [
        probe("ruby", "gemspec version",
              first_match((rb / "apexmail.gemspec").read_text(), r'spec\.version\s*=\s*"([^"]+)"')),
        probe("ruby", "SDK_VERSION constant",
              first_match((rb / "lib/apexmail.rb").read_text(), r'SDK_VERSION\s*=\s*"([^"]+)"')),
        changelog_latest(rb / "CHANGELOG.md") or probe("ruby", "changelog release heading", None),
    ]
    # java
    vals += [
        probe("java", "pom.xml project version",
              first_match((jv / "pom.xml").read_text(), r"<version>([^<]+)</version>")),
        probe("java", "SDK_VERSION constant",
              first_match((jv / "src/main/java/ee/apexmail/ApexMailClient.java").read_text(), r'SDK_VERSION\s*=\s*"([^"]+)"')),
        changelog_latest(jv / "CHANGELOG.md") or probe("java", "changelog release heading", None),
    ]
    # php
    vals += [
        probe("php", "composer.json version", json.loads((php / "composer.json").read_text()).get("version")),
        probe("php", "SDK_VERSION constant",
              first_match((php / "src/Client.php").read_text(), r"SDK_VERSION\s*=\s*'([^']+)'")),
        changelog_latest(php / "CHANGELOG.md") or probe("php", "changelog release heading", None),
    ]

    names = ["go"] * 2 + ["python"] * 5 + ["ruby"] * 3 + ["java"] * 3 + ["php"] * 3
    for sdk, value in zip(names, vals):
        if value is None:
            continue
        known = versions.setdefault(sdk, value)
        if known != value:
            errors.append(f"{sdk}: version mismatch ({known} vs {value})")
    versions = {k: v for k, v in versions.items()}

    if EXPECT_LOCKSTEP and len(set(versions.values())) > 1:
        errors.append(f"lockstep violated: per-SDK versions {versions}")

    table = (ROOT / "README.md").read_text()
    for sdk, version in versions.items():
        row = re.search(rf"\|\s*{sdk}\s*\|[^|]*\|\s*(\S+)\s*\|", table, re.IGNORECASE)
        if not row:
            errors.append(f"README.md: no version cell found for {sdk}")
        elif row.group(1) != version:
            errors.append(f"README.md: {sdk} listed at {row.group(1)} but SDK is at {version}")

    return errors


def main() -> int:
    errors = check()
    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print(f"check_versions: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("check_versions: OK (SDK version constants, changelogs and README table agree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
