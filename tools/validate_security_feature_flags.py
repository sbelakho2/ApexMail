#!/usr/bin/env python3
"""Validate production security feature gates stay enabled by default."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_TRUE_FLAGS = {
    "services/mail-server/crates/waf-engine/src/config.rs": [
        "enable_sqli",
        "enable_xss",
        "enable_path_traversal",
        "enable_command_injection",
        "enable_protocol_checks",
        "enable_nosqli",
        "enable_ssrf",
        "enable_smuggling",
        "enable_unicode_normalization",
    ],
    "services/mail-server/crates/spam-filter/src/config.rs": [
        "enable_bayesian",
        "enable_header_analysis",
        "enable_url_analysis",
        "enable_content_scoring",
    ],
    "services/mail-server/crates/ids-engine/src/config.rs": [
        "enable_smtp_validation",
        "enable_dns_validation",
        "enable_tls_validation",
    ],
    "services/mail-server/crates/ddos-protection/src/config.rs": [
        "enable_per_ip_adaptive",
        "enable_behavioral",
    ],
}

REQUIRED_FEATURES = {
    "services/mail-server/crates/dlp-engine/Cargo.toml": 'default = ["events"]',
    "services/mail-server/crates/spam-filter/Cargo.toml": 'default = ["full"]',
}


def collect_errors(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for relative_path, flags in REQUIRED_TRUE_FLAGS.items():
        text = (root / relative_path).read_text()
        for flag in flags:
            if not re.search(rf"\b{re.escape(flag)}\s*:\s*true\b", text):
                errors.append(f"{relative_path}: default for {flag} must remain true")
    for relative_path, required_line in REQUIRED_FEATURES.items():
        text = (root / relative_path).read_text()
        if required_line not in text:
            errors.append(f"{relative_path}: production security features require `{required_line}`")
    return errors


def run(root: Path = ROOT) -> int:
    errors = collect_errors(root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("security feature flag governance check passed")
    return 0


def self_test() -> int:
    """Drift-injection proof: every required default flipped/dropped is caught."""
    import tempfile

    def miss(detail: str) -> int:
        print(f"self-test FAIL: {detail}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for rel, flags in REQUIRED_TRUE_FLAGS.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("pub struct Config {\n"
                         + "".join(f"    pub {flag}: true,\n" for flag in flags)
                         + "}\n")
        for rel, required_line in REQUIRED_FEATURES.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"[features]\nevents = []\nfull = []\n{required_line}\n")
        if collect_errors(root):
            return miss(f"clean fixture must pass: {collect_errors(root)}")

        target = next(iter(REQUIRED_TRUE_FLAGS))
        flag = REQUIRED_TRUE_FLAGS[target][0]
        cfg = root / target
        good = cfg.read_text()
        cfg.write_text(good.replace(f"pub {flag}: true", f"pub {flag}: false"))
        if not any(f"default for {flag} must remain true" in e for e in collect_errors(root)):
            return miss("flipped-to-false defect not reported")
        cfg.write_text(good.replace(f"    pub {flag}: true,\n", ""))
        if not any(flag in e for e in collect_errors(root)):
            return miss("removed-flag defect not reported")
        cfg.write_text(good)

        rel = next(iter(REQUIRED_FEATURES))
        manifest = root / rel
        keep = manifest.read_text()
        manifest.write_text("[features]\nevents = []\nfull = []\n")
        if not any(REQUIRED_FEATURES[rel] in e for e in collect_errors(root)):
            return miss("dropped cargo default features not reported")
        manifest.write_text(keep)
    print("self-test: ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())