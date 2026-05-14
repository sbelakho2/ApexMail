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


def main() -> int:
    errors: list[str] = []
    for relative_path, flags in REQUIRED_TRUE_FLAGS.items():
        text = (ROOT / relative_path).read_text()
        for flag in flags:
            if not re.search(rf"\b{re.escape(flag)}\s*:\s*true\b", text):
                errors.append(f"{relative_path}: default for {flag} must remain true")
    for relative_path, required_line in REQUIRED_FEATURES.items():
        text = (ROOT / relative_path).read_text()
        if required_line not in text:
            errors.append(f"{relative_path}: production security features require `{required_line}`")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("security feature flag governance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())