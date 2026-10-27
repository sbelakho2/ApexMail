#!/usr/bin/env python3
"""Customer-DTO disclosure gate (external audit 2026-10-26, exposure lane E16b).

Customer-facing API RESPONSE structs must not carry raw `serde_json::Value`
at the disclosure boundary: a future producer filling such a field can leak
transport state, source IPs, hosts or provider keys through it without any
type-level obstacle (the Events API metadata finding). Structs that also
derive `Deserialize` are REQUEST bodies (input, not a disclosure boundary —
e.g. SendMessageRequest) and are exempt. This gate scans the
customer-mounted route files — the routers mounted behind customer auth at
/v1/ in crates/api-server/src/routes (verified against app.rs: events,
message_timeline, messages, routing, tracking_domains, webhooks,
suppressions, contacts, campaigns, campaign_experiments; admin/ and cp/
surfaces are deliberately NOT scanned) — for `serde_json::Value` (and
`Option<serde_json::Value>`) fields in structs deriving `Serialize`.

Request bodies (Deserialize-only structs) are exempt: they are INPUT, not a
disclosure boundary.

Every remaining Value field must be explicitly allowlisted below with a
justification (an already-allowlisted key-set projection, a customer-authored
round-trip that no server path can poison, or a field only ever built from
known-safe literals). A finding without an allowlist entry fails; an allowlist
entry that no longer matches a finding fails (stale allowlist).

--self-test proves a leaking struct fails, an allowlisted one passes and a
Deserialize-only one passes, on fixtures in a temp dir.

Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTES_DIR = (
    REPO_ROOT / "services" / "mail-server" / "crates" / "api-server" / "src" / "routes"
)

# The scan set: customer-mounted route files (mounted at /v1/* behind the
# authenticated layer in app.rs; admin/ and web (cp) routers are excluded).
# Globs are relative to the routes directory.
SCAN_SET = (
    "events.rs",
    "message_timeline.rs",
    "messages.rs",
    "routing.rs",
    "tracking_domains.rs",
    "webhook*.rs",
    "suppression*.rs",
    "contacts*.rs",
    "campaigns*.rs",
)

# Explicitly allowed remaining Value fields, each with its justification.
# Key format: <file basename>::<Struct>::<field>.
ALLOWLIST: dict[str, str] = {
    "events.rs::EventResponse::metadata": (
        "Customer-safe projection: customer_event_metadata() filters the raw "
        "events.metadata column onto the CUSTOMER_METADATA_KEYS allowlist and "
        "classifies provider free-text through sanitize_delivery_detail; raw "
        "metadata never crosses the boundary (the original E16 finding)."
    ),
    "messages.rs::MessageDetail::to": (
        "messages.to_emails round-trips the customer's own validated send "
        "recipients (parse_send_addresses) back to the same tenant; no "
        "server- or provider-written path populates it."
    ),
    "messages.rs::MessageDetail::tags": (
        "Customer-set message tags from the send request, echoed back to the "
        "same tenant; no server-written path exists."
    ),
    "messages.rs::MessageDetail::metadata": (
        "messages.metadata is written ONLY by sanitize_customer_metadata at "
        "the customer send boundary (bounded object; server-reserved queue "
        "keys and sales-provenance keys refused with 422). Operational "
        "jsonb_set writes target email_queue.metadata, which this DTO never "
        "reads; the customer reads back exactly what they wrote."
    ),
    "webhooks.rs::WebhookResponse::events": (
        "The customer's own webhook subscription list (validated canonical "
        "event-type vocabulary) read back from the webhooks row."
    ),
    "contacts.rs::ContactResponse::tags": (
        "Canonical migration-150 shape (bounded string array, coalesced to "
        "[] on read); customer-authored tags only, validated on every write "
        "path (validate_tags)."
    ),
    "contacts.rs::ContactResponse::metadata": (
        "Customer-authored contact metadata, object-checked by "
        "validate_metadata on every write path; read back to its author."
    ),
    "campaigns.rs::CampaignResponse::variables": (
        "Customer-authored campaign template variables, stored verbatim and "
        "echoed back to the same tenant."
    ),
    "campaigns.rs::CampaignResponse::utm_params": (
        "Customer-authored UTM parameters, stored verbatim and echoed back "
        "to the same tenant."
    ),
    "campaigns.rs::CampaignResponse::settings": (
        "Customer-authored campaign settings, stored verbatim and echoed "
        "back to the same tenant."
    ),
    "campaigns.rs::CampaignResponse::ab_test": (
        "Customer-authored A/B test configuration (campaigns.ab_config), "
        "stored verbatim and echoed back to the same tenant."
    ),
}

DERIVE_RE = re.compile(r"#\[derive\(([^)]*)\)\]")
# A braced-struct field line: name + a type that may wrap the Value in any
# generic (Option<Value>, Vec<Value>, HashMap<…, Value>, …). rustfmt keeps
# struct fields on one line, so the trailing comma anchors the type.
FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<field>\w+)\s*:\s*(?P<type>.*),$"
)
QUALIFIED_VALUE_RE = re.compile(r"serde_json\s*::\s*Value")
BARE_VALUE_RE = re.compile(r"(?<![:\w])Value\b")
CFG_TEST_MOD_RE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{")


# ─── rust scanning (structural, line+brace based) ───────────────────────────


def strip_cfg_test_mods(text: str) -> str:
    """Remove `#[cfg(test)] mod name { ... }` blocks (brace-matched)."""
    out = text
    while True:
        match = CFG_TEST_MOD_RE.search(out)
        if not match:
            return out
        depth = 1
        i = match.end()
        while i < len(out) and depth:
            if out[i] == "{":
                depth += 1
            elif out[i] == "}":
                depth -= 1
            i += 1
        out = out[: match.start()] + "\n" + out[i:]


def struct_bodies(text: str):
    """Yield (name, body) for every RESPONSE struct: derives Serialize and
    not Deserialize (a Serialize+Deserialize struct is a request body)."""
    for match in DERIVE_RE.finditer(text):
        derives = match.group(1)
        if "Serialize" not in derives or "Deserialize" in derives:
            continue
        head = text[match.end() :]
        struct = re.search(r"(?:pub\s+)?struct\s+(\w+)", head)
        if not struct:
            continue
        # Skip anything that is not a braced struct (tuple/unit structs have
        # no fields to leak; the scan set uses braced structs throughout).
        open_brace = head.find("{")
        semicolon = head.find(";")
        if open_brace == -1 or (semicolon != -1 and semicolon < open_brace):
            continue
        depth = 1
        i = open_brace + 1
        while i < len(head) and depth:
            if head[i] == "{":
                depth += 1
            elif head[i] == "}":
                depth -= 1
            i += 1
        yield struct.group(1), head[open_brace + 1 : i - 1]


def value_fields(path: Path) -> list[tuple[str, str]]:
    """(struct, field) pairs of raw Value fields in Serialize structs."""
    text = strip_cfg_test_mods(path.read_text(encoding="utf-8", errors="replace"))
    imports_bare_value = bool(
        re.search(r"^use\s+serde_json\s*::\s*Value\s*;", text, re.M)
    )
    findings = []
    for name, body in struct_bodies(text):
        for line in body.splitlines():
            stripped = line.split("//")[0]  # drop line comments
            field = FIELD_RE.match(stripped.rstrip())
            if not field:
                continue
            type_text = field.group("type")
            if QUALIFIED_VALUE_RE.search(type_text):
                pass  # serde_json::Value anywhere in the type is a finding
            elif BARE_VALUE_RE.search(type_text) and imports_bare_value:
                pass  # bare `Value` imported from serde_json in this file
            else:
                continue
            findings.append((name, field.group("field")))
    return findings


def scan_files(files: list[Path]) -> dict[str, list[str]]:
    """finding key -> [reason lines]; keys are basename::Struct::field."""
    findings: dict[str, list[str]] = {}
    for path in files:
        for struct, field in value_fields(path):
            key = f"{path.name}::{struct}::{field}"
            findings.setdefault(key, []).append(str(path))
    return findings


def resolve_scan_set(root: Path = REPO_ROOT, patterns: tuple[str, ...] = SCAN_SET):
    """Expand the scan-set globs; every pattern MUST match at least one file."""
    routes = root / "services" / "mail-server" / "crates" / "api-server" / "src" / "routes"
    files: list[Path] = []
    missing = []
    for pattern in patterns:
        matched = sorted(routes.glob(pattern))
        if not matched:
            missing.append(pattern)
        files.extend(matched)
    return sorted(set(files)), missing


def run_checks(
    files: list[Path],
    allowlist: dict[str, str],
    missing_patterns: list[str] | None = None,
) -> list[str]:
    problems: list[str] = []
    for pattern in missing_patterns or []:
        problems.append(
            f"scan-set pattern {pattern!r} matched no files — the customer route "
            f"set moved; update SCAN_SET (and verify the mounts in app.rs)"
        )
    findings = scan_files(files)
    for key in sorted(findings):
        if key not in allowlist:
            paths = ", ".join(findings[key])
            problems.append(
                f"customer response struct carries raw serde_json::Value: {key} "
                f"({paths}) — project to a safe DTO / filter keys, or add an "
                f"ALLOWLIST entry with a justification"
            )
    for key in sorted(allowlist):
        if key not in findings:
            problems.append(
                f"STALE allowlist entry {key} — the field is gone; remove the entry"
            )
    return problems


# ─── self-test ──────────────────────────────────────────────────────────────

FIXTURE_LEAK = """
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LeakyResponse {
    pub id: String,
    pub metadata: Option<serde_json::Value>,
}
"""

FIXTURE_ALLOWLISTED = """
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProjectedResponse {
    pub metadata: Option<serde_json::Value>,
}
"""

FIXTURE_DESERIALIZE_ONLY = """
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakyLookingRequest {
    pub metadata: Option<serde_json::Value>,
}
"""

FIXTURE_REQUEST_BODY_BOTH = """
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SendLikeRequest {
    pub metadata: Option<serde_json::Value>,
}
"""

FIXTURE_CFG_TEST = """
#[cfg(test)]
mod tests {
    #[derive(serde::Serialize)]
    struct TestOnlyFixture {
        raw: Option<serde_json::Value>,
    }
}
"""


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        leak = root / "leak.rs"
        leak.write_text(FIXTURE_LEAK)
        projected = root / "projected.rs"
        projected.write_text(FIXTURE_ALLOWLISTED)
        request_only = root / "request.rs"
        request_only.write_text(FIXTURE_DESERIALIZE_ONLY)
        request_both = root / "request_both.rs"
        request_both.write_text(FIXTURE_REQUEST_BODY_BOTH)
        cfg_test = root / "cfgtest.rs"
        cfg_test.write_text(FIXTURE_CFG_TEST)

        # (a) a leaking response struct FAILS.
        problems = run_checks([leak], {})
        assert any("LeakyResponse::metadata" in p for p in problems), problems

        # (b) the same field PASSES once allowlisted.
        allowlist = {
            "projected.rs::ProjectedResponse::metadata": "fixture justification"
        }
        problems = run_checks([projected], allowlist)
        assert not problems, problems

        # (c) a Deserialize-only struct PASSES (input is not a boundary), as
        # does a request body that derives Serialize for internal reuse.
        problems = run_checks([request_only, request_both], {})
        assert not problems, problems

        # (d) #[cfg(test)] modules are not production surface.
        problems = run_checks([cfg_test], {})
        assert not problems, problems

        # (e) stale allowlist entries FAIL.
        problems = run_checks(
            [projected], {"gone.rs::GoneResponse::raw": "obsolete"}
        )
        assert any("STALE allowlist entry" in p for p in problems), problems

        # (f) a scan-set pattern matching nothing FAILS.
        problems = run_checks([], {}, missing_patterns=["missing*.rs"])
        assert any("matched no files" in p for p in problems), problems

    print("customer-dtos self-test: ok (leak fails, allowlisted passes, request passes)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true", help="print current findings")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    files, missing = resolve_scan_set()
    if args.list:
        for key in sorted(scan_files(files)):
            tag = "allowlisted" if key in ALLOWLIST else "UNLISTED"
            print(f"{tag}\t{key}")
        return 0
    problems = run_checks(files, ALLOWLIST, missing)
    if problems:
        for problem in problems:
            print(f"customer-dtos: {problem}", file=sys.stderr)
        return 1
    print(
        f"customer-dtos: OK ({len(files)} customer route files scanned, "
        f"{len(ALLOWLIST)} allowlisted Value fields with justifications)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
