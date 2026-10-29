#!/usr/bin/env python3
"""The payment-neutrality lint (seventh external audit P0-A, step 10).

The billing engine is processor-independent: production code speaks to the
neutral `PaymentProvider` boundary (billing-service/src/payments/) and the
ONE registered adapter. This gate scans production Rust under
services/mail-server/crates/*/src and FAILS when a file OUTSIDE the allowed
provider paths names the processor directly:

  * `MollieClient` / `MollieProvider` (the wire client and the adapter are
    payments-boundary vocabulary; everything else resolves through the
    registry);
  * `impl`/`dyn PaymentProvider` (adapter construction lives in payments/);
  * `mollie_subscriptions` / `mollie_customers` / `mollie_mandate*` SQL
    (the legacy provider-tagged tables);
  * `STRIPE_SECRET_KEY` / `stripe_subscription` / `stripe_price` (Stripe is
    owner-gated, steps 11-18);
  * direct `MOLLIE_API_KEY` env reads (the adapter owns credentials);
  * provider id prefixes (pi_/pm_/cus_/mdt_/tr_) as STRING LITERALS.

Allowed provider-touching paths: billing-service/src/payments/**,
billing-service/src/mollie_client.rs, billing-service/src/mollie_webhooks.rs
(debt N-10 records its staged retirement), plus tests (cfg(test) regions,
per-crate tests/ dirs, embedded *_tests.rs modules), migrations and docs,
which are never scanned.

Exceptions live in the ALLOWLIST below (same discipline as
tools/stub-allowlist.toml): every in-crate occurrence is pinned by the
SHA-256 of its exact line (first 16 hex chars) with a reason naming the
NEUTRALITY_DEBT.md row that retires it, so a pin cannot quietly follow
edited code around; files OUTSIDE billing-service (this round's ownership
boundary) carry whole-file grants for the same reason. Entries expire (max
180 days): an expired exception fails the gate.

Usage: check_payment_neutrality.py [--self-test]
Exit codes: 0 = neutral, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN_ROOT = REPO / "services" / "mail-server" / "crates"
MAX_DAYS = 180

ALLOWED_FILES = {
    "services/mail-server/crates/billing-service/src/mollie_client.rs",
    "services/mail-server/crates/billing-service/src/mollie_webhooks.rs",
}
ALLOWED_PREFIX = "services/mail-server/crates/billing-service/src/payments/"

# Marker regexes, each with the neutrality rule it enforces. Order is the
# report order.
MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("MollieClient", re.compile(r"\bMollieClient\b")),
    ("MollieProvider", re.compile(r"\bMollieProvider\b")),
    ("adapter-construction-outside-payments",
     re.compile(r"\b(impl|dyn)\s+(crate::payments::)?PaymentProvider\b")),
    ("mollie_subscriptions-sql", re.compile(r"\bmollie_subscriptions\b")),
    ("mollie_customers-sql", re.compile(r"\bmollie_customers\b")),
    ("mollie_mandate-sql", re.compile(r"\bmollie_mandate\w*\b")),
    ("STRIPE_SECRET_KEY", re.compile(r"\bSTRIPE_SECRET_KEY\b")),
    ("stripe_subscription", re.compile(r"\bstripe_subscription\w*")),
    ("stripe_price", re.compile(r"\bstripe_price\w*")),
    ("MOLLIE_API_KEY-direct-read",
     re.compile(r'(var|set_var|remove_var)\s*\(\s*"MOLLIE_API_KEY"')),
    ("provider-id-prefix-literal", re.compile(r'"(pi|pm|cus|mdt|tr)_')),
]

SELF = Path(__file__).resolve()


def rel(p: Path) -> str:
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        return str(p)


def is_allowed_path(relp: str) -> bool:
    return relp in ALLOWED_FILES or relp.startswith(ALLOWED_PREFIX)


def iter_files() -> list[Path]:
    """Production Rust under crates/*/src, minus allowed paths and test
    code (per-crate tests/ dirs, embedded *_tests.rs modules, cfg(test)
    regions are handled at scan time)."""
    files: list[Path] = []
    if not SCAN_ROOT.exists():
        return files
    for p in sorted(SCAN_ROOT.rglob("*.rs")):
        relp = rel(p)
        if "/target/" in relp:
            continue
        if "/tests/" in relp:
            continue
        if "/src/" not in relp:
            continue
        if p.name.endswith("_tests.rs"):
            # Embedded test module inside src (the ui-foundation migration
            # tests class): test code may name provider fixtures.
            continue
        if is_allowed_path(relp):
            continue
        files.append(p)
    return files


def line_hash(text: str) -> str:
    return hashlib.sha256(text.strip().encode()).hexdigest()[:16]


# The named, owned, expiring exceptions (see the module docstring). The
# TOML lives here (not in a second file) so the gate and its census are one
# reviewable artifact.
ALLOWLIST_TOML = """
# -- file grants (outside billing-service ownership) -----------------------
# Whole-file grants: files OUTSIDE billing-service (this round's ownership
# boundary) whose production code still names the processor. Rewriting them
# is owner-gated follow-up (NEUTRALITY_DEBT.md, step 10+); the grant keeps
# the census honest and reviewed while pinning nothing in-crate.
[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/billing_ops.rs"
reason = "admin ops tooling: wire-client calls + legacy subscription/mandate SQL; retire with N-05/N-10"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/cross_tenant.rs"
reason = "admin cross-tenant audit reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/dashboard.rs"
reason = "admin dashboard reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/growth_analytics.rs"
reason = "admin growth analytics reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/insights.rs"
reason = "admin insights reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/mollie_settlements.rs"
reason = "settlement import drives the wire client directly; retire with N-10/N-12"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/predictive_analytics.rs"
reason = "admin predictive analytics reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/revenue.rs"
reason = "admin revenue analytics reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/admin/sse.rs"
reason = "admin SSE stream reads the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/billing.rs"
reason = "checkout quoting + customer mapping on legacy tables (the N-02 price-code consumers); retire with N-02/N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/api-server/src/routes/web.rs"
reason = "console billing surface drives the wire client; retire with N-10"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/compliance/src/entitlements.rs"
reason = "entitlement reader of the legacy subscription table; retire with N-03"
expires = "2027-04-27"

[[file_grant]]
path = "services/mail-server/crates/worker-processors/src/bin/worker.rs"
reason = "MOLLIE_API_KEY config plumbing into BillingConfig; retire with N-08"
expires = "2027-04-27"

# -- line-pinned in-crate exceptions ----------------------------------------
[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 1397
marker = "mollie_subscriptions-sql"
line_hash = "1c01b495c3e1ab62"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 1417
marker = "mollie_subscriptions-sql"
line_hash = "a4bb4307edb4165a"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 1425
marker = "mollie_subscriptions-sql"
line_hash = "dbb5c540384c26ac"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 1917
marker = "mollie_mandate-sql"
line_hash = "53a59d134d5b86c7"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 2085
marker = "mollie_subscriptions-sql"
line_hash = "7985c6c07088ef47"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 2506
marker = "mollie_subscriptions-sql"
line_hash = "390c9137e68212ee"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 2592
marker = "mollie_mandate-sql"
line_hash = "991018ada394be6f"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 2594
marker = "mollie_subscriptions-sql"
line_hash = "e20c9c96919be9b2"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 2654
marker = "mollie_mandate-sql"
line_hash = "ee10c8d9cda64f9e"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 3576
marker = "mollie_mandate-sql"
line_hash = "6fff5b4fd0cfd80f"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 3724
marker = "mollie_mandate-sql"
line_hash = "07db432a2e3454be"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 3785
marker = "mollie_mandate-sql"
line_hash = "a13312b7a2023cb2"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/maintenance.rs"
line = 3814
marker = "mollie_mandate-sql"
line_hash = "88a3aedabc7a6bf6"
reason = "transitional legacy mandate/dunning SQL reads (dedicated-IP mandate read + retry-candidate scan); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 264
marker = "mollie_subscriptions-sql"
line_hash = "c43e47f398ded8ed"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2293
marker = "mollie_subscriptions-sql"
line_hash = "e33d256dc6714634"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2344
marker = "mollie_mandate-sql"
line_hash = "9b1cca98b8a2631c"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2345
marker = "mollie_subscriptions-sql"
line_hash = "ee23941aeeb49771"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2347
marker = "mollie_mandate-sql"
line_hash = "a0ce18628f29b4f3"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2348
marker = "mollie_mandate-sql"
line_hash = "8066ed5d99ec943d"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/overage.rs"
line = 2349
marker = "mollie_mandate-sql"
line_hash = "a1fd421901f229b1"
reason = "transitional legacy-mandate fallback in the neutral credential lookup; retire with NEUTRALITY-DEBT rows N-09/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 333
marker = "mollie_subscriptions-sql"
line_hash = "01de90692f85d4c5"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 427
marker = "mollie_subscriptions-sql"
line_hash = "794f6dcf5b2fd1ae"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 429
marker = "mollie_mandate-sql"
line_hash = "be0990ca6f0bf314"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 442
marker = "mollie_mandate-sql"
line_hash = "7119e5b6606738bc"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 725
marker = "mollie_subscriptions-sql"
line_hash = "d921a23f6df6d143"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 824
marker = "mollie_subscriptions-sql"
line_hash = "f7fd84573843f2f9"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 881
marker = "mollie_subscriptions-sql"
line_hash = "c66cbeb7f1a89013"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 928
marker = "mollie_subscriptions-sql"
line_hash = "e74aa0b8348f7f08"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 945
marker = "mollie_subscriptions-sql"
line_hash = "6a31da98da8798ad"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 990
marker = "mollie_subscriptions-sql"
line_hash = "0e045e69f554a000"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 1218
marker = "mollie_subscriptions-sql"
line_hash = "16894ce2dc36fd26"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/plan_billing.rs"
line = 1269
marker = "mollie_subscriptions-sql"
line_hash = "2cdd43196e8e4489"
reason = "load-bearing legacy provider-table writes (activation upsert, renewal, sweep); retire with NEUTRALITY-DEBT rows N-05/N-06"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/routes.rs"
line = 1134
marker = "mollie_subscriptions-sql"
line_hash = "0dcbade639bdad58"
reason = "legacy admin-surface SQL reads; retire with NEUTRALITY-DEBT rows N-03/N-02"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/routes.rs"
line = 1732
marker = "mollie_subscriptions-sql"
line_hash = "5af1424a23990844"
reason = "legacy admin-surface SQL reads; retire with NEUTRALITY-DEBT rows N-03/N-02"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/routes.rs"
line = 1796
marker = "mollie_subscriptions-sql"
line_hash = "9703b44d3d713894"
reason = "legacy admin-surface SQL reads; retire with NEUTRALITY-DEBT rows N-03/N-02"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/routes.rs"
line = 1820
marker = "mollie_subscriptions-sql"
line_hash = "cbf75f314185abb9"
reason = "legacy admin-surface SQL reads; retire with NEUTRALITY-DEBT rows N-03/N-02"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 48
marker = "mollie_subscriptions-sql"
line_hash = "0a15993bc12cb4b6"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 50
marker = "mollie_subscriptions-sql"
line_hash = "7155af9c0c4a8b89"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 136
marker = "mollie_customers-sql"
line_hash = "793146428528dedf"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 222
marker = "mollie_subscriptions-sql"
line_hash = "76534b58e63a66f8"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 322
marker = "mollie_mandate-sql"
line_hash = "321a22d481115264"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 326
marker = "mollie_mandate-sql"
line_hash = "bc854fc5e54b70fc"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/subscriptions.rs"
line = 327
marker = "mollie_mandate-sql"
line_hash = "d83432d2646f796f"
reason = "legacy provider-named table reads (entitlement SQL, cancel capture); retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/usage.rs"
line = 728
marker = "mollie_subscriptions-sql"
line_hash = "eaf8a25aff8249d7"
reason = "billing-period reads on the legacy provider-named table; retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

[[allow]]
path = "services/mail-server/crates/billing-service/src/usage.rs"
line = 729
marker = "mollie_subscriptions-sql"
line_hash = "a7d02c32cd8a6771"
reason = "billing-period reads on the legacy provider-named table; retire with NEUTRALITY-DEBT row N-03"
owner = "payments-neutrality"
expires = "2027-04-27"

"""


def load_allowlist() -> tuple[dict[str, dict], dict[str, dict]]:
    data = tomllib.loads(ALLOWLIST_TOML)
    allow = {str(e.get("line_hash", "")): e for e in data.get("allow", [])}
    grants = {str(e.get("path", "")): e for e in data.get("file_grant", [])}
    return allow, grants


def scan_lines(lines: list[str], relp: str, *, today, allow: dict, grants: dict) -> list[str]:
    """One file's problems. cfg(test) regions are skipped wholesale."""
    import datetime as dt

    grant = grants.get(relp)
    problems: list[str] = []
    in_test, depth = 0, 0
    for no, line in enumerate(lines, 1):
        stripped = line.strip()
        if in_test == 0 and stripped.startswith("#[cfg(test)]"):
            in_test, depth = 1, line.count("{") - line.count("}")
            continue
        if in_test:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_test = 0
            continue
        for name, rx in MARKERS:
            if not rx.search(line):
                continue
            if grant is not None:
                try:
                    expires = dt.date.fromisoformat(str(grant.get("expires", "")))
                except ValueError:
                    problems.append(f"{relp}:{no}: {name} (file grant has no valid expiry)")
                    continue
                if expires < today:
                    problems.append(
                        f"{relp}:{no}: {name} (file grant EXPIRED {expires})"
                    )
                continue
            entry = allow.get(line_hash(line))
            if entry is None:
                problems.append(
                    f"{relp}:{no}: {name} (route through payments::, or pin the line in "
                    f"this gate's ALLOWLIST with its NEUTRALITY-DEBT row)"
                )
                continue
            try:
                expires = dt.date.fromisoformat(str(entry.get("expires", "")))
            except ValueError:
                problems.append(f"{relp}:{no}: {name} (allowlist entry has no valid expiry)")
                continue
            if expires < today:
                problems.append(
                    f"{relp}:{no}: {name} (allowlist entry EXPIRED {expires}): "
                    "remove the coupling"
                )
    return problems


def scan(files: list[Path], *, today, allow: dict, grants: dict) -> list[str]:
    problems: list[str] = []
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            problems.append(f"{rel(path)}: unreadable ({exc})")
            continue
        problems.extend(scan_lines(lines, rel(path), today=today, allow=allow, grants=grants))
    return problems


def self_test(tmp: Path) -> int:
    import datetime as dt

    today = dt.date(2026, 10, 29)
    # (a) A clean neutral file passes.
    clean = tmp / "clean.rs"
    clean.write_text(
        "let provider = payments::registry::from_env()?;\n"
        "let payment = provider.charge_saved_method(request).await?;\n"
        "// a comment may mention tr_example without a string literal\n"
    )
    problems = scan([clean], today=today, allow={}, grants={})
    if problems:
        print("self-test FAIL: clean file flagged:\n" + "\n".join(problems), file=sys.stderr)
        return 1

    # (b) Every marker class is flagged.
    dirty = tmp / "dirty.rs"
    dirty.write_text(
        "let c = MollieClient::from_env()?;\n"                       # MollieClient
        "let p = MollieProvider::from_env()?;\n"                     # MollieProvider
        "impl PaymentProvider for X {}\n"                            # construction
        "SELECT 1 FROM mollie_subscriptions;\n"                       # table
        "SELECT 1 FROM mollie_customers;\n"                           # table
        "s.mollie_mandate_id\n"                                       # mandate column
        "env::var(\"STRIPE_SECRET_KEY\")\n"                          # stripe secret
        "let x = stripe_subscription_id;\n"                          # stripe sub
        "let y = stripe_price_id;\n"                                 # stripe price
        "env::var(\"MOLLIE_API_KEY\")\n"                             # direct read
        "let id = \"tr_123\";\n"                                    # prefix literal
    )
    problems = scan([dirty], today=today, allow={}, grants={})
    joined = "\n".join(problems)
    for needle in (
        "MollieClient", "MollieProvider", "adapter-construction",
        "mollie_subscriptions-sql", "mollie_customers-sql", "mollie_mandate-sql",
        "STRIPE_SECRET_KEY", "stripe_subscription", "stripe_price",
        "MOLLIE_API_KEY-direct-read", "provider-id-prefix-literal",
    ):
        if needle not in joined:
            print(f"self-test FAIL: expected {needle!r} flagged, got:\n{joined}", file=sys.stderr)
            return 1

    # (c) A line-hash pin covers the exact line and only that line.
    pinned_line = "SELECT 1 FROM mollie_subscriptions;"
    allow = {line_hash(pinned_line): {"expires": "2027-01-01", "reason": "self-test"}}
    ok = tmp / "pinned.rs"
    ok.write_text(pinned_line + "\n")
    if scan([ok], today=today, allow=allow, grants={}):
        print("self-test FAIL: pinned line still flagged", file=sys.stderr)
        return 1
    edited = tmp / "edited.rs"
    edited.write_text(pinned_line + " -- edited\n")
    if not scan([edited], today=today, allow=allow, grants={}):
        print("self-test FAIL: an edited line must re-flag (pin follows no code)", file=sys.stderr)
        return 1
    expired = {line_hash(pinned_line): {"expires": "2026-01-01", "reason": "self-test"}}
    if not scan([ok], today=today, allow=expired, grants={}):
        print("self-test FAIL: an expired pin must fail", file=sys.stderr)
        return 1

    # (d) A cfg(test) region and a file grant behave as documented.
    testy = tmp / "testy.rs"
    testy.write_text("#[cfg(test)]\nmod tests {\n    let id = \"tr_x\";\n}\n")
    if scan([testy], today=today, allow={}, grants={}):
        print("self-test FAIL: cfg(test) regions are test code, never flagged", file=sys.stderr)
        return 1
    granted = tmp / "x.rs"
    granted.write_text("let c = MollieClient::from_env()?;\n")
    grants = {str(granted): {"expires": "2027-01-01"}}
    if scan([granted], today=today, allow={}, grants=grants):
        print("self-test FAIL: a live file grant covers its file", file=sys.stderr)
        return 1
    stale_grants = {str(granted): {"expires": "2026-01-01"}}
    if not scan([granted], today=today, allow={}, grants=stale_grants):
        print("self-test FAIL: an expired file grant must fail", file=sys.stderr)
        return 1

    print("self-test: ok (clean passes; all 11 markers flag; pins are exact and expiring)")
    return 0


def main(argv: list[str]) -> int:
    import datetime as dt

    if "--self-test" in argv:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            return self_test(Path(tmp))
    allow, grants = load_allowlist()
    problems = scan(iter_files(), today=dt.date.today(), allow=allow, grants=grants)
    if problems:
        print(
            f"PAYMENT NEUTRALITY FAILED: {len(problems)} provider coupling(s) outside the "
            "payments boundary:",
            file=sys.stderr,
        )
        for p in problems[:60]:
            print(f"  - {p}", file=sys.stderr)
        if len(problems) > 60:
            print(f"  … and {len(problems) - 60} more", file=sys.stderr)
        print(
            "route the code through payments:: (registry/engine), or pin the exact line in "
            "this gate's ALLOWLIST with its NEUTRALITY-DEBT.md row.",
            file=sys.stderr,
        )
        return 1
    print("payment neutrality: clean (no provider coupling outside the allowed paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
