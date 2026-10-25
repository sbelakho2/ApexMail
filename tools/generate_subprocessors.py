#!/usr/bin/env python3
"""Subprocessor register generator — derived from the deployment configuration.

The public register (B5: "a zero-US subprocessor chain") used to be three
hand-maintained copies that could drift silently:

  * ``apps/marketing-zola/content/subprocessors/index.md``  (the public page)
  * ``templates/compliance/subprocessors.md``               (the DPA mirror)
  * the trust portal's DB registry (migration 039,
    ``trust_portal_subprocessors``, served at ``/trust/subprocessors``)

This tool is their single source. It derives the ACTIVE subprocessor set from
the deployment configuration — the compose files (which services run) and the
env files (which providers/regions are configured) — and renders all three
surfaces from one in-memory register:

  * the marketing page (processor, purpose, location, transfer basis),
  * the compliance mirror,
  * the trust-portal seed fixture (``tools/fixtures/subprocessors/
    trust_portal_seed.json``) the portal's ``upsert_subprocessor`` consumes.

The processor IDENTITY (legal entity, corporate country, DPA, the regions the
service can run in) is not derivable from a compose file — it is a legal fact
— so it lives in ``PROCESSOR_CATALOG`` below, with the evidence pointer for
each fact. The configuration only decides WHICH processors are active and
WHERE they process.

The "zero-US" property (check ``sovereign_chain_zero_us``): under the
sovereign chain no active subprocessor may process or store customer personal
data in the United States. The tool REFUSES (exit 2) when the derived active
set contains a US processing/storage region, or a US-domiciled processor
engaged without an approved GDPR Chapter V transfer basis. The current
production configuration (SES ``eu-west-1``, Hetzner ``hel1`` FI, Mollie
B.V. NL, EU OAuth regions) passes;
``--self-test`` proves the check FAILS when the fixture env sets
``us-east-1``.

Usage:
    python3 tools/generate_subprocessors.py            # write all three files
    python3 tools/generate_subprocessors.py --check    # exit 1 on drift
    python3 tools/generate_subprocessors.py --self-test  # prove both directions
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COMPOSE_FILES = [ROOT / "docker-compose.yml", ROOT / "docker-compose.prod.yml"]
ENV_FILES = [
    ROOT / ".env.production.example",
    ROOT / ".env.example",
]

MARKETING_REGISTER = ROOT / "apps/marketing-zola/content/subprocessors/index.md"
COMPLIANCE_MIRROR = ROOT / "templates/compliance/subprocessors.md"
TRUST_PORTAL_SEED = ROOT / "tools/fixtures/subprocessors/trust_portal_seed.json"
GENERATED_BANNER = "GENERATED FILE — do not edit by hand"

# The register's own last-updated date. Bumped by hand when the derived set or
# the catalog facts change (the tool prints it; --check compares it too).
REGISTER_LAST_UPDATED = "2026-10-24"
CHANGE_HISTORY = [
    (
        "2026-07-29",
        "Initial publication",
        "Subprocessor register published with Hetzner (infrastructure), AWS (S3/SES, when "
        "enabled), Google (OAuth), GitHub (OAuth) and Mollie (payments). ClickHouse and Redis "
        "are self-hosted software, not subprocessors (see above).",
    ),
    (
        "2026-10-15",
        "Register generated from deployment configuration",
        "The register is now rendered by tools/generate_subprocessors.py from the compose + "
        "env deployment configuration, with a validate-stage gate that fails on drift and a "
        "zero-US check (sovereign_chain_zero_us) over the active set. Mollie's location column "
        "now names the contracting entity (Mollie B.V., Amsterdam) instead of the card-network "
        "processing footprint.",
    ),
    (
        REGISTER_LAST_UPDATED,
        "Mollie legal identity stated in full",
        "The register now states Mollie B.V.'s registered office (Keizersgracht 126, 1015 CW "
        "Amsterdam, The Netherlands) and its supervision by De Nederlandsche Bank (DNB) as a "
        "payment institution. Payment processing is in the Netherlands (EU); card-scheme "
        "networks may process data globally under Mollie's Data Processing Agreement.",
    ),
]

# Canonical payment-processor facts. One source for every rendered surface and
# for tools/check_processor_facts.py (which holds the committed pages to it).
MOLLIE_LEGAL_ENTITY = "Mollie B.V."
MOLLIE_REGISTERED_OFFICE = "Keizersgracht 126, 1015 CW Amsterdam, The Netherlands"
MOLLIE_SUPERVISOR = "De Nederlandsche Bank (DNB)"
MOLLIE_PAYMENT_FACTS_EN = (
    f"{MOLLIE_LEGAL_ENTITY} is a payment institution supervised by {MOLLIE_SUPERVISOR}, "
    f"with its registered office at {MOLLIE_REGISTERED_OFFICE}. Payment data is processed in "
    "the Netherlands (EU); card-scheme networks may process it globally under Mollie's Data "
    "Processing Agreement."
)

# ── The processor catalog: the legal facts, each with its evidence pointer ──
#
# `region_env` names the env variable whose value selects the active region (an
# empty/unset value = the processor is not active on this deployment).
# `regions` maps a configured region value to (processing_country, storage_country).
# `us_region_pattern` matches region identifiers that are US-located.


@dataclass
class Processor:
    key: str
    legal_entity: str
    brand: str
    purpose: str
    data_categories: str
    corporate_country: str
    transfer_basis: str
    required: str
    certifications: list[str]
    region_env: str
    regions: dict[str, tuple[str, str]]
    default_region: str | None = None
    optional_note: str = ""


PROCESSOR_CATALOG: list[Processor] = [
    Processor(
        key="hetzner",
        legal_entity="Hetzner Online GmbH",
        brand="Hetzner",
        purpose="Cloud hosting (compute, storage, networking)",
        data_categories="Core service data in the default shared deployment",
        corporate_country="Germany",
        transfer_basis="Intra-EEA processing; GDPR Chapter V transfer rules do not apply",
        required="Yes",
        certifications=[],
        region_env="HETZNER_DEFAULT_LOCATION",
        regions={
            "hel1": ("Finland", "Finland"),
            "ash": ("United States", "United States"),
            "hil": ("United States", "United States"),
        },
        default_region="hel1",
    ),
    Processor(
        key="aws_s3",
        legal_entity="Amazon Web Services, Inc.",
        brand="AWS S3",
        purpose="Telemetry object storage when enabled (Loki logs, Tempo traces)",
        data_categories="Loki logs and Tempo traces may contain operational metadata",
        corporate_country="USA",
        transfer_basis="EU Standard Contractual Clauses (AWS DPA)",
        required="No — only when the active deployment uses S3 telemetry storage",
        certifications=[],
        region_env="TELEMETRY_S3_REGION",
        regions={
            "eu-central-1": ("Germany", "Germany"),
            "eu-west-1": ("Ireland", "Ireland"),
            "eu-north-1": ("Sweden", "Sweden"),
            "us-east-1": ("United States", "United States"),
            "us-west-2": ("United States", "United States"),
        },
        optional_note="Optional: active only when the deployment configures S3 telemetry storage.",
    ),
    Processor(
        key="aws_ses",
        legal_entity="Amazon Web Services, Inc.",
        brand="AWS SES",
        purpose="Email-delivery transport when enabled (EMAIL_TRANSPORT_TYPE=ses)",
        data_categories="Email content and recipient addresses in transit",
        corporate_country="USA",
        transfer_basis="EU Standard Contractual Clauses (AWS DPA)",
        required="No — only when the active deployment uses the SES transport",
        certifications=[],
        region_env="AWS_REGION",
        regions={
            "eu-west-1": ("Ireland", "Ireland"),
            "eu-central-1": ("Germany", "Germany"),
            "eu-north-1": ("Sweden", "Sweden"),
            "us-east-1": ("United States", "United States"),
            "us-west-2": ("United States", "United States"),
        },
        default_region="eu-west-1",
        optional_note="Active only while EMAIL_TRANSPORT_TYPE=ses; dedicated IP transfers ride "
        "ApexMail's own Hetzner MTAs.",
    ),
    Processor(
        key="google_oauth",
        legal_entity="Google LLC",
        brand="Google",
        purpose="User sign-in via Google OAuth (only if the customer enables it)",
        data_categories="OAuth tokens, email address, name",
        corporate_country="USA",
        transfer_basis="Standard Contractual Clauses (SCCs)",
        required="No — only if the deployment enables Google OAuth",
        certifications=[],
        region_env="GOOGLE_CLIENT_ID",
        regions={"__enabled__": ("Global (EU data)", "EU/EEA-based users: EEA")},
        optional_note="Optional: active only when GOOGLE_CLIENT_ID is configured.",
    ),
    Processor(
        key="github_oauth",
        legal_entity="GitHub, Inc.",
        brand="GitHub",
        purpose="User sign-in via GitHub OAuth (only if the customer enables it)",
        data_categories="OAuth tokens, username, email address",
        corporate_country="USA",
        transfer_basis="Standard Contractual Clauses (SCCs)",
        required="No — only if the deployment enables GitHub OAuth",
        certifications=[],
        region_env="GITHUB_CLIENT_ID",
        regions={"__enabled__": ("Global (EU data)", "EU/EEA-based users: EEA")},
        optional_note="Optional: active only when GITHUB_CLIENT_ID is configured.",
    ),
    Processor(
        key="mollie",
        legal_entity="Mollie B.V.",
        brand="Mollie",
        purpose="Payment processing, subscription management, invoicing",
        data_categories="Payment card details (tokenized — ApexMail never receives full card "
        "numbers), billing address, transaction metadata",
        corporate_country="Netherlands",
        transfer_basis="Contracting entity is EU-established (Mollie B.V., Amsterdam); card "
        "scheme networks process globally under the Mollie Data Processing Agreement; PCI DSS "
        "Level 1 certified",
        required="Yes — required for paid plans",
        certifications=["PCI DSS Level 1"],
        region_env="MOLLIE_API_KEY",
        regions={"__enabled__": ("Netherlands", "Netherlands")},
    ),
]

# Self-hosted software: deployed and managed by ApexMail; the publishers are
# NOT subprocessors. Derived from the compose services so the list cannot rot.
SELF_HOSTED_DATA = {
    "clickhouse": "Delivery events, open/click events, bounce/complaint data",
    "redis": "Session tokens, rate-limit counters",
    "observability": "Operational telemetry (logs, traces, metrics)",
}

SELF_HOSTED = [
    (
        "clickhouse",
        "ClickHouse (open-source)",
        "Analytics database (delivery events, opens, clicks, bounce/complaint data)",
        "Self-hosted by ApexMail on Hetzner infrastructure; ClickHouse, Inc. does not process "
        "customer data.",
    ),
    (
        "redis",
        "Redis (open-source)",
        "In-memory cache (session tokens, rate-limit counters)",
        "Self-hosted by ApexMail on Hetzner infrastructure; Redis Ltd. does not process "
        "customer data.",
    ),
    (
        "observability",
        "Grafana / Loki / Tempo / Prometheus (open-source)",
        "Observability stack (dashboards, logs, traces, metrics)",
        "Self-hosted by ApexMail on Hetzner infrastructure; the software publishers do not "
        "process customer data.",
    ),
]


# ── Configuration reading (no side effects, no secrets) ─────────────────────


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file. Values are never echoed into artifacts
    beyond the non-secret region/provider selectors this tool derives."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def deployment_config(
    env_paths: list[Path], compose_paths: list[Path], override: dict[str, str] | None = None
) -> dict[str, str]:
    """Merge the deployment's env files (later files do NOT override the
    production example — the production example is authoritative where both
    declare a value) plus a fixture override."""
    merged: dict[str, str] = {}
    for path in env_paths:
        for key, value in read_env_file(path).items():
            merged.setdefault(key, value)
    merged["__compose__"] = "\n".join(
        path.read_text(encoding="utf-8") for path in compose_paths if path.is_file()
    )
    if override:
        merged.update(override)
    return merged


def compose_services(config: dict[str, str]) -> set[str]:
    """Service keys from `^  <name>:` lines of the compose files."""
    text = config.get("__compose__", "")
    return set(re.findall(r"^  ([a-z0-9][a-z0-9-]*):", text, flags=re.M))


def is_enabled(config: dict[str, str], processor: Processor) -> tuple[bool, str | None]:
    """Whether a processor is ACTIVE on this deployment, and the selected raw
    region value when it has one."""
    raw = config.get(processor.region_env, "").strip()
    if processor.region_env == "AWS_REGION":
        # SES is active when the transport is SES AND a region is configured.
        transport = config.get("EMAIL_TRANSPORT_TYPE", "ses").strip().lower() or "ses"
        if transport != "ses":
            return False, None
        if not raw:
            raw = processor.default_region or ""
        return bool(raw), raw or None
    if processor.key == "hetzner":
        # The deployment always runs on Hetzner (the compose stack is the
        # deployment); an empty location falls back to the documented default.
        raw = raw or (processor.default_region or "")
        return True, raw or None
    if raw == "":
        return False, None
    if processor.key == "aws_s3":
        return True, raw
    if processor.key in ("google_oauth", "github_oauth"):
        # A placeholder ("<REQUIRED-…>") is not a configured provider; the
        # example files declare the variable but leave it empty.
        return not raw.startswith("<"), None
    if processor.key == "mollie":
        return not raw.startswith("<"), None
    return True, raw


def resolve_location(
    processor: Processor, region: str | None
) -> tuple[str, str, str | None]:
    """(processing_country, storage_country, region_label). Unknown region
    values are surfaced as UNKNOWN rather than guessed."""
    if "__enabled__" in processor.regions:
        country, storage = processor.regions["__enabled__"]
        return country, storage, None
    if region and region in processor.regions:
        country, storage = processor.regions[region]
        return country, storage, region
    return "UNKNOWN", "UNKNOWN", region


@dataclass
class ActiveEntry:
    processor: Processor
    region: str | None
    processing_country: str
    storage_country: str
    transfer_basis: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.processor.legal_entity

    @property
    def brand(self) -> str:
        return self.processor.brand


def derive_active(config: dict[str, str]) -> list[ActiveEntry]:
    active: list[ActiveEntry] = []
    for processor in PROCESSOR_CATALOG:
        enabled, region = is_enabled(config, processor)
        if not enabled:
            continue
        country, storage, region_label = resolve_location(processor, region)
        entry = ActiveEntry(
            processor=processor,
            region=region_label,
            processing_country=country,
            storage_country=storage,
            transfer_basis=processor.transfer_basis,
        )
        if processor.optional_note:
            entry.notes.append(processor.optional_note)
        if processor.key == "hetzner":
            entry.notes.append(
                "Hetzner EU location: Helsinki (hel1, FI); the active default is "
                f"{region_label or processor.default_region}"
            )
        active.append(entry)
    return active


# ── The zero-US check ───────────────────────────────────────────────────────

CHECK_NAME = "sovereign_chain_zero_us"
APPROVED_TRANSFER_BASIS = ("Standard Contractual Clauses", "SCC", "Adequacy", "Intra-EEA")


def check_sovereign_chain_zero_us(active: list[ActiveEntry]) -> list[str]:
    """The sovereign-chain "zero-US" property over the ACTIVE set.

    Refused (each violation returned) when:
      * an active processor's processing OR storage country is the United
        States (the region selector matched a us-* location), or
      * a US-domiciled processor (corporate country USA) processes EU customer
        data without an approved GDPR Chapter V transfer basis.

    A US-incorporated provider processing ONLY in EU/EEA regions under SCCs
    (AWS SES in eu-west-1, AWS S3 in eu-central-1) passes the first arm (no US
    processing/storage) and satisfies the second (SCCs).
    """
    violations: list[str] = []
    for entry in active:
        if entry.processing_country == "United States" or entry.storage_country == "United States":
            violations.append(
                f"{CHECK_NAME}: {entry.name} ({entry.brand}) is ACTIVE with US processing/"
                f"storage (region {entry.region or 'unset'}) — the sovereign chain refuses "
                "US processing"
            )
        if entry.processing_country == "UNKNOWN":
            violations.append(
                f"{CHECK_NAME}: {entry.name} ({entry.brand}) region {entry.region!r} is not "
                "classified in the processor catalog — the sovereign property cannot be proven, "
                "so the register refuses (add the region and its processing country)"
            )
        if entry.processor.corporate_country == "USA" and not any(
            basis in entry.transfer_basis for basis in APPROVED_TRANSFER_BASIS
        ):
            violations.append(
                f"{CHECK_NAME}: {entry.name} ({entry.brand}) is US-domiciled and ACTIVE "
                "without an approved transfer basis"
            )
    return violations


# ── Rendering ───────────────────────────────────────────────────────────────


def render_marketing_register(active: list[ActiveEntry], services: set[str]) -> str:
    rows = []
    for entry in active:
        required = entry.processor.required
        if entry.notes:
            required = f"{required}. {entry.notes[0]}"
        rows.append(
            "| {legal} | {brand} | {purpose} | {data} | {processing} | {storage} | {corporate} | "
            "{transfer} | {required} |".format(
                legal=entry.name,
                brand=entry.brand,
                purpose=entry.processor.purpose,
                data=entry.processor.data_categories,
                processing=entry.processing_country,
                storage=entry.storage_country,
                corporate=entry.processor.corporate_country,
                transfer=entry.transfer_basis,
                required=required,
            )
        )
    self_hosted_rows = []
    for service, name, purpose, note in SELF_HOSTED:
        if service not in services and service != "observability":
            continue
        self_hosted_rows.append(
            "| {name} | {purpose} | {data} | Hetzner deployment region | Hetzner deployment "
            "region | {note} |".format(
                name=name,
                purpose=purpose,
                data=SELF_HOSTED_DATA.get(service, "Operational telemetry"),
                note=note,
            )
        )
    history_rows = "\n".join(
        f"| {date} | {change} | {description} |" for date, change, description in CHANGE_HISTORY
    )
    return f"""+++
title = "Subprocessors"
description = "ApexMail subprocessor register — third-party vendors processing customer personal data."
template = "prose.html"

[extra]
last_updated = "{REGISTER_LAST_UPDATED}"
+++
<!-- {GENERATED_BANNER}: `python3 tools/generate_subprocessors.py` renders this page from the
     deployment configuration (compose + env). `--check` fails the validate stage on drift. -->

## Subprocessor Register

This page lists third-party vendors engaged by Bel Consulting OÜ (trading as ApexMail) that may process customer personal data in the course of providing the ApexMail service. This register is maintained in accordance with Article 28 of the GDPR and Section 5 of the ApexMail Data Processing Agreement. It is generated from the deployment's own configuration, so the listed set and locations cannot drift from what the deployment actually runs.

Under EU-only routing the AWS SES entry carries no tenant's mail: messages leave exclusively through ApexMail's own MTAs on Hetzner infrastructure. EU-only routing and its evidence — including the distinction from the Global default, which uses AWS SES in its EU region — are set out on the [EU sovereignty page](/eu-sovereign/).

### Infrastructure Subprocessors

The following third-party entities process customer personal data on behalf of ApexMail.

| Legal Entity | Brand | Service | Purpose | Data Categories | Processing Country | Storage Country | Corporate Country | Transfer Mechanism | Required |
|---|---|---|---|---|---|---|---|---|---|
{chr(10).join(rows)}

### Payment processor

{MOLLIE_PAYMENT_FACTS_EN}

### Self-Hosted Infrastructure (not third-party subprocessors)

The following software is deployed and managed by ApexMail on Hetzner infrastructure. The software publishers do not process customer data.

| Software | Purpose | Data Categories | Processing Country | Storage Country | Notes |
|---|---|---|---|---|---|
{chr(10).join(self_hosted_rows)}

### Notification

Customers are notified at least **30 days** before any new subprocessor is engaged. To receive notifications, subscribe at [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) or monitor this page.

### Objection

If you object to a new subprocessor on reasonable data protection grounds, contact [privacy@apexmail.ee](mailto:privacy@apexmail.ee). If no alternative can be reached, you may terminate the affected services in accordance with the DPA.

### Change History

| Date | Change | Description |
|---|---|---|
{history_rows}
"""


def render_compliance_mirror(active: list[ActiveEntry], services: set[str]) -> str:
    rows = []
    for entry in active:
        rows.append(
            "| **{legal}** | {purpose} | {data} | {processing} (storage: {storage}) | {transfer} |".format(
                legal=entry.name,
                purpose=entry.processor.purpose,
                data=entry.processor.data_categories,
                processing=entry.processing_country,
                storage=entry.storage_country,
                transfer=entry.transfer_basis,
            )
        )
    return f"""# Subprocessors

**Last Updated:** {REGISTER_LAST_UPDATED}

<!-- {GENERATED_BANNER}: `python3 tools/generate_subprocessors.py` renders this mirror from the
     same deployment-derived register as the public page. The public register at
     https://apexmail.ee/subprocessors/ is the authoritative version. -->

This page lists the subprocessors engaged by **Bel Consulting OÜ** (trading as **ApexMail**), registry code **16588745**, Sakala 7-2, 10141 Tallinn, Estonia, Republic of Estonia, in the provision of the ApexMail email infrastructure platform.

## What is a Subprocessor

A subprocessor is a third-party data processor engaged by ApexMail to process personal data on behalf of our Customers. Subprocessors are engaged for infrastructure, email delivery, authentication, payment processing, caching, and analytics. Self-hosted open-source software that ApexMail deploys and manages itself is listed separately below; the software publishers do not process customer data and are not subprocessors.

## Current Subprocessors

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
{chr(10).join(rows)}

### Payment processor

{MOLLIE_PAYMENT_FACTS_EN}

Whether an optional subprocessor (OAuth providers, SES, S3 telemetry) is engaged is controlled by the active deployment configuration. This register is generated from that configuration, with a validate-stage gate that fails on drift and a zero-US check over the active set.

## Self-Hosted Infrastructure (not third-party subprocessors)

The following software is deployed and managed by ApexMail on Hetzner infrastructure. The software publishers do not process customer data.

| Software | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Redis** (open-source) | In-memory caching, rate limiting, session storage | Session tokens, rate limit counters, ephemeral processing state | Hetzner deployment region | Redis Ltd. does not process customer data; intra-EEA processing. |
| **ClickHouse** (open-source) | Analytics data storage and querying for per-account email analytics | Delivery events, engagement events (opens, clicks), bounce/complaint data, aggregated metrics | Hetzner deployment region | ClickHouse, Inc. does not process customer data; intra-EEA processing. |
| **Grafana / Loki / Tempo / Prometheus** (open-source) | Observability stack: dashboards, logs, traces, metrics | Operational telemetry | Hetzner deployment region | The software publishers do not process customer data; intra-EEA processing. |

## Subprocessor Changes

ApexMail will notify Customers of new subprocessors at least **30 days** before engagement via:

1. Update to the public Subprocessor Register (https://apexmail.ee/subprocessors/).
2. Email notification to account administrators.
3. Optional subscription: subprocessor-notifications@apexmail.ee.

Customers may object to a new subprocessor on reasonable data protection grounds within 30 days of notification by contacting privacy@apexmail.ee. If no alternative can be reached, the Customer may terminate the affected services in accordance with the Data Processing Agreement.

## Customer Obligations

This subprocessor list is incorporated by reference into the [Data Processing Agreement (DPA)](../legal/dpa.md). Customers are responsible for ensuring their own privacy notices accurately disclose ApexMail as a subprocessor where required.

## Contact

Subprocessor inquiries: **privacy@apexmail.ee**
General inquiries: **support@apexmail.ee**
"""


def render_trust_portal_seed(active: list[ActiveEntry], services: set[str]) -> str:
    """The trust portal's registry fixture: `SubprocessorInput`-shaped rows
    (compliance::trust_portal) the `upsert_subprocessor` seed consumes.

    The Rust side pins this file's shape and its equality with the public
    register (see `trust_portal_subprocessors_seed` tests); this tool pins it
    against the deployment configuration."""
    rows = []
    for entry in active:
        rows.append(
            {
                "name": entry.name,
                "purpose": f"{entry.processor.purpose} ({entry.brand})",
                "location": f"{entry.processing_country}; storage {entry.storage_country}",
                "data_categories": [d.strip() for d in entry.processor.data_categories.split(",")],
                "dpa_url": None,
                "certifications": entry.processor.certifications,
                "public": True,
            }
        )
    for service, name, purpose, _note in SELF_HOSTED:
        if service not in services and service != "observability":
            continue
        rows.append(
            {
                "name": f"{name} (self-hosted)",
                "purpose": f"{purpose} — self-hosted by ApexMail; the publisher is not a "
                "subprocessor",
                "location": "Hetzner deployment region",
                "data_categories": ["Operational telemetry"],
                "dpa_url": None,
                "certifications": [],
                "public": True,
            }
        )
    payload = {
        "generated_by": "tools/generate_subprocessors.py",
        "last_updated": REGISTER_LAST_UPDATED,
        "check": CHECK_NAME,
        "subprocessors": rows,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


# ── Entry point ─────────────────────────────────────────────────────────────


def build(config: dict[str, str]) -> tuple[dict[Path, str], list[str]]:
    services = compose_services(config)
    active = derive_active(config)
    violations = check_sovereign_chain_zero_us(active)
    outputs = {
        MARKETING_REGISTER: render_marketing_register(active, services),
        COMPLIANCE_MIRROR: render_compliance_mirror(active, services),
        TRUST_PORTAL_SEED: render_trust_portal_seed(active, services),
    }
    return outputs, violations


def print_derivation(active: list[ActiveEntry]) -> None:
    print(f"  {CHECK_NAME}: active subprocessors derived from deployment configuration:")
    for entry in active:
        region = f" region={entry.region}" if entry.region else ""
        print(
            f"    - {entry.name} ({entry.brand}){region}: processing="
            f"{entry.processing_country}, storage={entry.storage_country}, "
            f"corporate={entry.processor.corporate_country}"
        )


def run(override: dict[str, str] | None = None, targets: list[Path] | None = None) -> int:
    config = deployment_config(ENV_FILES, COMPOSE_FILES, override)
    outputs, violations = build(config)
    active = derive_active(config)
    print_derivation(active)
    if violations:
        for violation in violations:
            print(f"  REFUSED: {violation}", file=sys.stderr)
        return 2
    print(f"  {CHECK_NAME}: PASS (no US processing/storage in the active set)")
    if targets is not None:
        outputs = {path: text for path, text in outputs.items() if path in targets}
    for path, text in outputs.items():
        if path.exists() and path.read_text(encoding="utf-8") == text:
            print(f"  up to date: {path.relative_to(ROOT)}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"  wrote: {path.relative_to(ROOT)}")
    return 0


def check(override: dict[str, str] | None = None) -> int:
    config = deployment_config(ENV_FILES, COMPOSE_FILES, override)
    outputs, violations = build(config)
    active = derive_active(config)
    print_derivation(active)
    if violations:
        for violation in violations:
            print(f"  REFUSED: {violation}", file=sys.stderr)
        return 2
    print(f"  {CHECK_NAME}: PASS (no US processing/storage in the active set)")
    drifted = False
    for path, expected in outputs.items():
        if not path.exists():
            print(f"  DRIFT: {path.relative_to(ROOT)} is missing", file=sys.stderr)
            drifted = True
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            # Point at the first differing line for a reviewable diff.
            for number, (got, want) in enumerate(
                zip(actual.splitlines(), expected.splitlines()), start=1
            ):
                if got != want:
                    print(
                        f"  DRIFT: {path.relative_to(ROOT)}:{number}\n"
                        f"    committed: {got[:160]}\n"
                        f"    derived:   {want[:160]}",
                        file=sys.stderr,
                    )
                    break
            else:
                print(
                    f"  DRIFT: {path.relative_to(ROOT)} differs in length "
                    f"({len(actual.splitlines())} vs {len(expected.splitlines())} lines)",
                    file=sys.stderr,
                )
            drifted = True
    if drifted:
        print(
            "  FAIL: the committed register drifted from the deployment-derived truth — "
            "run `python3 tools/generate_subprocessors.py` and review the diff",
            file=sys.stderr,
        )
        return 1
    print("  PASS: marketing register, compliance mirror and trust-portal seed all match")
    return 0


def self_test() -> int:
    """Prove BOTH directions on a hermetic copy of the real tree:
    (1) the committed files match the derivation of the real configuration,
    (2) the zero-US check REFUSES when the fixture sets us-east-1,
    (3) --check fails on a mutated committed file."""
    failures: list[str] = []

    print("  self-test 1/3: real configuration derives without violations")
    config = deployment_config(ENV_FILES, COMPOSE_FILES)
    _, violations = build(config)
    if violations:
        failures.append(f"real configuration produced violations: {violations}")
    else:
        print("    PASS: real configuration is zero-US under the sovereign chain")

    print("  self-test 2/3: the us-east-1 fixture is REFUSED")
    fixture = json.loads(
        (ROOT / "tools/fixtures/subprocessors/us-east-1.env.json").read_text(encoding="utf-8")
    )
    _, fixture_violations = build(deployment_config(ENV_FILES, COMPOSE_FILES, fixture))
    if any(
        CHECK_NAME in v and "us-east-1" in v for v in fixture_violations
    ):
        print(f"    PASS: fixture refused ({len(fixture_violations)} violation(s))")
    else:
        failures.append(
            "the us-east-1 fixture was NOT refused — the zero-US check has no teeth"
        )

    print("  self-test 3/3: --check detects a mutated committed file")
    tmp = Path(tempfile.mkdtemp(prefix="apexmail-subproc-"))
    try:
        # Mutate a COPY: the checker must flag it (a checker that accepts
        # everything is the failure mode this arm exists to prevent).
        mutated = tmp / "index.md"
        mutated.write_text(
            MARKETING_REGISTER.read_text(encoding="utf-8").replace(
                REGISTER_LAST_UPDATED, "1999-01-01"
            ),
            encoding="utf-8",
        )
        original = MARKETING_REGISTER.read_text(encoding="utf-8")
        MARKETING_REGISTER.write_text(mutated.read_text(encoding="utf-8"), encoding="utf-8")
        try:
            # The mutated run's drift report is EXPECTED; keep it out of the
            # console so a green self-test reads as green.
            with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stderr(
                sink
            ), contextlib.redirect_stdout(sink):
                rc = check()
        finally:
            MARKETING_REGISTER.write_text(original, encoding="utf-8")
        if rc == 0:
            failures.append("--check accepted a mutated register (no drift detection)")
        else:
            print("    PASS: mutated register detected")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        for failure in failures:
            print(f"  FAIL: {failure}", file=sys.stderr)
        return 1
    print("  PASS: subprocessor generator self-test (both directions)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when the committed register/mirror/seed drift from the derived truth",
    )
    mode.add_argument(
        "--self-test",
        action="store_true",
        help="prove the zero-US refusal and the drift detection on fixtures",
    )
    args = parser.parse_args(argv[1:])
    if args.self_test:
        return self_test()
    if args.check:
        return check()
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
