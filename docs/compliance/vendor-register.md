# Vendor register (internal draft)

| Field | Value |
|---|---|
| Classification | Internal Policy, Confidential |
| Owner | ApexMail (privacy@apexmail.ee), Bel Consulting OÜ, registry code 16588745 |
| Written | 2026-10-28 |
| Review cycle | On every subprocessor register change, then quarterly |

## What this register covers

This register mirrors the subprocessors the published register already lists and adds the API provider roles the code and deployment configuration show. Every row cites the file that documents the relationship.

This vendor register is an internal evidence-core draft. It makes no vendor-certification claim beyond what the cited sources state, and the public register stays the customer-facing list.

## Subprocessors on the published register

| Vendor | Purpose | Data processed | Location | Transfer safeguard | Source |
|---|---|---|---|---|---|
| EU infrastructure provider (named only in the customer DPA subprocessor annex) | Cloud hosting: compute, storage and networking | Core service data in the default shared deployment | Finland (storage: Finland) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply | `templates/compliance/subprocessors.md` current subprocessors table |
| Amazon Web Services, Inc. | Email-delivery transport when `EMAIL_TRANSPORT_TYPE=ses` | Email content and recipient addresses in transit | Ireland (storage: Ireland) | EU Standard Contractual Clauses via the AWS DPA | `templates/compliance/subprocessors.md`; `EMAIL_TRANSPORT_TYPE=ses` in `.env.production.example` |
| Mollie B.V. | Payment processing, subscription management and invoicing | Tokenized payment references, billing address, transaction metadata; the merchant never receives full card numbers | Netherlands (storage: Netherlands) | EU-established contracting entity; card schemes process globally under the Mollie DPA; PCI DSS Level 1 | `templates/compliance/subprocessors.md`; Mollie base URL `https://api.mollie.com/v2` in `.env.production.example` |

## Optional, configuration-gated providers

| Provider | Role shown by the code | Engagement condition | Source |
|---|---|---|---|
| Google (OAuth) | Authorization and token endpoints for social login | Only when the deployment enables social login | `services/mail-server/crates/api-server/src/routes/sso.rs`; `social-login-oauth-google-github` in `docs/development/capability-registry.json` |
| GitHub (OAuth) | Authorization and token endpoints for social login | Only when the deployment enables social login | `services/mail-server/crates/api-server/src/routes/sso.rs`; `social-login-oauth-google-github` in `docs/development/capability-registry.json` |
| S3 telemetry | Optional telemetry sink named by the register | Controlled by the active deployment configuration | `templates/compliance/subprocessors.md` optional subprocessors paragraph |
| AI model runtime | Generation endpoint behind `AI_MODEL_ENABLED` (default false, EU endpoint expected) | Off by default; the service answers honestly with human escalation when disabled | `.env.production.example` (`AI_MODEL_ENDPOINT`, `AI_MODEL_ENABLED`) |

## Self-hosted software (not third-party subprocessors)

| Software | Purpose | Data processed | Source |
|---|---|---|---|
| Redis (open source) | Caching, rate limiting, session storage | Session tokens, rate-limit counters, ephemeral state | `templates/compliance/subprocessors.md` self-hosted table |
| ClickHouse (open source) | Per-account email analytics storage and queries | Delivery events, engagement events, bounce and complaint data, aggregated metrics | `templates/compliance/subprocessors.md` self-hosted table |
| Grafana, Loki, Tempo and Prometheus (open source) | Observability: dashboards, logs, traces and metrics | Operational telemetry | `templates/compliance/subprocessors.md` self-hosted table |

## Register discipline

| Control | What it enforces | Source |
|---|---|---|
| Generated register with drift gate | The committed register must match the deployment-derived truth or validation fails | `tools/generate_subprocessors.py`; invariant I23 in `docs/invariants.toml` |
| Zero-US check | An active provider set containing a US region is refused (fixture-proven) | `tools/generate_subprocessors.py --self-test`; invariant I23 in `docs/invariants.toml` |
| Finland hosting and dedicated-IP promise | Hosting and dedicated IP stay in Finland and the public register says so | Invariant I23 in `docs/invariants.toml`; `api-server` `ip_provider.rs` |
| Customer change notice | New subprocessors announced at least 30 days ahead by register update, admin email and optional subscription | `templates/compliance/subprocessors.md` subprocessor changes section |

## Reading this register

Rows repeat only what the cited file says. A provider that no source documents is not listed here, and an optional provider stays marked optional until the deployment configuration engages it.
