+++
title = "Data Locations"
description = "ApexMail data location matrix, where each category of customer data is stored and processed."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Data Location Matrix

This matrix describes the deployed EU/EEA configuration. Core service data (rows 1–6, 9–12) is processed and replicated exclusively inside EU data centres, so no third-country transfer occurs; the only third-country processing is the OAuth providers listed below, covered by EU Standard Contractual Clauses. Non-standard deployments (Dedicated Tenant, BYOC) are governed by their own written agreement.

| # | Data Category | Default Primary Location | Default Backup / Replica | Default Processing Region | Transfer Safeguard |
|---|---|---|---|---|---|
| 1 | Account data (name, email, company, address) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 2 | API keys (hashed) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 3 | Sender and recipient addresses | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 4 | Message content (subject, body, headers) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 5 | Attachments | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 6 | Events and logs (delivery, open, click, bounce) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 7 | Authentication (OAuth tokens, MFA secrets) | EU data centre, Finland; Google LLC / GitHub, Inc. (OAuth) | Provider-managed | EEA (core); US for OAuth providers | SCCs (OAuth providers) |
| 8 | Billing (invoices, transactions, payment tokens) | EU data centre, Finland; Mollie B.V. (Netherlands, EU) | Provider-managed within the EU | EEA (ApexMail and Mollie); card scheme networks under the Mollie DPA | Intra-EEA processing (Mollie B.V., Amsterdam) |
| 9 | Support tickets | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 10 | Analytics (aggregate delivery metrics, engagement) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 11 | Security logs (audit trails, access logs) | EU data centre, Finland | EU data centre, Finland (secondary site) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| 12 | Backups (database, file storage snapshots) | EU data centre, Finland | EU data centre, Finland (encrypted cold storage) | EEA (no third-country transfer) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |

## Sub-processor Locations

| Sub-processor | Purpose | Location | Transfer Safeguard |
|---|---|---|---|
| Hetzner Online GmbH | Core infrastructure (compute, storage, networking) | Finland (EU) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| Amazon Web Services, Inc. (AWS S3) | Telemetry object storage when enabled | Configured S3 region (default: `eu-central-1`, EU) | EU SCCs when the configured region is outside the EEA |
| Amazon Web Services, Inc. (AWS SES) | Email-delivery transport when enabled | Configured SES region (EU default) | EU SCCs when the configured region is outside the EEA |
| Mollie B.V. | Payment processing | Netherlands (EU); card scheme networks process globally under the Mollie DPA | Intra-EEA processing (Mollie B.V., Amsterdam) |
| Google LLC | Optional OAuth authentication | US | EU Standard Contractual Clauses |
| GitHub, Inc. | Optional OAuth authentication | US | EU Standard Contractual Clauses |

### Payment processor

Mollie B.V. is a payment institution supervised by De Nederlandsche Bank (DNB), with its registered office at Keizersgracht 126, 1015 CW Amsterdam, The Netherlands. Payment data is processed in the Netherlands (EU); card-scheme networks may process it globally under Mollie's Data Processing Agreement.

## Deployment Models

Dedicated Tenant and BYOC entries below describe a model only where a separate written agreement has approved it. They are not included in the public self-service plans.

| Model | Primary Region | Customer Control |
|---|---|---|
| Shared EU Cloud | EU data centres in Finland | ApexMail-managed |
| Dedicated Tenant | EU region agreed with customer (default: Finland) | Single-tenant, ApexMail-managed |
| BYOC (Bring Your Own Cloud) | Customer-chosen provider and region | Customer-managed infrastructure, ApexMail-managed application layer |

## EU-Only Routing

The matrix above covers storage. Delivery transport is governed by the tenant routing mode: under EU-only routing (`eu_only`), every send leaves through ApexMail's own EU MTAs and the shared third-party transport (AWS SES in its EU region) is forbidden, an unavailable own-MTA route holds the message instead of failing over. The full transport argument, each point linked to its evidence, is on the [EU sovereignty page](/eu-sovereign/).

## Contact

For data residency inquiries: **privacy@apexmail.ee**
