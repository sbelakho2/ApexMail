+++
title = "Data Locations"
description = "ApexMail data location matrix — where each category of customer data is stored and processed."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Data Location Matrix

This matrix describes the supplied EU/EEA-oriented deployment configuration, not a universal data-location guarantee. Core email-service and telemetry defaults target EEA regions; active storage locations, enabled providers, and transfer safeguards must be confirmed for the deployed environment and applicable agreement.

| # | Data Category | Default Primary Location | Default Backup / Replica | Default Processing Region | Transfer Safeguard |
|---|---|---|---|---|---|
| 1 | Account data (name, email, company, address) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 2 | API keys (hashed) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 3 | Sender and recipient addresses | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 4 | Message content (subject, body, headers) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 5 | Attachments | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 6 | Events and logs (delivery, open, click, bounce) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 7 | Authentication (OAuth tokens, MFA secrets) | Hetzner, Germany (Falkenstein/Nuremberg); Google LLC / GitHub, Inc. (OAuth) | Provider-managed | EEA (core); US for OAuth providers | SCCs (OAuth providers) |
| 8 | Billing (invoices, transactions, payment tokens) | Hetzner, Germany; Stripe, Inc. (US) | Provider-managed (India for Stripe support) | EEA (ApexMail); US/India (Stripe) | SCCs (Stripe) |
| 9 | Support tickets | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 10 | Analytics (aggregate delivery metrics, engagement) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 11 | Security logs (audit trails, access logs) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA default | Confirm active deployment |
| 12 | Backups (database, file storage snapshots) | Hetzner, Finland (Tuusula) | Hetzner, Germany (Nuremberg, cold storage) | EEA default | Confirm active deployment |

## Sub-processor Locations

| Sub-processor | Purpose | Location | Transfer Safeguard |
|---|---|---|---|
| Hetzner Online GmbH | Core infrastructure (compute, storage, networking) | Configured EU/EEA region | Confirm active deployment and applicable transfer safeguard |
| Amazon Web Services, Inc. (AWS S3) | Telemetry object storage when enabled | Configured S3 region (default: `eu-central-1`) | Confirm active deployment and applicable transfer safeguard |
| Amazon Web Services, Inc. (AWS SES) | Email-delivery transport when enabled | Configured SES region | Confirm active deployment and applicable transfer safeguard |
| Stripe, Inc. | Payment processing | US (primary), India (support) | EU Standard Contractual Clauses |
| Google LLC | Optional OAuth authentication | US | EU Standard Contractual Clauses |
| GitHub, Inc. | Optional OAuth authentication | US | EU Standard Contractual Clauses |

## Deployment Models

Dedicated Tenant and BYOC entries below describe a model only where a separate written agreement has approved it. They are not included in the public self-service plans.

| Model | Primary Region | Customer Control |
|---|---|---|
| Shared EU Cloud | EEA-oriented default configuration; confirm active regions | ApexMail-managed |
| Dedicated Tenant | EU region agreed with customer (default: Finland or Germany) | Single-tenant, ApexMail-managed |
| BYOC (Bring Your Own Cloud) | Customer-chosen provider and region | Customer-managed infrastructure, ApexMail-managed application layer |

## Contact

For data residency inquiries: **privacy@apexmail.ee**
