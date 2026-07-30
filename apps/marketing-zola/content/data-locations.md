+++
title = "Data Locations"
description = "ApexMail data location matrix — where each category of customer data is stored and processed."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## Data Location Matrix

All customer data is stored and processed within Hetzner data centers in Germany and Finland, unless otherwise noted below. Transfers outside the EEA rely on EU Standard Contractual Clauses (SCCs) or an adequacy decision under GDPR Article 45.

| # | Data Category | Primary Location | Backup / Replica | Processing Region | Transfer Safeguard |
|---|---|---|---|---|---|
| 1 | Account data (name, email, company, address) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 2 | API keys (hashed) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 3 | Sender and recipient addresses | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 4 | Message content (subject, body, headers) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 5 | Attachments | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 6 | Events and logs (delivery, open, click, bounce) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 7 | Authentication (OAuth tokens, MFA secrets) | Hetzner, Germany (Falkenstein/Nuremberg); Google LLC / GitHub, Inc. (OAuth) | Provider-managed | EEA (core); US for OAuth providers | SCCs (OAuth providers) |
| 8 | Billing (invoices, transactions, payment tokens) | Hetzner, Germany; Stripe, Inc. (US) | Provider-managed (India for Stripe support) | EEA (ApexMail); US/India (Stripe) | SCCs (Stripe) |
| 9 | Support tickets | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 10 | Analytics (aggregate delivery metrics, engagement) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 11 | Security logs (audit trails, access logs) | Hetzner, Germany (Falkenstein/Nuremberg) | Hetzner, Finland (Tuusula) | EEA only | Not applicable |
| 12 | Backups (database, file storage snapshots) | Hetzner, Finland (Tuusula) | Hetzner, Germany (Nuremberg, cold storage) | EEA only | Not applicable |

## Sub-processor Locations

| Sub-processor | Purpose | Location | Transfer Safeguard |
|---|---|---|---|
| Hetzner Online GmbH | Core infrastructure (compute, storage, networking) | Germany, Finland | Not applicable — EEA |
| Stripe, Inc. | Payment processing | US (primary), India (support) | EU Standard Contractual Clauses |
| Google LLC | Optional OAuth authentication | US | EU Standard Contractual Clauses |
| GitHub, Inc. | Optional OAuth authentication | US | EU Standard Contractual Clauses |

## Deployment Models

| Model | Primary Region | Customer Control |
|---|---|---|
| Shared EU Cloud | Germany, Finland (Hetzner) | ApexMail-managed |
| Dedicated Tenant | EU region agreed with customer (default: Finland or Germany) | Single-tenant, ApexMail-managed |
| BYOC (Bring Your Own Cloud) | Customer-chosen provider and region | Customer-managed infrastructure, ApexMail-managed application layer |

## Contact

For data residency inquiries: **privacy@apexmail.ee**
