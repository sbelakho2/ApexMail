# Subprocessors

**Last Updated:** 2026-08-29

This page lists the subprocessors engaged by **Bel Consulting OÜ** (trading as **ApexMail**), registry code **16588745**, Sakala 7-2, 10141 Tallinn, Estonia, Republic of Estonia, in the provision of the ApexMail email infrastructure platform. It mirrors the public Subprocessor Register at https://apexmail.ee/subprocessors/, which is the authoritative version.

## What is a Subprocessor

A subprocessor is a third-party data processor engaged by ApexMail to process personal data on behalf of our Customers. Subprocessors are engaged for infrastructure, email delivery, authentication, payment processing, caching, and analytics. Self-hosted open-source software that ApexMail deploys and manages itself is listed separately below; the software publishers do not process customer data and are not subprocessors.

## Current Subprocessors

### Infrastructure

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Hetzner Online GmbH** | Primary cloud infrastructure (compute, storage, networking) | Core platform data in the default shared deployment | Configured EU/EEA region | Confirm the active deployment and applicable transfer safeguard |

### Email Delivery and Telemetry

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Amazon Web Services (AWS SES)** | Email-delivery transport when enabled | Email content (subject, body, headers), recipient email addresses | Configured SES region | Confirm the active deployment and applicable transfer safeguard |
| **Amazon Web Services, Inc. (AWS S3)** | Telemetry object storage when enabled | Loki logs and Tempo traces may contain operational metadata | Configured S3 region (default: `eu-central-1`) | Confirm the active deployment and applicable transfer safeguard |

Whether AWS SES is enabled, and the delivery provider and region used, are controlled by the active deployment configuration. Confirm these details before relying on a data-location representation.

### Authentication

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Google LLC** | User sign-in via Google OAuth (only if the customer enables it) | OAuth tokens, email address, name | Global (EU data); EEA-based users: EEA | Standard Contractual Clauses (SCCs) |
| **GitHub, Inc.** | User sign-in via GitHub OAuth (only if the customer enables it) | OAuth tokens, username, email address | Global (EU data); EEA-based users: EEA | Standard Contractual Clauses (SCCs) |

### Payment Processing

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Stripe, Inc.** | Payment processing, subscription management, invoicing | Payment card details (tokenized — ApexMail never receives full card numbers), billing address, transaction metadata | USA (primary); India (support) | Standard Contractual Clauses (SCCs) per the Stripe Data Processing Agreement; Stripe is PCI DSS Level 1 certified |

### Self-Hosted Infrastructure (not third-party subprocessors)

The following software is deployed and managed by ApexMail on Hetzner infrastructure. The software publishers do not process customer data.

| Software | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Redis** (open-source) | In-memory caching, rate limiting, session storage | Session tokens, rate limit counters, ephemeral processing state | Configured deployment region | Redis Ltd. does not process customer data; confirm the active deployment and transfer safeguard. |
| **ClickHouse** (open-source) | Analytics data storage and querying for per-account email analytics | Delivery events, engagement events (opens, clicks), bounce/complaint data, aggregated metrics | Configured deployment region | ClickHouse, Inc. does not process customer data; confirm the active deployment and transfer safeguard. |

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
