# Subprocessors

**Last Updated:** 2026-10-24

<!-- GENERATED FILE — do not edit by hand: `python3 tools/generate_subprocessors.py` renders this mirror from the
     same deployment-derived register as the public page. The public register at
     https://apexmail.ee/subprocessors/ is the authoritative version. -->

This page lists the subprocessors engaged by **Bel Consulting OÜ** (trading as **ApexMail**), registry code **16588745**, Sakala 7-2, 10141 Tallinn, Estonia, Republic of Estonia, in the provision of the ApexMail email infrastructure platform.

## What is a Subprocessor

A subprocessor is a third-party data processor engaged by ApexMail to process personal data on behalf of our Customers. Subprocessors are engaged for infrastructure, email delivery, authentication, payment processing, caching, and analytics. Self-hosted open-source software that ApexMail deploys and manages itself is listed separately below; the software publishers do not process customer data and are not subprocessors.

## Current Subprocessors

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Hetzner Online GmbH** | Cloud hosting (compute, storage, networking) | Core service data in the default shared deployment | Germany (storage: Germany) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| **Amazon Web Services, Inc.** | Email-delivery transport when enabled (EMAIL_TRANSPORT_TYPE=ses) | Email content and recipient addresses in transit | Ireland (storage: Ireland) | EU Standard Contractual Clauses (AWS DPA) |
| **Mollie B.V.** | Payment processing, subscription management, invoicing | Payment card details (tokenized — ApexMail never receives full card numbers), billing address, transaction metadata | Netherlands (storage: Netherlands) | Contracting entity is EU-established (Mollie B.V., Amsterdam); card scheme networks process globally under the Mollie Data Processing Agreement; PCI DSS Level 1 certified |

### Payment processor

Mollie B.V. is a payment institution supervised by De Nederlandsche Bank (DNB), with its registered office at Keizersgracht 126, 1015 CW Amsterdam, The Netherlands. Payment data is processed in the Netherlands (EU); card-scheme networks may process it globally under Mollie's Data Processing Agreement.

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
