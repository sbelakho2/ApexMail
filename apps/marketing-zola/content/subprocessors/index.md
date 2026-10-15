+++
title = "Subprocessors"
description = "ApexMail subprocessor register — third-party vendors processing customer personal data."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
+++
<!-- GENERATED FILE — do not edit by hand: `python3 tools/generate_subprocessors.py` renders this page from the
     deployment configuration (compose + env). `--check` fails the validate stage on drift. -->

## Subprocessor Register

This page lists third-party vendors engaged by Bel Consulting OÜ (trading as ApexMail) that may process customer personal data in the course of providing the ApexMail service. This register is maintained in accordance with Article 28 of the GDPR and Section 5 of the ApexMail Data Processing Agreement. It is generated from the deployment's own configuration, so the listed set and locations cannot drift from what the deployment actually runs.

### Infrastructure Subprocessors

The following third-party entities process customer personal data on behalf of ApexMail.

| Legal Entity | Brand | Service | Purpose | Data Categories | Processing Country | Storage Country | Corporate Country | Transfer Mechanism | Required |
|---|---|---|---|---|---|---|---|---|---|
| Hetzner Online GmbH | Hetzner | Cloud hosting (compute, storage, networking) | Core service data in the default shared deployment | Germany | Germany | Germany | Intra-EEA processing; GDPR Chapter V transfer rules do not apply | Yes. Hetzner EU locations: Falkenstein/Nuremberg (fsn1/nbg1, DE) and Helsinki (hel1, FI); the active default is fsn1 |
| Amazon Web Services, Inc. | AWS SES | Email-delivery transport when enabled (EMAIL_TRANSPORT_TYPE=ses) | Email content and recipient addresses in transit | Ireland | Ireland | USA | EU Standard Contractual Clauses (AWS DPA) | No — only when the active deployment uses the SES transport. Active only while EMAIL_TRANSPORT_TYPE=ses; dedicated IP transfers ride ApexMail's own Hetzner MTAs. |
| Adyen N.V. | Adyen | Payment processing, subscription management, invoicing | Payment card details (tokenized — ApexMail never receives full card numbers), billing address, transaction metadata | Netherlands | Netherlands | Netherlands | Contracting entity is EU-established (Adyen N.V., Amsterdam); card scheme networks process globally under the Adyen Data Processing Agreement; PCI DSS Level 1 certified | Yes — required for paid plans |

### Self-Hosted Infrastructure (not third-party subprocessors)

The following software is deployed and managed by ApexMail on Hetzner infrastructure. The software publishers do not process customer data.

| Software | Purpose | Data Categories | Processing Country | Storage Country | Notes |
|---|---|---|---|---|---|
| ClickHouse (open-source) | Analytics database (delivery events, opens, clicks, bounce/complaint data) | Delivery events, open/click events, bounce/complaint data | Hetzner deployment region | Hetzner deployment region | Self-hosted by ApexMail on Hetzner infrastructure; ClickHouse, Inc. does not process customer data. |
| Redis (open-source) | In-memory cache (session tokens, rate-limit counters) | Session tokens, rate-limit counters | Hetzner deployment region | Hetzner deployment region | Self-hosted by ApexMail on Hetzner infrastructure; Redis Ltd. does not process customer data. |
| Grafana / Loki / Tempo / Prometheus (open-source) | Observability stack (dashboards, logs, traces, metrics) | Operational telemetry (logs, traces, metrics) | Hetzner deployment region | Hetzner deployment region | Self-hosted by ApexMail on Hetzner infrastructure; the software publishers do not process customer data. |

### Notification

Customers are notified at least **30 days** before any new subprocessor is engaged. To receive notifications, subscribe at [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) or monitor this page.

### Objection

If you object to a new subprocessor on reasonable data protection grounds, contact [privacy@apexmail.ee](mailto:privacy@apexmail.ee). If no alternative can be reached, you may terminate the affected services in accordance with the DPA.

### Change History

| Date | Change | Description |
|---|---|---|
| 2026-07-29 | Initial publication | Subprocessor register published with Hetzner (infrastructure), AWS (S3/SES, when enabled), Google (OAuth), GitHub (OAuth) and Adyen (payments). ClickHouse and Redis are self-hosted software, not subprocessors (see above). |
| 2026-10-15 | Register generated from deployment configuration | The register is now rendered by tools/generate_subprocessors.py from the compose + env deployment configuration, with a validate-stage gate that fails on drift and a zero-US check (sovereign_chain_zero_us) over the active set. Adyen's location column now names the contracting entity (Adyen N.V., Amsterdam) instead of the card-network processing footprint. |
