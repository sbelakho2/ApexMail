+++
title = "Subprocessors"
description = "ApexMail subprocessor register — third-party vendors processing customer personal data."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

## Subprocessor Register

This page lists third-party vendors engaged by Bel Consulting OÜ (trading as ApexMail) that may process customer personal data in the course of providing the ApexMail service. This register is maintained in accordance with Article 28 of the GDPR and Section 5 of the ApexMail Data Processing Agreement.

### Infrastructure Subprocessors

The following third-party entities process customer personal data on behalf of ApexMail.

| Legal Entity | Brand | Service | Purpose | Data Categories | Processing Country | Storage Country | Corporate Country | Transfer Mechanism | Required |
|---|---|---|---|---|---|---|---|---|---|---|
| Hetzner Online GmbH | Hetzner | Cloud hosting | Compute, storage, networking | Core service data in the default shared deployment | Configured EU/EEA region | Configured EU/EEA region | Germany | Confirm the active deployment and applicable transfer safeguard | Yes |
| Amazon Web Services, Inc. | AWS S3 | Telemetry object storage when enabled | Loki logs and Tempo traces may contain operational metadata | Configured S3 region (default: `eu-central-1`) | Configured S3 region (default: `eu-central-1`) | USA | Confirm the active deployment and applicable transfer safeguard | No — only when the active deployment uses S3 storage |
| Amazon Web Services, Inc. | AWS SES | Email-delivery transport when enabled | Email content and recipient addresses | Configured SES region | Configured SES region | USA | Confirm the active deployment and applicable transfer safeguard | No — only when the active deployment uses SES |
| Google LLC | Google | OAuth authentication | User sign-in via Google OAuth | OAuth tokens, email address, name | Global (EU data) | EU/EEA-based users: EEA | USA | Standard Contractual Clauses (SCCs) | No — only if customer enables Google OAuth |
| GitHub, Inc. | GitHub | OAuth authentication | User sign-in via GitHub OAuth | OAuth tokens, username, email address | Global (EU data) | EU/EEA-based users: EEA | USA | Standard Contractual Clauses (SCCs) | No — only if customer enables GitHub OAuth |
| Stripe, Inc. | Stripe | Payment processing | Subscription billing, invoicing, payment method storage | Payment method tokens, transaction metadata, invoice data | USA (primary); India (support) | USA | USA | Standard Contractual Clauses (SCCs) per Stripe Data Processing Agreement | Yes — required for paid plans |

### Self-Hosted Infrastructure (not third-party subprocessors)

The following software is deployed and managed by ApexMail on Hetzner infrastructure. The software publishers do not process customer data.

| Software | Purpose | Data Categories | Processing Country | Storage Country | Notes |
|---|---|---|---|---|---|---|
| ClickHouse (open-source) | Analytics database | Delivery events, open/click events, bounce/complaint data | Configured deployment region | Configured deployment region | Self-hosted by ApexMail. ClickHouse, Inc. does not process customer data. |
| Redis (open-source) | In-memory cache | Session tokens, rate limit counters | Configured deployment region | Configured deployment region | Self-hosted by ApexMail. Redis Ltd. does not process customer data. |

### Notification

Customers are notified at least **30 days** before any new subprocessor is engaged. To receive notifications, subscribe at [subprocessor-notifications@apexmail.ee](mailto:subprocessor-notifications@apexmail.ee) or monitor this page.

### Objection

If you object to a new subprocessor on reasonable data protection grounds, contact [privacy@apexmail.ee](mailto:privacy@apexmail.ee). If no alternative can be reached, you may terminate the affected services in accordance with the DPA.

### Change History

| Date | Change | Description |
|---|---|---|---|
| 2026-07-29 | Initial publication | Subprocessor register published |
| 2026-07-29 | Added subprocessors | Google (OAuth), GitHub (OAuth), Stripe (payments), ClickHouse (analytics) added |
