# Subprocessors

**Last Updated:** {{LAST_UPDATED}}

This page lists the subprocessors engaged by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia, in the provision of the ApexMail email infrastructure platform.

## What is a Subprocessor

A subprocessor is a third-party data processor engaged by ApexMail to process personal data on behalf of our Customers. Subprocessors are engaged for infrastructure, email delivery, payment processing, caching, analytics, and monitoring.

## Current Subprocessors

### Infrastructure

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Hetzner Online GmbH** | Primary cloud infrastructure (bare metal, cloud servers, block storage, networking) | All platform data (account data, email content, event logs, analytics) | Germany & Finland (EU/EEA) | Not applicable — processing remains within the EEA |

### Email Delivery

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Amazon Web Services (AWS) SES** | Email delivery transport (secondary delivery path) | Email content (subject, body, headers), recipient email addresses | EU region (Ireland, Frankfurt) | Not applicable — processing remains within the EEA |

AWS SES is used as a secondary delivery path. The primary delivery path is ApexMail's own MTA infrastructure hosted on Hetzner.

### Payment Processing

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Stripe, Inc.** | Payment processing, subscription management, invoicing | Payment card details (tokenized — ApexMail never receives full card numbers), billing address, transaction metadata | Processing entity: Stripe Payments Europe, Limited (Ireland). Data may be transferred to Stripe, Inc. (United States) for centralised reporting and fraud detection. | Standard Contractual Clauses (SCCs); Stripe is PCI DSS Level 1 certified |

### Caching and Data

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **Redis** (self-hosted open-source software on Hetzner) | In-memory caching, rate limiting, session storage | Session tokens, rate limit counters, ephemeral processing state | EU/EEA (Germany & Finland) | Not applicable — processing remains within the EEA. Redis Ltd. does not process customer data — ApexMail deploys and manages Redis on its own infrastructure. |

### Analytics and Monitoring

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **ClickHouse** (self-hosted open-source software deployed and managed by ApexMail on Hetzner infrastructure; ClickHouse, Inc. and ClickHouse Cloud are not subprocessors) | Analytics data storage and querying for per-account email analytics | Delivery events, engagement events (opens, clicks), aggregated metrics | EU/EEA (Germany & Finland) | Not applicable — processing remains within the EEA. ClickHouse, Inc. does not process customer data — ApexMail deploys and manages ClickHouse on its own infrastructure. |
| **Plausible Analytics** (self-hosted) | Privacy-focused marketing website analytics | Anonymized page view data (no cookies, no personal data) | EU/EEA (Estonia) | Not applicable — processing remains within the EEA |

### Support and Communications

| Subprocessor | Purpose | Data Processed | Location | Transfer Safeguard |
|---|---|---|---|---|
| **HubSpot, Inc.** | CRM for prospect and customer communications | Name, email address, company, communication history (prospects and customer contacts only) | EU (HubSpot Ireland) + US (HubSpot Inc.) | Standard Contractual Clauses (SCCs); HubSpot's DPA |

## Subprocessor Changes

ApexMail will notify Customers of new subprocessors at least **14 days** before engagement via:

1. Update to this page.
2. Email notification to account administrators.

Customers may object to a new subprocessor on reasonable data protection grounds within 14 days of notification.

## Customer Obligations

This subprocessor list is incorporated by reference into the [Data Processing Agreement (DPA)](../legal/dpa.md). Customers are responsible for ensuring their own privacy notices accurately disclose ApexMail as a subprocessor where required.

## Contact

Subprocessor inquiries: **{{PRIVACY_EMAIL}}**
General inquiries: **{{SUPPORT_EMAIL}}**
