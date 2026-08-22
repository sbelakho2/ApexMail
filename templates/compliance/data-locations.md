# Data Locations

**Last Updated:** {{LAST_UPDATED}}

This document describes where data is stored and processed by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia.

## Data Residency Commitment

This document describes the supplied EU/EEA-oriented deployment configuration; it is not a universal location guarantee. Core email-service data and telemetry defaults target EEA regions. The active locations, configured providers, and transfer safeguards must be confirmed for the deployed environment and applicable agreement.

## Primary Processing Locations

### Shared EU Cloud

| Service | Default Location | Provider |
|---|---|---|
| Primary infrastructure (compute, storage, networking) | Helsinki, Finland & Nuremberg, Germany | Hetzner Online GmbH |
| Email delivery (primary MTA) | Helsinki, Finland & Nuremberg, Germany | Own MTA on Hetzner infrastructure |
| Email delivery (AWS SES, when enabled) | Configured SES region | AWS SES |
| Database storage | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Analytics (ClickHouse) | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Caching (Redis) | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Backups | Configurable object-store region (default: `us-east-1`) — the backup region is set by deployment configuration and must be confirmed for the active environment | Self-managed encrypted backups with S3-compatible object storage |
| Log storage (Loki) | Configurable object-store region (default: `eu-central-1`) | Self-managed Loki with S3-compatible object storage |
| Trace storage (Tempo) | Configurable object-store region (default: `eu-central-1`) | Self-managed Tempo with S3-compatible object storage |

### Dedicated Tenant

Dedicated Tenant infrastructure is deployed in the region agreed with the Customer. Its region, storage providers, and any data-residency commitments are defined in the applicable agreement.

### BYOC (Bring Your Own Cloud)

In the BYOC model, the Customer chooses the cloud provider and region. ApexMail deploys and manages the application layer within the Customer's cloud environment. Data residency is determined by the Customer's infrastructure choices.

## Data Types and Storage

### Account and Billing Data

The locations in the following tables describe default deployment targets. Confirm
the active deployment before relying on a location for compliance purposes.

| Data Category | Storage Location |
|---|---|
| Account information (names, emails, company) | Database, EU/EEA (Hetzner) |
| Billing records (invoices, transactions) | Database, EU/EEA (Hetzner); Stripe (EU + US, per SCCs) |
| Payment card details | Not stored by ApexMail — processed by Stripe |
| API keys (hashed) | Database, EU/EEA (Hetzner) |
| Audit logs | Database, EU/EEA (Hetzner) + log storage |

### Email Content

| Data Category | Storage Location |
|---|---|
| Email subject, body, headers | Transient processing on MTA infrastructure, EU/EEA (Hetzner); stored for configured retention period |
| Email attachments | Transient processing on MTA infrastructure, EU/EEA (Hetzner); stored for configured retention period |
| Email delivery metadata | Database + analytics store, EU/EEA (Hetzner) |
| Delivery, open, click events | Database + analytics store, EU/EEA (Hetzner) |

### Recipient Data

| Data Category | Storage Location |
|---|---|
| Recipient email addresses | Database, EU/EEA (Hetzner) |
| Recipient lists | Database, EU/EEA (Hetzner) |
| Suppression lists | Database, EU/EEA (Hetzner) |
| Open/click tracking data (IP, user agent) | Analytics store, EU/EEA (Hetzner) |

### System Data

| Data Category | Storage Location |
|---|---|
| Application logs | Loki object storage in the configured region (default: `eu-central-1`) |
| Distributed traces | Tempo object storage in the configured region (default: `eu-central-1`) |
| Metrics | Prometheus time-series database, EU/EEA (Hetzner) |
| Monitoring data | Prometheus, EU/EEA (Hetzner) |
| Session data | Redis cache, EU/EEA (Hetzner) |
| Rate limit counters | Redis cache, EU/EEA (Hetzner) |

## Data Transfers

### Within EEA

All primary processing occurs within the EEA. Data may move between the Finnish and German data centers for redundancy and performance purposes.

### Outside EEA

Data transfers outside the EEA are limited to:

| Third Country | Purpose | Subprocessor | Transfer Safeguard |
|---|---|---|---|
| United States | Payment processing (tokenized card data and transaction metadata) | Stripe, Inc. | EU Standard Contractual Clauses (SCCs) |
| United States | CRM (prospect and customer communications) | HubSpot, Inc. | EU Standard Contractual Clauses (SCCs) |

Email content, recipient data, and event data use the active deployment's configured providers and regions. The supplied configuration defaults core service and telemetry storage to EEA regions, but a deployment override or enabled provider can change that result. Confirm active locations and apply the appropriate transfer safeguard, including SCCs where required.

## Geographic Redundancy

### Primary Region

- All Shared EU Cloud services operate from EU data centers.
- Multi-zone deployment within the primary region provides availability.
- Cross-zone data replication for critical databases.

### Failover

- Cross-region failover capability (Finland ↔ Germany) for critical services.
- Enterprise and Dedicated Tenant customers may configure additional redundancy.

### Status Page and External Monitoring

- Status page hosted on infrastructure independent of the primary ApexMail infrastructure.
- External probes from: Western Europe, Northern Europe, North America.
- Asia-Pacific probes planned.

## Data Sovereignty

ApexMail data is subject to:

- EU law (GDPR).
- Estonian law (Isikuandmete kaitse seadus, Raamatupidamise seadus).
- The laws of the Member State where the data center is physically located (Finland, Germany).

ApexMail will notify Customers before moving primary processing to a new jurisdiction that would change the applicable legal framework, and will not do so without consent where contractually required.

## Contact

Data residency inquiries: **{{PRIVACY_EMAIL}}**
General inquiries: **{{SUPPORT_EMAIL}}**
