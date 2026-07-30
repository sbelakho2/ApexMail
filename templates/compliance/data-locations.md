# Data Locations

**Last Updated:** {{LAST_UPDATED}}

This document describes where data is stored and processed by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia.

## Data Residency Commitment

ApexMail stores and processes all customer data within the European Economic Area (EEA) by default. Primary data processing occurs in data centers located in the European Union.

## Primary Processing Locations

### Shared EU Cloud

| Service | Location | Provider |
|---|---|---|
| Primary infrastructure (compute, storage, networking) | Helsinki, Finland & Nuremberg, Germany | Hetzner Online GmbH |
| Email delivery (primary MTA) | Helsinki, Finland & Nuremberg, Germany | Own MTA on Hetzner infrastructure |
| Email delivery (secondary SES) | Frankfurt, Germany & Dublin, Ireland | AWS SES (EU regions only) |
| Database storage | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Analytics (ClickHouse) | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Caching (Redis) | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner |
| Backups | Helsinki, Finland & Nuremberg, Germany | Self-managed on Hetzner block/object storage |
| Log storage | Helsinki, Finland & Nuremberg, Germany | Self-managed |

### Dedicated Tenant

Dedicated Tenant infrastructure is deployed in a single EU region as agreed with the Customer. The default region is Finland or Germany (Hetzner). Alternative EU regions are available upon request.

### BYOC (Bring Your Own Cloud)

In the BYOC model, the Customer chooses the cloud provider and region. ApexMail deploys and manages the application layer within the Customer's cloud environment. Data residency is determined by the Customer's infrastructure choices.

## Data Types and Storage

### Account and Billing Data

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
| Application logs | Log storage, EU/EEA (Hetzner) |
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

Email content, recipient data, and event data are **never transferred outside the EEA** through ApexMail's own infrastructure. The only non-EEA transfers are for payment processing and CRM, both covered by SCCs.

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
