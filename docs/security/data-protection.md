# Data Protection and Privacy

> Last updated: 2026-02-27

This document describes the data protection controls, privacy compliance framework, and tenant isolation mechanisms in the ApexMail platform.

---

## Table of Contents

- [Encryption](#encryption)
  - [Data at Rest](#data-at-rest)
  - [Data in Transit](#data-in-transit)
  - [Key Management](#key-management)
  - [Tracking Token Encryption](#tracking-token-encryption)
- [Tenant Isolation](#tenant-isolation)
- [GDPR Compliance](#gdpr-compliance)
- [CCPA Compliance](#ccpa-compliance)
- [Audit Logging](#audit-logging)
- [Data Residency](#data-residency)
- [Sub-Processors](#sub-processors)
- [Data Processing Agreement (DPA)](#data-processing-agreement-dpa)
- [Cookies and Tracking](#cookies-and-tracking)

---

## Encryption

### Data at Rest

All persistent data is encrypted at rest using **AES-256-GCM**, an industry-standard authenticated encryption algorithm that provides both confidentiality and integrity.

Encrypted data includes PII (email addresses, names, custom metadata), email content, API keys, and credentials.

### Data in Transit

All network communication is encrypted using TLS.

| Parameter               | Value                                       |
|-------------------------|---------------------------------------------|
| Preferred protocol      | TLS 1.3                                     |
| Minimum protocol        | TLS 1.2                                     |
| Cipher suites           | Modern authenticated encryption only; legacy ciphers are disabled |
| Certificate management  | Automated TLS certificate provisioning and renewal |
| HSTS                    | Enabled                                     |

- **Platform communication**: All communication between platform components is encrypted with TLS.
- **SMTP**: Outbound email delivery defaults to **AWS SES**, which enforces TLS for all API calls and uses opportunistic TLS (STARTTLS) for onward delivery to recipient servers. When self-hosted SMTP is enabled (`EMAIL_TRANSPORT_TYPE=smtp`), outbound connections prefer TLS via STARTTLS. MTA-STS policies are respected in both modes — if the recipient domain enforces MTA-STS, delivery over unencrypted connections is refused.

### Key Management

#### Key Derivation

Encryption keys are derived using industry-standard key derivation functions with strict separation of concerns.

#### Password Hashing

User and SMTP credential passwords are hashed using a memory-hard algorithm designed to make brute-force attacks economically infeasible. Each credential has a unique salt.

#### Per-Organization Encryption Keys

Each organization has its own encryption key:

- Keys are rotated periodically without downtime.
- When you delete your account, your encryption keys are permanently destroyed, making your data irrecoverable.

### Tracking Token Security

Tracking links (open tracking, click tracking, and unsubscribe links) are encrypted and signed to prevent tampering. The original destination URL is protected and cannot be modified by third parties.

Tracking tokens have limited lifetimes. Expired tokens display a friendly page prompting the recipient to request a fresh link.

---

## Tenant Isolation

ApexMail enforces strict tenant isolation at every layer of the stack. No tenant can access, modify, or infer the existence of another tenant's data.

### Data-Level Isolation

Tenant isolation is enforced at the data level:

- All queries are automatically scoped to the authenticated tenant, independent of application logic.
- Destructive or administrative operations require elevated privileges.
- Defense-in-depth ensures that no single layer failure can result in cross-tenant data access.

### Application-Level Scoping

In addition to data-level isolation, every API request is scoped to the authenticated tenant:

- Data belonging to other tenants is never accessible, even in memory.
- Authorization is enforced before data retrieval, not after.

### Rate Limiting Scoping

Rate limits are scoped per tenant:

- Each tenant's API rate limit is tracked independently.
- One tenant hitting their rate limit does not affect other tenants.
- Rate limits are tracked independently per tenant.

### Cache Isolation

All cached data is scoped per tenant. One tenant's cached data is never served to another tenant, preventing cache-based cross-tenant data leakage.

---

## GDPR Compliance

ApexMail provides comprehensive GDPR (General Data Protection Regulation) compliance tooling, managed primarily through the **compliance** application.

### Data Subject Rights

The platform supports all data subject rights defined in GDPR Articles 15–22:

| Right                    | GDPR Article | Implementation                                              |
|--------------------------|--------------|--------------------------------------------------------------|
| Right of access          | Art. 15      | Export all data associated with a data subject               |
| Right to erasure         | Art. 17      | Delete all data associated with a data subject               |
| Right to portability     | Art. 20      | Export data in machine-readable JSON format                   |
| Right to rectification   | Art. 16      | Update/correct personal data                                  |
| Right to restriction     | Art. 18      | Restrict processing of personal data                          |
| Right to object          | Art. 21      | Opt out of processing for specific purposes                   |

### DSAR Management Workflow

Data Subject Access Requests (DSARs) follow a structured workflow:

```
┌──────────┐     ┌──────────┐     ┌────────────┐     ┌────────────────────┐
│ Pending  │────▶│ Verified │────▶│ Processing │────▶│ Completed/Rejected │
└──────────┘     └──────────┘     └────────────┘     └────────────────────┘
```

1. **Pending**: DSAR received, awaiting identity verification of the data subject.
2. **Verified**: Data subject identity confirmed. The request is queued for processing.
3. **Processing**: The system is actively fulfilling the request (data export, deletion, etc.).
4. **Completed**: The request has been fulfilled and the data subject notified.
5. **Rejected**: The request was denied (e.g., identity verification failed, request outside GDPR scope).

### SLA Deadline Tracking

- GDPR mandates a **30-day response deadline** for DSARs (extendable to 90 days for complex requests).
- The compliance application tracks the deadline for each DSAR.
- **Overdue detection**: DSARs approaching or past their deadline are automatically escalated to the data protection officer (DPO).
- Dashboard visibility: Overdue and at-risk DSARs are surfaced in the compliance dashboard.

### Right to Be Forgotten

When a data subject exercises the right to erasure (Art. 17):

1. All PII associated with the data subject is permanently deleted from the database.
2. Email content, tracking events, and analytics data referencing the subject are purged.
3. The subject's email address is added to a permanent suppression list (hashed) to prevent re-collection.
4. Audit log entries are retained (with PII redacted) for compliance evidence.
5. Deletion cascades to all related data: analytics, billing records (anonymized), and logs.

### Consent Ledger

The consent ledger provides cryptographic proof of consent:

- Every consent event (grant, revocation, modification) is cryptographically recorded with timestamp, data subject identifier, purpose of processing, and consent source.
- Consent records are **append-only** — revocations are recorded as new entries, not modifications.
- Records are cryptographically linked to provide tamper evidence.

### Data Retention

Data retention periods vary by plan. Higher-tier plans offer longer retention. You can view your plan's retention period in **Settings → Billing**.

- **Auto-delete**: You can configure automatic deletion of data beyond the retention window in your account settings.
- **Retention scope**: Retention applies to email event data (opens, clicks, bounces), analytics aggregates, and webhook delivery logs. Core account data (domains, API keys, settings) is retained until account deletion.
- Expired data is automatically purged according to the retention schedule.

---

## CCPA Compliance

The California Consumer Privacy Act (CCPA) is supported within the same compliance framework as GDPR:

- **Right to know**: Covered by the data access/portability DSAR workflow.
- **Right to delete**: Covered by the erasure DSAR workflow.
- **Right to opt-out of sale**: ApexMail does not sell personal data. A "Do Not Sell" signal is respected and recorded.
- **Non-discrimination**: Service is not degraded for users who exercise CCPA rights.
- **Applicability**: CCPA features are available to all tenants but are specifically surfaced for tenants who indicate California-based data subjects.

---

## Audit Logging

ApexMail maintains a comprehensive, tamper-evident audit log of all security-relevant and compliance-relevant events.

### Cryptographic Hash Chain

Each audit log entry is cryptographically chained to the previous entry:

- Entries are hashed and signed, creating a tamper-evident chain.
- Any modification to a historical entry breaks the chain.
- Verification traverses the chain to detect inconsistencies.

### Event Types

Over **40 event types** are tracked, including but not limited to:

| Category          | Example Events                                                    |
|-------------------|-------------------------------------------------------------------|
| Authentication    | Login success/failure, API key creation/revocation, MFA enable    |
| Authorization     | Permission change, role assignment, tenant switch                 |
| Data access       | PII export, contact list download, DSAR initiated                 |
| Data modification | Contact update, domain verification, template edit                |
| Configuration     | Webhook URL change, sending domain update, plan upgrade           |
| Sending           | Campaign launch, send paused/resumed, suppression override        |
| Compliance        | Consent recorded, DSAR completed, data retention purge            |
| Security          | Rate limit triggered, brute-force block, suspicious activity      |

### Chain Integrity Verification

- **On-demand verification**: Administrators can trigger a full chain verification from the control plane.
- **Scheduled verification**: The most recent segment of the chain is verified automatically on a regular schedule.
- **Alerting**: Chain integrity failures trigger an immediate security alert.

### Retention and Export

| Parameter            | Value                          |
|----------------------|--------------------------------|
| Default retention    | Extended (configurable)        |
| Export formats       | JSON, CSV                      |
| Export access        | Admin role only                |

Audit logs can be exported for external compliance review, legal discovery, or integration with a SIEM system.

---

## Data Residency

| Aspect              | Detail                                         |
|----------------------|------------------------------------------------|
| Primary storage      | Region-constrained per deployment policy        |
| Backup storage       | Region-constrained per deployment policy        |
| Data sovereignty     | Configured according to tenant contract and environment |

- Cross-region transfer behavior follows tenant contract and deployment configuration.
- Data residency controls are enforced at the infrastructure and service policy layers.

---

## Sub-Processors

ApexMail uses the following sub-processors for specific operational functions:

Sub-processor details are available on request and in our Data Processing Agreement. All infrastructure sub-processors are located within the EU. A current sub-processor list is maintained at [apexmail.ee/legal/sub-processors](https://apexmail.ee/legal/sub-processors).

- Each sub-processor has a Data Processing Agreement (DPA) in place.
- Sub-processor changes are communicated to customers with 30-day advance notice.
- Stripe processes payment data under PCI DSS compliance; ApexMail does not store raw credit card numbers.

---

## Data Processing Agreement (DPA)

ApexMail's DPA includes the following commitments:

| Provision                  | Detail                                                    |
|----------------------------|-----------------------------------------------------------|
| Encryption standard        | AES-256 for data at rest                                   |
| Processing location        | EU only                                                    |
| Breach notification        | Within 48 hours of confirmed breach                        |
| Data deletion              | Within 30 days of contract termination                     |
| Audit rights               | Customer may audit upon reasonable notice                   |
| Sub-processor notification | 30-day advance notice of sub-processor changes             |

The DPA is available for execution by all customers and is automatically included in Enterprise plan agreements.

---

## Cookies and Tracking

- **No third-party tracking cookies**: ApexMail does not set or rely on third-party cookies.
- **First-party cookies**: Limited to session management (authenticated control plane sessions) and CSRF protection.
- **Email tracking**: Open and click tracking use first-party pixel and redirect mechanisms. No cookies are set during tracking — tracking relies entirely on encrypted token parameters in the URL.
- **DNT / GPC**: The Do Not Track and Global Privacy Control signals are respected and logged.
