# Data Retention Policy

> **Classification:** Internal Policy
> **Owner:** Data Protection Lead, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16192499, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Annually

---

## 1. Purpose

This policy defines how long each category of data is retained on the ApexMail
platform and the procedures for secure deletion. It supports GDPR data minimisation
(Art. 5(1)(e)) and ensures data is not kept longer than necessary for its stated
purpose.

---

## 2. Scope

Applies to all data stored, processed, or backed up by the ApexMail platform,
including data held in PostgreSQL, Redis, object storage, and encrypted backups on
Hetzner infrastructure (EU).

---

## 3. Retention Schedule

### 3.1 Customer-Generated Data

| Data Category | Default Retention | Enterprise Retention | Notes |
|---------------|-------------------|---------------------|-------|
| **Email content** (body, subject, headers) | 30 days after send | Configurable (up to 90 days) | Stored in PostgreSQL. Purged automatically. |
| **Recipient lists** | Duration of contract | Duration of contract | Deleted within 30 days of account closure. |
| **Email templates** | Duration of contract | Duration of contract | Part of account data. |
| **Attachments / hosted images** | 30 days after send | Configurable (up to 90 days) | Stored in object storage. |

### 3.2 Event and Analytics Data

| Data Category | Default Retention | Enterprise Retention | Notes |
|---------------|-------------------|---------------------|-------|
| **Event logs** (sends, deliveries, bounces, opens, clicks) | 90 days | 365 days | Contains recipient identifiers (hashed after aggregation). |
| **Analytics aggregates** (campaign stats, trends) | 2 years | 2 years | Anonymised/aggregated. No PII. |
| **Webhook delivery logs** | 30 days | 90 days | Contains endpoint URLs and response codes. |
| **API request logs** | 30 days | 90 days | Contains API keys (masked) and request metadata. |

### 3.3 Account and Administrative Data

| Data Category | Retention Period | Notes |
|---------------|-----------------|-------|
| **Account data** (name, email, org) | Duration of contract + 30 days | Deleted after account closure grace period. |
| **Billing records** | 7 years | Required by Estonian accounting law (Raamatupidamise seadus). |
| **Support tickets** | 2 years after resolution | May contain PII; reviewed before purge. |
| **Consent records** | Duration of consent + 3 years | Proof of consent for regulatory purposes. |

### 3.4 System and Security Data

| Data Category | Retention Period | Notes |
|---------------|-----------------|-------|
| **Audit logs** (admin actions, access logs) | 1 year minimum | Extended to 2 years for enterprise. |
| **Security incident records** | 1 year minimum after closure | Longer if legal proceedings anticipated. |
| **Application error logs** | 30 days | No PII in error logs by design. |
| **Infrastructure metrics** (CPU, memory, disk) | 90 days | No PII. |

### 3.5 Backups

| Backup Type | Retention Period | Notes |
|-------------|-----------------|-------|
| **Database backups** (PostgreSQL) | 30 days rolling | Encrypted at rest. Oldest backup deleted as new one is created. |
| **Redis snapshots** | 7 days | Ephemeral cache data. |
| **Configuration backups** | 90 days | Infrastructure-as-code; also in version control. |

---

## 4. Deletion Procedures

### 4.1 Automated Deletion

The following deletions are performed automatically by scheduled jobs:

- **Email content:** Daily job purges content older than the retention window.
- **Event logs:** Weekly job archives and then deletes logs past retention.
- **API request logs:** Daily rotation and purge.
- **Backups:** Oldest backup replaced on each backup cycle.

All automated deletion jobs are logged and monitored. Failures trigger alerts.

### 4.2 Manual Deletion (Account Closure)

When a customer closes their account:

1. Account is marked as `pending_deletion`.
2. Customer has a **30-day grace period** to reactivate or export data.
3. After 30 days, all customer data is permanently deleted:
   - Recipient lists.
   - Email content and templates.
   - Event logs and analytics.
   - API keys and webhooks.
4. Billing records are retained per §3.3 (7 years).
5. Deletion confirmation is logged in the audit trail.

### 4.3 Backup Purge

Data deleted from the primary database will persist in backups until the backup
retention window expires (30 days). This is documented in the DPA and communicated
to customers. No individual record restoration from backups is performed after
deletion.

---

## 5. GDPR Erasure Procedures

### 5.1 Customer Erasure Requests (Controller)

When Bel Consulting OÜ acts as data controller (customer account data):

1. Request received via email or dashboard.
2. Identity verified.
3. Data erased within **30 days** (Art. 17).
4. Confirmation sent to the data subject.
5. Exceptions: Data required for legal obligations (e.g., billing records) is
   retained with restricted processing.

### 5.2 Recipient Erasure Requests (Processor)

When a recipient contacts ApexMail directly:

1. Request forwarded to the data controller (the ApexMail customer).
2. ApexMail assists the controller in fulfilling the request.
3. If the controller is unreachable or unresponsive after 14 days, ApexMail may
   suppress the recipient address across the controller's account to prevent
   further processing.

### 5.3 Suppression Lists

Erased email addresses are added to a hashed suppression list to prevent
accidental re-import. The suppression list contains only a one-way hash of the
email address — no other personal data.

---

## 6. Data Export

Customers may export their data at any time via:

- **Dashboard:** CSV/JSON export of lists, campaigns, and analytics.
- **API:** Programmatic export of all account data.
- **Support request:** Full account export provided within 5 business days.

Exported data is provided in machine-readable formats (JSON, CSV) per GDPR
Art. 20 (right to data portability).

---

## 7. Exceptions

Retention periods may be extended in the following cases:

- **Legal hold:** Data subject to ongoing or anticipated legal proceedings.
- **Regulatory investigation:** Data requested by a supervisory authority.
- **Customer request:** Enterprise customers may contractually agree to extended
  retention within the bounds of GDPR.

All exceptions are documented with justification, approved by the Data Protection
Lead, and reviewed quarterly.

---

## 8. Monitoring and Compliance

- Automated retention jobs are monitored and alert on failure.
- Quarterly audit verifies that data older than retention periods has been purged.
- Annual review of retention periods against business needs and legal requirements.

---

## 9. Related Documents

- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Access Control Policy](./access-control.md)
- [Incident Response Plan](./incident-response.md)
