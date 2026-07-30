# GDPR Compliance Framework

> **Classification:** Internal Policy
> **Owner:** Data Protection Lead, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Annually, or upon material change in processing activities

---

## 1. Scope

This document defines how ApexMail (operated by Bel Consulting OÜ) complies with
Regulation (EU) 2016/679 (General Data Protection Regulation). It covers all personal
data processed through the ApexMail platform, internal tooling, and supporting
infrastructure hosted on Hetzner Cloud ARM servers in the European Union.

---

## 2. Roles and Responsibilities

### 2.1 Data Controller vs Data Processor

| Role | Party | Description |
|------|-------|-------------|
| **Data Controller** | ApexMail Customer | Determines the purposes and means of processing their end-users' personal data (e.g., recipient lists, email content). |
| **Data Processor** | Bel Consulting OÜ | Processes personal data on behalf of the controller according to documented instructions. |
| **Sub-processor** | Hetzner Online GmbH | Infrastructure provider; hosts compute and storage in EU data centres. |

Bel Consulting OÜ acts as a **data controller** for:

- Account registration data of ApexMail customers (name, email, billing info).
- Usage analytics collected for platform operation and improvement.
- Employee and contractor data.

Bel Consulting OÜ acts as a **data processor** for:

- Recipient lists uploaded by customers.
- Email content composed and sent by customers.
- Engagement events (opens, clicks) tied to identifiable recipients.

### 2.2 Data Protection Officer (DPO)

Given the current scale of operations, a formal DPO appointment is not legally
required under Article 37. However, the Data Protection Lead assumes equivalent
responsibilities internally and is the point of contact for the Estonian Data
Protection Inspectorate (Andmekaitse Inspektsioon).

---

## 3. Lawful Bases for Processing

Each processing activity must be mapped to one of the six lawful bases under
Article 6(1). The primary bases used by ApexMail:

| Processing Activity | Lawful Basis | GDPR Article |
|---------------------|--------------|--------------|
| Customer account management | Contract performance | Art. 6(1)(b) |
| Sending emails on behalf of customers | Contract performance (processor obligation) | Art. 6(1)(b) / Art. 28 |
| Billing and invoicing | Contract performance / Legal obligation | Art. 6(1)(b), (c) |
| Platform security monitoring | Legitimate interest | Art. 6(1)(f) |
| Marketing communications to customers | Consent | Art. 6(1)(a) |
| Aggregate analytics (anonymised) | N/A (not personal data post-anonymisation) | Recital 26 |
| Abuse detection and prevention | Legitimate interest | Art. 6(1)(f) |

A **Legitimate Interest Assessment (LIA)** is documented for each activity relying
on Art. 6(1)(f).

---

## 4. Data Minimisation Principles

1. **Collect only what is necessary.** Registration requires only email, password
   hash, and organisation name. Additional fields are optional.
2. **Retention limits.** Every data category has a defined retention period (see
   [Data Retention Policy](./data-retention.md)).
3. **Pseudonymisation.** Engagement events (opens/clicks) are stored with hashed
   recipient identifiers where feasible. Raw email addresses are separated from
   event logs after aggregation windows close.
4. **No unnecessary copies.** Email content is stored in PostgreSQL only for the
   retention window. No additional copies are made outside the primary database
   and its encrypted backups.

---

## 5. Consent Management

Where consent is the lawful basis (e.g., marketing emails to ApexMail customers):

- Consent is **freely given, specific, informed, and unambiguous** (Art. 7).
- Collected via explicit opt-in (no pre-ticked boxes).
- Recorded with timestamp, IP address, and the exact wording presented.
- Withdrawal is as easy as giving consent (one-click unsubscribe).
- Withdrawal is processed within **24 hours** in automated flows.

For customer-managed consent (their recipients):

- ApexMail provides list management tools including double opt-in support.
- Customers are contractually required (via Terms of Service and DPA) to have a
  valid lawful basis for each recipient they upload.
- ApexMail enforces unsubscribe link requirements in all outbound emails.

---

## 6. Data Subject Rights

ApexMail supports the following rights, distinguishing between direct data subjects
(ApexMail customers) and indirect data subjects (recipients of customer emails):

### 6.1 Right of Access (Art. 15)

- **Customers:** Can export all account data via the dashboard or API.
- **Recipients:** Requests are forwarded to the relevant customer (data controller).
  ApexMail assists the controller in fulfilling the request within 30 days.

### 6.2 Right to Rectification (Art. 16)

- **Customers:** Can update account data directly in the dashboard.
- **Recipients:** Handled by the data controller. ApexMail provides APIs to update
  recipient records.

### 6.3 Right to Erasure (Art. 17)

- **Customers:** Account deletion removes all personal data within 30 days.
  Backups containing the data are purged within the backup retention window.
- **Recipients:** Controllers can delete individual recipients via API or dashboard.
  ApexMail also supports bulk suppression list imports for erasure.

### 6.4 Right to Data Portability (Art. 20)

- **Customers:** Full data export in JSON and CSV formats via API.
- **Recipients:** Recipient data is exportable by the data controller.

### 6.5 Right to Restriction of Processing (Art. 18)

- Supported via account suspension functionality. Data is retained but not
  actively processed while restriction is in effect.

### 6.6 Right to Object (Art. 21)

- Customers can object to processing based on legitimate interest. Objections
  are assessed on a case-by-case basis within 30 days.

---

## 7. Data Processing Agreement (DPA)

A DPA is executed with every customer in accordance with Article 28. The DPA covers:

### 7.1 Template Structure

1. **Parties and definitions** — Controller (customer), Processor (Bel Consulting OÜ).
2. **Subject matter and duration** — Email sending and analytics for the contract term.
3. **Nature and purpose of processing** — Delivery of transactional and marketing emails.
4. **Categories of data subjects** — Customer's email recipients.
5. **Types of personal data** — Email address, name (if provided), engagement data.
6. **Obligations of the processor** — Process only on documented instructions, ensure
   confidentiality, implement appropriate security measures.
7. **Sub-processors** — Listed with notification procedure for changes (14-day advance
   notice; customer may object).
8. **International transfers** — Details on safeguards (see §9).
9. **Audit rights** — Customer may request evidence of compliance annually.
10. **Data breach notification** — Processor notifies controller without undue delay
    (see §8).
11. **Return and deletion of data** — Upon contract termination.

### 7.2 Current Sub-processors

| Sub-processor | Purpose | Location |
|---------------|---------|----------|
| Hetzner Online GmbH | Infrastructure (compute, storage) | EU (Germany/Finland) |

---

## 8. Data Breach Notification

### 8.1 Detection

Breaches may be detected through:

- Automated monitoring and alerting (see [Incident Response](./incident-response.md)).
- Employee or contractor reports.
- External reports via the security contact.

### 8.2 Internal Escalation

Upon detection, the incident response process is triggered immediately. The Data
Protection Lead is notified within **1 hour** of confirmed breach identification.

### 8.3 Notification to Supervisory Authority

Under Article 33, breaches involving personal data must be reported to the
**Andmekaitse Inspektsioon** (Estonian DPA) within **72 hours** of becoming aware of
the breach, unless the breach is unlikely to result in a risk to data subjects.

The notification includes:

- Nature of the breach (categories and approximate number of data subjects).
- Contact details of the Data Protection Lead.
- Likely consequences of the breach.
- Measures taken or proposed to address the breach.

### 8.4 Notification to Data Subjects

Under Article 34, where the breach is likely to result in a **high risk** to the
rights and freedoms of data subjects, affected individuals are notified **without
undue delay**. Notification is made in clear, plain language and includes:

- Nature of the breach.
- Likely consequences.
- Measures taken to mitigate.
- Advice on protective steps data subjects can take.

### 8.5 Notification to Customers (Controller Notification)

As a data processor, Bel Consulting OÜ notifies affected customers (data
controllers) **without undue delay** upon becoming aware of a breach involving their
data, enabling controllers to fulfil their own notification obligations.

---

## 9. Cross-Border Transfer Safeguards

### 9.1 Current Data Residency

All primary data processing and storage occurs within the EU:

- **Compute:** Hetzner Cloud ARM servers (EU data centres).
- **Database:** PostgreSQL (hosted on Hetzner, EU).
- **Cache:** Redis (hosted on Hetzner, EU).
- **Backups:** Stored on Hetzner, EU.

### 9.2 Transfers Outside the EEA

Currently, no personal data is routinely transferred outside the EEA. If a transfer
becomes necessary (e.g., new sub-processor):

1. **Adequacy decision** — Preferred where available (Art. 45).
2. **Standard Contractual Clauses (SCCs)** — EU Commission-approved SCCs
   (Commission Implementing Decision 2021/914) are used where no adequacy
   decision exists.
3. **Transfer Impact Assessment (TIA)** — Conducted before engaging any
   sub-processor outside the EEA to evaluate the legal framework of the
   recipient country.

### 9.3 Customer Data Localisation

All customer data remains in the EU. There is no option to store data outside
the EU at this time.

---

## 10. Data Protection Impact Assessment (DPIA)

### 10.1 When Required

A DPIA is conducted before any processing that is likely to result in a **high risk**
to data subjects, including:

- Large-scale processing of personal data.
- Systematic monitoring of individuals.
- Introduction of new technologies that process personal data.
- AI/ML model training on data that includes personal identifiers.

### 10.2 DPIA Process

1. **Description** of the processing (purpose, scope, context).
2. **Necessity and proportionality** assessment.
3. **Risk identification** — Risks to data subjects' rights and freedoms.
4. **Mitigation measures** — Technical and organisational controls.
5. **Consultation** — If residual risk remains high, consult the supervisory authority
   (Art. 36).

### 10.3 Current DPIAs

| Processing Activity | Status | Last Reviewed |
|---------------------|--------|---------------|
| Email sending pipeline | Completed | 2025-11-01 |
| AI-powered content analysis | Completed | 2025-12-15 |
| Engagement tracking (opens/clicks) | Completed | 2025-10-20 |

---

## 11. Record of Processing Activities (ROPA)

Maintained under Article 30. The register includes:

### 11.1 As Data Controller

| Activity | Data Categories | Lawful Basis | Retention | Recipients |
|----------|----------------|--------------|-----------|------------|
| Customer registration | Name, email, password hash | Contract | Duration + 30d | Internal only |
| Billing | Name, address, payment ref | Contract / Legal | 7 years (accounting) | Payment processor |
| Support tickets | Name, email, ticket content | Contract | 2 years | Internal only |
| Platform analytics | Anonymised usage data | N/A | 2 years | Internal only |

### 11.2 As Data Processor

| Activity | Data Categories | Controller | Retention | Sub-processors |
|----------|----------------|------------|-----------|----------------|
| Email delivery | Recipient email, name, content | Customer | Per retention policy | Hetzner |
| Engagement tracking | Email, IP (hashed), user agent | Customer | 90d / 365d (enterprise) | Hetzner |
| List management | Recipient PII per controller | Customer | Duration of contract | Hetzner |

---

## 12. Technical and Organisational Measures

Summary of measures under Article 32 (detailed in related policies):

- **Encryption at rest:** PostgreSQL with encrypted volumes.
- **Encryption in transit:** TLS 1.2+ for all connections.
- **Access control:** RBAC, MFA enforcement (see [Access Control](./access-control.md)).
- **Pseudonymisation:** Hashed identifiers in event logs.
- **Backup integrity:** Encrypted backups with integrity checks.
- **Incident response:** Documented procedure (see [Incident Response](./incident-response.md)).
- **Vulnerability management:** Regular scanning and patching (see [Vulnerability Management](./vulnerability-management.md)).
- **Change management:** Controlled deployment process (see [Change Management](./change-management.md)).

---

## 13. Training and Awareness

- All team members complete GDPR awareness training upon onboarding.
- Annual refresher training is mandatory.
- Role-specific training for personnel handling personal data.
- Training records are maintained.

---

## 14. Review and Updates

This policy is reviewed:

- **Annually** as part of the compliance review cycle.
- **Upon material changes** to processing activities, infrastructure, or applicable law.
- **After data protection incidents** to incorporate lessons learned.

Changes are tracked in version control and communicated to the team.
