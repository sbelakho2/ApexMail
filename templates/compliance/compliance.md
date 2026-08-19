# Compliance

**Last Updated:** {{LAST_UPDATED}}

This page describes ApexMail's compliance posture against relevant regulatory frameworks. It is separate from the [Security](trust-center.md) page, which covers technical security controls. Use this page to understand ApexMail's responsibilities and your responsibilities under each framework.

**Operated by {{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, {{ADDRESS}}, Republic of Estonia.

---

## GDPR (General Data Protection Regulation)

### ApexMail's Role

ApexMail acts as a **data processor** when processing personal data on behalf of customers (data controllers). Customers determine the purposes and means of processing personal data sent through the ApexMail platform. ApexMail processes that data only as instructed by the customer and as necessary to provide the email delivery service.

In limited contexts (e.g., account registration data, billing information), ApexMail acts as a **data controller** for its own business operations.

### DPA Availability

A standard [Data Processing Agreement (DPA)](../legal/dpa.md) is publicly available and pre-signed. The DPA includes:
- Subject matter, nature, and duration of processing
- Categories of data subjects and personal data
- ApexMail's obligations as processor
- Customer's obligations as controller
- Technical and organizational measures (see [Security Measures](security-measures.md))
- Subprocessor management obligations
- Data subject request assistance
- Breach notification obligations (within 48 hours of discovery)
- Deletion and return of data at contract end
- Audit and inspection rights

### Subprocessors

ApexMail uses the following categories of subprocessors. The full list with named entities is maintained at [Subprocessors](subprocessors.md).

| Category | Purpose | Data Accessed |
|---|---|---|
| Cloud Infrastructure (Hetzner) | Hosting and compute | Encrypted at rest |
| Email Infrastructure | SMTP relay and delivery | Message content, sender/recipient |
| Monitoring and Logging | Service health, error tracking | Metadata (not message body) |
| Payment Processing (Stripe) | Billing | Payment information (not stored by ApexMail) |
| Customer Support | Ticket management | Account metadata, support history |

All subprocessors are bound by data processing agreements with terms no less protective than ApexMail's DPA. Subprocessor changes are communicated to customers at least 30 days in advance.

### Data Subject Rights Support

ApexMail provides the following mechanisms to assist customers in fulfilling data subject requests (DSRs):

| Right | How ApexMail Supports It |
|---|---|
| Right of Access | Customer can export message data, events, and account information via API or dashboard export |
| Right of Rectification | Customer can update account data; email content cannot be retroactively modified after sending |
| Right of Erasure | Customer can delete account data, message logs, and recipient data via dashboard or API |
| Right of Restriction | Customer can pause processing for specific domains or accounts |
| Right of Portability | Data export in machine-readable JSON/CSV format via API |
| Right to Object | Customer can cease sending to specific recipients via suppression lists |
| Automated Decisions | ApexMail does not perform automated decision-making on personal data |

Customers should direct DSR requests to their account administrator. ApexMail will assist within 14 calendar days of receipt.

### Deletion Process

- Account owners can initiate full data deletion from the dashboard (Settings > Account > Delete Account).
- Deletion is irreversible after a 7-day grace period.
- Message content, metadata, events, templates, domains, and API keys are permanently deleted within 30 days.
- Backup data expires according to the standard retention rotation (maximum 12 months).
- A deletion confirmation certificate is provided upon request.

### Export Process

- Message events and delivery logs can be exported via the Events API or dashboard export.
- Account data export (JSON format) is available from Settings > Account > Export Data.
- Template and domain configurations can be exported via API.

### Breach Notification

- ApexMail notifies customers of a confirmed personal data breach without undue delay and no later than 48 hours after discovery (per DPA).
- The notification includes: nature of the breach, categories and approximate number of affected records, likely consequences, measures taken or proposed.
- Data Protection Lead assesses regulatory notification obligations. The Estonian Data Protection Inspectorate (AKI) is notified within 72 hours if the breach is likely to result in risk to data subjects.
- Affected data subjects are notified without undue delay if the breach is likely to result in high risk.

### Data Location

The supplied deployment configuration targets European Union / European Economic Area regions for core service data and telemetry. Active regions, storage providers, and backup locations are deployment-specific and are confirmed in the applicable agreement. See [Data Locations](data-locations.md) for full details.

### Transfer Safeguards

- The supplied configuration defaults core service and telemetry object storage to EU/EEA regions; active storage locations must be confirmed for the deployed environment.
- If a transfer is required (e.g., for a customer using a non-EU recipient email provider), the transfer occurs as part of the email delivery process (inherent to SMTP email routing).
- Standard Contractual Clauses (SCCs) or another valid transfer mechanism are used where an active provider or deployment transfers personal data outside the EU/EEA. The email delivery SMTP path is outside ApexMail's control and is an inherent function of internet email.

### Customer Responsibilities

- Determine the legal basis for processing personal data through ApexMail.
- Ensure appropriate notice has been provided to data subjects.
- Configure suppression lists, unsubscribe handling, and data retention settings per your policies.
- Respond to data subject requests received directly; ApexMail assists on instruction.
- Ensure the DPA is executed and maintained.
- Notify ApexMail of any processing instructions that differ from the standard DPA.

---

## HIPAA (Health Insurance Portability and Accountability Act)

### Current Status

**Not currently available.** ApexMail is focused on EU data protection compliance (GDPR). HIPAA compliance is not part of the current roadmap.

### BAA Availability

A [Business Associate Agreement (BAA) template](../../docs/compliance/baa-template.md) is available for customers who require HIPAA-equivalent contractual protections under EU regulatory frameworks. The BAA template can be adapted for specific regulatory requirements upon request.

### Which Plans May Be Eligible in the Future

If HIPAA compliance were to be added in the future, it would apply to:
- **Eligible plans**: Enterprise and Dedicated Tenant only.
- **Eligible deployment**: Private Cloud or dedicated infrastructure.
- **Not eligible**: Free, Developer, Pro, Growth, Business (shared multi-tenant infrastructure).

### Current Restrictions

- Protected Health Information (PHI) should not be sent through ApexMail in its current state.
- No Business Associate Agreement is in effect.
- No HIPAA security rule compliance attestation is available.
- Customers requiring HIPAA compliance should discuss alternative arrangements with our sales team.

### Required Customer Configuration (If Available in Future)

If HIPAA support is offered, customers would need to:
- Execute a BAA before sending PHI.
- Use a Dedicated Tenant or Private Cloud deployment.
- Configure data retention to align with HIPAA requirements.
- Disable features that log message content in accessible logs.
- Restrict support access (support personnel would not access PHI without explicit authorization).
- Enable audit logging for all PHI access events.

---

## SOC 2 (System and Organization Controls)

### Current Status

**SOC 2 Type I**: Planned — readiness assessment in progress.
**SOC 2 Type II**: Planned — after Type I completion.

### Scope

The planned SOC 2 audit scope covers the ApexMail multi-tenant platform:
- API (REST and SMTP)
- Message queue and processing
- Dashboard and authentication
- Webhook delivery
- Billing system

The Trust Services Criteria being evaluated are:
- **Security**: Information and systems are protected against unauthorized access.
- **Availability**: Information and systems are available for operation and use.
- **Confidentiality**: Information designated as confidential is protected.
- **Processing Integrity**: System processing is complete, valid, accurate, timely, and authorized.

**Privacy** is not currently included in scope (GDPR compliance covers equivalent territory).

### Type I vs. Type II

- **Type I**: Assessment of the design of controls at a point in time. Target: Q3 2027.
- **Type II**: Assessment of the operating effectiveness of controls over a period (minimum 6 months). Target: Q2 2028.

### Report Availability

- SOC 2 reports are not yet available.
- Once available, reports will be provided under NDA to customers and prospects upon request.
- Bridge letters will be available between report periods.

### Target Timeline

The timeline is credible and resourced:
1. Q1 2027: Complete readiness assessment (internal gap analysis).
2. Q2 2027: Remediate identified gaps.
3. Q3 2027: Select external auditor (CPA firm) and complete Type I audit.
4. Q4 2027 - Q2 2028: Monitoring period for Type II.
5. Q2 2028: Complete Type II audit.

---

## ISO 27001 (Information Security Management)

### Current Status

**Planned** — To be evaluated based on customer demand. ISO 27001 is on the roadmap but is not the current priority (GDPR and SOC 2 are prioritized first). If multiple enterprise customers require ISO 27001 certification, the timeline will be accelerated.

### Applicable Standards

- **ISO 27001:2022** — Information Security Management System (ISMS) requirements.
- **ISO 27017** — Cloud-specific information security controls.
- **ISO 27018** — Protection of personally identifiable information (PII) in public clouds.

### Customer Responsibility

- Customers are responsible for their own ISO 27001 certification scope.
- ApexMail's ISO 27001 certification would cover the ApexMail platform as a service provider; it does not automatically extend to the customer's broader ISMS scope.
- Customers may reference ApexMail's certification in their own ISMS scope as an external service provider.

---

## Other Frameworks

### PCI DSS

**Not applicable.** ApexMail does not store, process, or transmit credit card data. Payment processing is handled entirely by Stripe, which is PCI DSS Level 1 certified. The payment form on the ApexMail dashboard is hosted by Stripe (Stripe Elements); card data never touches ApexMail servers.

### CCPA / CPRA

ApexMail is an EU-based company. CCPA/CPRA assessment is available upon request for customers who process California residents' data through the platform. As a service provider (processor), ApexMail does not sell personal information and processes data only for the purpose of providing the email delivery service.

### UK GDPR

Following the UK's withdrawal from the EU, ApexMail processes UK-resident personal data under the UK GDPR framework. The standard DPA includes UK-specific provisions. ApexMail maintains an EU representative where required. The UK Information Commissioner's Office (ICO) is the relevant supervisory authority for UK-related data protection matters.

### Swiss FADP

ApexMail processing of personal data from Switzerland is conducted under the revised Swiss Federal Act on Data Protection (nFADP). The standard DPA covers Swiss-specific obligations. The Swiss Federal Data Protection and Information Commissioner (FDPIC) is the relevant supervisory authority.

---

## Certification and Assurance Summary

See the [Trust Center](trust-center.md#certifications-and-audit-status) for the current certification and framework status table with status, scope, assessor, and timeline information.

---

## Document Requests

Compliance-related documents (DPA, subprocessor list, BAA template, security measures summary) are public or available under NDA. See the [Trust Center](trust-center.md#document-requests) for the full document availability matrix.

---

## Contact

Compliance inquiries: **{{PRIVACY_EMAIL}}**
Security inquiries: **{{SECURITY_EMAIL}}**
Data Protection Lead: **{{PRIVACY_EMAIL}}**
General inquiries: **{{SUPPORT_EMAIL}}**
