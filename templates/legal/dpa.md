# Data Processing Agreement (DPA)

**Last Updated:** {{LAST_UPDATED}}

This Data Processing Agreement ("DPA") forms part of the Terms of Service between:

- **Data Controller**: The Customer (as defined in the Terms).
- **Data Processor**: **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, VAT **{{VAT_NUMBER}}**, registered address **{{ADDRESS}}**, Republic of Estonia ("ApexMail").

This DPA applies where ApexMail processes Personal Data on behalf of the Customer in the course of providing the Service, to the extent that GDPR (Regulation (EU) 2016/679) applies.

## 1. Definitions

Capitalized terms not defined here have the meaning given in the Terms or in GDPR. "Personal Data", "Data Subject", "Processing", "Controller", "Processor", "Subprocessor", "Personal Data Breach", and "Supervisory Authority" have the meanings defined in GDPR Art. 4.

## 2. Processing Instructions

### 2.1 Scope and Purpose

ApexMail shall process Personal Data only:
- On documented instructions from the Customer (including as set out in the Terms and this DPA).
- As required by applicable EU or Member State law, in which case ApexMail shall inform the Customer before processing unless the law prohibits such notification.

### 2.2 Nature and Purpose of Processing

Provision of the ApexMail email infrastructure service, including sending, receiving, tracking, and analyzing email communications, and related support and security functions.

### 2.3 Data Categories

- Email addresses of Customer's Recipients.
- Names of Recipients (if provided by Customer).
- Email content (subject, body, headers, attachments).
- Delivery and engagement metadata (timestamps, statuses, open/click events).
- Technical data (IP addresses, user agents associated with engagement events).

### 2.4 Data Subjects

- Customer's Recipients (individuals receiving email via the Service).
- Customer's Account Users (individuals using the ApexMail dashboard and API).

### 2.5 Duration

For the term of the Agreement plus the post-termination retention period specified in the Privacy Policy (30 days for account data). Email content and event metadata follow the retention categories of ApexMail's retention policy: message content defaults to 7 days and event metadata to 30 days, both plan-dependent and capped at 365 days for Enterprise customers.

## 3. Confidentiality

ApexMail shall ensure that persons authorized to process Personal Data are bound by appropriate confidentiality obligations, whether contractual or statutory.

## 4. Security Measures

### 4.1 Technical and Organizational Measures (TOMs)

ApexMail implements and maintains the technical and organizational measures described in Annex 1 (Security Measures), which covers:

- Access control (physical and logical).
- Data encryption (at rest and in transit).
- Network security (firewalls, intrusion detection/prevention, DDoS protection).
- Application security (WAF, input validation, SAST/DAST).
- Operational security (logging, monitoring, alerting).
- Business continuity and disaster recovery.
- Incident response.
- Vulnerability management.
- Personnel security and training.

### 4.2 Vulnerability Remediation Targets

ApexMail maintains the following remediation targets for vulnerabilities identified in the Service:

- **Critical:** Immediate containment; target permanent remediation within 7 days.
- **High:** Target within 30 days.
- **Medium:** Target within 90 days.
- **Low:** Risk-based — addressed in regular maintenance cycles.
- **Actively exploited:** Emergency process regardless of severity.

### 4.3 Review

ApexMail may update the TOMs provided that the updates do not materially reduce the overall level of security.

## 5. Subprocessors

### 5.1 Authorized Subprocessors

The current authorized subprocessors are listed in the ApexMail Subprocessor Register at https://apexmail.ee/subprocessors/, which forms part of this DPA.

### 5.2 Subprocessor Obligations

ApexMail shall:
- Impose data protection obligations on each Subprocessor that are no less protective than this DPA.
- Remain fully liable to Customer for Subprocessor performance.

### 5.3 New Subprocessors

ApexMail shall notify Customer of new Subprocessors at least 14 days before engagement. Customer may object to a new Subprocessor within 14 days on reasonable data protection grounds. If the objection cannot be resolved, Customer may terminate the affected Service without penalty.

### 5.4 Subprocessor List

The current list of Subprocessors is maintained at:

```
https://apexmail.ee/subprocessors
```

## 6. International Transfers

### 6.1 Primary Location

Core infrastructure processing in Germany and Finland. Optional Google and GitHub OAuth processing. Stripe payment processing. International transfers protected through applicable safeguards.

### 6.2 Transfer Safeguards

Where a Subprocessor processes Personal Data outside the EEA, ApexMail ensures appropriate safeguards are in place, which may include:

- An adequacy decision by the European Commission.
- Standard Contractual Clauses (SCCs) per Commission Implementing Decision (EU) 2021/914.
- Binding Corporate Rules (BCRs) approved by a competent Supervisory Authority.

### 6.3 SCC Mechanism

Where applicable, the EU Standard Contractual Clauses (Module 2: Controller-to-Processor) are incorporated by reference into this DPA for transfers to Subprocessors in third countries without an adequacy decision.

## 7. Government Requests

ApexMail shall:
- Notify Customer promptly upon receiving a legally binding request from a government authority for disclosure of Personal Data, unless prohibited by law.
- Challenge any such request if it reasonably believes it to be unlawful or overbroad.
- Provide only the minimum information necessary to comply.

## 8. Data Subject Rights (DSR) Assistance

ApexMail shall, taking into account the nature of the Processing:
- Assist Customer by appropriate technical and organizational measures to fulfill Customer's obligation to respond to Data Subject requests under GDPR Chapter III.
- Notify Customer promptly upon receiving a direct Data Subject request and not respond to it except on the Customer's documented instructions.

## 9. Data Protection Impact Assessment (DPIA) Assistance

ApexMail shall, taking into account the nature of the Processing and the information available:
- Provide reasonable assistance to Customer with Data Protection Impact Assessments (DPIAs).
- Provide reasonable assistance with prior consultation of a Supervisory Authority, where required.

## 10. Personal Data Breach Notification

### 10.1 Notification to Customer

ApexMail shall notify Customer **without undue delay after becoming aware of a personal data breach**.

### 10.2 Notification Contents

The notification shall, to the extent available:
- Describe the nature of the breach, including categories and approximate number of Data Subjects and records concerned.
- Communicate the name and contact details of the Data Protection Lead or other contact point.
- Describe the likely consequences of the breach.
- Describe the measures taken or proposed to address the breach, including mitigation measures.

### 10.3 Further Information

Where it is not possible to provide all information at once, ApexMail may provide it in phases without undue further delay.

## 11. Audits

### 11.1 Audit Rights

Customer may, no more than once per 12-month period and at Customer's expense, audit ApexMail's compliance with this DPA.

### 11.2 Audit Procedure

Audits shall be:
- Conducted during normal business hours with at least 30 days' notice.
- Limited to facilities, systems, and processes relevant to the Processing.
- Conducted by an independent auditor under confidentiality obligations.
- Performed without unreasonably disrupting ApexMail's operations.

### 11.3 Alternative Evidence

In lieu of an on-site audit, ApexMail may provide:
- SOC 2 control mapping and readiness documentation (note: ApexMail is not currently SOC 2 certified).
- Penetration test summary (note: first external test planned; summary will be available after completion and remediation in accordance with ApexMail's security-assessment program. The first external penetration test has not yet been completed).
- Current ISO 27001 certificate (if available).
- Answers to a standard industry questionnaire (SIG, CAIQ, HECVAT).

## 12. Deletion and Return of Data

Upon termination of the Service:

- Customer may export Personal Data within 30 days using provided export tools.
- ApexMail shall delete all remaining copies of Personal Data unless retention is required by EU or Member State law.
- Deletion is performed as follows: Personal Data is deleted row-level from the primary processing stores through ApexMail's erasure pipeline; records subject to statutory retention (e.g., billing) have the data subject's identifiers replaced with an irreversible redaction marker (anonymization) instead of deletion; opt-out (suppression) records are retained to keep suppression enforceable; audit records are moved to an archive store for their retention period. Copies in backups become inaccessible through the encrypted backup rotation, which retains no backup beyond the configured retention window (default 90 days). This is a logical-deletion and rotation process; ApexMail does not perform physical media sanitization under NIST SP 800-88 as part of standard service termination.

## 13. Liability

Each party's liability under this DPA is subject to the liability provisions of the Terms of Service. Nothing in this DPA limits either party's liability for breaches of Data Subject rights or for damage caused by Processing that infringes GDPR.

## 14. Annexes

- **Annex 1**: Technical and Organizational Measures (TOMs) — see [Security Measures](../compliance/security-measures.md).
- **Annex 2**: Subprocessors — see [Subprocessors](../compliance/subprocessors.md).
- **Annex 3**: SCC Module 2 (incorporated by reference, Commission Implementing Decision (EU) 2021/914).

## 15. Contact

Data Protection inquiries:
**{{PRIVACY_EMAIL}}**

General inquiries:
**{{SUPPORT_EMAIL}}**
