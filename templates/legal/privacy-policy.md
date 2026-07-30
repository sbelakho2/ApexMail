# Privacy Policy

**Last Updated:** {{LAST_UPDATED}}

## 1. Introduction

**{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, VAT **{{VAT_NUMBER}}**, with registered address at **{{ADDRESS}}**, Republic of Estonia ("we", "us", "our"), is committed to protecting the privacy and security of personal data.

This Privacy Policy explains how we collect, use, disclose, and safeguard personal data in compliance with:

- Regulation (EU) 2016/679 (General Data Protection Regulation — GDPR).
- The Estonian Personal Data Protection Act (Isikuandmete kaitse seadus).
- Applicable EU and Estonian data protection law.

For questions about this policy, contact our Data Protection Lead at **{{PRIVACY_EMAIL}}**.

## 2. Data Subjects and Categories

We process personal data about the following categories of individuals.

### 2.1 Website Visitors

| Field | Detail |
|---|---|
| Data collected | IP address, browser type, device information, pages visited, referring URL, timestamp |
| Source | Automated collection via web server logs and analytics |
| Purpose | Website operation, security monitoring, performance analytics |
| Legal basis | Legitimate interest (GDPR Art. 6(1)(f)) — website security and improvement |
| Processor or recipient | Hetzner (hosting), Plausible Analytics (privacy-focused, self-hosted) |
| Location | EU data centers (Hetzner Germany, Finland) — web server logs, analytics |
| Retention | 30 days for raw logs; aggregated analytics retained indefinitely |
| Rights | Access, erasure, objection |

### 2.2 Prospects

| Field | Detail |
|---|---|
| Data collected | Name, email address, company name, phone number (if provided), communication history |
| Source | Directly from the individual via web forms, email, or sales contact |
| Purpose | Responding to inquiries, providing product information, sales communication |
| Legal basis | Legitimate interest (GDPR Art. 6(1)(f)) — business development; Consent (Art. 6(1)(a)) for marketing |
| Processor or recipient | HubSpot CRM (EU-hosted), internal sales team |
| Location | EU data centers (Hetzner Germany, Finland) — CRM hosted in EU |
| Retention | 24 months after last contact, or until consent is withdrawn |
| Rights | Access, rectification, erasure, objection, data portability |

### 2.3 Account Users

| Field | Detail |
|---|---|
| Data collected | Name, email address, company name, billing address, VAT ID, payment method details, API key metadata, login timestamps, IP addresses, audit log entries |
| Source | Directly from the account holder during registration and account management |
| Purpose | Service provision, authentication, billing, support, security, compliance |
| Legal basis | Contract performance (GDPR Art. 6(1)(b)); Legal obligation (Art. 6(1)(c)) — accounting/tax |
| Processor or recipient | Stripe (payment processing), Hetzner (infrastructure), internal support team |
| Location | EU data centers (Hetzner Germany, Finland) — account data; Stripe processes payment data per their own infrastructure |
| Retention | Duration of contract + 30 days; billing records 7 years per Estonian accounting law |
| Rights | Access, rectification, erasure (subject to legal obligations), data portability, restriction |

### 2.4 Customer Recipients

| Field | Detail |
|---|---|
| Data collected | Email address, name (if provided by customer), email content (subject, body, headers, attachments), delivery events (accepted, delivered, opened, clicked), bounce information, complaint data, IP address and user agent (open/click tracking) |
| Source | Provided by ApexMail customers when sending email through the platform |
| Purpose | Email delivery, deliverability monitoring, abuse prevention, compliance, customer analytics |
| Legal basis | Contract performance (GDPR Art. 6(1)(b)) — we act as processor on behalf of our customer (the data controller) |
| Processor or recipient | Hetzner (infrastructure — Germany, Finland), AWS SES (delivery transport — EU region), Redis (caching — Hetzner Germany), ClickHouse (analytics — Hetzner Germany) |
| Location | EU data centers (Hetzner Germany, Finland) — PostgreSQL (Germany), Redis (Germany), file storage (Germany) |
| Retention | Email content: 30 days (configurable up to 90 days for Enterprise); Event logs: 90 days (730 days for Enterprise); Configurable per customer contract |
| Rights | Exercised via the data controller (ApexMail customer); We assist controllers with DSR fulfillment |

### 2.5 Support Contacts

| Field | Detail |
|---|---|
| Data collected | Name, email address, support ticket content, attachments, communication history |
| Source | Directly via support@apexmail.ee, dashboard support widget, or API |
| Purpose | Technical support, troubleshooting, service improvement |
| Legal basis | Contract performance (Art. 6(1)(b)); Legitimate interest (Art. 6(1)(f)) |
| Processor or recipient | Internal support team, ticketing system (EU-hosted) |
| Location | EU data centers (Hetzner Germany, Finland) |
| Retention | 2 years after ticket resolution |
| Rights | Access, rectification, erasure, data portability |

### 2.6 Security Researchers

| Field | Detail |
|---|---|
| Data collected | Name, email address, vulnerability report content, communication history |
| Source | Directly via security@apexmail.ee or vulnerability disclosure program |
| Purpose | Vulnerability assessment, remediation coordination, responsible disclosure |
| Legal basis | Legitimate interest (Art. 6(1)(f)) — security of our services |
| Location | EU data centers (Hetzner Germany, Finland) |
| Retention | Duration of disclosure process + 90 days after resolution |
| Rights | Access, rectification, erasure |

## 3. Processing Activities

### 3.1 Authentication

We process login credentials (email, hashed password), session tokens, and IP addresses for authentication. Multi-factor authentication codes (TOTP) are processed in-memory and not stored.

### 3.2 Billing

Payment card details are processed by Stripe and never touch our servers. We receive tokens and transaction metadata. Invoice data (amounts, timestamps, VAT) is retained for 7 years per Estonian accounting law (Raamatupidamise seadus § 12).

### 3.3 Analytics

We collect aggregated, anonymized platform usage metrics for operational purposes. Per-account analytics (delivery rates, engagement metrics) are available to account holders. Self-hosted Plausible Analytics (no third-party cookies) is used on our marketing website.

### 3.4 Support

Support interactions are logged, including account context, communications, and resolution steps. Support data is used for service improvement and training internal systems.

### 3.5 Message Content Processing

Email content (subject, body, headers, attachments) is processed transiently for delivery. Content is not mined, analyzed, or used for purposes other than delivery, deliverability (spam scoring, bounce classification), and abuse detection.

### 3.6 Opens and Clicks

When tracking is enabled, we record open events (via transparent tracking pixel) and click events (via link rewriting). Data collected: IP address, user agent, timestamp, and geographic inference. This data is provided to the sending customer and processed on their behalf.

### 3.7 IP Addresses and User Agents

IP addresses are logged for authentication, rate limiting, fraud detection, and abuse monitoring. User agents are logged for compatibility analytics.

### 3.8 Cookies

See our [Cookie Policy](cookie-policy.md). ApexMail's marketing website uses minimal cookies: session cookies (necessary) and self-hosted analytics (no tracking cookies). The ApexMail dashboard uses essential session cookies and localStorage for preferences. No third-party advertising or tracking cookies are used.

### 3.9 Fraud Prevention

We process sending patterns, authentication attempts, and account behavior using automated analysis to detect fraud, abuse, and terms-of-service violations. This may include automated decisions (rate limiting, account suspension) with human review available on appeal.

### 3.10 Abuse Monitoring

Automated systems scan email sending patterns, bounce/complaint rates, and content signatures (spam, phishing, malware) to detect abuse. Accounts flagged for abuse are subject to review, throttling, or suspension per our [Acceptable Use Policy](aup.md).

### 3.11 Automated Decisions

Automated decisions are limited to: rate limiting based on usage thresholds, suspension for AUP violations, and fraud blocking. Individuals subject to automated decisions may contact **{{SUPPORT_EMAIL}}** for human review.

### 3.12 Data Transfers

Personal data is stored and processed in EU data centers (Hetzner Germany and Finland). Data categories and their storage locations: PostgreSQL databases on Hetzner Germany, Redis caches on Hetzner Germany, file storage on Hetzner Germany. We do not transfer personal data outside the EEA without adequate safeguards (Standard Contractual Clauses, adequacy decisions, or binding corporate rules). Subprocessors outside the EEA are listed with transfer mechanisms in our [Data Processing Agreement](dpa.md).

### 3.13 Subprocessor Changes

Customers are notified of new subprocessors at least 14 days before engagement. Subprocessor changes are published at our [Subprocessors page](https://apexmail.ee/subprocessors).

## 4. Data Subject Rights

Under GDPR, data subjects have the following rights:

| Right | GDPR Article | How to exercise |
|---|---|---|
| Right of access | Art. 15 | Request confirmation and copy of personal data |
| Right to rectification | Art. 16 | Request correction of inaccurate data |
| Right to erasure | Art. 17 | Request deletion ("right to be forgotten") |
| Right to restriction | Art. 18 | Restrict processing under certain conditions |
| Right to data portability | Art. 20 | Receive data in structured, machine-readable format |
| Right to object | Art. 21 | Object to processing based on legitimate interests |
| Rights related to automated decisions | Art. 22 | Human review of automated decisions |

Submit requests to **{{PRIVACY_EMAIL}}**. We respond within 30 days (extendable by 60 days for complex requests). Identity verification may be required.

## 5. Supervisory Authority

You have the right to lodge a complaint with the **Estonian Data Protection Inspectorate** (Andmekaitse Inspektsioon):

- Website: https://www.aki.ee
- Address: Väike-Ameerika 19, 10129 Tallinn, Estonia
- Email: info@aki.ee

## 6. Changes to This Policy

We may update this Privacy Policy from time to time. Material changes are communicated via email to account holders and by updating the "Last Updated" date. Continued use after changes constitutes acceptance.

## 7. Contact

**{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**)
{{ADDRESS}}
Registry code: {{REGISTRY_CODE}}
VAT: {{VAT_NUMBER}}
Privacy inquiries: **{{PRIVACY_EMAIL}}**
General inquiries: **{{SUPPORT_EMAIL}}**
