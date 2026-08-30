+++
title = "Data Processing Agreement"
description = "ApexMail DPA — Article 28 data-processing terms."
template = "prose.html"

[extra]
last_updated = "2026-07-30"
+++

## 1. Scope

This Data Processing Agreement ("DPA") supplements the Terms of Service and governs the processing of personal data by **Bel Consulting OÜ** (registry code 16588745, VAT EE102951727, Sakala 7-2, 10141 Tallinn, Estonia), trading as ApexMail ("**Processor**") on behalf of the Customer ("**Controller**") under Article 28 of Regulation (EU) 2016/679 (General Data Protection Regulation).

## 2. Definitions

Terms used in this DPA have the meanings given in the GDPR unless otherwise defined.

## 3. Processing Details

| Element | Description |
|---|---|
| **Subject matter** | Email sending, delivery tracking, analytics |
| **Duration** | Term of the service agreement |
| **Nature** | Automated processing and transmission of email messages |
| **Purpose** | Provision of email infrastructure services |
| **Data categories** | Email addresses, message content, delivery metadata, IP addresses |
| **Data subjects** | Customer's end users (email recipients) |

## 4. Processor Obligations

The Processor shall:
- Process data only on documented instructions from the Controller.
- Ensure personnel are bound by confidentiality.
- Implement appropriate technical and organisational measures (Article 32).
- Assist the Controller in responding to data subject requests.
- Delete or return all personal data upon termination of the agreement.
- Make available all information necessary to demonstrate compliance with Article 28.
- Allow for and contribute to audits and inspections conducted by the Controller or an authorised auditor.

## 5. Sub-processors

### 5.1 Authorised Sub-processors

The current authorised subprocessors are maintained in the [ApexMail Subprocessor Register](https://apexmail.ee/subprocessors/), which is incorporated into this DPA by reference.

| Sub-processor | Purpose | Location | Transfer Safeguard |
|---|---|---|---|
| Hetzner Online GmbH | Core infrastructure (compute, storage) | Germany and Finland (EU) | Intra-EEA processing; GDPR Chapter V transfer rules do not apply |
| Amazon Web Services, Inc. | Telemetry object storage when enabled | Configured S3 region (default: `eu-central-1`) | EU Standard Contractual Clauses (AWS DPA) |
| Amazon Web Services, Inc. | Email-delivery transport when enabled | Configured SES region | EU Standard Contractual Clauses (AWS DPA) |
| Google LLC | Optional OAuth authentication | Global (US entity, data processed per OAuth config) | Standard Contractual Clauses |
| GitHub, Inc. | Optional OAuth authentication | Global (US entity) | Standard Contractual Clauses |
| Stripe, Inc. | Payment processing | US (primary), India (support) | Standard Contractual Clauses |

Self-hosted infrastructure (ClickHouse, Redis) runs on Hetzner servers under ApexMail's operational control. The upstream open-source publishers do not process customer data.

### 5.2 Notification of Changes

The Processor shall notify the Controller at least **30 days** before adding or replacing any sub-processor, giving the Controller the opportunity to object. If the Controller objects on reasonable data protection grounds and no alternative can be reached, the Controller may terminate the affected services.

## 6. International Transfers

The supplied deployment configuration targets EU/EEA regions for core infrastructure and telemetry object storage. Active providers and locations are deployment-specific; see the [Data Locations](/data-locations/) page for a complete category-by-category matrix. No personal data is transferred outside the EEA without appropriate safeguards (Standard Contractual Clauses or an adequacy decision under Article 45).

## 7. Security Measures

- AES-256-GCM encryption at rest
- TLS 1.2+ in transit (TLS 1.3 preferred)
- Argon2id password hashing
- Audit logging with hash-chain integrity
- Security controls and audit logging; ApexMail is not currently SOC 2 certified
- Access control with multi-factor authentication
- Weekly automated vulnerability scanning; first external penetration test planned — results to be published after completion and remediation

## 8. Data Breach Notification

The Processor shall notify the Controller **without undue delay** after becoming aware of a personal data breach involving the Controller's data. ApexMail contractually targets an initial notification within 48 hours, based on the information reasonably available at that time. The notification shall include:
- The nature of the breach.
- Categories and approximate number of data subjects and records concerned.
- Contact details of the Data Protection Lead.
- Likely consequences and measures taken or proposed.

## 9. Return and Deletion of Data

Upon termination of the agreement, the Processor shall, at the Controller's choice, return or delete all personal data processed on behalf of the Controller, unless EU or Estonian law requires retention (e.g., billing records retained for 7 years per the Estonian Accounting Act).

## 10. Audit Rights

The Controller may request an audit of the Processor's compliance with this DPA at reasonable intervals. The audit shall be conducted at the Controller's expense and subject to confidentiality obligations.

## 11. Governing Law

This DPA is governed by the laws of the Republic of Estonia and the GDPR. Any disputes shall be resolved in the courts of Tallinn, Estonia.
