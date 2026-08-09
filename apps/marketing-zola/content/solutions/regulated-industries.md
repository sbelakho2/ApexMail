+++
title = "Regulated Industries Email Solution"
description = "GDPR, HIPAA, and contractual compliance for transactional email. DPA support, BAA review eligibility, data residency, audit logs, private deployment."
template = "prose.html"
+++

## Regulated Industries

Send transactional email from infrastructure designed for organizations subject to GDPR, HIPAA, SOC 2, ISO 27001, or contractual compliance obligations. EU data residency, DPA, BAA eligibility, audit logs, and private deployment models.

## Audience

Healthcare providers sending appointment reminders. Financial institutions sending transaction confirmations. Government agencies sending citizen notifications. Legal firms sending case updates. Any organization where email infrastructure falls under regulatory scope.

## Business Context

Regulated organizations cannot treat email as a generic utility. Every message event may be auditable. Data location must be documented and verifiable. Breach notification timelines are contractual. Generic SaaS email providers rarely offer the contractual controls, audit evidence, and deployment flexibility that regulated procurement demands.

## Core Problem

- Standard SaaS email providers process data in multiple jurisdictions with limited transparency.
- DPAs are often non-negotiable or absent on lower-tier plans.
- HIPAA BAAs are unavailable from most transactional email services.
- Audit logs, access reviews, and change management evidence are not standard offerings.
- Procurement cycles require SIG/CAIQ/HECVAT responses that generic providers cannot fulfill.

## ApexMail Solution

- **EU Data Residency** — All account data, message metadata, event data, and backups processed and stored in EEA data centers.
- **DPA** — Standard DPA available on Business and Enterprise plans. Custom DPA negotiation on Enterprise.
- **HIPAA BAA** — BAA review eligibility on Enterprise and Dedicated Tenant plans. Customer configuration required.
- **Audit Logs** — Immutable audit trail of all administrative actions: API key creation, permission changes, domain modifications, subaccount operations.
- **SIG/CAIQ/HECVAT** — Standard security questionnaire responses maintained and updated quarterly for Enterprise procurement.
- **Private Deployment** — Dedicated Tenant and BYOC models for organizations that require data isolation, custom retention, or customer-controlled infrastructure.

## Technical Implementation

1. Engage sales for a compliance walkthrough and deployment model selection.
2. Sign the DPA (and BAA where applicable).
3. Provision the account with the required data residency region.
4. Configure audit log streaming to your SIEM (Enterprise).
5. Enable mandatory SSO, MFA, and IP allowlisting.
6. Review subprocessor list and configure opt-outs where available.
7. Complete procurement security review (SIG/CAIQ/HECVAT available).
8. Go-live with production sending.

## Relevant Features

| Feature | Shared Cloud | Dedicated Tenant | BYOC |
|---|---|---|---|
| DPA | Business+ | Included | Included |
| BAA eligibility | Enterprise | Included | Included |
| Audit logs | Growth+ | Included | Included |
| Data residency (EEA) | All plans | All plans | Customer region |
| Custom retention | Enterprise | Included | Customer-defined |
| SSO (SAML) | Business+ | Included | Included |
| SCIM provisioning | Enterprise | Included | Included |
| IP allowlisting | Pro+ | Included | Included |
| SIEM log streaming | Enterprise | Included | Included |
| SIG/CAIQ/HECVAT | Enterprise | Included | Included |

## Security Considerations

- All API and SMTP connections require TLS 1.2+.
- Message content encrypted at rest using AES-256.
- Administrative access requires MFA (mandatory on Enterprise).
- Session duration configurable. Automatic revocation on role change.
- Penetration testing and vulnerability scanning performed regularly. Reports available under NDA for Enterprise customers.

## Compliance Considerations

- ApexMail acts as a data processor for email content, recipient addresses, and message metadata.
- Customer is the data controller and responsible for recipient consent, opt-out management, and lawful basis for processing.
- Subprocessor list published and maintained. Change notification provided to DPA customers 30 days in advance.
- Breach notification to customers without undue delay after becoming aware of a personal data breach. Supervisory authority notification as required under GDPR Article 33 (within 72 hours where applicable). Contractual timeline for BAA customers.
- DPA does not itself guarantee GDPR compliance. Customer configuration, consent management, and data minimization remain the customer's responsibility.

## Known Limitations

- HIPAA BAA requires Enterprise or Dedicated Tenant plan and customer configuration of PHI-safe sending practices.
- SOC 2 Type II attestation is planned (Q2 2028 target). Not currently available. See the [Trust Center](/trust/) for current certification and assessment status.
- Private deployment (BYOC) shifts infrastructure security responsibility to the customer for the cloud account layer.

## Recommended Next Action

[Contact sales](/contact/sales/) for a compliance walkthrough, DPA review, and deployment model evaluation.
