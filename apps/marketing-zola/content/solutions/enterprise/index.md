+++
title = "Enterprise Solution"
description = "Enterprise transactional email: procurement, contract options, SLA, support, security review, data residency, Private Cloud, migration, billing, account management. Annual commitment from €3,000/month."
template = "prose.html"
+++

## Enterprise

Enterprise-grade transactional email for organizations exceeding 5M emails/month. Architecture review, dedicated tenancy or BYOC deployment, negotiated support, contractual SLA, quarterly business reviews, and custom retention policies.

## Who Enterprise Is For

Organizations that require:
- Volume exceeding 5 million emails per month.
- Custom contract terms outside standard self-serve plans.
- Security review, architecture validation, and procurement approval.
- Dedicated infrastructure or customer-cloud deployment.
- Negotiated SLA with contractual uptime and response commitments.
- Named account management and quarterly business reviews.

## Qualification Criteria

Enterprise engagement typically begins when an organization meets one or more of the following:
- Monthly volume above 5M emails.
- Compliance frameworks requiring dedicated infrastructure (HIPAA, PCI-adjacent, FedRAMP-relevant).
- Data sovereignty mandates requiring region-specific deployment.
- Custom SLA requirements beyond 99.9% uptime.
- Security review or penetration test access required.
- Custom billing (invoice, purchase order, multi-year commitment).

Volume below 5M but with complex security, compliance, or procurement needs may still qualify. Contact sales to discuss.

## Volume Range

| Tier | Monthly Volume | Pricing Model |
|---|---|---|
| Enterprise (shared infrastructure) | 5M–50M | Annual commitment from €3,000/month |
| Enterprise (dedicated infrastructure) | 10M–500M+ | Dedicated Tenant from €4,000/month |
| Enterprise (customer cloud) | 50M–1B+ | BYOC from €6,500/month |

All tiers include overage at negotiated rate per thousand emails above included volume.

## Contract Options

| Option | Minimum Term | Payment | Features |
|---|---|---|---|
| Annual | 12 months | Monthly or annual | Standard enterprise features, 10% annual prepay discount |
| Multi-year | 24–36 months | Monthly, quarterly, or annual | Custom pricing, locked rates, priority roadmap input |
| BYOC | 12–24 months | Monthly or annual | Customer cloud deployment, engineering support minimum 24 months |

Custom contract terms available. Purchase order and invoice billing supported.

## SLA Options

| Component | Enterprise (Shared) | Dedicated Tenant | BYOC |
|---|---|---|---|
| Uptime target | 99.9% | 99.95% | Negotiated per contract |
| Service credits | Available | Available | Negotiated |
| Response SLA | 2-hour critical | 1-hour critical | 30-min critical |
| Postmortem | Initial incident report within 5 business days; final root-cause when validation completes | Initial incident report within 5 business days; final root-cause when validation completes | Initial incident report within 5 business days; final root-cause when validation completes |
| Scheduled maintenance | Standard window | Customer-defined window | Customer-defined window |

**Postmortem timing note:** All plans receive an initial incident report within 5 business days for major (SEV-1/SEV-2) incidents. Final root-cause analysis is published when validation completes. This timeline reflects the coordination and review depth required across shared, dedicated, and customer-cloud deployments.

Full SLA terms defined in contract and order form. Service credits apply when targets are not met.

## Support Options

| Tier | Channels | Response Target | Included In |
|---|---|---|---|
| Standard | Email, portal | 4 business hours | Business plan |
| Enterprise | Email, portal, Slack, phone, dedicated CSM | 2-hour critical | Enterprise plan |
| Premium | Email, portal, Slack, phone, private Slack, dedicated CSM | 1-hour critical | Dedicated Tenant |

All Enterprise and Premium tiers include:
- Named Customer Success Manager.
- Monthly service reviews.
- Quarterly business reviews.
- Architecture review and optimization.
- Migration planning and support.
- Security questionnaire completion (SIG, CAIQ, HECVAT).

## Procurement Support

ApexMail provides a complete procurement package to support vendor assessment and onboarding. See [Procurement Materials](#procurement-materials) below.

Enterprise buyers receive:
- Complete procurement document package.
- Pre-completed vendor questionnaire (SIG/CAIQ/HECVAT).
- Security and compliance documentation.
- Architecture and data flow review.
- Legal review coordination (DPA, contract, SLA).
- Purchase order and invoice billing.
- Multi-year pricing with locked rates.

## Security Review

Available to enterprise prospects and customers:
- SOC 2 control mapping and readiness documentation available during Enterprise review. ApexMail is not currently SOC 2 certified.
- External penetration-test summary: first external test planned. Summary will become available after completion and remediation.
- Architecture review with ApexMail engineering.
- Security controls documentation package.
- Shared responsibility model per deployment type.
- Access control and authentication review.
- Encryption key management review (customer-managed keys available on Dedicated Tenant and BYOC).

## SSO and SCIM

Enterprise plan includes SAML 2.0-based Single Sign-On (SSO) and SCIM 2.0 provisioning:

| Feature | Description |
|---|---|
| SAML SSO | Identity provider-initiated and service provider-initiated flows. Supported providers: Okta, Entra ID (Azure AD), Google Workspace, OneLogin, PingFederate, and any SAML 2.0-compliant IdP. |
| SCIM 2.0 | Automated user and group provisioning/deprovisioning via SCIM 2.0 protocol. Supports `POST /Users`, `GET /Users`, `PUT /Users`, `PATCH /Users`, `DELETE /Users`, and equivalent group operations. |
| Just-in-Time provisioning | Users created on first SSO login when SCIM is not configured. |
| Role mapping | SAML attribute mapping for role assignment (`memberOf`, `groups`, custom attributes). |
| Session enforcement | Configurable session timeout, IP binding, and forced re-authentication policies. |

SSO and SCIM are included in the Enterprise plan. Configuration typically takes 1–3 business days with support from the ApexMail engineering team.

## Audit Logs

Enterprise plan includes premium audit logs with configurable retention:

| Feature | Business | Enterprise |
|---|---|---|
| Dashboard audit events | Yes | Yes |
| API audit events | Yes | Yes |
| Admin action logging | — | Yes |
| Export (JSON/CSV) | — | Yes |
| Retention | 30 days | Configurable (up to 730 days) |
| SIEM integration | — | Via API or webhook streaming |
| Immutable log storage | — | Write-once-read-many (WORM) |
| Log integrity verification | — | Hash-chained entries with verification API |

Audit logs capture: user authentication events, API key creation/revocation, role and permission changes, domain configuration changes, webhook modifications, suppression list changes, and billing/plan modifications.

## Compliance Review

- DPA (Data Processing Agreement) — pre-signed, Article 28 GDPR compliant.
- BAA (Business Associate Agreement) — eligibility review for HIPAA-regulated entities.
- Compliance framework mapping (GDPR, HIPAA, SOC 2, ISO 27001 alignment).
- Subprocessor register with change notification commitment.
- Data residency matrix by data category.
- Transfer mechanism documentation.
- Audit and assessment facilitation.

**Important:** ApexMail provides compliance-supporting features and documentation. Customer configuration, use, and legal obligations remain the customer's responsibility. ApexMail does not provide legal advice.

## Data Residency

Enterprise customers may select deployment regions:
- **Shared EU Cloud:** EU/EEA data centers (Finland, Germany).
- **Dedicated Tenant:** Customer-selected EEA region within ApexMail-managed infrastructure.
- **BYOC:** Customer-defined region in their own cloud accounts (AWS, GCP, Azure, OpenStack).

Data residency options cover all material data categories: account data, message metadata, delivery logs, event data, and backups. See the [Architecture page](/architecture/) for the geographic distribution table.

## Private Cloud Relationship

Enterprise plan is a commercial engagement tier. Private Cloud is a deployment architecture choice.

| | Enterprise (Shared) | Dedicated Tenant | BYOC |
|---|---|---|---|
| Infrastructure | Multi-tenant | Dedicated | Customer-owned |
| Deployment model | Shared Cloud | Private Cloud | Private Cloud |
| Commercial tier | Enterprise | Enterprise | Enterprise |
| Included in Enterprise price | Yes | Additional €4,000+/mo | Additional €6,500+/mo |

Enterprise plan may include shared-cloud or private deployment. Private Cloud (Dedicated Tenant or BYOC) is an architectural choice available to Enterprise customers. Latency characteristics are architecture-dependent, not a contractual SLA.

## Migration Support

Enterprise customers receive:
- Migration assessment and planning.
- Current provider analysis (API mapping, configuration parity).
- Data migration support (suppression lists, templates, domains).
- Parallel sending period with validation.
- DNS cutover coordination.
- Post-migration monitoring and stabilization (2–4 weeks).
- Migration timeline typically 2–8 weeks depending on volume and complexity.

## Billing Options

- **Credit card:** Available for Enterprise shared infrastructure.
- **Invoice:** Net-30 terms available. Purchase order references supported.
- **Wire transfer / SEPA:** Supported for EU customers.
- **Annual prepay:** 10% discount for annual prepayment.
- **Multi-year:** Locked rates, custom payment schedules.
- **Tax:** VAT reverse charge for EU B2B customers with valid VAT ID. Tax applied according to billing country.

## Account Management

Enterprise customers receive:
- Named Customer Success Manager (CSM).
- Monthly operational review.
- Quarterly business review (QBR).
- Priority feature request channel.
- Beta and early-access program eligibility.
- Dedicated onboarding support.
- Direct escalation path to engineering.

## Contact Process

1. **Submit inquiry** via the [Enterprise Pricing form](/contact/sales/) or email enterprise@apexmail.ee.
2. **Qualification call** (2–5 business days): volume, requirements, deployment preference.
3. **Architecture and security review** (1–3 weeks): technical deep-dive with engineering.
4. **Commercial proposal** (1–2 weeks): custom pricing, SLA, and contract terms.
5. **Contract and DPA** (2–6 weeks): legal review and execution.
6. **Deployment** (1–6 weeks depending on model): provisioning, integration, and go-live.

## Enterprise Pricing

The Enterprise plan starts at **€3,000/month** on an annual commitment.

**What the starting price includes:**

*Commercial and procurement:*
- Assessment meetings (initial qualification call, requirements gathering, solution-fit analysis).
- Architecture proposal (technical deep-dive, deployment model recommendation, sizing guidance).
- Commercial scoping (custom pricing proposal, SLA negotiation, contract term alignment).
- Security questionnaire completion (SIG, CAIQ, HECVAT).

*Service delivery:*
- Monthly sending volume up to 5,000,000 emails.
- Monthly billing (annual commitment).
- 12-month minimum term.
- 10 managed dedicated IPs.
- Up to 10 sending domains.
- Up to 25 team members with role-based access.
- Standard enterprise support (email, portal, Slack, phone, dedicated CSM).
- 99.9% uptime SLA (Enterprise, annual contract) with service credits.
- DPA included. BAA eligibility review available.
- Standard EU/EEA data residency.
- Security review and documentation package.

*Deployment and operations:*
- Deployment-record management (deployment event log with git commit, artifact hash, timestamp — immutable, append-only).
- Region tracking (data residency matrix by data category with geographic distribution table).
- BYOIP validation support (Bring Your Own IP range assessment for Dedicated Tenant).

**What the starting price does not include:**
- Dedicated infrastructure (Private Cloud deployment: Dedicated Tenant from €4,000/month; BYOC from €6,500/month).
- Cloud-provider costs (BYOC: compute, storage, networking, egress billed directly by customer to their cloud provider).
- One-time setup fees (Dedicated Tenant from €10,000; BYOC from €20,000).
- Custom deployment outside standard EEA regions (requires architectural review and separate scoping).
- Additional dedicated IPs beyond included allocation.
- Professional services beyond standard onboarding.
- Overage: billed at negotiated rate per thousand emails above included volume.

**Annual vs Monthly:**
- Annual commitment: 10% discount applied. Early termination may incur fees per contract.
- Custom volumes and multi-year terms available. Contact sales for a tailored proposal.

## Procurement Materials

The following materials are available to qualified enterprise prospects:

| Document | Availability |
|---|---|
| Company Profile | Public |
| Product Overview | Public |
| Security Overview | Public |
| Compliance Overview | Public |
| DPA | Public |
| Subprocessor List | Public |
| SLA Template | Qualified prospects |
| Support Policy | Public |
| Business Continuity Summary | Under NDA |
| Disaster Recovery Summary | Under NDA |
| Incident Response Summary | Under NDA |
| Data Retention Policy | Public |
| Data Deletion Policy | Public |
| Architecture Overview | Public |
| Insurance Details | Under NDA |
| Certification Status | Qualified prospects |
| Standard Vendor Questionnaire (SIG/CAIQ/HECVAT) | Under NDA |

All materials are version-controlled. The correct legal entity (Bel Consulting OÜ) is used on all documents. Confidential reports are not publicly exposed.

## Known Limitations

- BYOC model: customer manages cloud infrastructure, databases, and networking.
- Minimum 12-month commitment for dedicated infrastructure.
- Enterprise plan (shared infrastructure) still uses multi-tenant architecture — use Dedicated Tenant or BYOC for hardware-level isolation.
- Custom data residency outside standard EEA regions requires architectural review.
- Overage rate, dedicated IP count, and team member count above stated limits are negotiated per contract.

## Recommended Next Action

[Contact sales](/contact/sales/) to schedule an architecture review and receive a custom proposal. Or email [enterprise@apexmail.ee](mailto:enterprise@apexmail.ee).
