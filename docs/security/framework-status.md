# Framework Certification Status

> **Last Updated:** 2026-07-29
> **Owner:** Compliance Team (`compliance@apexmail.ee`)
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia

---

## Framework Status Overview

The following table provides the current status of ApexMail's alignment with industry frameworks. No buyer should mistake a roadmap item for an active certification.

| Framework | Current Status | Scope | Relevant Product | Auditor / Assessor | Last Assessment | Next Milestone | Evidence Availability | Contact Process |
|-----------|---------------|-------|------------------|--------------------|-----------------|----------------|-----------------------|-----------------|
| **SOC 2 Type II** | Planned | Trust Services Criteria (Security, Availability, Confidentiality) | ApexMail Cloud | To be selected | N/A | Readiness assessment Q1 2027 | Controls documentation internal | compliance@apexmail.ee |
| **GDPR** | Controls being mapped | Data processing, subject rights, breach notification | All products | Internal assessment | 2026-05 | Ongoing monitoring | DPA, subprocessor list, data location summary | privacy@apexmail.ee |
| **HIPAA** | Planned | Technical and administrative safeguards for PHI | ApexMail Cloud (Enterprise) | To be selected | N/A | Readiness assessment Q2 2027 | BAA template available | compliance@apexmail.ee |
| **ISO 27001** | Not planned | ISMS for email delivery platform | N/A | N/A | N/A | Under evaluation | N/A | compliance@apexmail.ee |
| **PCI DSS** | Not planned | Credit card payment processing | Stripe (handled externally) | N/A | N/A | N/A | Stripe PCI Attestation of Compliance | compliance@apexmail.ee |

---

## Status Definitions

| Status | Definition |
|--------|------------|
| **Not planned** | No active roadmap item; may be evaluated in future |
| **Planned** | On roadmap with target quarter; no active work |
| **Controls being mapped** | Internal mapping of controls to framework requirements in progress |
| **Internal assessment** | Internal review of control effectiveness against framework |
| **Readiness assessment** | Pre-audit gap analysis, typically by external advisor |
| **Audit scheduled** | External audit date committed |
| **Audit in progress** | External audit currently active |
| **Certified** | Audit completed, certification issued, valid and current |
| **Certification expired** | Previously certified but not renewed |

---

## Scope Limitations

### GDPR

- ApexMail is **primarily a data processor** for email-sending customers
- ApexMail acts as a **data controller** for account registration, billing, and service communications
- Subject rights support: export and deletion APIs available; DSAR process documented
- Data location: European Union (primary), with documented subprocessors

### HIPAA

- HIPAA compliance is **planned** and not yet certified
- BAA is **not currently available** but a template exists for future use
- Protected health information **should not be sent** through ApexMail until HIPAA controls are validated
- Target plans: Enterprise and Private Cloud
- Target deployment: ApexMail Cloud (EU region) and Private Cloud

### SOC 2

- Current status is **planned** only
- Type II scope will cover Security, Availability, and Confidentiality criteria
- Report availability: to be determined after audit completion
- No timeline commitment beyond "planned" until an auditor is engaged

### ISO Frameworks

- ISO 27001 is not currently planned due to focus on SOC 2 and jurisdictional equivalents
- ISO 27701 (privacy) is under evaluation as an extension to eventual ISO 27001

---

## Certification Expiry

- Expired certifications are **removed immediately** from this page and any marketing references
- Certification status is reviewed monthly by the Compliance Team
- Any certification claim in marketing must reference this table or its equivalent status page

---

## Completion Requirements

- [x] No buyer can mistake a roadmap item for an active certification
- [x] Expired certifications are removed immediately (monthly review enforced)
- [x] Scope limitations are visible for each framework
- [x] Status definitions are unambiguous
- [x] Evidence availability stated per framework

---

## References

- [Security & Compliance Overview](compliance.md)
- [GDPR Compliance Framework](../compliance/gdpr-compliance.md)
- [BAA Template](../compliance/baa-template.md)
- [Data Location Summary](../compliance/data-retention.md)
- [Subprocessor List](../templates/compliance/subprocessors.md)
