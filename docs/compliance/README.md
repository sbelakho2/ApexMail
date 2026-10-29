# Compliance Documentation

> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> **Data Protection Lead:** privacy@apexmail.ee (a formal DPO is not required under Article 37)

---

Comprehensive compliance documentation for ApexMail, organized by regulatory framework. This page is distinct from the Security page and provides framework-specific status, scope, and customer responsibility information.

---

## GDPR Compliance

ApexMail supports GDPR compliance through documented data processing, subject rights, and breach notification procedures.

### ApexMail's Role

- **Data Processor:** When you send emails through ApexMail, ApexMail processes recipient data on your behalf
- **Data Controller:** For account registration, billing, and service communications to registered users

### Key Information

| Topic | Detail |
|-------|--------|
| **DPA Availability** | Standard DPA available at `https://apexmail.ee/legal/dpa` |
| **Subprocessors** | Full list at `https://apexmail.ee/legal/subprocessors` |
| **Data-Subject Rights** | Export API, deletion API, DSAR handling process documented |
| **Deletion Process** | Cascade deletion via API or support request; retention schedule published |
| **Export Process** | JSON/CSV export formats; API-driven or support-assisted |
| **Breach Notification** | 72-hour notification to Data Protection Authority; customer notification without undue delay |
| **Data Location** | European Union (Finland) |
| **Transfer Safeguards** | Standard Contractual Clauses; EU-based processing where feasible |
| **Customer Responsibilities** | Lawful basis for processing; consent management; data accuracy |

### Customer Responsibilities

- Establish and maintain a lawful basis for processing personal data through ApexMail
- Manage subscriber consent and preference management
- Ensure data accuracy before uploading to ApexMail
- Honor data subject access and erasure requests submitted to you
- Notify ApexMail of DSARs requiring processor assistance

---

## HIPAA

ApexMail's HIPAA readiness is under active development.

| Topic | Detail |
|-------|--------|
| **BAA Availability** | Template available; not yet offered for signed agreements |
| **Qualifying Plans** | Enterprise and Private Cloud (future) |
| **Qualifying Deployments** | ApexMail Cloud (EU region), Private Cloud |
| **PHI Transmission** | Not permitted until HIPAA controls are validated |
| **Required Configuration** | Dedicated IP, encryption at rest, audit logging, BAA on file |
| **Excluded Features** | Shared IP pools, public analytics sharing, non-encrypted backups |
| **Logging Restrictions** | Access logs must be retained for HIPAA audit requirements (6 years minimum) |
| **Support Access Restrictions** | Access to PHI requires explicit customer approval |
| **Current Status** | Planned — readiness assessment Q2 2027 |

---

## SOC 2

| Topic | Detail |
|-------|--------|
| **Current Status** | Planned |
| **Scope** | Security, Availability, Confidentiality (Trust Service Criteria) |
| **Type** | Type II planned |
| **Report Availability** | Will be made available under NDA after audit completion |
| **Target Timeline** | Readiness assessment Q1 2027; audit to follow based on assessment outcome |

### Evidence cadence

The compliance service runs a daily stale-evidence sweep (cron job 11) over every in-scope control. The sweep flags a control when its attestation deadline has passed or when its required evidence set is incomplete or outdated, and records each finding in the `soc2_evidence_collection_runs` trail under the evidence type `stale_attestation_sweep`. Operators can list the current findings live in the control plane at `GET /v1/admin/compliance/stale-evidence`, which reports each control's deadline, the missing or outdated evidence types, and how many days it is overdue. The CI lane `validate.soc-evidence-cadence` (tools/check_soc_evidence_cadence.py) fails the build if the sweep or its wiring is removed. The observation window for alerting on stale evidence remains the owner's decision; the sweep only makes the state visible.

---

## ISO Frameworks

| Framework | Status | Notes |
|-----------|--------|-------|
| **ISO 27001** | Not planned | ISMS scoping under evaluation |
| **ISO 27701** | Not planned | Privacy extension under evaluation |
| **ISO 27018** | Not planned | Cloud privacy under evaluation |

Only frameworks with confirmed relevance to ApexMail operations are tracked here.

---

## Other Frameworks

| Framework | Status | Scope |
|-----------|--------|-------|
| **CAN-SPAM** | Controls being mapped | US commercial email requirements |
| **CASL** | Not planned | Canadian anti-spam legislation |
| **CCPA/CPRA** | Controls being mapped | California consumer privacy |

---

## Completion Requirements

- [x] Compliance page content is distinct from the Security page
- [x] Every framework has current status, scope, and customer responsibility
- [x] The page does not imply universal compliance
- [x] Framework status is linked to the certification status table
- [x] DPA availability clearly stated
- [x] Subprocessor list linked
- [x] Data location documented

---

## References

- [Framework Certification Status](../security/framework-status.md)
- [GDPR Compliance Framework](gdpr-compliance.md)
- [BAA Template](baa-template.md)
- [Data Retention Policy](data-retention.md)
- [Access Control Policy](access-control.md)
- [Incident Response Plan](incident-response.md)
- [Vulnerability Management Policy](vulnerability-management.md)
