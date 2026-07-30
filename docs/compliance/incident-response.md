# Security Incident Response Plan

> **Classification:** Internal Policy — Confidential
> **Owner:** Engineering Lead, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Annually, and after every P1/P2 incident

---

## 1. Purpose

This document defines the process for detecting, responding to, and recovering from
security incidents affecting the ApexMail platform, its infrastructure, and
customer data. The goal is to minimise damage, reduce recovery time, and meet all
regulatory notification obligations under GDPR.

---

## 2. Scope

This plan covers all systems operated by Bel Consulting OÜ for the ApexMail
platform:

- Hetzner Cloud ARM servers (EU).
- PostgreSQL databases.
- Redis instances.
- Application services (API, worker, tracking, MTA).
- DNS, TLS certificates, and domain infrastructure.
- Source code repositories and CI/CD pipelines.
- Internal tooling and admin interfaces.

---

## 3. Incident Classification

### 3.1 Severity Levels

| Level | Name | Description | Response Time | Example |
|-------|------|-------------|---------------|---------|
| **P1** | Critical | Active data breach, complete service outage, or active exploitation of a vulnerability affecting customer data. | **15 minutes** | Database exfiltration, RCE exploit in production, full platform down. |
| **P2** | High | Partial service degradation with data risk, confirmed vulnerability being actively scanned, or unauthorised access without confirmed data exposure. | **1 hour** | Suspicious admin login, partial outage affecting email delivery, credential exposure in logs. |
| **P3** | Medium | Potential security issue under investigation, minor service degradation, or policy violation without immediate data risk. | **4 hours** | Failed intrusion attempt, elevated error rates, dependency vulnerability (CVSS 7-8.9). |
| **P4** | Low | Informational security event, minor policy deviation, or low-severity vulnerability. | **Next business day** | Routine scan findings, minor configuration drift, dependency vulnerability (CVSS < 7). |

### 3.2 Incident vs Event

- **Security event:** An observable occurrence (e.g., failed login attempt). Logged
  and monitored but does not trigger the incident response process.
- **Security incident:** A security event that has been assessed and confirmed to
  require a coordinated response.

---

## 4. Response Team

### 4.1 Roles

| Role | Responsibility | Assigned To |
|------|---------------|-------------|
| **Incident Commander (IC)** | Owns the incident end-to-end. Makes decisions on escalation, communication, and resource allocation. Single point of authority. | Engineering Lead (primary), CTO (backup) |
| **Communications Lead** | Manages all external and internal communications. Drafts customer notifications, status page updates, and regulatory notifications. | Product / Business Lead |
| **Engineering Lead** | Directs technical investigation, containment, and remediation. Coordinates engineering resources. | Senior Engineer on rotation |
| **Data Protection Lead** | Assesses GDPR implications. Determines if breach notification is required. Prepares DPA notification. | Designated DPL |

### 4.2 On-Call

- A primary on-call engineer is available 24/7 and reachable within 15 minutes.
- Escalation to the Incident Commander if the on-call engineer assesses the event
  as P1 or P2.
- On-call rotation is managed via PagerDuty / internal tooling.

### 4.3 Escalation Path

```
Alert triggered
  → On-call engineer (15 min)
    → Incident Commander (if P1/P2)
      → Data Protection Lead (if personal data involved)
        → External counsel (if regulatory notification required)
```

---

## 5. Response Phases

### 5.1 Phase 1: Detection and Triage

**Objective:** Confirm the incident and assess severity.

1. Alert received via monitoring, customer report, or manual observation.
2. On-call engineer acknowledges the alert within **15 minutes**.
3. Initial triage: Determine scope, affected systems, and severity level.
4. Assign incident severity (P1–P4).
5. Open an incident channel (dedicated chat channel or thread).
6. Begin incident log (timestamped record of all actions taken).

### 5.2 Phase 2: Containment

**Objective:** Limit the blast radius and prevent further damage.

**Short-term containment (immediate):**

- Isolate affected systems (network segmentation, disable compromised accounts).
- Revoke compromised credentials and rotate secrets.
- Block malicious IPs or attack vectors at the firewall/application level.
- If data exfiltration is suspected, preserve forensic evidence before changes.

**Long-term containment (stabilise):**

- Deploy temporary fixes or mitigations.
- Redirect traffic away from compromised components.
- Enable enhanced monitoring on affected and adjacent systems.
- Confirm containment is effective before proceeding to eradication.

### 5.3 Phase 3: Eradication

**Objective:** Remove the root cause.

1. Identify the root cause and attack vector.
2. Remove malware, backdoors, or unauthorised access mechanisms.
3. Patch the vulnerability that was exploited.
4. Verify eradication by scanning affected systems.
5. Review adjacent systems for indicators of compromise (IOCs).

### 5.4 Phase 4: Recovery

**Objective:** Restore normal operations.

1. Restore systems from clean backups if required.
2. Rebuild compromised systems from known-good images.
3. Gradually restore services with enhanced monitoring.
4. Verify data integrity (database checksums, application health checks).
5. Confirm all systems are operating normally.
6. Remove temporary containment measures once stable.

### 5.5 Phase 5: Lessons Learned

**Objective:** Improve future response capability.

1. Schedule a post-incident review within **5 business days** of resolution.
2. All response team members participate.
3. Produce a post-incident report (see §8).
4. Identify action items with owners and deadlines.
5. Update runbooks, monitoring, and this plan as needed.

---

## 6. Communication

### 6.1 Internal Communication

**During the incident:**

- All communication in the dedicated incident channel.
- Status updates from the IC every **30 minutes** (P1) or **2 hours** (P2).
- No speculation in public channels.

**Internal notification template:**

```
INCIDENT [P1/P2/P3/P4] — [Short description]
Status: [Investigating / Contained / Resolved]
Affected systems: [List]
Impact: [Customer-facing impact description]
IC: [Name]
Next update: [Time]
```

### 6.2 Customer Communication

**When to notify customers:**

- Any confirmed data breach affecting their data.
- Service outages exceeding 30 minutes.
- Security events that may require customer action (e.g., credential rotation).

**Customer notification template:**

```
Subject: [ApexMail Security Notice / Service Update]

We are writing to inform you of a security incident affecting the
ApexMail platform.

What happened:
[Clear, factual description of the incident]

What data was affected:
[Specific data types, not speculative]

What we have done:
[Actions taken to contain and resolve]

What you should do:
[Specific actions the customer should take, if any]

Next steps:
[Timeline for further updates]

Contact:
[Dedicated support channel for this incident]
```

### 6.3 Regulatory Communication (GDPR Breach Notification)

**Timeline:**

| Action | Deadline | Responsible |
|--------|----------|-------------|
| Internal assessment of GDPR implications | Within **4 hours** of incident confirmation | Data Protection Lead |
| Notification to supervisory authority (Andmekaitse Inspektsioon) | Within **72 hours** of becoming aware of the breach | Data Protection Lead |
| Notification to affected data controllers (customers) | **Without undue delay** after breach confirmation | Communications Lead + DPL |
| Notification to affected data subjects (if high risk) | **Without undue delay** after assessment | Data Controller (customer), assisted by ApexMail |

**Supervisory authority notification includes (Art. 33):**

1. Nature of the breach (categories and approximate number of data subjects).
2. Name and contact details of the Data Protection Lead.
3. Description of likely consequences.
4. Description of measures taken or proposed.

If full information is not available within 72 hours, an initial notification is
filed with a commitment to provide supplementary information as it becomes available.

### 6.4 Status Page

- P1/P2 incidents are reflected on the public status page within **30 minutes**
  of confirmation.
- Updates posted at the same cadence as internal updates.
- Incident resolved status posted once recovery is confirmed.

---

## 7. Evidence Preservation

For all P1 and P2 incidents:

- **Do not destroy evidence.** Containment actions should preserve forensic data.
- Capture system logs, access logs, database query logs, and network captures.
- Take disk snapshots of affected systems before remediation.
- All evidence stored in a restricted, tamper-evident location.
- Chain of custody documented.
- Retention: Minimum **1 year** after incident closure, or longer if legal
  proceedings are anticipated.

---

## 8. Post-Incident Review

### 8.1 Timeline

- **P1:** Review within 3 business days of resolution.
- **P2:** Review within 5 business days of resolution.
- **P3/P4:** Reviewed in the next scheduled security review.

### 8.2 Post-Incident Report Template

```
Incident ID: [INC-YYYY-NNN]
Severity: [P1/P2/P3/P4]
Duration: [Detection to resolution]
Incident Commander: [Name]

Timeline:
[Timestamped sequence of events from detection to resolution]

Root Cause:
[Technical description of the root cause]

Impact:
- Systems affected: [List]
- Data affected: [Types and volume]
- Customer impact: [Description]
- Duration of impact: [Time]

Response Assessment:
- What went well: [List]
- What could be improved: [List]
- Detection time: [Time from occurrence to detection]
- Response time: [Time from detection to containment]

Action Items:
| # | Action | Owner | Deadline | Status |
|---|--------|-------|----------|--------|
| 1 | [Action] | [Name] | [Date] | Open |

GDPR Assessment:
- Personal data involved: [Yes/No]
- Breach notification filed: [Yes/No, reference]
- Data subjects notified: [Yes/No/Not required]
```

### 8.3 Blameless Culture

Post-incident reviews focus on systemic improvements, not individual blame.
The goal is to identify process, tooling, and architectural changes that prevent
recurrence.

---

## 9. Testing and Maintenance

### 9.1 Plan Testing

- **Tabletop exercises:** Conducted quarterly. Walk through a hypothetical P1
  scenario with the response team.
- **Live drills:** Conducted annually. Simulate a realistic incident end-to-end
  without prior notice to the on-call team.

### 9.2 Plan Updates

This plan is updated:

- After every P1 or P2 incident (incorporating lessons learned).
- After tabletop exercises or live drills.
- Annually during the scheduled compliance review.
- When team composition or infrastructure changes materially.

---

## 10. Related Documents

- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Data Retention Policy](./data-retention.md)
- [Vulnerability Management Policy](./vulnerability-management.md)
- [Access Control Policy](./access-control.md)
- [Change Management Policy](./change-management.md)
