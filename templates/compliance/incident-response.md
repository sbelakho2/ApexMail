# Incident Response Policy

**Last Updated:** {{LAST_UPDATED}}

This Incident Response Policy defines the procedures for detecting, responding to, and recovering from security incidents affecting the ApexMail platform, operated by **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**).

## 1. Scope

This policy applies to all ApexMail services, infrastructure, and data. It covers:

- Security incidents (unauthorized access, data breaches, malware, DDoS).
- Availability incidents (service outages, performance degradation).
- Data integrity incidents (data corruption, accidental deletion).
- Confidentiality incidents (credential leaks, API key exposure).

## 2. Incident Severity Classification

| Severity | Definition | Example |
|---|---|---|
| **Severity 1 (Critical)** | System-wide outage or confirmed data breach affecting multiple customers | API completely unavailable, confirmed exfiltration of customer data |
| **Severity 2 (High)** | Major feature unavailable or degraded for significant portion of users | SMTP relay degraded, dashboard unavailable, suspected unauthorized access |
| **Severity 3 (Medium)** | Partial feature degradation or limited customer impact | Webhook delivery delayed, search slow, one customer affected |
| **Severity 4 (Low)** | Minor issue with no immediate customer impact | Non-critical bug, cosmetic issue, informational alert |

## 3. Detection

Incidents may be detected through:

- **Automated monitoring**: Prometheus alerting via Alertmanager triggers on threshold violations.
- **External monitoring**: Blackbox exporter probes from multiple geographic locations trigger on service unavailability.
- **Customer reports**: Issues reported to support@apexmail.ee.
- **Security tooling**: IDS/IPS, WAF, DDoS protection, threat intelligence alerts.
- **Internal observation**: Team members observing anomalous behavior.
- **Vulnerability disclosure**: Reports to security@apexmail.ee.
- **Subprocessor notification**: Subprocessors notifying ApexMail of incidents.

## 4. Response Process

### 4.1 Triage (0–15 minutes)

1. Incident detected or reported.
2. On-call engineer acknowledges and assesses severity.
3. Incident declared in incident management system.
4. Status page updated for Severity 1 and 2 incidents.

**Target**: Acknowledge within 15 minutes of confirmed incident.

### 4.2 Containment (15–60 minutes)

1. Incident commander assigned.
2. Containment actions initiated:
   - Isolate affected systems.
   - Revoke compromised credentials.
   - Block malicious IPs or traffic.
   - Activate failover if applicable.
3. Communication lead assigned for customer and internal updates.
4. Logs and evidence preserved for forensic analysis.

### 4.3 Investigation (1–24 hours)

1. Root cause analysis initiated.
2. Forensic evidence collected and analyzed.
3. Impact assessment:
   - What systems were affected?
   - What data was accessed or exfiltrated?
   - Which customers are affected?
   - Duration of impact.
4. Interim status updates published every 30 minutes for active Severity 1/2 incidents.

### 4.4 Remediation (1–72 hours)

1. Root cause addressed.
2. Additional controls implemented to prevent recurrence.
3. Systems restored to normal operation.
4. Verification testing confirms resolution.
5. Status page updated to "Resolved."

### 4.5 Recovery

1. Systems returned to normal operation.
2. Monitoring confirmed stable.
3. Backups restored if necessary.
4. Credentials rotated if compromised.

### 4.6 Post-Incident (within 5 business days)

1. Incident postmortem conducted.
2. Postmortem document published:
   - Timeline of events.
   - Root cause.
   - Impact summary.
   - Remediation actions.
   - Preventative measures.
   - Lessons learned.
3. Preventative actions tracked to completion.

**Target**: Preliminary summary within 1 business day. Major incident postmortem within 5 business days.

## 5. Communication Plan

### 5.1 Internal Communication

- Incident declared in internal incident channel.
- Incident commander coordinates response.
- Executive escalation for Severity 1 incidents.

### 5.2 Customer Communication

| Incident Type | Communication Method | Timing |
|---|---|---|
| Severity 1 | Status page, email to affected customers | Within 15 min (status), within 1 hour (email) |
| Severity 2 | Status page, email to affected customers | Within 15 min (status), within 2 hours (email) |
| Severity 3 | Status page | Within 1 hour |
| Severity 4 | Status page (optional) | At discretion |

### 5.3 Regulatory Communication

- Data Protection Lead assesses notification obligations under GDPR.
- Supervisory authority (Estonian Data Protection Inspectorate) notified within 72 hours if personal data breach is likely to result in risk to data subjects.
- Affected data subjects notified without undue delay if breach is likely to result in high risk (GDPR Art. 34).

### 5.4 External Status Page

The status page (`https://apexmail.ee/status`) is the authoritative source for service availability. It is:

- Externally hosted and monitored independently.
- Updated in real-time during incidents.
- Backed by external probes from multiple geographic locations.

## 6. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **Incident Commander** | Overall incident coordination, decision authority |
| **On-Call Engineer** | Initial triage, technical investigation, remediation |
| **Communication Lead** | Status page updates, customer communication, internal updates |
| **Data Protection Lead** | GDPR notification assessment, data breach compliance |
| **Engineering Manager** | Resource allocation, escalation |
| **Executive Sponsor** | Severity 1 oversight, external communication if required |

## 7. Data Breach Specific Procedures

For personal data breaches (per GDPR Art. 4(12)):

1. Data Protection Lead notified immediately.
2. Breach documented with: nature, categories of data, approximate number of records, likely consequences.
3. If breach is likely to result in risk to data subjects:
   - Supervisory authority notified within 72 hours.
4. If breach is likely to result in high risk:
   - Affected data subjects notified without undue delay.
5. If ApexMail is acting as processor:
   - Data controller (Customer) notified without undue delay (within 48 hours per DPA).
6. All breach notifications, actions, and decisions documented.

## 8. Testing

- Tabletop exercises: semi-annually.
- Full incident response simulation: annually.
- Disaster recovery test: annually (Enterprise: semi-annually).
- After-action reviews following every Severity 1 incident.

## 9. Tools and Infrastructure

- **Monitoring**: Prometheus, Alertmanager, Blackbox exporter.
- **Logging**: Structured logging with correlation IDs, centralized log aggregation.
- **Communication**: Internal incident channel (real-time), email (asynchronous).
- **Status Page**: Externally hosted, independent of primary infrastructure.
- **Incident Management**: Ticketing system with severity classification and SLA tracking.

## 10. Contact

Report incidents: **{{SUPPORT_EMAIL}}**
Report security vulnerabilities: **{{SECURITY_EMAIL}}**
Data protection inquiries: **{{PRIVACY_EMAIL}}**
