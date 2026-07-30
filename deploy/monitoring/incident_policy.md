# ApexMail Incident Response Policy

## 1. Scope

This policy governs the detection, response, and post-incident review process for
all ApexMail production services, including the REST API, SMTP relay, message
queue, dashboard, authentication, domains, templates, inbound processing,
analytics, grader, dedicated IP infrastructure, and support portal.

## 2. Severity Classification

| Severity  | Definition | Example |
|-----------|-----------|---------|
| **Critical** (P1) | Service unavailable or data loss. Affects all customers. | API returns 5xx for all requests; SMTP relay rejects all connections. |
| **High** (P2) | Major feature degraded. Affects majority of customers. | Domain verification broken; templates fail to render. |
| **Medium** (P3) | Partial impairment. Affects subset of customers. | Analytics dashboard delayed; dedicated IP warm-up stalled. |
| **Low** (P4) | Minor issue. No customer impact. | Non-critical metric alert; cosmetic UI issue. |

## 3. Response Time Objectives

| Severity  | Acknowledge | First Update | Resolution Target |
|-----------|-------------|-------------|-------------------|
| Critical  | 15 minutes  | 30 minutes  | 4 hours           |
| High      | 30 minutes  | 1 hour      | 8 hours           |
| Medium    | 2 hours     | 4 hours     | 2 business days   |
| Low       | 1 business day | N/A     | Next release      |

### 3.1 Acknowledge

An incident responder must triage the alert and acknowledge it in the incident
management system within the acknowledge window. The acknowledgment must
include: incident ID, responder name, initial severity assessment, and affected
services.

### 3.2 Updates

Status updates must be posted to the incident channel at least once every
30 minutes for Critical incidents and every 1 hour for High incidents. Each
update must describe: current impact, investigation progress, next steps, and
estimated time to resolution.

### 3.3 Escalation

| Time Since Acknowledge | Escalation Action |
|------------------------|-------------------|
| +15 min (Critical)     | Notify SRE lead    |
| +30 min (Critical)     | Notify CTO         |
| +1 hour (Critical)     | Notify CEO         |
| +2 hours (High)        | Notify SRE lead    |
| +4 hours (High)        | Notify CTO         |

## 4. Communication Channels

- **Primary**: `#incidents` Slack channel (internal)
- **Customer-facing**: `status.apexmail.com` status page
- **Enterprise notifications**: Direct email to technical contacts
- **Post-incident**: Incident report published to trust portal within 5 business days

## 5. Incident Commander

For Critical and High severity incidents, an Incident Commander is designated:
1. First responder serves as IC until relieved
2. IC coordinates investigation, communication, and escalation
3. IC is responsible for maintaining the incident timeline
4. IC declares incident resolved

## 6. Post-Incident Process

### 6.1 Incident Summary (within 1 business day)

A summary must be published on the status page within 1 business day of
resolution, containing:
- Incident duration
- Impact description
- Services affected
- Root cause (if known; mark as "under investigation" if not)

### 6.2 Postmortem (within 5 business days)

A blameless postmortem must be completed within 5 business days of resolution:
- **Timeline**: Detailed chronological event log
- **Root Cause Analysis**: What caused the incident
- **Detection**: How was it discovered? Could it have been detected faster?
- **Response**: What went well? What could improve?
- **Impact**: Quantified customer and business impact
- **Prevention**: Action items with owners and due dates to prevent recurrence
- **Review**: Postmortem review meeting with stakeholders

### 6.3 Action Items

All postmortem action items must be:
- Assigned to a specific owner
- Given a due date within 30 days
- Tracked in the project management system
- Reviewed at the next incident review meeting

## 7. On-Call Rotation

| Shift | Coverage | Handoff Time |
|-------|----------|-------------|
| Primary | 24x7x365 | 09:00 UTC |
| Secondary | 24x7x365 | 09:00 UTC |
| SRE Lead Escalation | 24x7x365 | Immediate on page |

### 7.1 Handoff Protocol

1. Outgoing on-call engineer documents all open incidents and alerts
2. Incoming on-call engineer acknowledges handoff
3. Both engineers review monitoring dashboards together
4. Handoff is logged in the incident management channel

## 8. Testing

- **Tabletop exercises**: Quarterly, simulating a Critical incident
- **Chaos engineering**: Monthly controlled failure injection in staging
- **Alert testing**: Bi-weekly validation that alerting paths function
- **Runbook review**: Monthly review and update of all incident runbooks

## 9. Review and Maintenance

This policy is reviewed quarterly by the SRE team and updated as needed.
Last review: 2026-07-29
Next review: 2026-10-29
