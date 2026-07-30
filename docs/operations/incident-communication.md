# Incident Communication & Severity Matrix

> **Last Updated:** 2026-07-29
> **Owner:** SRE Team
> **Contact:** `incident@apexmail.ee`

---

## Severity Levels

### SEV-1 — Critical

**Definition:** Complete outage or severe security incident affecting a majority of customers.

| Criteria | Detail |
|----------|--------|
| Complete outage of API, SMTP, or Dashboard |
| Widespread message-processing failure (>50% of traffic) |
| Confirmed data breach |
| Authentication system unavailable |
| Status page unreachable |

**Response:**
- **Detection to notification:** < 15 minutes
- **Update interval:** Every 30 minutes
- **Owner:** SRE Lead + Engineering Lead
- **Communication channels:** Status page, Twitter/X, email to affected customers

### SEV-2 — Major

**Definition:** Major degradation or significant regional failure.

| Criteria | Detail |
|----------|--------|
| Significant regional failure affecting a single geographic region |
| Delayed sending affecting >10% of customers |
| Webhook delivery degraded |
| Dashboard substantially impaired |

**Response:**
- **Detection to notification:** < 30 minutes
- **Update interval:** Every 1 hour
- **Owner:** SRE on-call
- **Communication channels:** Status page, email to affected

### SEV-3 — Minor

**Definition:** Partial degradation or limited feature outage.

| Criteria | Detail |
|----------|--------|
| Partial degradation of a non-critical feature |
| Limited to a small customer subset |
| Analytics delayed but eventually correct |
| Documentation site down |

**Response:**
- **Detection to notification:** < 2 hours
- **Update interval:** Every 4 hours
- **Owner:** Engineering team
- **Communication channels:** Status page

### SEV-4 — Informational

**Definition:** Minor defect or cosmetic issue.

| Criteria | Detail |
|----------|--------|
| Cosmetic issue in dashboard |
| Non-critical documentation problem |
| Minor UI bug not affecting core functionality |

**Response:**
- **Detection to notification:** < 24 hours
- **Update interval:** As resolved
- **Owner:** Engineering team
- **Communication channels:** None required (tracked internally)

---

## Required Incident Fields

Every public incident communication must include:

| Field | Description |
|-------|-------------|
| **Incident Title** | Concise description of what is affected |
| **Detection Time** | When the incident was first detected (UTC) |
| **Start Time** | When the impact began (UTC) |
| **Affected Components** | Which monitored components are impacted |
| **Affected Regions** | Geographic scope of impact |
| **Customer Impact** | What customers are experiencing |
| **Current Mitigation** | What is being done right now |
| **Next Update Time** | When the next status update will be published |
| **Resolved Time** | When the incident was resolved (UTC) |
| **Root Cause** | What caused the incident (post-resolution) |
| **Corrective Action** | What was done to resolve |
| **Preventive Action** | What will prevent recurrence |

---

## Postmortem Template

```markdown
# Incident Postmortem: [INCIDENT TITLE]

**Incident ID:** INC-YYYY-NNNN
**Severity:** SEV-1 / SEV-2 / SEV-3 / SEV-4
**Date:** YYYY-MM-DD
**Duration:** HH hours MM minutes
**Author:** [Name]
**Review Date:** YYYY-MM-DD

## Summary

[One-paragraph summary of what happened]

## Timeline (all times UTC)

| Time | Event |
|------|-------|
| HH:MM | Incident detected |
| HH:MM | On-call notified |
| HH:MM | Status page updated |
| HH:MM | Mitigation started |
| HH:MM | Incident resolved |

## Root Cause

[Detailed explanation of the root cause]

## Contributing Factors

- [Factor 1]
- [Factor 2]

## Customer Impact

- [Describe impact in terms customers understand]

## Detection

[How the incident was detected — monitoring alert, customer report, etc.]

## Resolution

[What was done to resolve the incident]

## Corrective Actions

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| [Action 1] | [Name] | YYYY-MM-DD | [Open/Done] |

## Preventive Actions

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| [Action 1] | [Name] | YYYY-MM-DD | [Open/Done] |

## Lessons Learned

- [Lesson 1]
- [Lesson 2]

## What Went Well

- [Positive observation 1]

## What Went Poorly

- [Improvement area 1]
```

---

## Operational Status Guidance

### Status Display Rules

If status information is displayed anywhere on the site:

| Rule | Requirement |
|------|-------------|
| Data Source | Must be fetched from the status service (status.apexmail.io) |
| Timestamp | Last update timestamp must be visible |
| Failure State | Must be neutral, not misleading |
| API Failure | Must not default to "All systems operational" |
| Cache | Cached status must display the age of the data |

### Permitted Failure Wording

> Status information is temporarily unavailable.

### Prohibited Failure Wording

> All systems operational. (when status data cannot be retrieved)

---

## Locations to Inspect for Status Statements

| Location | Static Statement? | Replaced with Dynamic? |
|----------|-------------------|----------------------|
| Footer | Check | Yes |
| Homepage | Check | Yes |
| Pricing | Check | Yes |
| Dashboard | Check | Yes |
| Login | Check | Yes |
| Signup | Check | Yes |
| Documentation | Check | Yes |
| Contact | Check | Yes |
| Support | Check | Yes |
| Enterprise | Check | Yes |
| Email Templates | Check | Yes |

---

## Completion Requirements

- [x] Incident owners know when and how to publish (this document)
- [x] Update intervals defined per severity
- [x] Postmortem template exists
- [x] Simulated status-service failure does not display a false green state
- [x] No static "All systems operational" statement remains unverified
- [x] Severity matrix published and accessible

---

## References

- [Performance Methodology](../operations/performance-methodology.md)
- [Disaster Recovery Plan](../operations/disaster-recovery.md)
- [Disaster Recovery Testing](../operations/disaster-recovery-testing.md)
- [SLO Management](../operations/slo-management.md)
- [On-Call Guide](../operations/on-call.md)
- [Incident Response Runbook](../operations/runbooks/incident-response.md)
