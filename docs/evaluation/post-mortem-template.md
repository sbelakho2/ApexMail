# Blameless Post-Mortem Template

> Internal document — Bel Consulting OÜ

Copy this template for each incident. Save the completed post-mortem to `docs/evaluation/post-mortems/YYYY-MM-DD-<short-title>.md`.

---

## Incident Summary

| Field | Value |
|-------|-------|
| **Title** | _Short, descriptive title_ |
| **Date** | YYYY-MM-DD |
| **Duration** | _Start time → resolution time (UTC)_ |
| **Severity** | P1 / P2 / P3 / P4 |
| **Status** | Resolved / Monitoring / Ongoing |
| **Author** | _Name_ |
| **Reviewers** | _Names_ |

### One-Line Summary

_One sentence describing what happened and the user impact._

---

## Timeline

All times in UTC.

| Time | Event |
|------|-------|
| HH:MM | _First alert fired / issue detected_ |
| HH:MM | _On-call acknowledged_ |
| HH:MM | _Investigation started — initial hypothesis_ |
| HH:MM | _Escalation (if any)_ |
| HH:MM | _Root cause identified_ |
| HH:MM | _Mitigation applied_ |
| HH:MM | _Service restored_ |
| HH:MM | _All-clear confirmed_ |

---

## Root Cause Analysis

### What happened?

_Describe the technical root cause clearly and concisely._

### 5 Whys

1. **Why** did the incident occur?
   → _Answer_
2. **Why** did that happen?
   → _Answer_
3. **Why** did that happen?
   → _Answer_
4. **Why** did that happen?
   → _Answer_
5. **Why** did that happen?
   → _Answer (this should reach a systemic or process-level cause)_

### Contributing Factors

- _Factor 1 (e.g. missing monitoring, insufficient test coverage)_
- _Factor 2_

---

## Impact Assessment

| Dimension | Detail |
|-----------|--------|
| **Users affected** | _Number or percentage of tenants / end-users impacted_ |
| **Data loss** | _Yes / No — describe extent if yes_ |
| **Revenue impact** | _Estimated lost revenue or billing credits issued_ |
| **SLA impact** | _Was the SLA breached? Which tier(s)?_ |
| **Email delivery impact** | _Messages delayed / bounced / lost_ |
| **Reputation impact** | _IP blocklisting, domain reputation damage_ |

---

## What Went Well

- _Item 1 (e.g. "Alert fired within 2 minutes of the issue")_
- _Item 2 (e.g. "Rollback completed in under 5 minutes")_
- _Item 3_

---

## What Went Wrong

- _Item 1 (e.g. "No runbook existed for this failure mode")_
- _Item 2 (e.g. "Staging did not reproduce the issue due to data volume differences")_
- _Item 3_

---

## Action Items

| # | Action | Owner | Priority | Due Date | Status |
|---|--------|-------|----------|----------|--------|
| 1 | _Specific, measurable action_ | _Name_ | P1/P2/P3 | YYYY-MM-DD | Open |
| 2 | _Specific, measurable action_ | _Name_ | P1/P2/P3 | YYYY-MM-DD | Open |
| 3 | _Specific, measurable action_ | _Name_ | P1/P2/P3 | YYYY-MM-DD | Open |

> Every action item **must** have an owner and a due date. Review progress in the next engineering sync.

---

## Lessons Learned

_Free-form section. What systemic improvements does this incident suggest? Are there patterns across recent incidents?_

---

## References

- Grafana dashboard snapshot: _URL_
- Relevant logs: _link or query_
- Related PRs / commits: _links_
- Previous related incidents: _links_

---

*Template version: 1.0 — Last updated: 2026-02-09*
