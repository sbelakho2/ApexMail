# SLO Management

Service Level Objectives (SLOs) define the reliability targets for ApexMail.

## Overview

ApexMail uses SLOs to:
- Set measurable reliability targets
- Guide engineering decisions
- Communicate reliability expectations
- Trigger alerts before user impact

## Core SLOs

### API Availability

**Target**: 99.9% (3 nines)

| Window | Allowed Downtime |
|--------|------------------|
| Daily | 1 minute 26 seconds |
| Weekly | 10 minutes 5 seconds |
| Monthly | 43 minutes 50 seconds |
| Yearly | 8 hours 46 minutes |

**SLI Definition**:
```
Availability = (Successful requests / Total requests) × 100

Successful = HTTP status < 500
Excludes: Health checks, metrics endpoints
```

### API Latency

**Target**: P99 < 500ms

| Percentile | Target |
|------------|--------|
| P50 | < 50ms |
| P90 | < 200ms |
| P95 | < 300ms |
| P99 | < 500ms |

**SLI Definition**:
```
Latency = Time from request received to response sent
Excludes: Client network time, long-polling endpoints
```

### Email Delivery Rate

**Target**: 98% within 5 minutes

| Metric | Target |
|--------|--------|
| Delivery rate | 98% |
| Time to deliver | < 5 minutes |
| Bounce rate | < 2% |

**SLI Definition**:
```
Delivery Rate = (Delivered messages / Sent messages) × 100

Delivered = Confirmed by receiving MTA (SES delivery event or SMTP 250 OK)
Excludes: Invalid addresses, suppressed recipients
```

### Tracking Availability

**Target**: 99.95%

Open and click tracking must be highly available since tracking failures mean lost data.

**SLI Definition**:
```
Tracking Availability = (Successful tracking requests / Total requests) × 100
```

---

## Error Budget

The error budget is the allowed unreliability:

```
Error Budget = 100% - SLO Target

For 99.9% availability:
Error Budget = 100% - 99.9% = 0.1%
```

### Error Budget Policies

| Budget Remaining | Policy |
|------------------|--------|
| > 50% | Normal development velocity |
| 25-50% | Extra caution on risky changes |
| 10-25% | Freeze non-critical changes |
| < 10% | Reliability-only work |
| Exhausted | All hands on reliability |

### Monthly Budget Tracking

```
Monthly Error Budget (30 days):
- Total minutes: 43,200
- Budget (0.1%): 43.2 minutes

Current status:
- Budget used: 12.5 minutes (29%)
- Budget remaining: 30.7 minutes (71%)
- Burn rate: Normal
```

---

## Monitoring

### SLO Dashboard

Access the SLO dashboard at `/ops/slo` or via API:

```http
GET /v1/ops/slo/status
Authorization: Bearer {{admin_token}}
```

Response:
```json
{
  "slos": [
    {
      "name": "API Availability",
      "target": 99.9,
      "current": 99.95,
      "status": "healthy",
      "errorBudget": {
        "total": 43.2,
        "remaining": 35.8,
        "percentRemaining": 82.9
      },
      "windows": {
        "7d": 99.97,
        "30d": 99.95,
        "90d": 99.93
      }
    },
    {
      "name": "API Latency P99",
      "target": 500,
      "current": 245,
      "unit": "ms",
      "status": "healthy"
    }
  ]
}
```

### Alert Thresholds

| SLO | Warning | Critical |
|-----|---------|----------|
| Availability | < 99.95% (5m) | < 99.9% (5m) |
| Latency P99 | > 400ms | > 500ms |
| Delivery Rate | < 98.5% | < 98% |
| Error Budget | < 30% remaining | < 10% remaining |

### Burn Rate Alerts

Burn rate measures how quickly you're consuming error budget:

```
Burn Rate = Error Rate / Error Budget Rate

Example:
- SLO: 99.9% (0.1% error budget)
- Current error rate: 0.5%
- Burn rate: 0.5% / 0.1% = 5x

At 5x burn rate, monthly budget exhausted in 6 days
```

Alert thresholds:
| Burn Rate | Window | Action |
|-----------|--------|--------|
| 14.4x | 1 hour | Page immediately |
| 6x | 6 hours | Page during business hours |
| 3x | 1 day | Ticket for review |
| 1x | 3 days | Normal monitoring |

---

## Incident Response

### When SLO is Breached

1. **Acknowledge** alert within SLA (15 min for SEV1)
2. **Assess** impact and severity
3. **Communicate** via status page
4. **Mitigate** to stop the bleeding
5. **Resolve** root cause
6. **Document** with post-mortem

### Severity Classification

| Severity | SLO Impact | Response |
|----------|------------|----------|
| SEV1 | Multiple SLOs breached | All hands, 15 min response |
| SEV2 | Single SLO breached | On-call, 1 hour response |
| SEV3 | SLO at risk (warning) | Normal business hours |
| SEV4 | Minor degradation | Scheduled maintenance |

---

## SLO Review Process

### Weekly Review

- Review SLO performance
- Check error budget consumption
- Identify reliability risks
- Plan reliability improvements

### Monthly Review

- Adjust SLO targets if needed
- Review incident trends
- Update error budget policies
- Capacity planning

### Quarterly Review

- Business alignment check
- SLO target adjustments
- Architecture review
- Tooling improvements

---

## Reporting

### SLO Report (Monthly)

```markdown
# SLO Report - January 2024

## Summary
- All SLOs met ✅
- Error budget: 71% remaining
- Major incidents: 0

## API Availability
- Target: 99.9%
- Actual: 99.95%
- Status: ✅ Met

## API Latency (P99)
- Target: 500ms
- Actual: 245ms
- Status: ✅ Met

## Email Delivery
- Target: 98%
- Actual: 98.7%
- Status: ✅ Met

## Incidents
No major incidents this month.

## Improvements
- Deployed read replicas (improved latency)
- Added circuit breaker for email service
- Upgraded Redis for better queue performance
```

### Customer-Facing SLA

Based on internal SLOs, we offer customers:

| Plan | Availability SLA | Credits |
|------|------------------|---------|
| Free / Starter / Pro / Growth | Best effort | None |
| Scale | 99.9% | 10% monthly cap |
| Enterprise | 99.9% | 25% monthly cap |

---

## Best Practices

### Setting SLO Targets

1. **Start realistic** - Don't promise more than you can deliver
2. **Use historical data** - Base targets on actual performance
3. **Include buffer** - Internal target stricter than customer SLA
4. **Review regularly** - Adjust as system matures

### Managing Error Budget

1. **Track continuously** - Real-time budget monitoring
2. **Communicate status** - Team aware of budget health
3. **Enforce policies** - Follow budget-based decisions
4. **Learn from exhaustion** - Post-mortem when budget depleted

### Avoiding SLO Pitfalls

- ❌ Too many SLOs (focus on what matters)
- ❌ SLOs without ownership
- ❌ Ignoring error budget
- ❌ Never adjusting targets
- ❌ SLOs not tied to user experience
