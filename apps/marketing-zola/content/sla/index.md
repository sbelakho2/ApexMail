+++
title = "Service Level Agreement"
description = "ApexMail SLA — our uptime and performance commitments."
template = "prose.html"

[extra]
last_updated = "2026-09-09"
+++

## 1. Scope

This Service Level Agreement ("SLA") applies to Business and Enterprise plan customers and defines our uptime and performance commitments.

## 2. Uptime Commitment

| Metric | Target |
|---|---|
| API availability | 99.9% monthly |
| SMTP relay availability | 99.9% monthly |
| Dashboard availability | 99.9% monthly |

## 3. Performance Targets

| Metric | Target |
|---|---|
| Production API P95 (gateway) | ≤500ms |
| Email acceptance to first delivery attempt | ≤30 seconds |
| Webhook delivery (P95) | ≤5 seconds |

### Metric Definitions

**Production API P95 (gateway):** Measured at the API gateway layer for all production `POST /v1/messages` requests. Start timestamp: request ingress at gateway. End timestamp: response egress from gateway. Percentile: P95. Qualifying requests: HTTP 200-299 responses from the messages endpoint, excluding sandbox/test API key traffic. Exclusions: health-check probes, preflight OPTIONS, sandbox API keys. Sample period: trailing 30-day window, 1-minute aggregation buckets.

## 4. Measurement

Uptime is measured by our external monitoring system (Blackbox exporter + Prometheus) from multiple geographic locations. Scheduled maintenance windows (announced 48 hours in advance) are excluded.

## 5. Service Credits

Eligible plans carry a 99.9% monthly availability commitment. When measured
monthly uptime falls below it, a service credit applies per the tiered bands
below — the credit percentage is the tenant's monthly recurring charge for the
affected month.

| Measured monthly availability | Service credit |
|---|---:|
| ≥ 99.9% | 0% (commitment met) |
| 99.0% – 99.899% | 10% |
| 95.0% – 98.999% | 25% |
| < 95.0% | 50% |

**Plan schedules:**

- **Business** — graduated, no flat cap below the tiers:
  99.0–99.899% → 10% · 95.0–98.999% → 20% · <95% → 30% of the monthly charge.
- **Enterprise Cloud and contracted deployments** — the tiers above up to 25%
  (or the contracted figure where an order form specifies one).

Credits are calculated from measured monthly uptime below the commitment and
capped by the customer's plan.

## 6. Exclusions

Credits do not apply to: force majeure, customer-caused issues, scheduled maintenance, or beta features.

## 7. Claiming Credits

Submit credit requests to support@apexmail.ee within 30 days of the incident. Credits are applied to the next billing cycle.
