+++
title = "Service Level Agreement"
description = "ApexMail SLA — our uptime and performance commitments."
template = "prose.html"

[extra]
last_updated = "2026-05-07"
+++

## 1. Scope

This Service Level Agreement ("SLA") applies to Scale and Enterprise plan customers and defines our uptime and performance commitments.

## 2. Uptime Commitment

| Metric | Target |
|---|---|
| API availability | 99.9% monthly |
| SMTP relay availability | 99.9% monthly |
| Dashboard availability | 99.9% monthly |

## 3. Performance Targets

| Metric | Target |
|---|---|
| API response time (P95) | ≤100ms |
| Email acceptance to first delivery attempt | ≤30 seconds |
| Webhook delivery (P95) | ≤5 seconds |

## 4. Measurement

Uptime is measured by our external monitoring system (Blackbox exporter + Prometheus) from multiple geographic locations. Scheduled maintenance windows (announced 48 hours in advance) are excluded.

## 5. Service Credits

| Plan | Availability commitment | Monthly credit cap |
|---|---:|---:|
| Scale | 99.9% | 10% |
| Enterprise | 99.9% | 25% |

Credits are calculated from measured monthly uptime below the commitment and capped by the customer's plan.

## 6. Exclusions

Credits do not apply to: force majeure, customer-caused issues, scheduled maintenance, or beta features.

## 7. Claiming Credits

Submit credit requests to support@apexmail.ee within 30 days of the incident. Credits are applied to the next billing cycle.
