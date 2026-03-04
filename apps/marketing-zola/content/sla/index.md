+++
title = "Service Level Agreement"
description = "ApexMail SLA — our uptime and performance commitments."
template = "prose.html"

[extra]
last_updated = "2025-12-01"
+++

## 1. Scope

This Service Level Agreement ("SLA") applies to Enterprise plan customers and defines our uptime and performance commitments.

## 2. Uptime Commitment

| Metric | Target |
|---|---|
| API availability | 99.99% monthly |
| SMTP relay availability | 99.99% monthly |
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

| Monthly Uptime | Credit (% of monthly fee) |
|---|---|
| 99.9% – 99.99% | 10% |
| 99.0% – 99.9% | 25% |
| 95.0% – 99.0% | 50% |
| Below 95.0% | 100% |

## 6. Exclusions

Credits do not apply to: force majeure, customer-caused issues, scheduled maintenance, or beta features.

## 7. Claiming Credits

Submit credit requests to support@apexmail.ee within 30 days of the incident. Credits are applied to the next billing cycle.
