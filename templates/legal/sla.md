# Service Level Agreement (SLA)

**Last Updated:** {{LAST_UPDATED}}

This Service Level Agreement ("SLA") is between **{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**), registry code **{{REGISTRY_CODE}}**, registered at **{{ADDRESS}}**, Republic of Estonia ("ApexMail"), and the Customer. It sets out the service availability commitments and remedies for the ApexMail email infrastructure platform.

This SLA is incorporated into the [Terms of Service](terms-of-service.md).

## 1. Applicability

This SLA applies to Customers on the following plans:

| Plan | SLA Included |
|---|---|
| Free | Best-effort — no SLA commitment |
| Starter | Best-effort — no SLA commitment |
| Scale | Yes — 99.9% uptime |
| Enterprise | Yes — 99.9% uptime (enhanced SLA) |
| Dedicated Tenant | Yes — 99.95% uptime (custom) |
| BYOC | Application SLA only — infrastructure availability is Customer's responsibility |

## 2. Uptime Commitment

### 2.1 Scale Plan

| Service | Monthly Uptime Target |
|---|---|
| REST API | 99.9% |
| SMTP Relay | 99.9% |
| Dashboard | 99.9% |
| Webhook Delivery | Best-effort (excluded from SLA credits; retried for up to 72 hours) |

### 2.2 Enterprise Plan

| Service | Monthly Uptime Target |
|---|---|
| REST API | 99.9% |
| SMTP Relay | 99.9% |
| Dashboard | 99.9% |
| Webhook Delivery | Best-effort (excluded from SLA credits; retried for up to 72 hours) |
| Inbound Processing | 99.9% |
| Event Streaming | 99.9% |
| Enhanced support response | Per Enterprise agreement |

### 2.3 Dedicated Tenant

| Service | Monthly Uptime Target |
|---|---|
| All Services | 99.95% |
| Named technical owner | Yes |
| Monthly service review | Yes |
| Custom maintenance window | Yes |

### 2.4 BYOC

ApexMail is responsible for application-layer availability (99.9% for the ApexMail application components). Infrastructure availability is the Customer's responsibility per the [responsibility matrix](https://apexmail.ee/architecture).

## 3. Performance Targets

| Metric | Target |
|---|---|
| Production API P95 (gateway) | ≤ 500ms |
| Email acceptance to first delivery attempt (P95) | ≤ 30 seconds |
| Webhook delivery (P95) | ≤ 5 seconds |
| Dashboard page load (P95) | ≤ 2 seconds |

### 3.1 Production API P95 (gateway)

API latency is measured from request ingress at the API gateway to response egress from the gateway. Start timestamp: `X-Request-Start` header set at gateway ingress. End timestamp: response write completion at gateway. Percentile: P95. Qualifying requests: all `POST /v1/messages` returning HTTP 2xx in production (non-sandbox). Exclusions: health-check probes, preflight OPTIONS, sandbox/test API key traffic, internal inter-service calls. Sample period: trailing 30-day window aggregated into 1-minute buckets. Measurement excludes network latency between the client and the API gateway.

## 4. Measurement

### 4.1 How Uptime is Measured

Uptime is measured by our external monitoring infrastructure (Blackbox exporter + Prometheus) from at least three geographic locations. Measurements exclude:

- Scheduled maintenance (announced at least 48 hours in advance).
- Emergency maintenance (announced as soon as practicable).
- Customer-caused incidents (configuration errors, invalid API usage).
- Force majeure events (natural disasters, war, government action, major internet disruptions).
- Third-party services outside ApexMail's control (upstream ISPs, DNS providers, recipient mail servers).

### 4.2 Calculation

```
Monthly Uptime % = (Total Minutes in Month - Downtime Minutes) / Total Minutes in Month × 100
```

Downtime is measured from the moment an incident is confirmed (not detected) to the moment the service is restored.

## 5. Service Credits

### 5.1 Scale Plan

| Monthly Uptime | Credit (% of monthly fee) |
|---|---|
| < 99.9% – ≥ 99.0% | 10% |
| < 99.0% – ≥ 95.0% | 25% |
| < 95.0% | 50% |

### 5.2 Enterprise Plan

| Monthly Uptime | Credit (% of monthly fee) |
|---|---|
| < 99.9% – ≥ 99.0% | 10% |
| < 99.0% – ≥ 95.0% | 25% |
| < 95.0% | 50% |

### 5.3 Dedicated Tenant

| Monthly Uptime | Credit (% of monthly fee) |
|---|---|
| < 99.95% – ≥ 99.9% | 10% |
| < 99.9% – ≥ 99.0% | 25% |
| < 99.0% | 50% |

### 5.4 Credit Caps

The maximum monthly credit is capped at the percentages above per incident. Total credits in a calendar month are capped at 50% of the monthly fee. Credits are the sole and exclusive remedy for SLA breaches.

## 6. Exclusions

Service credits do not apply to:

- Force majeure events.
- Customer-caused incidents (code errors, configuration mistakes, credential compromises).
- Scheduled maintenance announced 48+ hours in advance.
- Emergency maintenance announced as soon as practicable.
- Beta, preview, or experimental features.
- Third-party service failures outside ApexMail's control.
- Suspension per the Acceptable Use Policy.
- Stripe payment-processing outages.
- DNS provider outages.
- Recipient mail server rejections or delivery failures (bounces, blocks, greylisting).

## 7. Claiming Credits

### 7.1 Eligibility

To claim credits, the Customer must:

1. Be current on all payment obligations.
2. Submit a credit request to **{{SUPPORT_EMAIL}}** within 30 days of the incident.
3. Include: dates and times of alleged downtime, affected services, and supporting evidence (logs, error messages, monitoring data).

### 7.2 Processing

ApexMail will:
- Acknowledge the claim within 2 business days.
- Investigate and respond within 10 business days.
- Apply approved credits to the next billing cycle.

### 7.3 Verification

ApexMail's monitoring data is the definitive record for determining uptime. Claims are verified against internal monitoring, logging, and incident records.

## 8. Incident Communication

During a service-impacting incident:

| Timeframe | Action |
|---|---|
| 0–15 minutes | Acknowledge confirmed incident on status page |
| Every 30 minutes | Update status page |
| Within 1 hour | Notify affected Enterprise/Dedicated Tenant customers via email |
| Within 1 business day | Publish preliminary incident summary |
| Within 5 business days | Publish initial incident report for major incidents. Final root-cause analysis published when validation completes. |

## 9. Maintenance Windows

### 9.1 Scheduled Maintenance

- Standard window: Saturdays 02:00–06:00 EET.
- Announced at least 48 hours in advance via status page and email.
- Scheduled maintenance does not count toward downtime.

### 9.2 Emergency Maintenance

- Performed as needed for critical security patches or fixes.
- Announced as soon as practicable.
- Emergency maintenance does not count toward downtime.

### 9.3 Dedicated Tenant Custom Windows

Dedicated Tenant customers may negotiate custom maintenance windows as part of their onboarding.

## 10. Support Response

| Plan | Standard Response | Priority Response |
|---|---|---|
| Free | Best-effort | N/A |
| Starter | 24 hours | N/A |
| Scale | 8 hours | 4 hours |
| Enterprise | 4 hours | 1 hour |
| Dedicated Tenant | 1 hour | 30 minutes |

Response time is measured from ticket creation to first human response during business hours (Mon–Fri, 09:00–18:00 EET). Priority response is available for Severity 1 incidents (service down).

## 11. Contact

**{{LEGAL_NAME}}** (trading as **{{TRADING_NAME}}**)
{{ADDRESS}}
Registry code: {{REGISTRY_CODE}}
VAT: {{VAT_NUMBER}}
Support: **{{SUPPORT_EMAIL}}**
Security: **{{SECURITY_EMAIL}}**
