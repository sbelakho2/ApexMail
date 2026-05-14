# ApexMail Service Level Agreement (SLA)

**Effective Date:** 14 May 2026
**Version:** 1.0
**Applies to:** ApexMail API, SMTP relay, and email delivery services

---

## 1. Service Commitment

ApexMail will use commercially reasonable efforts to make the ApexMail API and SMTP
relay services available with a **Monthly Uptime Percentage** of at least **99.9%**
(the "Service Commitment").

"Monthly Uptime Percentage" is calculated as:

```
(Total Minutes in Month − Downtime Minutes) ÷ Total Minutes in Month × 100
```

"Downtime" means more than 5% of requests to the API returning HTTP 5xx errors
for a consecutive 5-minute window, or complete service unavailability confirmed
by external monitoring probes.

### 1.1 Covered Services

| Service | Coverage | SLO Target |
|---------|----------|------------|
| REST API (`api.apexmail.ee`) | All HTTP endpoints under `/v1/` | 99.9% availability |
| SMTP Relay (`smtp.apexmail.ee`) | Submission and relay ports (587, 465, 25) | 99.9% availability |
| Tracking Pixel | Real-time open/click tracking endpoints | 99.9% availability |
| Webhook Delivery | Delivery of webhook events to customer endpoints | Best-effort (see §2) |

---

## 2. Performance Guarantees

### 2.1 API Latency

| Metric | Target | Measurement Period |
|--------|--------|-------------------|
| p95 API response time | < 500 ms | Rolling 5-minute window |
| p99 API response time | < 1000 ms | Rolling 5-minute window |

### 2.2 Email Delivery

| Metric | Target | Measurement Period |
|--------|--------|-------------------|
| Email delivery within 5 minutes of submission | ≥ 99.9% of all accepted messages | Rolling 7-day window |
| First-hop SMTP acceptance | < 1 second at p95 | Rolling 5-minute window |

### 2.3 API Throughput

| Tier | Guaranteed Throughput | Burst Capacity |
|------|----------------------|----------------|
| Starter | 100 req/s | 200 req/s for 60s |
| Growth | 500 req/s | 1000 req/s for 120s |
| Enterprise | Custom (per contract) | Custom (per contract) |

> **Note:** Throughput guarantees apply per API key. Exceeding sustained
> throughput limits will trigger rate limiting as described in
> [`docs/api/rate-limits.md`](api/rate-limits.md).

### 2.4 Authentication

| Metric | Target | Measurement Period |
|--------|--------|-------------------|
| Auth success rate | ≥ 99.9% of valid credential attempts | Rolling 7-day window |

---

## 3. Service Credits

If ApexMail fails to meet the Service Commitment, you may request a service credit
as outlined below.

### 3.1 Credit Schedule

| Monthly Uptime Percentage | Credit Percentage |
|---------------------------|-------------------|
| < 99.9% but ≥ 99.0% | 10% of monthly fee |
| < 99.0% but ≥ 95.0% | 25% of monthly fee |
| < 95.0% | 50% of monthly fee |

### 3.2 Latency and Delivery Credits

| Condition | Credit Percentage |
|-----------|-------------------|
| p95 latency exceeds 500ms for > 1% of measured 5m windows in a month | 5% of monthly fee |
| Email delivery SLO (within 5min) falls below 99.0% in any 7d window | 10% of monthly fee |

### 3.3 Credit Request Process

1. Submit a credit request via the ApexMail support portal within **30 days**
   of the incident end.
2. Include: account identifier, incident timestamps (UTC), affected endpoints,
   and any supporting evidence (Grafana dashboard snapshots, monitoring logs).
3. ApexMail will validate the claim against internal monitoring data and respond
   within **10 business days**.
4. Credits will be applied to the next billing cycle and are non-transferable.

### 3.4 Maximum Credit

Total credits issued in any single billing month **shall not exceed 50%** of
the monthly fee for that month.

---

## 4. Exclusions

This SLA does **not** apply to:

1. **Scheduled maintenance** — Announced at least 48 hours in advance via the
   [status page](https://status.apexmail.ee) and the `status` webhook channel.
2. **Emergency maintenance** — Unplanned but necessary security patches or
   critical infrastructure fixes, notified as soon as practicable.
3. **Customer-caused outages** — Including but not limited to:
   - Exceeding rate limits or throughput caps
   - Misconfigured DNS, SPF, DKIM, or DMARC records
   - Sending to invalid, non-existent, or hard-bounced recipient addresses
   - Sending content that violates the [Acceptable Use Policy](acceptable-use.md)
   - Using revoked, expired, or incorrect API keys
4. **Third-party dependencies** — Failures of upstream ISPs, DNS providers,
   cloud infrastructure (AWS/Azure/GCP), or certificate authorities.
5. **Force majeure** — Natural disasters, war, terrorism, civil unrest, strikes,
   pandemics, or other events outside ApexMail's reasonable control.
6. **Free-tier / trial accounts** — SLA coverage requires an active paid
   subscription (Starter, Growth, or Enterprise plan).
7. **Beta / preview features** — Features labelled as "Beta", "Preview", or
   "Early Access" are excluded from SLA coverage.
8. **Webhook delivery** — Webhook delivery is best-effort with at-least-once
   semantics; retries follow exponential backoff for up to 72 hours.

---

## 5. Reporting & Monitoring

### 5.1 Real-Time Status

- **Status page:** [`https://status.apexmail.ee`](https://status.apexmail.ee)
- **Incident notifications:** Subscribe via the status page to receive email,
  SMS, or Slack notifications for active incidents.
- **API health endpoints:**
  - `GET /v1/health/liveness` — Lightweight process health
  - `GET /v1/health/readiness` — Full dependency check

### 5.2 Monthly Reports

ApexMail publishes monthly performance reports that include:

- Monthly Uptime Percentage for the prior month
- p50/p95/p99 latency distributions
- Email delivery time distributions
- Error rate breakdowns (4xx vs 5xx)
- Incident summary with root cause analysis

Reports are published to the customer portal and the status page by the
**5th business day** of each month.

### 5.3 Monitoring Tools

Customers can monitor their own SLA compliance using:

- **Grafana dashboards:** SLO compliance panel at
  [`deploy/monitoring/dashboards/slo-compliance.json`](../deploy/monitoring/dashboards/slo-compliance.json)
- **Prometheus metrics:** All SLA-relevant metrics are exposed via the
  `/metrics` endpoint with a `slo` label
- **Alert rules:** Pre-configured PrometheusRule alerts for SLO burn-rate
  violation at [`deploy/prometheus/alerts/`](../deploy/prometheus/alerts/)

---

## 6. Definitions

| Term | Definition |
|------|------------|
| **Monthly Uptime Percentage** | The percentage of minutes in a calendar month during which the ApexMail service was available, as defined in §1. |
| **Downtime** | A 5-minute period during which the error rate exceeds 5% as determined by internal and external monitoring. |
| **Error Rate** | The ratio of HTTP 5xx responses to total HTTP responses, measured over consecutive 5-minute windows. |
| **Valid Credential** | An API key or authentication token that is active, non-revoked, and has sufficient permissions for the requested operation. |
| **Business Day** | Monday through Friday, excluding public holidays in the European Union. |

---

## 7. SLA Changes

ApexMail may update this SLA from time to time. Material changes will be
communicated via:

1. Email notification to the account owner at least **30 days** in advance
2. A notice on the status page
3. An update to the `CHANGELOG.md` at the repository root

Continued use of the ApexMail service after the effective date of a change
constitutes acceptance of the updated SLA.

---

## 8. Governing Law

This SLA is governed by the laws of the Republic of Estonia. Any disputes
arising under this SLA shall be resolved in the courts of Tallinn, Estonia.

---

*For questions about this SLA, contact [support@apexmail.ee](mailto:support@apexmail.ee)
or open a ticket via the customer portal.*
