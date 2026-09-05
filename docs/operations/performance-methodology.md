# Performance Methodology

> **Last Updated:** 2026-07-29
> **Owner:** SRE Team
> **Version:** 1.0.0

---

This page defines how ApexMail measures and reports performance, delivery, and uptime metrics. Every published performance statistic must reference a definition in this document.

---

## 1. Delivery Metrics

### 1.1 API Acceptance Rate

**Definition:** The percentage of valid API requests that are accepted for processing during a measurement period.

| Parameter | Value |
|-----------|-------|
| Numerator | Number of API requests returning HTTP 2xx (accepted for processing) |
| Denominator | Total valid API requests received |
| Excluded | HTTP 401 (authentication failures), HTTP 422 (customer configuration errors), requests with malformed syntax |
| Measurement Period | Rolling 30 days |
| Update Frequency | Daily |

### 1.2 Processing Success Rate

**Definition:** The percentage of accepted messages that are successfully processed and dispatched to the sending pipeline.

| Parameter | Value |
|-----------|-------|
| When Considered Processed | Message handed off to delivery engine after validation, template rendering, and attachment processing |
| Queued Messages | Counted as in-flight, not as success or failure |
| Delayed Messages | Counted when processing completes |
| Provider Rejection | Counted as failure |
| Internal Retries | Maximum 3 internal retries before counted as failure |
| Measurement Period | Rolling 30 days |

### 1.3 Recipient-Server Acceptance Rate

**Definition:** The percentage of dispatched messages accepted (HTTP 250) by the recipient's mail server.

| Parameter | Value |
|-----------|-------|
| SMTP Response Classes Included | Class 2xx (250 OK, 251, 252) |
| Temporary Deferrals (4xx) | Not counted until retry window completes |
| Permanent Bounces (5xx) | Counted as non-acceptance |
| Retry Window | Up to 72 hours from initial send |
| Measurement Period | Rolling 30 days |

### 1.4 Inbox Placement

ApexMail **does not currently measure** inbox placement as a service metric. Recipient-server acceptance confirms delivery to the destination mail server, not placement within a specific folder (inbox vs spam). Do not conflate acceptance rate with inbox placement.

---

## 2. Latency Metrics

### 2.1 API Response Latency (p95)

**Definition:** The 95th percentile time between receiving a complete API request and returning an HTTP response.

| Parameter | Value |
|-----------|-------|
| Start Event | Request fully received by API server |
| End Event | HTTP response sent to client |
| Metric Type | p95 (95th percentile) |
| Sample Size | All API requests in period |
| Sample Period | Rolling 30 days |
| Regions | EU (primary); US East measurement included where noted |
| Recipient Providers | All |
| Message Size Limits | Up to 10 MB |
| Attachment Handling | Included in measurement |
| Retry Inclusion | Excluded (self-healing retries not counted) |
| Deferred Message Exclusion | Excluded |
| Traffic Type | Real production traffic only |

### 2.2 End-to-End Delivery Latency (p95)

**Definition:** The 95th percentile time between API acceptance and recipient-server acceptance.

| Parameter | Value |
|-----------|-------|
| Start Event | API returns 2xx (message accepted) |
| End Event | Recipient server returns 2xx (SMTP 250) |
| Metric Type | p95 |
| Sample Size | All delivered messages in period |
| Sample Period | Rolling 30 days |
| Regions | EU |

### 2.3 Measurement Notes

- "Under 1.2 seconds" must specify exactly what it measures and at what percentile.
- Mean and median are not used interchangeably.
- All measurements include the measurement period.

---

## 3. Uptime and Availability

### 3.1 System Boundaries

Each component has separate availability tracking:

| Component | Monitored? | Probe URL | Independent |
|-----------|------------|-----------|-------------|
| Marketing Website | Yes | `https://apexmail.ee` | Same cluster |
| Dashboard (console) | Yes | `https://app.apexmail.ee/health/live` | Same cluster |
| Authentication | Yes | `https://api.apexmail.ee/health/live` | Same cluster |
| API | Yes | `https://api.apexmail.ee/health/ready` | Same cluster |
| Queue Processing | Yes | Internal probe | Same cluster |
| Delivery Processing | Yes | Internal probe | Same cluster |
| Webhooks | Yes | `https://api.apexmail.ee/health/ready` (delivered by api-server) | Same cluster |
| Documentation | Yes | `https://apexmail.ee/docs` | Same cluster |
| Status Page | Yes | `https://status.apexmail.ee` | **Independent** |
| Billing | Yes | internal `billing-service` healthcheck (port 4100, no public host) | Same cluster |
| Private Cloud CP | Yes (where applicable) | Tenant-specific | Mixed |

### 3.2 Calculation Rules

| Parameter | Value |
|-----------|-------|
| Probe Interval | 60 seconds |
| Probe Locations | EU: 3 regions; US: 2 regions |
| Failed Probe Threshold | 3 consecutive failures = component degraded |
| Partial Outage | If any probe passes, component is "degraded" not "down" |
| Degraded Performance | Response time > 5x baseline = degraded |
| Scheduled Maintenance | Excluded from availability calculation; must be announced 48 hours prior |
| Third-Party Dependency | Included in measurement; failures count against availability |
| Measurement Period | Rolling 90 days |
| Rounding | Availability percentage rounded to 2 decimal places |

### 3.3 SLA vs Historical

- **SLA availability** is the contractual commitment (e.g., "99.9% uptime").
- **Historical availability** is the measured uptime over a rolling 90-day period.
- These numbers may differ; the SLA is a target, historical is the actual.
- Uptime is displayed per-component, not as a single global number, unless the monitored scope is clearly stated.

---

## 4. Monitoring Systems

| System | Purpose | Provider |
|--------|---------|----------|
| Status Page | Public availability display | status.apexmail.io |
| Internal Monitoring | Probe-based monitoring | Prometheus + Grafana |
| External Monitoring | Multi-region synthetic probes | Independent service |
| Real-User Monitoring | Client-side performance | Where enabled per consent |

---

## 5. Geographic Coverage

| Region | Monitoring Locations |
|--------|---------------------|
| EU | Frankfurt, Helsinki, Amsterdam |
| US East | Virginia, Ohio |

---

## 6. Exclusions

- Development and staging environments
- Private Cloud instances (customer responsibility)
- Third-party status pages for integrated services
- DNS propagation delays
- Client-side network issues outside ApexMail control

---

## 7. Data-Quality Limitations

- Probe-based monitoring may miss transient sub-60-second outages
- Synthetic probes do not replicate all customer traffic patterns
- Third-party API failures affecting probe delivery are noted
- Real-user monitoring requires opt-in consent

---

## 8. Methodology Changes

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-29 | Initial publication |

Methodology changes are versioned. Historical results using prior methodology remain interpretable via archived methodology versions.

---

## 9. Update Schedule

- Performance data: Updated daily
- Methodology review: Annually (or when monitoring systems change)
- Ad-hoc: If a metric definition or measurement system changes materially

---

## 10. Contact

For questions about performance methodology: `sre@apexmail.ee`

---

## Completion Requirements

- [x] Technical buyers can understand how every number was produced
- [x] Methodology changes are versioned
- [x] Historic results remain interpretable
- [x] Every performance statistic links to its definition or this page
