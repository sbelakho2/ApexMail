+++
title = "Performance Methodology"
description = "How ApexMail measures and reports performance, delivery, latency, and uptime metrics. Every published statistic is defined here."
template = "prose.html"

[extra]
last_updated = "2026-07-29"
+++

This page defines every performance metric published by ApexMail, including how it is measured, the measurement period, geographic coverage, exclusions, and limitations. Every publicly displayed performance number must link to its definition on this page or to the relevant section below.

The three canonical latency labels used across the site are:

1. **Production API SLA: P95 ≤ 500ms measured at gateway** — contractual SLA metric for Enterprise plans, measured server-side at the API gateway.
2. **Sandbox validation target: typically under 120ms** — guidance target for sandbox/test-mode validation latency; no email is sent.
3. **Private Cloud illustrative: architecture-dependent, not an SLA** — deployment-specific; contractual Private Cloud latency targets are defined per-deployment in customer agreements.

---

## 1. Delivery Metrics

"Delivery rate" must never appear without a specific definition. The following metrics are the only permitted public delivery measurements.

### 1.1 API Acceptance Rate

**Definition**: The percentage of valid API requests that are accepted for processing within a measurement period.

| Parameter | Value |
|---|---|
| Numerator | Number of API requests returning HTTP 202 (Accepted) and enqueued for processing |
| Denominator | Total number of API requests that pass authentication and input validation |
| Excluded | HTTP 401 (authentication failure), HTTP 400 (input validation failure), HTTP 429 (rate limited before acceptance) |
| Excluded | Requests rejected due to customer misconfiguration (unverified domain, suspended account) |
| Measurement period | Rolling 30 days |
| Data source | API gateway metrics (Prometheus counter) |

### 1.2 Processing Success Rate

**Definition**: The percentage of accepted messages that are successfully processed by the ApexMail delivery pipeline and handed off to the recipient's mail server or queued for delivery.

| Parameter | Value |
|---|---|
| Numerator | Messages that complete processing with status `processed` or `queued_for_delivery` |
| Denominator | Total messages accepted into the processing pipeline (API Acceptance count) |
| When a message counts as "processed" | When it has passed internal validation, template rendering, recipient resolution, and is handed to the delivery engine or queued for outbound delivery |
| Queued messages | Count as in-flight, not as success or failure |
| Delayed messages | Counted when processing completes |
| Provider rejection | Counted as failure |
| Internal retries | Maximum 3 internal retries before counted as failure |
| Measurement period | Rolling 30 days |
| Data source | Queue processor metrics (Prometheus counter) |

### 1.3 Recipient-Server Acceptance Rate

**Definition**: The percentage of delivery attempts that result in a successful handoff to the recipient's mail server, measured after all retries are exhausted.

| Parameter | Value |
|---|---|
| Numerator | Delivery attempts receiving SMTP 2xx response codes (250 OK, 251, 252) |
| Denominator | Total delivery attempts (excluding internal failures before SMTP connection) |
| SMTP response classes included | 2xx (success) |
| Temporary deferrals (4xx) | Not counted as success. Retried according to delivery retry schedule. Only final outcome after all retries is measured |
| Permanent bounces (5xx) | Not counted as success |
| Retry window | Up to 72 hours from initial send for standard accounts |
| Does this measure inbox placement? | **No.** This measures SMTP handoff success. ApexMail does not measure inbox placement as a service-level metric. Recipient-server acceptance confirms delivery to the destination mail server, not placement within a specific folder |
| Measurement period | Rolling 30 days |
| Data source | SMTP delivery metrics (Prometheus counter) |

### 1.4 Inbox Placement

ApexMail does **not** measure or publish inbox placement rates as a service-level metric. Inbox placement is determined by the recipient's mail provider, which ApexMail does not control. Statements implying inbox placement guarantees or measurement must not be made. Inbox placement testing via seed lists is available as a product feature on qualifying plans; seed results do not guarantee recipient-wide placement.

---

## 2. Latency Metrics

### 2.1 Production API Latency (SLA Metric)

This is the contractual SLA metric for Enterprise plans: **Production API SLA: P95 ≤ 500ms measured at gateway**.

Any published API latency number must specify the exact measurement boundaries.

| Parameter | Value |
|---|---|
| Start event | Timestamp of the last byte of the request received by the API server |
| End event | Timestamp of the first byte of the response sent by the API server |
| Does NOT include | Network round-trip time from client to server, client-side processing, DNS resolution, or TLS handshake beyond the server's TLS termination point |
| Metric type | p50 (median), p95, p99 |
| Sample size | All API requests in the measurement period |
| Sample period | Rolling 30 days |
| Regions | All active production API regions, identified in the applicable deployment |
| Included requests | All authenticated API requests (any HTTP method, any endpoint) |
| Excluded requests | Health-check probes, unauthenticated requests, rate-limited requests (HTTP 429) |
| Measurement | Server-side timing via Prometheus histogram |

**Permitted public statement example**:

> Production API SLA: P95 ≤ 500ms measured at gateway — measured server-side over a rolling 30-day period for all authenticated requests in the EU region.

**Prohibited statements**:

> Average API latency is under Xms. *(Must specify p50/p95/p99 — "average" is ambiguous.)*
>
> API responds in under Xms. *(Must specify what start and end events measure and exclude network round-trip.)*

### 2.2 Sandbox Validation Latency (Guidance)

**Sandbox validation target: typically under 120ms**. This is a guidance target, not an SLA.

| Parameter | Value |
|---|---|
| What it measures | Internal request validation, authentication, and queue acceptance in sandbox/test mode |
| Does NOT include | Outbound SMTP delivery — no email is sent in sandbox mode |
| Environment | Sandbox/test mode only |
| Metric type | p50, p95 |
| Sample size | All sandbox-mode requests in the measurement period |
| Sample period | Rolling 7 days |
| Regions | Configured sandbox region |
| Limitations | Guidance target only. Actual latency varies with request size, validation complexity, and template rendering. Does not touch production delivery pipeline. |

### 2.3 Queue-Processing Latency

| Parameter | Value |
|---|---|
| Start event | Timestamp when message enters the processing queue (after API acceptance) |
| End event | Timestamp when message exits the processing queue and is handed to the delivery engine |
| Metric type | p50, p95, p99 |
| Sample size | All accepted messages in the measurement period |
| Sample period | Rolling 30 days |
| Regions | Configured queue-processing region |
| Included | Internal validation, template rendering, recipient resolution, spam-filter assessment |
| Excluded | Messages held for scheduled/send-at delivery before their scheduled time |
| Measurement | Queue processor metrics (Prometheus histogram) |

### 2.4 First-Delivery-Attempt Latency

| Parameter | Value |
|---|---|
| Start event | Timestamp of API acceptance (HTTP 202 returned) |
| End event | Timestamp of first SMTP connection to recipient server (SYN sent to recipient MX) |
| Metric type | p50, p95, p99 |
| Sample size | All accepted messages with at least one delivery attempt in the measurement period |
| Sample period | Rolling 30 days |
| Regions | Originating from EU data center to global recipient servers |
| Included | Queue time, processing, SMTP connection establishment |
| Excluded | Deferred messages on their retry attempts (only first attempt measured). Scheduled messages measured from their scheduled release time, not from API acceptance |

### 2.5 End-to-End Delivery Latency

| Parameter | Value |
|---|---|
| Start event | Timestamp of API acceptance (HTTP 202 returned) |
| End event | Timestamp of successful SMTP handoff (2xx received from recipient server) |
| Type of measurement | Real traffic only; synthetic traffic is measured separately |
| Metric type | p50, p95, p99 |
| Sample size | All accepted messages successfully delivered in measurement period |
| Sample period | Rolling 30 days |
| Message size | All messages up to the platform maximum (10 MB including attachments) |
| Attachments | Included in measurement; larger attachments increase latency |
| Retry inclusion | Only first-successful-delivery latency is measured. Messages that succeed after retry are measured from API acceptance to the successful retry handoff, with retry delay included in the latency |
| Deferred message exclusion | Deferred messages are included only when they ultimately succeed. Permanently bounced messages are excluded |
| Regions | Originating from EU data center to global recipient servers |
| Time zone | All timestamps in UTC |

**Permitted public statement example**:

> End-to-end delivery latency: p95 is under X seconds, measured from API acceptance to SMTP handoff, including retry delays, over a rolling 30-day period.

### 2.6 Webhook Latency

| Parameter | Value |
|---|---|
| Start event | Timestamp when the event is published to the webhook delivery queue |
| End event | Timestamp when the webhook HTTP request is completed (response received or timeout) |
| Metric type | p50, p95, p99 |
| Target | p95 ≤ 5 seconds |
| Sample size | All webhook delivery attempts in the measurement period |
| Sample period | Rolling 30 days |
| Regions | Originating from EU data center to global webhook endpoints |
| Included | DNS resolution, TCP connection, TLS handshake, HTTP request-response cycle |
| Excluded | Retry and backoff periods after initial delivery failure |
| Timeout | 10 seconds per webhook delivery attempt |
| Measurement | Webhook delivery service metrics (Prometheus histogram) |

### 2.7 Private Cloud Latency

**Private Cloud illustrative: architecture-dependent, not an SLA.** Private Cloud latency is deployment-specific and depends on customer region, network topology, VPC configuration, and proximity between the customer's application and the ApexMail API infrastructure. Contractual Private Cloud latency targets are defined per-deployment in the customer agreement.

Public-facing Private Cloud latency comparisons are illustrative scenarios only, not performance guarantees.

### 2.8 Measurement Notes

- "Under 1.2 seconds" must specify exactly what it measures and at what percentile.
- Mean and median are not used interchangeably.
- All measurements include the measurement period.
- Sandbox, production, and Private Cloud latencies are not the same metric and must not be conflated.

---

## 3. Uptime and Availability

### 3.1 Component Definitions

Uptime is measured per component, not as a single global number. Each component has its own availability calculation.

| Component | Definition | Measurement |
|---|---|---|
| **REST API** | `api.apexmail.ee` — all API endpoints | External probe; HTTP 2xx on `/health` |
| **SMTP Relay** | `smtp.apexmail.ee:587` — SMTP STARTTLS handshake and banner response | External probe; SMTP connection, banner, and STARTTLS negotiation |
| **Dashboard** | `app.apexmail.ee` — web dashboard application | External probe; HTTP 2xx on login page and authenticated health endpoint |
| **Authentication** | API auth endpoints — login, token refresh, SSO | External probe; HTTP 2xx on auth health endpoint |
| **Queue Processing** | Internal message queue consumer health | Internal probe; queue depth within threshold, consumer process running |
| **Delivery Engine** | Outbound SMTP delivery workers | Internal probe; delivery worker count above minimum, no stalled workers |
| **Webhooks** | Outbound webhook delivery service | External probe; HTTP 2xx on webhook health endpoint |
| **Documentation** | `docs.apexmail.ee` — API and guide documentation | External probe; HTTP 2xx on documentation home page |
| **Status Page** | `status.apexmail.ee` — public status dashboard | External probe; independently hosted and monitored separately |
| **Billing** | Billing API and invoice generation | Internal probe; billing service reachable, no stalled invoice jobs |
| **Private Cloud CP** | Management API for Private Cloud deployments | Internal probe (where applicable) |

### 3.2 Calculation Rules

| Rule | Value |
|---|---|
| Probe interval | in minutes |
| Probe locations | Minimum 3 independently operated geographic locations, documented with each measurement period |
| Failed-probe threshold | 3 consecutive failures from at least 2 locations before component marked degraded |
| Partial outage | If some probe locations succeed and some fail, component marked degraded. If all locations fail, component marked down |
| Degraded performance | Response time > 5x baseline for 3 consecutive probes marks component degraded |
| Scheduled maintenance | Published at least 48 hours in advance on the status page. Excluded from availability calculation |
| Third-party dependency | Included in measurement; failures count against availability |
| Measurement period | Rolling 90 days for public display |
| Rounding | Availability percentage rounded to 2 decimal places (e.g., 99.97%) |

### 3.3 SLA vs. Historical Availability

- **SLA (Service Level Agreement)**: A contractual commitment to a minimum uptime percentage over a billing period. Defined per plan in the customer agreement. Not displayed as a general number on the website.
- **Historical availability**: The actual measured uptime over a past period (displayed on the status page). This is descriptive, not prescriptive.
- The status page displays historical availability only. SLA commitments are documented in customer agreements, not on the public status page.

---

## 4. Monitoring Systems

| System | Purpose | Visibility |
|---|---|---|
| Blackbox Exporter | External HTTP, HTTPS, SMTP, and DNS probes from multiple geographic locations | Status page data source |
| Prometheus | Internal metrics collection (all services, host metrics, database metrics) | Not publicly accessible |
| Alertmanager | Alert routing to on-call engineers | Not publicly accessible |
| Grafana | Internal dashboards for engineering and SRE | Not publicly accessible |
| compose healthchecks | Per-service health probes in `docker-compose.prod.yml` | Source available in repository |

### Probe Locations

| Location | Provider | Type |
|---|---|---|
| Deployment-selected primary probe | Documented for the measurement period | Primary probe; not a representation of every production region |
| Independent secondary probe | Documented for the measurement period | Independent secondary probe |
| Independent tertiary probe | Documented for the measurement period | Independent tertiary probe |

---

## 5. Exclusions

The following are excluded from performance calculations:

- **Test traffic**: Messages sent to test domains, sandbox environments, or internal test recipients.
- **Customer misconfiguration**: Failures caused by missing DNS records (SPF, DKIM, DMARC), unverified domains, or incorrect API key usage.
- **Recipient issues**: Full mailbox, invalid recipient address, recipient server policy rejection — counted in bounce metrics, not performance metrics.
- **Force majeure events**: Events qualifying as force majeure under the Terms of Service (natural disasters, internet backbone failures, DDoS attacks exceeding mitigation capacity).
- **Scheduled maintenance**: Published maintenance windows with at least 48 hours' notice.

---

## 6. Data Quality Limitations

- Probe-based measurements may miss transient failures shorter than the probe interval (in minutes).
- SMTP probe success does not guarantee every customer's SMTP connection succeeds; it verifies that the SMTP service is operational from the probe locations.
- Internal metrics (queue depth, worker count) are self-reported and may lag up to 15 seconds.
- Geographic coverage is limited to EU probe locations. Customers accessing from other regions may experience different network latency.
- Recipient-server acceptance rates are affected by recipient policies, reputation, and blocklists, which are partially outside ApexMail's direct control.

---

## 7. Methodology Changes

| Version | Date | Change Description |
|---|---|---|
| 1.0 | 2026-07-29 | Initial publication of performance methodology |
| 1.1 | 2026-07-29 | Added sandbox validation latency, queue-processing latency, first-delivery-attempt latency, webhook latency, and Private Cloud latency sections. Added three canonical latency labels distinguishing Production API SLA, Sandbox validation, and Private Cloud illustrative. |

When methodology changes would materially affect published numbers:
- The previous methodology's numbers are archived.
- A notice is published on the status page and in the changelog.
- The new methodology is versioned and the old version remains accessible for at least 12 months.

---

## 8. Update Schedule

| Item | Frequency |
|---|---|
| Methodology page review | Annually |
| Probe location review | Semi-annually |
| Metric definitions review | On any change to the measurement pipeline |
| Public performance numbers update | Continuously (automated), with monthly verification audit |

---

## 9. Contact

Questions about performance methodology: **support@apexmail.ee**
Report discrepancies in published metrics: **support@apexmail.ee**
Security concerns: **security@apexmail.ee**
