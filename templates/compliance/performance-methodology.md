# Performance Methodology

**Last Updated:** {{LAST_UPDATED}}

This page defines every performance metric published by ApexMail, including how it is measured, the measurement period, geographic coverage, exclusions, and limitations. Every publicly displayed performance number must link to its definition on this page or to the relevant section below.

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
| Excluded | Requests rejected due to customer misconfiguration (e.g., unverified domain, suspended account) |
| Measurement period | Rolling 30 days |
| Data source | API gateway metrics (Prometheus counter `api_requests_accepted_total` / `api_requests_received_valid_total`) |

### 1.2 Processing Success Rate

**Definition**: The percentage of accepted messages that are successfully processed by the ApexMail delivery pipeline and handed off to the recipient's mail server or queued for delivery.

| Parameter | Value |
|---|---|
| Numerator | Messages that complete processing with status `processed` or `queued_for_delivery` |
| Denominator | Total messages accepted into the processing pipeline (API Acceptance count) |
| When a message counts as "processed" | When it has passed internal validation, template rendering, recipient resolution, and is handed to the delivery engine or queued for outbound delivery |
| Do queued messages count? | Yes — a message queued for delivery is considered successfully processed from the pipeline perspective. Delivery to recipient server is tracked separately (see §1.3) |
| Do delayed messages count? | Yes — delayed messages are still processed; they are not failures |
| Does provider rejection count? | No — if the message is rejected by the internal pipeline (e.g., policy violation, blocklist match), it is not counted as successfully processed |
| Do internal retries count? | A retried message counts once (when first enqueued). Retry attempts are not double-counted |
| Measurement period | Rolling 30 days |
| Data source | Queue processor metrics (Prometheus counter `pipeline_messages_processed_total` / `pipeline_messages_accepted_total`) |

### 1.3 Recipient-Server Acceptance Rate

**Definition**: The percentage of delivery attempts that result in a successful handoff to the recipient's mail server, measured after all retries are exhausted.

| Parameter | Value |
|---|---|
| Numerator | Delivery attempts receiving SMTP 2xx response codes (250 OK, 251 User not local, 252 Cannot verify) |
| Denominator | Total delivery attempts (excluding internal failures before SMTP connection) |
| SMTP response classes included | 2xx (success) |
| Treatment of temporary deferrals (4xx) | Not counted as success. Retried according to the delivery retry schedule. Only the final outcome after all retries is measured |
| Treatment of permanent bounces (5xx) | Not counted as success |
| Time window for retry completion | Up to 72 hours from initial send for standard accounts; configurable for Enterprise |
| Does this measure inbox placement? | **No.** This measures SMTP handoff success. ApexMail does not measure inbox placement. A recipient server accepting a message does not guarantee inbox delivery |
| Measurement period | Rolling 30 days |
| Data source | SMTP delivery metrics (Prometheus counter `smtp_delivery_accepted_total` / `smtp_delivery_attempt_total`) |

### 1.4 Inbox Placement

ApexMail does **not** measure or publish inbox placement rates. Inbox placement is determined by the recipient's mail provider, which ApexMail does not control. Statements implying inbox placement guarantees or measurement must not be made.

---

## 2. Latency Metrics

### 2.1 API Latency

Any published API latency number must specify the exact measurement boundaries.

| Parameter | Value |
|---|---|
| Start event | Timestamp of the last byte of the request received by the API server |
| End event | Timestamp of the first byte of the response sent by the API server |
| Does NOT include | Network round-trip time from client to server, client-side processing, DNS resolution, or TLS handshake beyond the server's TLS termination point |
| Metric type | p50 (median), p95, p99 |
| Sample size | All API requests in the measurement period |
| Sample period | Rolling 30 days |
| Regions | All regions where API servers are deployed (EU — Helsinki) |
| Included requests | All authenticated API requests (any HTTP method, any endpoint) |
| Excluded requests | Health-check probes, unauthenticated requests, rate-limited requests (HTTP 429) |
| Measurement | Server-side timing via Prometheus histogram `http_request_duration_seconds` |

**Permitted public statement example**:

> API p95 latency is under Xms, measured server-side over a rolling 30-day period for all authenticated requests in the EU region.

**Prohibited public statements**:

> Average API latency is under Xms. _(Must specify p50/p95/p99 — "average" is ambiguous.)_

> API responds in under Xms. _(Must specify what start and end events measure and exclude network round-trip.)_

### 2.2 End-to-End Delivery Latency

| Parameter | Value |
|---|---|
| Start event | Timestamp of API acceptance (HTTP 202 returned) |
| End event | Timestamp of successful SMTP handoff (2xx received from recipient server), or first delivery attempt for queued messages |
| Type of measurement | Real traffic only; synthetic traffic is measured separately |
| Metric type | p50, p95, p99 |
| Sample size | All accepted messages successfully delivered in measurement period |
| Sample period | Rolling 30 days |
| Message size | All messages up to the platform maximum (10 MB including attachments) |
| Attachments | Included in measurement; larger attachments increase latency |
| Retry inclusion | Only first-successful-delivery latency is measured. Messages that succeed after retry are measured from API acceptance to the successful retry handoff, with retry delay included in the latency |
| Deferred message exclusion | Deferred messages are included only when they ultimately succeed. Permanently bounced messages are excluded (no successful end event exists) |
| Regions | Originating from EU data center to global recipient servers |
| Recipient providers | All recipient mail servers (not limited to specific providers) |
| Time zone | All timestamps in UTC |

**Permitted public statement example**:

> End-to-end delivery latency: p95 is under X seconds, measured from API acceptance to SMTP handoff, including retry delays, over a rolling 30-day period.

---

## 3. Uptime and Availability

### 3.1 Component Definitions

Uptime is measured per component, not as a single global number. Each component has its own availability calculation.

| Component | Definition | Uptime Measurement |
|---|---|---|
| **REST API** | `api.apexmail.com` — all API endpoints (HTTP 2xx on `/health`, `/v1/health`) | External probe; SSL certificate validity also checked |
| **SMTP Relay** | `smtp.apexmail.com:587` — SMTP STARTTLS handshake and banner response | External probe; SMTP connection, banner, and STARTTLS negotiation |
| **Dashboard** | `app.apexmail.com` — web dashboard application | External probe; HTTP 2xx on login page and authenticated health endpoint |
| **Authentication** | `api.apexmail.com/auth` — login, token refresh, SSO | External probe; HTTP 2xx on auth health endpoint |
| **Queue Processing** | Internal message queue consumer health (queue depth, processing latency) | Internal probe; queue depth within threshold, consumer process running |
| **Delivery Engine** | Outbound SMTP delivery workers | Internal probe; delivery worker count above minimum, no stalled workers |
| **Webhooks** | Outbound webhook delivery service | External probe; HTTP 2xx on webhook health endpoint; webhook dispatch latency within threshold |
| **Documentation** | `docs.apexmail.com` — API and guide documentation | External probe; HTTP 2xx on documentation home page |
| **Status Page** | `status.apexmail.com` — public status dashboard | External probe; independently hosted and monitored separately |
| **Billing** | Billing API and invoice generation | Internal probe; billing service reachable, no stalled invoice jobs |
| **Private Cloud Control Plane** | Management API for Private Cloud deployments | Internal probe (where applicable); control plane API responding |

### 3.2 Calculation Rules

| Rule | Value |
|---|---|
| Probe interval | 60 seconds per component |
| Probe locations | Minimum 3 geographic locations (Helsinki, Frankfurt, Amsterdam) |
| Failed-probe threshold | 2 consecutive probe failures from at least 2 locations before component is marked degraded |
| Partial outage handling | If some probe locations succeed and some fail, component is marked degraded. If all locations fail, component is marked down |
| Degraded performance handling | If response time exceeds 5 seconds for HTTP probes (3 consecutive probes), component is marked degraded even if returning 2xx |
| Scheduled maintenance | Published at least 48 hours in advance on the status page. Does not count against uptime SLA if declared as maintenance. Displayed as "Under Maintenance" on status page |
| Third-party dependency handling | If a component depends on a third-party service (e.g., Stripe for billing) and that service is unavailable, the dependent component is marked degraded with a note identifying the third-party dependency |
| Measurement period | Rolling 90 days for public display; rolling 365 days for SLA calculations |
| Rounding rules | Uptime is calculated to 4 decimal places, displayed to 2 decimal places (e.g., 99.97%). Round half-up |

### 3.3 SLA vs. Historical Availability

- **SLA (Service Level Agreement)**: A contractual commitment to a minimum uptime percentage over a billing period. Defined per plan in the customer agreement. Not displayed as a general number on the website.
- **Historical availability**: The actual measured uptime over a past period (displayed on the status page). This is descriptive, not prescriptive.
- The status page displays historical availability only. SLA commitments are documented in customer agreements, not on the public status page.

---

## 4. Monitoring Systems

| System | Purpose | Public Visibility |
|---|---|---|
| Blackbox Exporter | External HTTP, HTTPS, SMTP, and DNS probes from multiple geographic locations | Status page data source |
| Prometheus | Internal metrics collection (all services, host metrics, database metrics) | Not publicly accessible |
| Alertmanager | Alert routing to on-call engineers | Not publicly accessible |
| Grafana | Internal dashboards for engineering and SRE | Not publicly accessible |
| compose healthchecks | Per-service health probes in `docker-compose.prod.yml` | Source available in repository |

### Probe Location Details

| Location | Provider | Type |
|---|---|---|
| Helsinki, Finland | Hetzner | Primary — same region as production infrastructure |
| Frankfurt, Germany | Hetzner | Secondary — independent region |
| Amsterdam, Netherlands | Independent VPS | Tertiary — fully independent infrastructure |

---

## 5. Exclusions

The following are excluded from performance calculations:

- **Test traffic**: Messages sent to test domains, sandbox environments, or internal test recipients.
- **Customer misconfiguration**: Failures caused by missing DNS records (SPF, DKIM, DMARC), unverified domains, or incorrect API key usage.
- **Recipient issues**: Full mailbox, invalid recipient address, recipient server policy rejection — these are counted in bounce metrics, not performance metrics.
- **Force majeure events**: Events qualifying as force majeure under the Terms of Service (natural disasters, internet backbone failures, DDoS attacks exceeding mitigation capacity).
- **Scheduled maintenance**: Published maintenance windows with at least 48 hours' notice.

---

## 6. Data Quality Limitations

- Probe-based measurements may miss transient failures shorter than the probe interval (60 seconds).
- SMTP probe success does not guarantee every customer's SMTP connection succeeds; it verifies that the SMTP service is operational from the probe locations.
- Internal metrics (queue depth, worker count) are self-reported and may lag up to 15 seconds.
- Geographic coverage is limited to EU probe locations. Customers accessing from other regions (e.g., Asia, Americas) may experience different network latency.
- Recipient-server acceptance rates are affected by recipient policies, reputation, and blocklists, which are partially outside ApexMail's direct control.

---

## 7. Methodology Changes

| Version | Date | Change Description |
|---|---|---|
| 1.0 | {{LAST_UPDATED}} | Initial publication of performance methodology |
| _(Future entries)_ | _(Date)_ | _(Description of change and reason)_ |

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

Questions about performance methodology: **{{SUPPORT_EMAIL}}**
Report discrepancies in published metrics: **{{SUPPORT_EMAIL}}**
Security concerns: **{{SECURITY_EMAIL}}**
