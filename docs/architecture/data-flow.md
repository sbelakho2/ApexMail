# Data Flow Architecture

> **Implementation Note (2026-02):** This document describes the conceptual data flow. The actual implementation uses:
> - **Rust tracking service** as the current API implementation
> - **PostgreSQL-native queues** instead of BullMQ (see [queue-system.md](./queue-system.md))
> - **Rust MTA crate** instead of Postfix (for inbound SMTP only)
> - **AWS SES** for shared-pool sending (default for tenants without dedicated IPs)
> - **Hetzner SMTP** for dedicated IP sending (automatic for tenants with dedicated IPs)
> - Routing is **per-message** via `TransportRouter` based on tenant dedicated IP ownership
> - Code examples below are pseudo-code; actual implementation is in `services/mail-server/crates/`

## Email Sending Pipeline

### Overview
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Email Sending Pipeline                             │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
  │  API    │────▶│ Validate │────▶│  Queue   │────▶│  Render  │────▶│Transport│
  │ Request │     │ & Enrich │     │(Postgres)│     │ Template │     │(SES/SMTP)│
  └─────────┘     └──────────┘     └──────────┘     └──────────┘     └─────────┘
       │                                                                   │
       │                                                              ┌────┴────┐
       ▼                                                              │         │
  ┌─────────┐                                                    ┌────┴───┐ ┌───┴────┐
  │  Log    │                                                    │AWS SES │ │Direct  │
  │ Attempt │                                                    │(default│ │MX SMTP │
  └─────────┘                                                    │        │ │(opt-in)│
                                                                 └────┬───┘ └───┬────┘
                                                                      │         │
                                                                      ▼         ▼
                                                                 ┌─────────────────┐
                                                                 │    Deliver       │
                                                                 │    Email         │
                                                                 └─────────────────┘
```

### Step-by-Step Flow

#### 1. API Request Reception
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### 2. Validation Layer
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### 3. Queue Insertion
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### 4. Worker Processing
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### 5. Delivery Transport

Routing is **per-message** via `TransportRouter`:

**Tenant without dedicated IPs → AWS SES (shared pool):**
```
Worker builds RFC 5322 MIME message
  → TransportRouter checks routing cache
  → No dedicated IPs → SesTransport
  → SES v2 SendEmail API (RawMessage)
  → SES handles DKIM signing, MX delivery, retries
  → SNS publishes events (bounce/complaint/delivery)
  → /v1/ses/notifications webhook processes events
  → Database updated
```

**Tenant with dedicated IPs → Hetzner SMTP:**
```
Worker builds RFC 5322 MIME message
  → TransportRouter checks routing cache
  → Has dedicated IPs → SmtpTransport
  → SmtpSender resolves MX records
  → Select Hetzner floating IP (round-robin, warmup-aware)
  → TcpSocket::bind(source_ip) → STARTTLS → deliver
  → Custom DKIM signing (per-domain keys)
  → Bounce/complaint via DSN + FBL servers

# Permanent failure:
incoming → active → bounce → notification
```

> **During warmup**, messages exceeding the IP's daily limit are deferred through the normal requeue path (retried once capacity frees up) — they do NOT overflow to SES shared sending automatically.

---

## Event Collection Pipeline

### Overview
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Event Collection Pipeline                          │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
  │ Webhook │────▶│  Parse   │────▶│ Validate │────▶│  Store   │────▶│ Publish │
  │ /Event  │     │ Payload  │     │  Dedup   │     │ (Postgres│     │  (CDC)  │
  └─────────┘     └──────────┘     └──────────┘     └──────────┘     └─────────┘
       │                                                                   │
       │                                                                   │
       ▼                                                                   ▼
  ┌─────────┐                                                        ┌─────────┐
  │ Sources │                                                        │ClickHse │
  │ - Opens │                                                        │ Analytics│
  │ - Clicks│                                                        └─────────┘
  │ - Bounce│
  │ - Complt│
  └─────────┘
```

### Event Types

#### Open Events
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### Click Events
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### Bounce Events
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

#### Complaint Events
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Deduplication Strategy

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### CDC to Analytics

```rust
// ClickHouse OLAP engine for enterprise-scale analytics
// Events are synced from PostgreSQL to ClickHouse via async inserts

// ClickHouse initialization (services/mail-server/crates/analytics/src/clickhouse_engine.rs)
use crate::config::ClickHouseConfig;

let config = ClickHouseConfig {
    url: "http://clickhouse:8123".to_string(),
    database: "apexmail".to_string(),
    user: "default".to_string(),
    password: "".to_string(),
    max_connections: 20,
    query_timeout_secs: 30,
};

let engine = ClickHouseEngine::new(config).await?;

// Insert events using async inserts for high throughput
engine.insert_events(&events).await?;

// Time-series query with ClickHouse OLAP performance (sub-second on billions of rows)
let series = engine.time_series(
    tenant_id,
    start_date,
    end_date,
    "day",  // granularity
    Some(&["delivered", "opened", "clicked"]),
).await?;
```

---

## Analytics Query Flow

### Overview
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Analytics Query Flow                               │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │Dashboard│────▶│ API/Next │────▶│ Analytics│────▶│ClickHouse│
  │ Request │     │  Route   │     │  Engine  │     │  (OLAP)  │
  └─────────┘     └──────────┘     └──────────┘     └──────────┘
                                          │
                                          ▼
                                   ┌──────────┐
                                   │  Cache   │
                                   │ (Redis)  │
                                   └──────────┘
```

### Query Types

#### Time-Series Aggregations
```sql
-- Hourly email metrics
SELECT
    toStartOfHour(timestamp) AS hour,
    countIf(event_type = 'sent') AS sent,
    countIf(event_type = 'delivered') AS delivered,
    countIf(event_type = 'open') AS opens,
    countIf(event_type = 'click') AS clicks,
    countIf(event_type = 'bounce') AS bounces
FROM email_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND account_id = {accountId:UUID}
GROUP BY hour
ORDER BY hour;
```

#### Funnel Analysis
```sql
-- Campaign funnel
SELECT
    campaign_id,
    count(DISTINCT message_id) AS sent,
    count(DISTINCT IF(event_type = 'delivered', message_id, NULL)) AS delivered,
    count(DISTINCT IF(event_type = 'open', message_id, NULL)) AS opened,
    count(DISTINCT IF(event_type = 'click', message_id, NULL)) AS clicked
FROM email_events
WHERE campaign_id = {campaignId:String}
GROUP BY campaign_id;
```

#### Cohort Analysis
```sql
-- Weekly cohort engagement
SELECT
    toMonday(first_event) AS cohort_week,
    dateDiff('week', first_event, event_week) AS weeks_since_first,
    uniqExact(recipient) AS active_users
FROM (
    SELECT
        recipient,
        min(timestamp) OVER (PARTITION BY recipient) AS first_event,
        toMonday(timestamp) AS event_week
    FROM email_events
    WHERE event_type IN ('open', 'click')
      AND account_id = {accountId:UUID}
)
GROUP BY cohort_week, weeks_since_first
ORDER BY cohort_week, weeks_since_first;
```

---

## CRM Data Flow

### Lead Scoring Pipeline
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Lead Scoring Pipeline                              │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Contact │────▶│ Collect  │────▶│ Calculate│────▶│  Store   │
  │ Events  │     │ Signals  │     │  Score   │     │  Score   │
  └─────────┘     └──────────┘     └──────────┘     └──────────┘
       │                                                   │
       │                                                   │
       ▼                                                   ▼
  ┌─────────┐                                        ┌─────────┐
  │ Sources │                                        │ Trigger │
  │ - Email │                                        │ Actions │
  │ - Web   │                                        │ - Notify│
  │ - CRM   │                                        │ - Assign│
  │ - API   │                                        │ - Auto  │
  └─────────┘                                        └─────────┘
```

### Score Calculation
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

---

## AI Inference Flow

### Content Generation
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              AI Content Generation                              │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Request │────▶│ Context  │────▶│ ONNX     │────▶│ Post-    │
  │ Content │     │ Building │     │ Inference│     │ Process  │
  └─────────┘     └──────────┘     └──────────┘     └──────────┘
       │                                                   │
       │                                                   │
       ▼                                                   ▼
  ┌─────────┐                                        ┌─────────┐
  │ Inputs  │                                        │ Output  │
  │ - Tone  │                                        │ - Text  │
  │ - Topic │                                        │ - Score │
  │ - Length│                                        │ - Meta  │
  └─────────┘                                        └─────────┘
```

### Embedding Generation
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

---

## Security Data Flow

### Audit Log Pipeline
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              Audit Log Pipeline                                 │
└────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Action  │────▶│  Sign    │────▶│  Chain   │────▶│  Store   │
  │ Event   │     │ (HMAC)   │     │ (Hash)   │     │  (WORM)  │
  └─────────┘     └──────────┘     └──────────┘     └──────────┘
```

### Cryptographic Chain
```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```
