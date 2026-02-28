# Data Flow Architecture

> **Implementation Note (2026-02):** This document describes the conceptual data flow. The actual implementation uses:
> - **Rust tracking service** instead of TypeScript API
> - **PostgreSQL-native queues** instead of BullMQ (see [queue-system.md](./queue-system.md))
> - **Rust MTA crate** instead of Postfix (for inbound SMTP only)
> - **AWS SES** as the default outbound delivery transport (self-hosted SMTP available as opt-in)
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
```typescript
// POST /v1/messages
{
  "to": "user@example.com",
  "from": "sender@company.com",
  "subject": "Welcome!",
  "template_id": "welcome-001",
  "variables": {
    "name": "John",
    "company": "Acme"
  },
  "metadata": {
    "campaign_id": "camp_123"
  }
}
```

#### 2. Validation Layer
```typescript
// Validation checks performed:
// 1. Email syntax validation (RFC 5322)
// 2. Domain existence (DNS MX lookup)
// 3. Suppression list check (bounces, complaints, unsubs)
// 4. Rate limiting (per-sender, per-domain)
// 5. Template existence and variable validation

interface ValidationResult {
  valid: boolean;
  recipient: string;
  checks: {
    syntax: boolean;
    mx_exists: boolean;
    not_suppressed: boolean;
    rate_allowed: boolean;
    template_valid: boolean;
  };
  enrichment?: {
    mx_host: string;
    domain_reputation: number;
    historical_engagement: number;
  };
}
```

#### 3. Queue Insertion
```typescript
// Message written to BullMQ queue with priority
await messageQueue.add('send', {
  messageId: 'msg_abc123',
  to: 'user@example.com',
  from: 'sender@company.com',
  templateId: 'welcome-001',
  variables: { ... },
  priority: calculatePriority(campaign, sender),
  scheduledAt: null, // or ISO timestamp for delayed send
}, {
  priority: 1,
  attempts: 3,
  backoff: {
    type: 'exponential',
    delay: 5000,
  },
});
```

#### 4. Worker Processing
```typescript
// Worker picks up job and processes
messageQueue.process('send', async (job) => {
  const { messageId, templateId, variables, to } = job.data;
  
  // 1. Load template
  const template = await templateEngine.load(templateId);
  
  // 2. Render with variables
  const { html, text, subject } = await template.render(variables);
  
  // 3. Apply tracking pixels
  const trackedHtml = trackingService.injectPixel(html, messageId);
  
  // 4. Rewrite links for click tracking
  const finalHtml = trackingService.rewriteLinks(trackedHtml, messageId);
  
  // 5. Build MIME message
  const message = mimeBuilder.build({
    to,
    from: job.data.from,
    subject,
    html: finalHtml,
    text,
    headers: {
      'X-ApexMail-ID': messageId,
      'List-Unsubscribe': `<mailto:unsub@domain.com?subject=${messageId}>`,
    },
  });
  
  // 6. Submit to delivery transport
  //    Default: SES v2 SendEmail API (RawMessage)
  //    Opt-in:  Direct SMTP via SmtpSender (outbound-queue)
  await transport.send(message);
  
  // 7. Update status
  await db.messages.update({
    where: { id: messageId },
    data: { status: 'sent', sentAt: new Date() },
  });
});
```

#### 5. Delivery Transport

**AWS SES (default — `EMAIL_TRANSPORT_TYPE=ses`):**
```
Worker builds RFC 5322 MIME message
  → SES v2 SendEmail API (RawMessage)
  → SES handles DKIM signing, MX delivery, retries
  → SNS publishes events (bounce/complaint/delivery)
  → /v1/ses/notifications webhook processes events
  → Database updated
```

**Self-Hosted SMTP (opt-in — `EMAIL_TRANSPORT_TYPE=smtp`):**
```
Outbound-queue SmtpSender:
  → Resolve MX records (cached, TTL-aware)
  → IpPool selects source IP (round-robin, warmup-aware)
  → TcpSocket::bind(source_ip) → STARTTLS → deliver
  → Custom DKIM signing (per-domain keys)
  → Bounce/complaint via DSN + FBL servers

# Permanent failure:
incoming → active → bounce → notification
```

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
```typescript
// Tracking pixel request
// GET /t/o/{{messageId}}.gif

interface OpenEvent {
  type: 'open';
  messageId: string;
  timestamp: Date;
  ip: string;
  userAgent: string;
  geo?: {
    country: string;
    region: string;
    city: string;
  };
  device?: {
    type: 'mobile' | 'desktop' | 'tablet';
    os: string;
    client: string;
  };
}
```

#### Click Events
```typescript
// Click redirect
// GET /t/c/{{linkId}}?r={{base64Url}}

interface ClickEvent {
  type: 'click';
  messageId: string;
  linkId: string;
  originalUrl: string;
  timestamp: Date;
  ip: string;
  userAgent: string;
  geo?: GeoData;
  device?: DeviceData;
}
```

#### Bounce Events
```typescript
// From SES SNS notifications (default) or SMTP DSN (self-hosted opt-in)

interface BounceEvent {
  type: 'bounce';
  messageId: string;
  timestamp: Date;
  bounceType: 'hard' | 'soft' | 'block';
  bounceCode: string;
  bounceMessage: string;
  recipient: string;
  diagnosticCode?: string;
}
```

#### Complaint Events
```typescript
// From feedback loops (FBL)

interface ComplaintEvent {
  type: 'complaint';
  messageId: string;
  timestamp: Date;
  feedbackType: 'abuse' | 'fraud' | 'other';
  userAgent?: string;
  recipient: string;
}
```

### Deduplication Strategy

```typescript
// Events deduplicated using Redis with TTL
async function processEvent(event: EmailEvent): Promise<boolean> {
  const dedupKey = `event:${event.type}:${event.messageId}:${event.timestamp.getTime()}`;
  
  const isNew = await redis.set(dedupKey, '1', {
    NX: true,           // Only set if not exists
    EX: 86400 * 7,      // Expire after 7 days
  });
  
  if (!isNew) {
    logger.debug('Duplicate event ignored', { event });
    return false;
  }
  
  // Process unique event
  await eventStore.insert(event);
  return true;
}
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
```typescript
interface ScoringSignal {
  type: 'email_open' | 'email_click' | 'page_view' | 'form_submit' | 'api_call';
  weight: number;
  decay: number;  // Daily decay factor
  timestamp: Date;
}

function calculateScore(contact: Contact): number {
  const signals = contact.signals;
  const now = Date.now();
  
  return signals.reduce((score, signal) => {
    const daysSince = (now - signal.timestamp.getTime()) / (1000 * 60 * 60 * 24);
    const decayedWeight = signal.weight * Math.pow(signal.decay, daysSince);
    return score + decayedWeight;
  }, 0);
}

// Example scoring rules
const scoringRules = [
  { type: 'email_open', weight: 1, decay: 0.95 },
  { type: 'email_click', weight: 5, decay: 0.90 },
  { type: 'page_view', weight: 2, decay: 0.98 },
  { type: 'form_submit', weight: 20, decay: 0.85 },
  { type: 'demo_request', weight: 50, decay: 0.80 },
];
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
```typescript
// Sentence embedding for semantic search
async function generateEmbedding(text: string): Promise<Float32Array> {
  // 1. Tokenize
  const tokens = tokenizer.encode(text, {
    maxLength: 512,
    padding: true,
    truncation: true,
  });
  
  // 2. Run inference
  const feeds = {
    input_ids: new ort.Tensor('int64', tokens.inputIds, [1, tokens.length]),
    attention_mask: new ort.Tensor('int64', tokens.attentionMask, [1, tokens.length]),
  };
  
  const results = await session.run(feeds);
  
  // 3. Mean pooling
  const embeddings = results.last_hidden_state.data as Float32Array;
  return meanPool(embeddings, tokens.attentionMask);
}
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
```typescript
interface AuditEntry {
  id: string;
  timestamp: Date;
  actor: { type: 'user' | 'system'; id: string };
  action: string;
  resource: { type: string; id: string };
  changes?: { before?: unknown; after?: unknown };
  previousHash: string;
  hash: string;
  signature: string;
}

function createAuditEntry(action: AuditAction, previousEntry: AuditEntry | null): AuditEntry {
  const entry: Partial<AuditEntry> = {
    id: generateId(),
    timestamp: new Date(),
    actor: action.actor,
    action: action.type,
    resource: action.resource,
    changes: action.changes,
    previousHash: previousEntry?.hash ?? '0000000000000000000000000000000000000000000000000000000000000000',
  };
  
  // Create hash chain
  const hashInput = JSON.stringify({
    ...entry,
    previousHash: entry.previousHash,
  });
  entry.hash = crypto.createHash('sha256').update(hashInput).digest('hex');
  
  // Sign with HSM/KMS
  entry.signature = signWithHSM(entry.hash);
  
  return entry as AuditEntry;
}
```
