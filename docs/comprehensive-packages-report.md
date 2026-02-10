# ApexMail – Comprehensive Packages & Infrastructure Report

> Generated from a full source-code audit of `packages/db`, `packages/lib`, `packages/sdk-node`,
> `packages/sdk-python`, `services/mail-server`, and all root infrastructure files.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Package: @apexmail/db](#2-package-apexmaildb)
   - [Connection Pool](#21-connection-pool-poolts)
   - [Schema Fingerprinting](#22-schema-fingerprinting-fingerprintts)
   - [Transaction Helpers](#23-transaction-helpers-transactionts)
   - [Migrations & Database Schema](#24-migrations--database-schema)
   - [Repositories](#25-repositories)
3. [Package: @apexmail/lib](#3-package-apexmaillib)
   - [Result & Option Types](#31-result--option-types)
   - [Error Codes](#32-error-codes)
   - [Cryptography](#33-cryptography)
   - [ID Generation](#34-id-generation)
   - [Logging](#35-logging)
   - [Cache (Redis)](#36-cache-redis)
   - [Queue (Postgres-backed)](#37-queue-postgres-backed)
   - [HTTP Client](#38-http-client)
   - [Storage](#39-storage)
   - [Templates](#310-templates)
   - [Attachments](#311-attachments)
   - [Time](#312-time)
   - [Validation](#313-validation)
   - [JSON Helpers](#314-json-helpers)
   - [Mail Server Client (gRPC)](#315-mail-server-client-grpc)
   - [Company Info](#316-company-info)
4. [Package: @apexmail/node (Node.js SDK)](#4-package-apexmailnode-nodejs-sdk)
5. [Package: sdk-python (Python SDK)](#5-package-sdk-python-python-sdk)
6. [Service: mail-server (Rust)](#6-service-mail-server-rust)
7. [Root Infrastructure](#7-root-infrastructure)
8. [Cross-Cutting Concerns](#8-cross-cutting-concerns)
9. [Appendices](#9-appendices)

---

## 1. Project Overview

| Property | Value |
|---|---|
| **Legal entity** | Bel Consulting OÜ (Estonia), registry 16192499 |
| **Trade name** | ApexMail |
| **License** | PROPRIETARY (SDKs: MIT) |
| **Package manager** | pnpm 8.14.0 + Turborepo |
| **Node.js** | ≥ 20.11.0 |
| **Primary language** | TypeScript (ESM) |
| **Database** | PostgreSQL 16 (via PgBouncer) |
| **Cache** | Redis 7 |
| **Mail server** | Rust (tokio / tonic gRPC) |
| **URLs** | api.apexmail.ee · app.apexmail.ee · docs.apexmail.ee |

### Monorepo Layout

```
/
├── apps/              18 application packages (api, worker, tracking, web, …)
├── packages/
│   ├── db/            Database layer
│   ├── lib/           Shared utilities
│   ├── sdk-node/      Official Node.js SDK
│   └── sdk-python/    Official Python SDK
├── services/
│   └── mail-server/   Rust mail server (6 crates)
├── deploy/            Prometheus, alerting, nginx
├── docs/              Architecture & operations docs
└── tools/             Bootstrap, migration, chaos, verification scripts
```

---

## 2. Package: @apexmail/db

**Path:** `packages/db/`  
**NPM name:** `@apexmail/db`  
**Dependencies:** `@apexmail/lib`, `pg`, `pg-pool`  
**Exports:** `pool`, `fingerprint`, `transaction`, `repositories/*`

### 2.1 Connection Pool (`pool.ts`)

~420 lines. Wraps `pg.Pool` with production-grade extras.

#### Service-specific pool sizes

| Service | Max connections |
|---|---|
| api | 20 |
| worker | 30 |
| mta | 10 |
| *default* | 10 |

#### Features

| Feature | Code ref | Detail |
|---|---|---|
| Leak detection | G-210 | Tracks checked-out clients; warns after 30 s |
| Health check | C-075 | `SELECT 1` every 30 s |
| Slow queries | C-066 | Warns when query > 500 ms |
| PgBouncer mode | — | Avoids `DISCARD ALL` / prepared statements |
| Type parsers | — | `int8` → JS number, `timestamptz` → ISO string |

#### Public API

```ts
class DatabasePool {
  query<T>(text: string, params?: unknown[]): Promise<Result<QueryResult<T>, Error>>
  getClient(): Promise<PoolClient>
  getStats(): PoolStats
  end(): Promise<void>
  isHealthy(): Promise<boolean>
}

function getDatabase(service: string): DatabasePool          // singleton
function createDatabase(config: DatabaseConfig): DatabasePool
function disconnectAllPools(): Promise<void>
```

### 2.2 Schema Fingerprinting (`fingerprint.ts`)

~340 lines. SHA-256 hash of a deterministic representation of the full schema.

```ts
calculateSchemaFingerprint(pool): Promise<string>
validateSchemaFingerprint(pool, expected): Promise<boolean>
compareSchemas(pool1, pool2): Promise<SchemaDiff>
validateRequiredSchema(pool): Promise<ValidationResult>
```

Extracts: tables, columns, indexes, constraints, functions, triggers.

### 2.3 Transaction Helpers (`transaction.ts`)

~291 lines.

| Helper | Isolation | Extras |
|---|---|---|
| `withTransaction<T>()` | READ COMMITTED | Auto-rollback, retry on 40001/40P01 |
| `withReadTransaction<T>()` | READ COMMITTED | Read-only |
| `withSerializableTransaction<T>()` | SERIALIZABLE | Auto-retry |
| `withAdvisoryLock<T>()` | — | `pg_advisory_lock` for distributed coordination |

Savepoint support with SQL-injection-safe name sanitisation (`sanitizeSavepointName`).

### 2.4 Migrations & Database Schema

#### Migration 001 – Initial Schema

| Table | Key Columns | Indexes |
|---|---|---|
| **organizations** | id PK, name, slug, plan, status, settings JSONB | — |
| **users** | id PK, org_id FK, email, password_hash, role, status | — |
| **messages** | id PK, org_id FK, from, to, subject, status, idempotency_key | `idx_messages_org_status`, `idx_messages_idempotency` |
| **suppressions** | id PK, org_id FK, email, type, reason | `idx_suppressions_email` |
| **audit_logs** | id PK, org_id FK, action, resource, ip, hash, previous_hash | `idx_audit_logs_org`, `idx_audit_logs_hash` |

#### Migration 010 – Performance Indexes

25+ indexes added, **all prefixed with `tenant_id`** for multi-tenant query efficiency:

| Table | Indexes (partial list) |
|---|---|
| messages | status, created_at, campaign_id, from_email, message_id, scheduled, tags (GIN) |
| events | message_id, type+timestamp, recipient_hash, dedup_key, campaign |
| suppressions | email_hash, type, scope |
| api_keys | key_hash (UNIQUE), tenant+active, prefix, expiry |
| domains | domain (UNIQUE), tenant+status, verification |
| templates | tenant+slug (UNIQUE), tenant+active, engine |
| webhooks | tenant+enabled, events (GIN) |
| audit_logs | resource, action, timestamp range, hash chain |

#### Migration 011 – Analytics Two-Phase Processing

Adds `processing BOOLEAN DEFAULT FALSE` and `processing_at TIMESTAMPTZ` to `analytics_queue`.  
Index: `idx_analytics_queue_two_phase (processed, processing, created_at)`.

### 2.5 Repositories

15 repository classes. Every method returns `Result<T, Error>` and is tenant-scoped.

---

#### 2.5.1 `TenantsRepository`

```ts
interface Tenant {
  id: string
  name: string
  slug: string
  plan: 'free' | 'growth' | 'scale' | 'enterprise'
  status: 'active' | 'suspended' | 'pending'
  settings: TenantSettings
  metadata: Record<string, unknown>
  createdAt: Date
  updatedAt: Date
}
```

| Method | Notes |
|---|---|
| `create(data)` | — |
| `findById(id)` | — |
| `findBySlug(slug)` | — |
| `update(id, data)` | — |
| `suspend(id)` | Sets status → suspended |

---

#### 2.5.2 `UsersRepository`

```ts
interface User {
  id: string
  tenantId: string
  email: string
  name: string
  role: 'owner' | 'admin' | 'member' | 'viewer'
  status: 'active' | 'invited' | 'disabled'
  emailVerified: boolean
  mfaEnabled: boolean
  preferences: Record<string, unknown>
  metadata: Record<string, unknown>
}
```

| Method | Notes |
|---|---|
| `create(data)` | — |
| `findById(id)` | — |
| `findByEmail(tenantId, email)` | — |
| `verifyCredentials(email, password)` | Cross-tenant protection (A-002) |

---

#### 2.5.3 `DomainsRepository`

```ts
interface Domain {
  id: string; tenantId: string; domain: string
  status: 'pending' | 'verified' | 'failed' | 'expired'
  verificationToken: string
  verificationMethod: 'dns_txt' | 'dns_cname' | 'meta_tag'
  dnsRecords: DnsRecords          // spf, dkim, dmarc, mx, returnPath
  healthStatus: Record<string, unknown>
}
```

| Method | Notes |
|---|---|
| `create(data)` | — |
| `findById(tenantId, id)` | — |
| `findByDomain(domain)` | — |
| `update(tenantId, id, data)` | — |

---

#### 2.5.4 `MessagesRepository` (~1 455 lines)

The largest repository. Handles idempotent email creation with a transactional insert into both `messages` and `email_queue` (per G-200, B-046).

```ts
type MessageStatus =
  | 'pending' | 'queued' | 'sending' | 'sent'
  | 'delivered' | 'bounced' | 'deferred' | 'failed'

type BounceType = 'hard' | 'soft'
type Priority   = 'high' | 'normal' | 'low'

interface Message {
  id: string; tenantId: string; userId: string
  idempotencyKey: string; messageId: string         // RFC 5322
  status: MessageStatus
  fromEmail: string; fromName: string; replyTo: string
  recipients: EmailRecipient[]
  subject: string; htmlBody: string; textBody: string
  headers: MessageHeaders
  attachments: EmailAttachment[]
  templateId: string; templateData: Record<string, unknown>
  campaignId: string; tags: string[]
  priority: Priority; scheduledAt: Date
  sentAt: Date; deliveredAt: Date; bouncedAt: Date
  bounceType: BounceType; bounceReason: string
  mtaMessageId: string; ipAddress: string; sendingDomain: string
  attempts: number; maxAttempts: number
  metadata: Record<string, unknown>
}
```

| Method | Notes |
|---|---|
| `create(data)` | Transactional INSERT into messages + email_queue; idempotency check first |
| `findByIdempotencyKey(tenantId, key)` | — |
| `update(tenantId, id, data)` | — |

---

#### 2.5.5 `EventsRepository` (~1 136 lines)

```ts
type EventType =
  | 'queued' | 'sending' | 'sent' | 'deferred' | 'delivered'
  | 'bounced' | 'dropped' | 'opened' | 'clicked'
  | 'unsubscribed' | 'complained' | 'list_unsubscribe'

interface Event {
  id: string; tenantId: string; messageId: string
  recipientEmail: string; recipientEmailHash: string   // SHA-256
  eventType: EventType; timestamp: Date
  ipAddress: string; userAgent: string; deviceType: string
  location: EventLocation
  linkUrl: string; linkId: string
  bounceType: string; bounceCode: string; bounceReason: string
  feedbackType: string; mtaResponse: string
  rawPayload: Record<string, unknown>
  deduplicationKey: string           // SHA-256(msg+recipient+type+⌊ts/60⌋+link)
  metadata: Record<string, unknown>
}
```

| Method | Notes |
|---|---|
| `create(data)` | `ON CONFLICT (deduplication_key) DO NOTHING` |
| `createBulk(events)` | Batch insert |

Deduplication: minute-precision timestamp bucketing for open/click events.

---

#### 2.5.6 `ApiKeysRepository` (~789 lines)

```ts
type ApiKeyScope =
  | 'messages:send' | 'messages:read' | 'messages:write'
  | 'domains:read'  | 'domains:write'
  | 'suppressions:read' | 'suppressions:write'
  | 'events:read'
  | 'templates:read' | 'templates:write'
  | 'analytics:read'
  | 'webhooks:read' | 'webhooks:write'
  | 'admin'

interface ApiKey {
  id: string; tenantId: string; userId: string
  name: string; prefix: string              // first 8 chars
  keyHash: string; scopes: ApiKeyScope[]
  rateLimit: number                          // req / min
  allowedIps: string[]; allowedDomains: string[]
  expiresAt: Date; lastUsedAt: Date; usageCount: number
  isActive: boolean; metadata: Record<string, unknown>
}
```

| Method | Notes |
|---|---|
| `create(data)` | Returns `ApiKeyWithSecret` containing the plaintext `secretKey` |
| `verify(keyHash)` | — |
| `update(tenantId, id, data)` | — |
| `rotate(tenantId, id)` | Generates new key, returns new secret |

IP/CIDR validation per F-245.

---

#### 2.5.7 `SuppressionsRepository` (~807 lines)

```ts
type SuppressionType  = 'bounce' | 'complaint' | 'unsubscribe' | 'manual' | 'list_unsubscribe'
type SuppressionScope = 'global' | 'tenant' | 'domain' | 'campaign'

interface Suppression {
  id: string; tenantId: string
  email: string; emailHash: string
  type: SuppressionType; scope: SuppressionScope; scopeId: string
  reason: string; source: string; originalMessageId: string
  bounceType: string; bounceCode: string; feedbackType: string
  expiresAt: Date
  metadata: Record<string, unknown>
}
```

Hard bounces → global scope, never expire.  
Lookup priority: **global → tenant → domain → campaign**.

| Method | Notes |
|---|---|
| `create(data)` | `ON CONFLICT` upsert |
| `checkSuppression(tenantId, email)` | Cascading scope check |

---

#### 2.5.8 `TemplatesRepository` (~905 lines)

```ts
type TemplateEngine = 'handlebars' | 'mjml' | 'liquid' | 'ejs'

interface Template {
  id: string; tenantId: string
  name: string; slug: string; description: string; category: string
  currentVersion: number
  htmlContent: string; textContent: string
  subject: string; preheader: string
  variables: string[]; defaultData: Record<string, unknown>
  engine: TemplateEngine
  isActive: boolean; isDefault: boolean
  metadata: Record<string, unknown>
}
```

Template syntax validation (E-155). Auto variable extraction per engine.

| Method | Notes |
|---|---|
| `create(data)` | — |
| `update(tenantId, id, data)` | Auto-increments `currentVersion` |
| `findById(tenantId, id)` | — |
| `findBySlug(tenantId, slug)` | — |

---

#### 2.5.9 `AuditLogsRepository` (~806 lines)

**52 distinct `AuditAction` values** covering auth, tenants, users, API keys, domains, messages, templates, webhooks, suppressions, billing, system, SMTP credentials, and subscriptions.

```ts
interface AuditLog {
  id: string; tenantId: string; userId: string
  action: AuditAction
  resourceType: string; resourceId: string
  ipAddress: string; userAgent: string
  changes: { before: unknown; after: unknown; fields: string[] }
  metadata: Record<string, unknown>
  previousHash: string               // hash-chain link
  hash: string                       // SHA-256 of this entry
  timestamp: Date
}
```

**Immutable, hash-chained** audit trail.  
Uses advisory lock per tenant (RACE-003 fix) for atomic hash-chain insertion.

---

#### 2.5.10 `WebhooksRepository` (~473 lines)

```ts
interface Webhook {
  id: string; tenantId: string; name: string
  url: string; secret: string
  events: string[]; enabled: boolean
  headers: Record<string, string>
  failureCount: number
  lastTriggeredAt: Date; lastSuccessAt: Date; lastFailureAt: Date
  disabledReason: string
}

interface WebhookQueueItem { /* delivery tracking */ }
```

| Method | Notes |
|---|---|
| `create(data)` | — |
| `findByTenant(tenantId, pagination)` | Paginated |
| `findByTenantFiltered(tenantId, filters)` | SQL-level filtering (FIX-500-098) |
| `findEnabledByEvent(tenantId, event)` | — |
| `update(tenantId, id, data)` | — |

---

#### 2.5.11 `InboundMessagesRepository` (~442 lines)

```ts
interface InboundMessage {
  id: string; tenantId: string; domainId: string
  messageIdHeader: string
  fromAddress: string; toAddress: string; subject: string
  textBody: string; htmlBody: string; rawMessage: string
  headers: Record<string, string>; attachments: unknown[]
  spamScore: number; spamStatus: string; virusStatus: string
  spfResult: string; dkimResult: string; dmarcResult: string
  receivedAt: Date; clientIp: string; sessionId: string
}

interface UnmatchedBounce { /* bounces that don't correlate to a message */ }
interface UnmatchedComplaint { /* complaints without correlation */ }
```

---

#### 2.5.12 `SubscriptionsRepository` (~337 lines)

```ts
interface SubscriptionPreference {
  id: string; tenantId: string; email: string
  category: string; subscribed: boolean
}

interface EmailCategory {
  id: string; tenantId: string; name: string
  description: string; active: boolean; displayOrder: number
}
```

`SubscriptionStatus` includes a global unsubscribe check.

| Method | Notes |
|---|---|
| `createCategory(data)` | — |
| `getPreferences(tenantId, email)` | — |
| `updatePreference(tenantId, email, category, subscribed)` | — |

---

#### 2.5.13 `SmtpCredentialsRepository` (~326 lines)

```ts
interface SmtpCredential {
  id: string; tenantId: string
  username: string; isActive: boolean
}
```

HMAC-based password hashing with **timing-safe** comparison.  
`ON CONFLICT` upsert for TOCTOU fix (A-015).

| Method | Notes |
|---|---|
| `create(tenantId, data)` | Returns credential + plaintext password |
| `verify(username, password)` | Constant-time |
| `findByTenant(tenantId)` | — |
| `setActive(tenantId, id, active)` | — |
| `regeneratePassword(tenantId, id)` | — |

---

#### 2.5.14 `ReputationRepository` (~414 lines)

```ts
interface ReputationStats {
  tenantId: string; date: Date
  sent: number; delivered: number; bounces: number
  complaints: number; opens: number; clicks: number; unsubscribes: number
}

type ReputationAlertType =
  | 'high_bounce_rate' | 'high_complaint_rate'
  | 'low_delivery_rate' | 'reputation_warning'

interface ReputationSummary {
  /* aggregates with trend: 'improving' | 'stable' | 'declining' */
}
```

Runtime column whitelist to prevent SQL injection in dynamic queries.

---

#### 2.5.15 `SystemRepository` (~495 lines)

```ts
interface SystemAlert {
  id: string
  alertType: string
  severity: 'info' | 'warning' | 'error' | 'critical'
  title: string; message: string; acknowledged: boolean
}

interface IdempotencyRecord { /* dedup tracking */ }
interface CompactionLogEntry { /* maintenance log */ }
interface ReconciliationLogEntry { /* data reconciliation log */ }
```

| Method | Notes |
|---|---|
| `createAlert(data)` | — |
| `getActiveAlerts()` | — |
| `getIdempotencyRecord(key)` | — |
| `createIdempotencyRecord(key, data)` | — |

---

## 3. Package: @apexmail/lib

**Path:** `packages/lib/`  
**NPM name:** `@apexmail/lib`  
**Dependencies:** `@grpc/grpc-js`, `@grpc/proto-loader`, `handlebars`, `ioredis`, `nanoid`, `pg`, `pino`, `pino-pretty`, `undici`, `uuid`  
**Exports:** 16 sub-modules via barrel `index.ts`.

Design philosophy: **Thin Interface Pattern** — each sub-module is a focused utility consumed by `api`, `worker`, and `web`.

### 3.1 Result & Option Types

Rust-inspired algebraic types (`result.ts`).

```ts
type Result<T, E> = { ok: true; value: T } | { ok: false; error: E }

function ok<T>(value: T): Result<T, never>
function err<E>(error: E): Result<never, E>

// Methods on Result:
unwrap(): T                   // throws if err
unwrapOr(fallback: T): T
map<U>(fn: (v: T) => U): Result<U, E>
mapErr<F>(fn: (e: E) => F): Result<T, F>

// Static constructors:
Result.fromPromise<T>(p: Promise<T>): Promise<Result<T, Error>>
Result.fromThrowable<T>(fn: () => T): Result<T, Error>

type Option<T> = T | null | undefined
```

### 3.2 Error Codes

24 standardised codes (`error-codes.ts`):

| Category | Codes |
|---|---|
| **Auth** | `AUTH_REQUIRED`, `INVALID_API_KEY`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `INSUFFICIENT_SCOPE`, `FORBIDDEN` |
| **Validation** | `BAD_REQUEST`, `VALIDATION_ERROR`, `INVALID_INPUT`, `INVALID_ID`, `INVALID_EMAIL` |
| **Resource** | `NOT_FOUND`, `CONFLICT`, `DUPLICATE_KEY`, `DOMAIN_EXISTS`, `VERIFICATION_EXPIRED` |
| **Rate limiting** | `RATE_LIMITED`, `DAILY_LIMIT_REACHED` |
| **Server** | `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE` |
| **CSRF** | `CSRF_ORIGIN_MISMATCH`, `CSRF_MISSING_HEADER` |
| **Idempotency** | `IDEMPOTENCY_CONFLICT` |

### 3.3 Cryptography

`crypto/index.ts` — ~837 lines.

| Capability | Detail |
|---|---|
| **HMAC** | SHA-256 / 384 / 512 with **timing-safe** verify |
| **AES-256-GCM** | Encrypt / decrypt with random IV |
| **Password hashing** | scrypt (`$scrypt$N$r$p$salt$hash`) |
| **Hash chains** | For immutable audit logs |
| **DKIM key pairs** | RSA-2048 generation |

### 3.4 ID Generation

`id/index.ts` — ~285 lines.

| Generator | Format / Example |
|---|---|
| UUID v7 | Time-ordered `0191a3b4-…` |
| UUID v4 | Random |
| nanoid | Short alphanumeric |
| Message-ID | `<uuid@domain>` (RFC 5322) |
| API key | `am_live_<base64(32+)>` / `am_test_<base64(32+)>` |
| VERP | `bounce+local=domain@apexmail.ee` |
| Tracking ID | `trk_<nanoid>` |
| Click ID | `clk_<nanoid>` |
| Tenant ID | `ten_<nanoid>` |
| DKIM selector | `apexmailYYYYWW` |
| Webhook secret | `whsec_<nanoid>` |
| Domain verification token | Random hex |

### 3.5 Logging

`logger/index.ts` — ~205 lines. Pino wrapper.

- Structured JSON output, configurable level via `LOG_LEVEL` env
- Extensive **redact paths**: passwords, API keys, tokens, secrets, authorization headers
- `getLogger(name)` singleton, `createLogger(name, opts)` factory
- Child loggers via `logger.child({ module })` pattern

### 3.6 Cache (Redis)

`cache/index.ts` — ~574 lines.

```ts
interface CacheProvider {
  get<T>(key: string): Promise<T | null>
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>
  setNX<T>(key: string, value: T, ttlSeconds: number): Promise<boolean>
  delete(key: string): Promise<void>
  exists(key: string): Promise<boolean>
  incr(key: string): Promise<number>
  incrWithExpire(key: string, ttl: number): Promise<number>  // C-132 atomic pipeline
  decr(key: string): Promise<number>
  expire(key: string, ttl: number): Promise<void>
  ttl(key: string): Promise<number>
  keys(pattern: string): Promise<string[]>
  mget<T>(keys: string[]): Promise<(T | null)[]>
  mset<T>(entries: [string, T][], ttl?: number): Promise<void>
  subscribe(channel: string, handler: (msg: string) => void): Promise<void>
  publish(channel: string, message: string): Promise<void>
}
```

Implementation: `RedisCacheProvider` backed by **ioredis**.  
Key prefix: `apexmail:`. **Requires `REDIS_PASSWORD`** in production.

### 3.7 Queue (Postgres-backed)

`queue/index.ts` — ~515 lines.

Uses `SELECT … FOR UPDATE SKIP LOCKED` for distributed dequeue.

```ts
interface QueueJob<T = unknown> {
  id: string
  queue: string
  payload: T
  priority: number
  attempts: number
  maxAttempts: number
  visibilityTimeout: number
  tenantId: string
  scheduledAt: Date
  createdAt: Date
}
```

Tenant-aware **fair scheduling** (round-robin across tenants).

| Method | Notes |
|---|---|
| `enqueue(queue, payload, opts)` | Priority, scheduling, dedup |
| `dequeue(queue, count)` | SKIP LOCKED |
| `complete(jobId)` | — |
| `fail(jobId, error)` | — |
| `retry(jobId)` | Increments attempts |
| `deadLetter(jobId, reason)` | — |
| `getStats(queue)` | Counts by status |
| `purge(queue, olderThan)` | — |

### 3.8 HTTP Client

`http/index.ts` — ~309 lines. **Undici**-based.

| Feature | Detail |
|---|---|
| Circuit breaker | closed → open → half-open (threshold: 5 failures, window: 60 s, half-open after 30 s) |
| Retries | Exponential back-off, 30% jitter |
| User-Agent | `ApexMail/1.0` |
| Timeout | Configurable per request |

### 3.9 Storage

`storage/index.ts` — ~457 lines.

```ts
interface StorageProvider {
  put(path: string, data: Buffer, metadata?: Record<string, string>): Promise<void>
  get(path: string): Promise<{ data: Buffer; metadata: Record<string, string> }>
  delete(path: string): Promise<void>
  exists(path: string): Promise<boolean>
  list(prefix: string): Promise<string[]>
}
```

Implementation: `LocalStorageProvider` with sidecar `.meta` JSON files.  
**Path traversal protection** (null bytes, URL decoding, unicode normalisation, backslash handling).

### 3.10 Templates

`templates/index.ts` — ~725 lines.

| Feature | Detail |
|---|---|
| Engines | Handlebars, MJML → HTML (simplified built-in converter), Liquid, EJS |
| XSS prevention | `escapeHtml`, `sanitizeUrl` (blocks `javascript:`, `data:`, `vbscript:`), `sanitizeAttr` |
| Variable extraction | Per-engine regex to pull `{{var}}`, `{%var%}`, `<%= var %>`, `<mj-*>` placeholders |

### 3.11 Attachments

`attachments/index.ts` — ~542 lines.

- Local & S3 storage backends
- **Content-addressed deduplication** (SHA-256 of file content)
- Default max size: **25 MB**
- Automatic cleanup of expired attachments

### 3.12 Time

`time/index.ts` — ~270 lines.

```ts
interface TimeProvider {
  now(): Date
  unixMs(): number
  unixSec(): number
}

class SystemTimeProvider implements TimeProvider { /* real clock */ }
class MockTimeProvider implements TimeProvider   { /* controllable in tests */ }
```

Duration helpers, date range helpers (`startOfDay`, `startOfWeek`, `startOfMonth`, `addDays`, `addMonths`, `differenceInDays`, `differenceInHours`).

### 3.13 Validation

`validation/index.ts` — ~645 lines.

| Capability | Detail |
|---|---|
| **Email syntax** | RFC 5322 regex |
| **MX verification** | DNS MX record lookup |
| **Disposable domains** | 37 known disposable providers (mailinator, guerrillamail, …) |
| **Role-based emails** | 30+ role prefixes (postmaster, abuse, noreply, …) |
| **Typo correction** | Levenshtein distance against common domains (gmail, yahoo, outlook, …) |

### 3.14 JSON Helpers

`json/index.ts`

```ts
safeJsonParse<T>(text: string): T | null
parseJsonOrDefault<T>(text: string, fallback: T): T
safeJsonStringify(value: unknown): string       // handles BigInt, circular refs
parseDbJson<T>(raw: unknown): T
```

### 3.15 Mail Server Client (gRPC)

`mail-server-client.ts` — ~600 lines. TypeScript gRPC client for the Rust mail server.

Proto loaded lazily (FIX-500-375).

#### gRPC Services

**OutboundService**

| RPC | Request → Response | Notes |
|---|---|---|
| `SendEmailNow` | `SendRequest → SendResponse` | Immediate delivery |
| `QueueEmail` | `QueueRequest → QueueResponse` | Deferred / scheduled |
| `QueueBulkEmails` | `BulkQueueRequest → BulkQueueResponse` | Batch queue |
| `GetDeliveryStatus` | `{emailId} → DeliveryStatus` | — |
| `CancelEmail` | `{emailId} → {success, error}` | — |
| `GetQueueStats` | `{} → MailServerQueueStats` | — |

**MailstoreService** — Optional, for mailbox access.

#### Key Types

```ts
interface SendResult {
  success: boolean; emailId: string
  messageId?: string; error?: string
  recipients: Array<{ email: string; accepted: boolean; error: string }>
}

interface QueueResult {
  success: boolean; emailId: string
  status: string; error?: string
}

interface MailServerQueueStats {
  pendingCount: number; sendingCount: number
  sentToday: number; failedToday: number
  bouncedToday: number; averageDeliveryTimeMs: number
}

interface DeliveryStatus {
  emailId: string
  status: 'queued' | 'sending' | 'sent' | 'delivered' | 'bounced' | 'failed' | 'cancelled'
  queuedAt?: Date; sentAt?: Date; deliveredAt?: Date; bouncedAt?: Date
  attempts: number; lastError?: string
}
```

Also exports `createDripEmailSender(client, defaultFrom)` helper for drip-campaign integration.

### 3.16 Company Info

`company.ts` — Legal & branding constants.

| Field | Value |
|---|---|
| Name | Bel Consulting OÜ |
| Address | Sakala 7-2, 10141 Tallinn, Estonia |
| Registry | 16192499 |
| VAT | EE102951727 |
| Bank | Swedbank EE382200221012345678 |
| Domain | apexmail.ee |

---

## 4. Package: @apexmail/node (Node.js SDK)

**Path:** `packages/sdk-node/`  
**NPM name:** `@apexmail/node`  
**Version:** 1.0.0  
**License:** MIT  
**Runtime deps:** **none** (zero dependencies, uses native `fetch`)  
**Node.js:** ≥ 18.0.0

### Constructor

```ts
class ApexMail {
  constructor(apiKey: string)
  constructor(config: ApexMailConfig)
}
```

| Config property | Default |
|---|---|
| `baseUrl` | `https://api.apexmail.ee` |
| `timeout` | 30 000 ms |
| `maxRetries` | 3 |
| `retryableStatuses` | 408, 429, 500, 502, 503, 504 |

API key regex: `am_(live\|test)_[a-zA-Z0-9]{32,}`.  
Idempotency-Key header support (FIX-500-274).

### Resource APIs

#### `apexmail.emails` (EmailsApi)

| Method | Signature | Notes |
|---|---|---|
| `send` | `(opts: SendEmailOptions) → Promise<SendEmailResponse>` | Client-side validation (F-246): email format, subject ≤ 998 chars, body ≤ 10 MB, no whitespace-only |
| `batch` | `(opts: BatchSendOptions) → Promise<BatchSendResponse>` | Max 1 000 per batch |
| `get` | `(id: string) → Promise<Email>` | ID validation |
| `list` | `(opts?: ListEmailsOptions) → Promise<ListEmailsResponse>` | Cursor pagination, filter by status/tag |
| `cancel` | `(id: string) → Promise<void>` | — |

#### `apexmail.domains` (DomainsApi)

| Method | Signature |
|---|---|
| `create` | `(opts) → Promise<Domain>` |
| `get` | `(id) → Promise<Domain>` |
| `list` | `(opts?) → Promise<ListDomainsResponse>` |
| `verify` | `(id) → Promise<Domain>` |
| `delete` | `(id) → Promise<void>` |

#### `apexmail.apiKeys` (ApiKeysApi)

| Method | Signature |
|---|---|
| `create` | `(opts) → Promise<ApiKey>` |
| `list` | `(opts?) → Promise<ListApiKeysResponse>` |
| `revoke` | `(id) → Promise<void>` |

#### `apexmail.webhooks` (WebhooksApi)

| Method | Signature |
|---|---|
| `create` | `(opts) → Promise<Webhook>` |
| `get` | `(id) → Promise<Webhook>` |
| `list` | `(opts?) → Promise<ListWebhooksResponse>` |
| `update` | `(id, opts) → Promise<Webhook>` |
| `delete` | `(id) → Promise<void>` |

#### `apexmail.analytics` (AnalyticsApi)

| Method | Signature | Notes |
|---|---|---|
| `get` | `(opts?: GetAnalyticsOptions) → Promise<Analytics>` | Date range validation; `groupBy`: hour / day / week / month |

### Error Hierarchy

```
ApexMailError                           (base)
├── ValidationError     (400)
├── AuthenticationError (401)
├── ForbiddenError      (403)
├── NotFoundError       (404)
├── ConflictError       (409)
└── RateLimitError      (429)  ← has retryAfter: number
```

### Webhook Event Types (FIX-500-459)

```
message.accepted    message.queued      message.sending
message.sent        message.delivered   message.opened
message.clicked     message.bounced     message.complained
message.failed      message.deferred    message.dropped
message.unsubscribed

domain.verified     domain.failed
suppression.added
*                   (wildcard)
```

### Test Coverage

~440 lines in `index.test.ts` covering constructor overloads, all email operations, error mapping, client-side validation.

---

## 5. Package: sdk-python (Python SDK)

**Path:** `packages/sdk-python/`  
**PyPI name:** `apexmail`  
**Version:** 1.0.0  
**License:** MIT  
**Python:** ≥ 3.9  
**Dependencies:** `httpx ≥ 0.25.0`, `pydantic ≥ 2.0.0`

### Clients

```python
class ApexMail:              # sync, context manager
class AsyncApexMail:         # async, async context manager
```

Both extend `BaseClient` (FIX-500-466) which provides:
- API key validation (`am_(live|test)_[a-zA-Z0-9]{32,}`)
- HTTPS enforcement (except localhost)
- Masked API key in `__repr__`
- Retry with exponential back-off + jitter (retryable: `{408, 429, 500, 502, 503, 504}`)

### Resources

Each has sync + async variants.

#### `client.emails`

| Method | Parameters | Returns |
|---|---|---|
| `send()` | from_, to, subject, html/text, cc, bcc, reply_to, tags, attachments, headers, scheduled_at, metadata, idempotency_key | `SendEmailResponse` |
| `batch(emails)` | list of email dicts (max 1 000) | `BatchSendResponse` |
| `get(email_id)` | — | `Email` |
| `list()` | — | `EmailListResponse` |

#### `client.domains`

| Method | Parameters |
|---|---|
| `create(domain)` | domain name |
| `get(domain_id)` | — |
| `list()` | — |
| `verify(domain_id)` | — |
| `delete(domain_id)` | — |

#### `client.webhooks`

| Method | Parameters |
|---|---|
| `create(url, events, …)` | — |
| `get(webhook_id)` | — |
| `list()` | — |
| `update(webhook_id, …)` | — |
| `delete(webhook_id)` | — |
| `test(webhook_id, event_type)` | *Python-only (not in Node SDK)* |

### Pydantic Models

```python
class EmailStatus(str, Enum):   # same values as MessageStatus
class DomainStatus(str, Enum):  # pending, verified, failed, expired
class WebhookEvent(str, Enum):  # same 17+ events as Node SDK

class EmailAddress(BaseModel):  # email, name?
class Tag(BaseModel)
class Attachment(BaseModel)     # filename, content (base64), content_type

class SendEmailRequest(BaseModel)
class SendEmailResponse(BaseModel)
class Email(BaseModel)
class EmailListResponse(BaseModel)

class DNSRecord(BaseModel)
class Domain(BaseModel)
class DomainListResponse(BaseModel)

class Webhook(BaseModel)
class WebhookListResponse(BaseModel)
```

### Exception Hierarchy

```
ApexMailError                            (base)
├── ValidationError      (400)
├── AuthenticationError  (401)
├── ForbiddenError       (403)
├── NotFoundError        (404)
├── ConflictError        (409)
├── RateLimitError       (429)  ← retry_after: float | None
└── ServerError          (500)           ← Python-only
```

### Build & QA Config (pyproject.toml)

- Build: hatchling
- Testing: pytest + pytest-asyncio + respx (mock httpx)
- Type checking: mypy (strict)
- Linting: ruff
- Coverage target: configured via `[tool.coverage.run]`

---

## 6. Service: mail-server (Rust)

**Path:** `services/mail-server/`  
**Architecture:** Cargo workspace, **no third-party email SaaS** — everything self-hosted.

### Crates

| Crate | Purpose |
|---|---|
| `mailstore-core` | Mailbox storage engine |
| `smtp-edge` | Inbound SMTP server |
| `submission` | SMTP submission (port 587) for authenticated clients |
| `outbound-queue` | Queue processing & delivery |
| `mail-proto` | gRPC proto definitions + build script |
| `mail-common` | Shared types & utilities |

### Key Dependencies

| Dependency | Usage |
|---|---|
| `tokio` | Async runtime |
| `tonic` | gRPC server |
| `sqlx` | PostgreSQL (async, compile-time checked queries) |
| `rustls` | TLS without OpenSSL |
| `mail-parser` / `mail-builder` / `mail-auth` | RFC-compliant email parsing, building, authentication |
| `rsa` | DKIM signing |
| `argon2` | Password hashing (mail accounts) |
| `trust-dns-resolver` | DNS (MX, SPF, DKIM, DMARC lookups) |
| `metrics` / `metrics-exporter-prometheus` | Observability |

### Mail Server Database Schema

(Separate PostgreSQL schema from the main app database)

#### Table: `email_queue`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | — |
| from_address | VARCHAR(255) | — |
| to_addresses | TEXT[] | — |
| cc_addresses | TEXT[] | — |
| bcc_addresses | TEXT[] | — |
| reply_to | VARCHAR(255) | — |
| subject | TEXT | — |
| text_body | TEXT | — |
| html_body | TEXT | — |
| headers | JSONB | — |
| attachments | JSONB | — |
| status | VARCHAR(20) | `pending` / `processing` / `sent` / `failed` / `deferred` / `cancelled` |
| attempts | INT | Default 0 |
| max_attempts | INT | Default 5 |
| last_error | TEXT | — |
| next_retry_at | TIMESTAMPTZ | — |
| tenant_id | VARCHAR(50) | — |
| campaign_id | VARCHAR(100) | — |
| sequence_id | VARCHAR(100) | — |
| contact_id | VARCHAR(100) | — |
| priority | INT | Default 0 |
| tags | TEXT[] | — |
| metadata | JSONB | — |
| sent_at / created_at / updated_at | TIMESTAMPTZ | — |

**Indexes:** `idx_eq_status_retry_priority`, `idx_eq_campaign`, `idx_eq_tenant_created`, `idx_eq_sent_at`

#### Table: `mail_accounts`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | — |
| email | VARCHAR(255) UNIQUE | — |
| domain | VARCHAR(255) | — |
| password_hash | TEXT | argon2 |
| display_name | VARCHAR(255) | — |
| quota_bytes | BIGINT | Default 1 073 741 824 (1 GB) |
| used_bytes | BIGINT | Default 0 |
| is_active | BOOLEAN | Default true |

**Index:** `idx_ma_domain`

#### Table: `mail_mailboxes`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | — |
| account_id | UUID FK → mail_accounts | ON DELETE CASCADE |
| name | VARCHAR(255) | — |
| parent_id | UUID FK → self | Nullable, ON DELETE CASCADE |
| mailbox_type | VARCHAR(20) | `inbox` / `sent` / `drafts` / `trash` / `spam` / `archive` / `custom` |
| total_messages / unread_messages | INT | — |

**Constraint:** `UNIQUE(account_id, name, parent_id)`

#### Table: `mail_messages`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | — |
| account_id | UUID FK → mail_accounts | ON DELETE CASCADE |
| mailbox_id | UUID FK → mail_mailboxes | ON DELETE CASCADE |
| message_id | VARCHAR(255) | RFC 5322 Message-ID |
| from_address / from_name | VARCHAR | — |
| to/cc/bcc_addresses | JSONB | — |
| subject | TEXT | — |
| date | TIMESTAMPTZ | — |
| text_body / html_body | TEXT | — |
| raw_size | INT | — |
| is_read / is_starred / is_deleted / is_spam | BOOLEAN | — |
| labels | TEXT[] | — |
| headers / attachments | JSONB | — |

**Indexes:** `idx_mm_mailbox_date`, `idx_mm_unread`, `idx_mm_message_id`, **full-text GIN** on `to_tsvector('english', subject || ' ' || COALESCE(text_body, ''))`

#### Table: `email_delivery_log`

| Column | Type |
|---|---|
| id | UUID PK |
| email_id | UUID FK → email_queue |
| attempt_number | INT |
| mx_host | VARCHAR(255) |
| smtp_response | TEXT |
| success | BOOLEAN |
| error_message | TEXT |
| attempted_at | TIMESTAMPTZ |

#### Table: `dkim_keys`

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | — |
| domain | VARCHAR(255) | — |
| selector | VARCHAR(63) | — |
| private_key_pem / public_key_pem | TEXT | — |
| is_active | BOOLEAN | Default true |
| rotated_at | TIMESTAMPTZ | — |

**Constraint:** `UNIQUE(domain, selector)`

#### Triggers

`update_updated_at_column()` — auto-sets `updated_at = NOW()` on `email_queue`, `mail_accounts`, `mail_mailboxes`, `mail_messages`.

---

## 7. Root Infrastructure

### Docker Compose — Development (`docker-compose.yml`)

| Service | Image / Build | Port | Memory |
|---|---|---|---|
| **postgres** | `postgres:16-alpine` | 5432 (localhost only) | 1 GB |
| **redis** | `redis:7-alpine` | 6379 | 512 MB (maxmemory 256 MB, allkeys-lru) |
| **api** | `Dockerfile.api` | 3000 | — |
| **worker** | `Dockerfile.worker` | 9090 (metrics) | — |
| **tracking** | `Dockerfile.tracking` | 3001 | — |
| **mailpit** | `axllent/mailpit:v1.21` | 1025 (SMTP), 8025 (Web UI) | — (profile: `dev`) |
| **prometheus** | `prom/prometheus:v2.54.1` | 9091 → 9090 | — (profile: `monitoring`) |
| **grafana** | `grafana/grafana:11.3.0` | 3002 → 3000 (localhost only) | 512 MB (profile: `monitoring`) |

**Network:** `apexmail` (bridge)  
**Volumes:** `postgres_data`, `redis_data`, `prometheus_data`, `grafana_data`

#### Required Environment Variables (dev)

```
POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
REDIS_PASSWORD (optional in dev)
JWT_SECRET, API_KEY_SECRET
```

### Docker Compose — Production (`docker-compose.prod.yml`)

Overrides on top of the dev compose:

| Change | Detail |
|---|---|
| **nginx** added | TLS termination, ports 80/443, certbot volumes |
| **postgres** | No host port, 4 GB / 2 CPU limits |
| **redis** | No host port, `requirepass` mandatory, 1 GB limit |
| **api / worker / tracking** | 2 replicas each, restart on-failure (max 5), 2 GB memory |

Additional required secrets: `CORS_ORIGINS`, `TRACKING_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`.

### Dockerfiles (Multi-stage, all 3 identical pattern)

```
Stage 1 — builder (node:20-alpine)
  └─ pnpm install (frozen lockfile)
  └─ turbo prune + build (lib → db → target app)
  └─ pnpm deploy --prod (production-only deps)

Stage 2 — production (node:20-alpine)
  └─ tini (PID 1 signal handling)
  └─ non-root user: apexmail (UID 1001)
  └─ COPY from builder
  └─ EXPOSE port
```

| Dockerfile | Target app | Port |
|---|---|---|
| `Dockerfile.api` | api | 3000 |
| `Dockerfile.tracking` | tracking | 3001 |
| `Dockerfile.worker` | worker | 9090 |

### Turborepo (`turbo.json`)

| Pipeline | Deps | Cache |
|---|---|---|
| `build` | `^build` (topological) | ✅ |
| `dev` | — | ❌ |
| `test`, `test:unit`, `test:integration`, `test:e2e`, `test:coverage` | `build` | ✅ |
| `lint`, `typecheck` | — | ✅ |
| `clean` | — | ❌ |

**Global deps:** `.env`, `tsconfig.base.json`  
**Env passthrough:** `NODE_ENV`, `DATABASE_URL`, `REDIS_URL`, `NEXT_PUBLIC_*`

### Root `package.json` Scripts

| Script | Command |
|---|---|
| `dev` | `turbo run dev` |
| `build` | `turbo run build` |
| `test` | `turbo run test` |
| `test:unit` / `test:integration` / `test:e2e` | Scoped Turbo runs |
| `test:coverage` | Coverage report |
| `lint` / `typecheck` / `format` | Quality gates |
| `db:migrate` / `db:seed` | Database lifecycle |
| `bootstrap` | `tools/bootstrap.sh` |
| `verify:routes` / `verify:unused` | Static analysis tools |
| `sbom:generate` | Software bill of materials |
| `chaos:run` | Chaos engineering |
| `reconcile` | Data reconciliation |

---

## 8. Cross-Cutting Concerns

### Security Hardening

| Ref | Concern | Implementation |
|---|---|---|
| A-002 | Cross-tenant credential check | `UsersRepository.verifyCredentials` |
| A-015 | TOCTOU race on SMTP credential creation | `ON CONFLICT` upsert |
| F-245 | IP allowlist CIDR validation | `ApiKeysRepository` |
| F-246 | Client-side email validation | Node SDK `EmailsApi.send()` |
| G-200 | Transactional message + queue insert | `MessagesRepository.create()` |
| G-210 | Connection leak detection | `DatabasePool` |
| RACE-003 | Audit log hash chain race | Advisory lock per tenant |
| — | SQL injection | Savepoint name sanitisation, column whitelists in ReputationRepository |
| — | Path traversal | 6-layer protection in `StorageProvider` |
| — | XSS | Template `escapeHtml`, `sanitizeUrl`, `sanitizeAttr` |
| — | Timing attacks | Constant-time HMAC verify & SMTP credential check |
| — | Credential leaks | Pino redact paths, masked `__repr__` in Python SDK |

### FIX-500 Bug Fix References Found

| Ref | Location | Fix |
|---|---|---|
| FIX-500-098 | WebhooksRepository | SQL-level filtering instead of in-memory |
| FIX-500-274 | Node SDK | Idempotency-Key header support |
| FIX-500-375 | mail-server-client.ts | Lazy proto loading |
| FIX-500-459 | Node SDK | Comprehensive webhook event types |
| FIX-500-466 | Python SDK | Shared BaseClient extraction |

### Email Authentication Stack

| Protocol | Where |
|---|---|
| **SPF** | DNS records via `DomainsRepository.dnsRecords` |
| **DKIM** | RSA-2048 key pairs (`crypto/index.ts`), `dkim_keys` table, selectors (`apexmailYYYYWW`) |
| **DMARC** | DNS records via `DomainsRepository.dnsRecords` |
| **VERP** | Bounce address encoding (`id/index.ts`) |

### Observability

- **Logging:** Pino (structured JSON, redacted secrets)
- **Metrics:** Prometheus (`/metrics` endpoint on worker:9090), Grafana dashboards
- **Alerting:** `deploy/alerting-rules.yml` for Prometheus
- **Health checks:** HTTP `GET /health` on all services

---

## 9. Appendices

### A. Complete Table Inventory

#### Application Database (26 tables implied by repositories)

| # | Table | Repository |
|---|---|---|
| 1 | organizations / tenants | TenantsRepository |
| 2 | users | UsersRepository |
| 3 | messages | MessagesRepository |
| 4 | events | EventsRepository |
| 5 | suppressions | SuppressionsRepository |
| 6 | api_keys | ApiKeysRepository |
| 7 | domains | DomainsRepository |
| 8 | templates | TemplatesRepository |
| 9 | template_versions | TemplatesRepository (versioning) |
| 10 | audit_logs | AuditLogsRepository |
| 11 | webhooks | WebhooksRepository |
| 12 | webhook_queue | WebhooksRepository |
| 13 | inbound_messages | InboundMessagesRepository |
| 14 | unmatched_bounces | InboundMessagesRepository |
| 15 | unmatched_complaints | InboundMessagesRepository |
| 16 | email_categories | SubscriptionsRepository |
| 17 | subscription_preferences | SubscriptionsRepository |
| 18 | smtp_credentials | SmtpCredentialsRepository |
| 19 | reputation_stats | ReputationRepository |
| 20 | reputation_alerts | ReputationRepository |
| 21 | system_alerts | SystemRepository |
| 22 | idempotency_records | SystemRepository |
| 23 | compaction_log | SystemRepository |
| 24 | reconciliation_log | SystemRepository |
| 25 | email_queue (app-side) | MessagesRepository (transactional insert) |
| 26 | analytics_queue | Migration 011 |

#### Mail Server Database (6 tables)

| # | Table |
|---|---|
| 1 | email_queue |
| 2 | mail_accounts |
| 3 | mail_mailboxes |
| 4 | mail_messages |
| 5 | email_delivery_log |
| 6 | dkim_keys |

### B. All Enumerations at a Glance

| Enum | Values |
|---|---|
| MessageStatus | pending, queued, sending, sent, delivered, bounced, deferred, failed |
| EventType | queued, sending, sent, deferred, delivered, bounced, dropped, opened, clicked, unsubscribed, complained, list_unsubscribe |
| SuppressionType | bounce, complaint, unsubscribe, manual, list_unsubscribe |
| SuppressionScope | global, tenant, domain, campaign |
| BounceType | hard, soft |
| Priority | high, normal, low |
| UserRole | owner, admin, member, viewer |
| UserStatus | active, invited, disabled |
| TenantPlan | free, growth, scale, enterprise |
| TenantStatus | active, suspended, pending |
| DomainStatus | pending, verified, failed, expired |
| VerificationMethod | dns_txt, dns_cname, meta_tag |
| TemplateEngine | handlebars, mjml, liquid, ejs |
| MailboxType | inbox, sent, drafts, trash, spam, archive, custom |
| MtaEmailStatus | pending, processing, sent, failed, deferred, cancelled |
| DeliveryStatus (gRPC) | queued, sending, sent, delivered, bounced, failed, cancelled |
| ApiKeyScope | (14 scopes — see §2.5.6) |
| AuditAction | (52 values — auth/tenant/user/key/domain/message/template/webhook/suppression/billing/system/smtp/subscription) |
| AlertSeverity | info, warning, error, critical |
| ReputationAlertType | high_bounce_rate, high_complaint_rate, low_delivery_rate, reputation_warning |
| ReputationTrend | improving, stable, declining |
| WebhookEvent (SDK) | (17 event types + wildcard — see §4) |
| ErrorCode | (24 codes — see §3.2) |

### C. SDK Method Matrix

| Operation | Node.js (`@apexmail/node`) | Python (`apexmail`) |
|---|---|---|
| Send email | `emails.send(opts)` | `emails.send(…)` |
| Batch send | `emails.batch(opts)` | `emails.batch(emails)` |
| Get email | `emails.get(id)` | `emails.get(id)` |
| List emails | `emails.list(opts?)` | `emails.list()` |
| Cancel email | `emails.cancel(id)` | — |
| Create domain | `domains.create(opts)` | `domains.create(domain)` |
| Get domain | `domains.get(id)` | `domains.get(id)` |
| List domains | `domains.list(opts?)` | `domains.list()` |
| Verify domain | `domains.verify(id)` | `domains.verify(id)` |
| Delete domain | `domains.delete(id)` | `domains.delete(id)` |
| Create API key | `apiKeys.create(opts)` | — |
| List API keys | `apiKeys.list(opts?)` | — |
| Revoke API key | `apiKeys.revoke(id)` | — |
| Create webhook | `webhooks.create(opts)` | `webhooks.create(…)` |
| Get webhook | `webhooks.get(id)` | `webhooks.get(id)` |
| List webhooks | `webhooks.list(opts?)` | `webhooks.list()` |
| Update webhook | `webhooks.update(id, opts)` | `webhooks.update(id, …)` |
| Delete webhook | `webhooks.delete(id)` | `webhooks.delete(id)` |
| Test webhook | — | `webhooks.test(id, event_type)` |
| Get analytics | `analytics.get(opts?)` | — |

---

*End of report.*
