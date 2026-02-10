# ApexMail Platform — Comprehensive Analysis Report

## Security, Compliance, Enterprise & Operational Features

*Generated from full source code review of 6 apps: compliance, enterprise, isolation, ha, observability, ops*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [GDPR & CCPA Compliance](#3-gdpr--ccpa-compliance)
4. [Data Retention & Deletion](#4-data-retention--deletion)
5. [Audit Logging](#5-audit-logging)
6. [SSO / SAML / OIDC](#6-sso--saml--oidc)
7. [Role-Based Access Control (RBAC)](#7-role-based-access-control-rbac)
8. [Tenant Isolation](#8-tenant-isolation)
9. [Encryption & Key Management](#9-encryption--key-management)
10. [High Availability Architecture](#10-high-availability-architecture)
11. [Monitoring, Alerting & Metrics](#11-monitoring-alerting--metrics)
12. [Operational Tooling](#12-operational-tooling)
13. [Security Incident Handling](#13-security-incident-handling)
14. [Abuse Detection & Content Scanning](#14-abuse-detection--content-scanning)
15. [IP Warmup & Deliverability](#15-ip-warmup--deliverability)
16. [Trust Center & Transparency](#16-trust-center--transparency)
17. [Security Hardening & Bug Fixes](#17-security-hardening--bug-fixes)
18. [Identified Gaps & Recommendations](#18-identified-gaps--recommendations)

---

## 1. Executive Summary

ApexMail is a multi-tenant email platform built on **TypeScript/Node.js** using the **Hono** web framework, backed by **PostgreSQL** and **Redis**. The platform encompasses ~30,000+ lines of backend code across six operational/security modules, each deployed as an independent microservice.

**Key strengths:**
- Full GDPR/CCPA data subject request lifecycle with automated erasure across 7+ tables
- Cryptographic audit trail with hash-chain integrity verification (SHA-256 + HMAC-SHA256)
- AES-256-GCM encryption at rest with HKDF key derivation and automatic rotation
- PostgreSQL Row-Level Security (RLS) for tenant data isolation
- Multi-region HA with STONITH fencing, circuit breakers, and chaos engineering
- SLO/error-budget framework with multi-window burn-rate alerting
- OpenTelemetry distributed tracing with W3C Trace Context propagation
- Public status page and trust center with compliance documentation
- ISP-aware IP warmup management with per-ISP schedules

**Primary tech stack:**

| Component | Technology |
|---|---|
| Runtime | Node.js + TypeScript |
| Framework | Hono (w/ cors, compress, secureHeaders) |
| Database | PostgreSQL (pg Pool), Row-Level Security |
| Cache/Queue | Redis (ioredis) |
| Metrics | Prometheus (prom-client) |
| Tracing | OpenTelemetry (Jaeger + Zipkin exporters) |
| Encryption | AES-256-GCM, HKDF, HMAC-SHA256, scrypt |
| Config Validation | Zod schemas |
| Shared Library | @apexmail/lib (crypto, logger, Result type) |

---

## 2. Architecture Overview

### Service Map

| App | Port | Purpose |
|---|---|---|
| `compliance` | 4400 | GDPR/CCPA, risk scoring, content scanning, audit, secrets |
| `enterprise` | 4300 | SSO, sub-accounts, white-label, log streaming, QBR |
| `isolation` | 4500 | Tenant isolation, RLS, rate limiting, per-tenant encryption |
| `ha` | configurable | Health, failover, backup, replication, multi-region, chaos |
| `observability` | configurable | Metrics, alerting, tracing, logging, dashboards |
| `ops` | 9090 | SLOs, incidents, status page, trust center, IP warmup |

### Authentication Mechanisms

| App | Method |
|---|---|
| compliance | Bearer token with timing-safe comparison |
| enterprise | X-API-Key (Redis lookup) + Bearer JWT (RS256/384/512) |
| isolation | Internal API key header |
| ha | X-API-Key or Bearer for /api/* and /internal/* (FIX-500-025) |
| ops | X-API-Key or Bearer for /api/* routes (FIX-500-026) |

### Graceful Shutdown

All apps handle `SIGTERM`, `SIGINT` (and isolation adds `SIGUSR2`), properly draining connections, stopping cron jobs, and flushing audit buffers before exit.

---

## 3. GDPR & CCPA Compliance

### Source: `apps/compliance/src/gdpr/automation.ts` (1,074 lines)

**Data Subject Request Types:**
- `access` — Full data export
- `erasure` — Right to be forgotten
- `portability` — Machine-readable export
- `rectification` — Data correction
- `restriction` — Processing restriction
- `objection` — Processing objection

**Request Status Lifecycle:**
`pending` → `in_progress` → `completed` | `failed` | `cancelled` | `rejected`

**Erasure implementation (GDPR-001):**
Deletes data from **7+ tables** including backups:
```
emails, contacts, campaigns, campaign_contacts,
analytics_events, webhooks, audit_logs (anonymized)
```
Each deletion is wrapped in a database transaction. Audit logs are anonymized rather than deleted to maintain the integrity chain.

**Data Export (GDPR-002):**
- Generates secure, time-limited export tokens
- Exports data in JSON format with sections: profile, contacts, emails, campaigns, analytics, preferences
- Token expiry enforced on download

**Consent Management:**
- 6 consent types: `marketing`, `analytics`, `third_party`, `profiling`, `newsletter`, `data_processing`
- Double opt-in verification flow
- Full consent history tracking with timestamps
- Consent can be withdrawn; all downstream processing is stopped
- Grace period: 30 days before permanent deletion (configurable)

**Data Retention:**
- Maximum retention: 730 days (configurable)
- Automated cleanup via daily cron job
- GDPR queue processed every minute

### Enterprise Compliance Module: `apps/enterprise/src/services/compliance.ts`

Supports **6 compliance frameworks:**
- HIPAA (with BAA, zero-retention option)
- SOC 2 (30-minute session timeout)
- GDPR
- CCPA
- PCI DSS
- ISO 27001

**Data Classification:**
- PII fields: `email`, `name`, `phone`, `address`, `ip_address`
- PHI fields: `medical_record`, `health_data`, `insurance_id`
- Automated scanning for classified data in content

---

## 4. Data Retention & Deletion

| Domain | Default Retention | Mechanism |
|---|---|---|
| Audit logs | 365 days | Configurable via `compliance` config; daily archive cron at 2AM |
| GDPR data | 730 days max | 30-day grace period, then permanent deletion |
| Backups | 90 days | HA backup service with retention policy enforcement |
| Metrics data | 24 hours in-memory | Time-windowed eviction in metrics collector |
| Incident history | 5,000 max | Bounded in-memory array with splice trimming (FIX-500-328) |
| Alert history | 10,000 max | Bounded array with periodic cleanup |
| Post-mortems | 1,000 max | Oldest completed entries evicted |
| Tracing spans | 1,000 max in-memory | FIFO eviction in local exporter |
| Secrets | 90-day rotation cycle | Auto-rotation with version history |

**Secure Deletion:**
- Database deletions use `DELETE FROM` within transactions
- Encryption keys are rotated and old versions are removed
- GDPR erasure covers backups explicitly (GDPR-001)
- Workspace deletion uses a 30-day cleanup queue (isolation app)

---

## 5. Audit Logging

### Compliance App: Cryptographic Hash Chain

**Source:** `apps/compliance/src/audit/hash-chain.ts` (851 lines)

**Architecture:**
- Each audit entry contains: `SHA-256 hash` + `previous hash pointer` + `HMAC-SHA256 signature`
- Creates a tamper-evident chain: any modification to a historical entry breaks the chain
- Chain verification runs daily at 3AM via cron job
- Uses `SCAN` instead of `KEYS` for Redis iteration (C-062) — production safe

**Entry Structure:**
- 14 action types: `create`, `read`, `update`, `delete`, `login`, `logout`, `export`, `import`, `approve`, `reject`, `escalate`, `archive`, `restore`, `purge`
- 13 resource types: `email`, `contact`, `campaign`, `list`, `template`, `api_key`, `webhook`, `domain`, `user`, `team`, `billing`, `integration`, `settings`

**Export formats:** JSON, CSV, PDF

**Webhooks:** Configurable audit event webhooks for external SIEM integration

### Isolation App: Buffered Audit Service

**Source:** `apps/isolation/src/services/audit.ts` (641 lines)

- **40+ event types** across 9 categories: auth, org, workspace, member, data, security, billing, email, settings
- **3 severity levels** for triage
- **Buffered batch inserts** with atomic splice (FIX-500-422) and unshift-on-failure (FIX-500-423)
- **Hash chain verification** with advisory lock and `SERIALIZABLE` isolation (AUDIT-001)
- **Critical events flushed immediately** with Redis pub/sub notification
- **Signing key required** in all environments (SOC2-002)
- **Configurable retention** with automated cleanup

### HA App: Multi-layer Audit Events

The HA module records failover events, backup operations, and fencing actions directly to the database with timestamps and metadata.

---

## 6. SSO / SAML / OIDC

### Source: `apps/enterprise/src/services/sso.ts` (1,298 lines)

**Supported protocols:**
- SAML 2.0
- OIDC (OpenID Connect)

**JWT verification:**
- Algorithms: RS256, RS384, RS512
- JWKS caching with automatic refresh (FIX-500-019)

**Session management:**
- SOC 2 compliant 30-minute session timeout
- Session state tracked per user

**Trust Center declares support for:**
- SAML 2.0 and OIDC for enterprise SSO
- Integration with Okta, Azure AD, Google Workspace

---

## 7. Role-Based Access Control (RBAC)

### Isolation App Roles

**Organization-level → Workspace-level hierarchy:**

| Role | Capabilities |
|---|---|
| `owner` | Full control, billing, deletion |
| `admin` | User management, configuration |
| `member` | Standard operations |
| `viewer` | Read-only access |

**Enforcement:**
- Role checked on every workspace member operation
- Workspace member limits enforced (500 users/workspace default)
- Organization limits enforced (100 workspaces/org default)

### Secrets Manager Access Control

**Source:** `apps/compliance/src/secrets/manager.ts`

- Three access levels: `read`, `write`, `admin`
- Per-secret access control lists
- Access checked before any secret operation

### Enterprise Sub-Accounts

**Source:** `apps/enterprise/src/services/sub-accounts.ts`

- Agency/reseller sub-account hierarchy
- Maximum 100 sub-accounts per parent
- Isolated permissions per sub-account

---

## 8. Tenant Isolation

### Source: `apps/isolation/` (full app, ~3,300 lines)

**Multi-layer isolation architecture:**

#### Layer 1: PostgreSQL Row-Level Security (RLS)

**Source:** `apps/isolation/src/services/data-isolation.ts` (725 lines)

- RLS policies created for all 4 DML operations: `SELECT`, `INSERT`, `UPDATE`, `DELETE`
- Uses PostgreSQL session variables (`app.current_workspace_id`) to scope queries
- **Isolated connections** with leak detection (5-minute threshold)
- Connection context set via `SET LOCAL app.current_workspace_id = $1`

#### Layer 2: Query Validation

**Dangerous patterns blocked:**
- `information_schema` access
- `pg_catalog` access
- `SET search_path` / `SET role` / `SET session` commands
- SQL identifier sanitization (FIX-500-343)

#### Layer 3: Tenant Filter Injection

- All queries have tenant workspace ID filters automatically injected
- Resource ownership verified before access
- Cross-tenant access attempts generate Redis security alerts and audit entries

#### Layer 4: Schema-Level Isolation

- Support for **dedicated schemas per tenant** (for high-isolation customers)
- Migration between shared and dedicated isolation modes
- Uses table allowlists for safe migration

#### Layer 5: Rate Limiting

**Source:** `apps/isolation/src/services/rate-limit.ts` (415 lines)

- **Sliding window** via Redis sorted sets with `MULTI`
- **Token bucket** algorithm (noted TOCTOU race — FIX-500-421 TODO)
- **Workspace quota enforcement:**
  - Per-minute API requests (1,000 default)
  - Per-month email sends (10,000 default)
  - Per-month webhook calls
  - Storage limits (1GB default)
- **Distributed rate limiting** via Lua script for atomicity

---

## 9. Encryption & Key Management

### Field-Level Encryption

**Source:** `apps/isolation/src/services/encryption.ts` (667 lines)

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** HKDF from master key to per-organization data keys
- **Per-organization data keys** stored encrypted in the database
- **Key rotation** with advisory lock (FIX-500-425) to prevent concurrent rotations
- On rotation: all affected records are re-encrypted with the new key
- **Encryption policies** define which resources/fields are encrypted
- **Searchable hashing** for encrypted fields that need indexing

### Secrets Management

**Source:** `apps/compliance/src/secrets/manager.ts` (702 lines)

- **AES-256-GCM** with **scrypt** key derivation
- 6 secret types: `api_key`, `webhook_secret`, `encryption_key`, `smtp_password`, `oauth_token`, `certificate`
- Version history maintained for all secrets
- Automatic rotation with configurable intervals (90-day default)
- Secret rotation cron runs hourly

### Backup Encryption

**Source:** `apps/ha/src/services/backup.ts`

- Backups encrypted with `@apexmail/lib/crypto`:
  - `createAES256GCMCipher`
  - `encryptBufferAES256GCM` / `decryptBufferAES256GCM`
  - `createSHA256Hash` for integrity verification
- Production encryption is mandatory (FIX-500-339)
- Post-creation checksum verification (E-175)

### Trust Center Declarations

- TLS 1.3 for encryption in transit
- AES-256-GCM for encryption at rest
- HSM-backed key management with automatic rotation

---

## 10. High Availability Architecture

### Source: `apps/ha/` (full app, ~5,500+ lines)

**Recovery Objectives:**
- **RPO:** 60 seconds (Recovery Point Objective)
- **RTO:** 300 seconds (Recovery Time To Objective)

### Failover State Machine

**Source:** `apps/ha/src/services/failover.ts` (1,250 lines)

**States:** `NORMAL` → `DETECTING` → `FAILING_OVER` → `FAILED_OVER` → `FAILING_BACK` → `NORMAL`

**Key features:**
- Atomic state transitions with validation
- **Distributed locking** via Redis `SET NX` with Lua compare-and-delete release (FIX-500-183)
- **Fencing tokens** (FIX-500-336) to prevent stale operations
- **Split-brain detection** with STONITH fencing
- Pre-failover replication lag verification (max 10s / 16MB)
- Cooldown periods between failover attempts (5 minutes)
- Bounded history (max 1,000 events, FIX-500-241)

### Multi-Region Architecture

**Source:** `apps/ha/src/services/multi-region.ts` (937 lines)

**Region states:** `HEALTHY`, `DEGRADED`, `UNHEALTHY`, `MAINTENANCE`, `OFFLINE`
**Region roles:** `PRIMARY`, `SECONDARY`, `STANDBY`, `OBSERVER`

**STONITH fencing (HA-003):**
1. Acquire distributed lock
2. Send fence API call to target region
3. Record region in Redis `fenced-regions` set
4. Publish notification via pub/sub
5. Record event in database
6. Auto-unfence on failover failure (rollback)

**Routing modes:**
- Active-active
- Active-passive
- Round-robin
- Latency-based
- Geo-proximity
- Weighted

**Validation (FIX-500-337):** Max 20 regions, regex pattern validation, deduplication

### Circuit Breaker

**Source:** `apps/ha/src/services/circuit-breaker.ts` (577 lines)

- Standard `CLOSED` → `OPEN` → `HALF_OPEN` pattern
- Configurable failure threshold, success threshold, monitoring window
- Request volume threshold before evaluation
- Fallback function support
- **Redis persistence** with graceful degradation (FIX-500-340)
- State change pub/sub notifications
- Health status aggregation across all breakers

### Backup & Restore

**Source:** `apps/ha/src/services/backup.ts` (1,436 lines)

- **Full backups** (weekly) — `pg_dump` with gzip compression + AES-256-GCM encryption
- **Incremental backups** (daily)
- **WAL archiving** (every 5 minutes) with partial-file safety:
  - Stat check before archiving (FIX-500-185)
  - Write to `.partial` file, then atomic rename to final
  - Cleanup on failure
- **Manifest files** for each backup set
- **Point-in-time recovery** (PITR) support
- Post-creation **checksum verification** (E-175)
- PG notice capture during backup (FIX-500-184)

### Replication Monitoring

**Source:** `apps/ha/src/services/replication.ts` (908 lines)

- Streaming + logical replication monitoring via `pg_stat_replication`
- Replication slot management (physical + logical)
- Lag tracking with configurable thresholds (30s default)
- SQL identifier sanitization (`sanitizeIdentifier`, `quoteIdentifier`)
- Connection string escaping
- Pool cleanup on init failure (CONN-002)

### Chaos Engineering

**Source:** `apps/ha/src/services/chaos.ts` (855 lines)

**Experiment types:**
- Latency injection
- Failure injection
- Resource exhaustion
- Network partition
- DNS failure
- Disk pressure
- Memory pressure
- CPU pressure

**Safety:**
- **Disabled in production** without explicit `CHAOS_FORCE_ENABLE` flag (FIX-500-338)
- Abort thresholds with automatic experiment termination
- Before/during/after metric snapshots for comparison
- Experiment scheduling and CRUD management
- Per-request fault injection targeting by service, endpoint, user, or region

---

## 11. Monitoring, Alerting & Metrics

### Metrics Collection

**Ops App:** `apps/ops/src/metrics/collector.ts` (710 lines)

- **Prometheus-compatible** via `prom-client`
- 4 metric types: Counter, Gauge, Histogram, Summary
- Default metrics auto-collected (Node.js runtime)
- Built-in ApexMail metrics:
  - HTTP requests (duration, total, by method/route/status)
  - Email sends (total, duration, queue size)
  - Campaign metrics (created, active)
  - Contact metrics (total, imported)
  - Database queries (duration, active connections)
  - Cache metrics (hits, misses)
  - Queue metrics (waiting, active, completed)
  - Health check results (status, latency)
  - SLO metrics (current value, error budget, burn rate)
  - Alert counters (by severity, action)
- Push gateway support with exponential backoff retry (FIX-500-335, 3 attempts)
- In-memory data store with 24h TTL and max 100K keys (FIX-500-326)

**Observability App:** `apps/observability/src/services/metrics.ts` (800 lines)

- Batched DB inserts (C-092/FIX-500-449)
- SQL injection prevention: whitelisted aggregation functions and intervals, sanitized `groupBy` labels (FIX-500-271/272)

### Alerting

**Ops App:** `apps/ops/src/alerts/manager.ts` (942 lines)

**8 default alert rules:**
1. API error rate > 5% for 5 minutes → warning
2. API p95 latency > 500ms for 3 minutes → warning
3. Email delivery failure > 2% for 5 minutes → **critical** (PagerDuty)
4. DB connection pool > 80% for 1 minute → warning
5. Memory usage > 85% for 5 minutes → warning
6. SLO burn rate > 10x for 1 minute → **critical** (PagerDuty)
7. Queue backlog > 10,000 for 5 minutes → warning
8. Certificate expiry < 14 days → warning

**Notification channels:** Slack, Email, PagerDuty, Webhook, SMS

**Escalation policies:**
- **Default:** L1 (Slack, immediate) → L2 (Slack+Email, 15 min) → L3 (PagerDuty+Slack+Email, 30 min)
- **Critical:** L1 (PagerDuty+Slack, immediate) → L2 (PD+Slack+Email+Eng Lead, 5 min) → L3 (PD+Slack+Email+SMS+VP+CTO, 15 min)

**Deduplication:** 5-minute window with key-based deduplication cache

**Observability App:** `apps/observability/src/services/alerting.ts` (1,187 lines)

- Bounded local caches: 10K rules, 1K channels, 10K silences, 50K alerts
- Consecutive failure tracking per rule (max 5, FIX-500-186)
- Alert value validation (G-219)
- Redis cooldown for notification deduplication

### SLO / Error Budget Management

**Source:** `apps/ops/src/slo/manager.ts` (670 lines)

**5 default SLOs:**

| SLO | Target | Window | Critical Burn Rate |
|---|---|---|---|
| API Availability | 99.9% | 30 days | 14.4x in 5 min |
| API Latency P99 | 99% (< 500ms) | 30 days | 14.4x in 5 min |
| Email Delivery Rate | 99.5% | 30 days | 10x in 15 min |
| Email Processing Latency | 99% (< 30s) | 30 days | 14.4x in 15 min |
| Web Availability | 99.9% | 30 days | 14.4x in 5 min |

**SLI types:** availability, latency, error_rate, throughput, saturation
**Aggregations:** avg, p50, p90, p95, p99, max, min, sum, count

**Error budget tracking:**
- Budget remaining / consumed percentages
- Consumption rate (minutes/day)
- Projected exhaustion date
- Multi-window burn rate (5-min short / 60-min long)
- Status: healthy → warning → critical → exhausted

### Distributed Tracing

**Ops App:** `apps/ops/src/tracing/tracer.ts` (593 lines)

- **OpenTelemetry** with `NodeTracerProvider`
- Exporters: OTLP HTTP (configurable endpoint), local in-memory
- **W3C Trace Context propagation** (`traceparent` header)
- Configurable sampling rate (default 10%)
- Span types: HTTP server/client, database, queue producer/consumer
- `@TraceMethod` decorator for easy instrumentation
- Statistics: total spans, by kind, by status, average/p95/p99 latency

**Observability App:** `apps/observability/src/services/tracing.ts` (801 lines)

- Jaeger + Zipkin `BatchSpanProcessors`
- Span TTL-based eviction (5 min, max 10K active spans)
- Custom span processor for DB buffering

### Structured Logging

**Observability App:** `apps/observability/src/services/logging.ts` (654 lines)

- 6 levels: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- Structured JSON format
- Buffered batch database inserts
- **Trace context correlation** (traceId, spanId attached to log entries)
- Full-text search querying (ILIKE)
- Contextual log retrieval (surrounding logs)
- Statistics: by level, by service, error rate, logs/minute
- Child logger support for request scoping

### Dashboards

**Observability App:** `apps/observability/src/services/dashboards.ts` (1,073 lines)

- Dashboard CRUD with layout, panels, variables, time ranges
- **14 panel types:** graph, stat, gauge, table, heatmap, histogram, logs, alert-list, pie-chart, time-series, state-timeline, node-graph, bar-gauge, text
- **5 template dashboards:**
  1. Email Overview
  2. Delivery Performance
  3. Infrastructure
  4. Security
  5. Business Metrics
- Snapshots for sharing
- Permissions: view, edit, admin

---

## 12. Operational Tooling

### Health Checking

**Ops App:** `apps/ops/src/health/checker.ts` (702 lines)

**8 default checks:**
1. Primary Database (PostgreSQL)
2. Redis Cache
3. Redis Queue
4. API Service (HTTP)
5. Email Service (HTTP)
6. Worker Service (HTTP)
7. SMTP Provider (TCP)
8. Object Storage (S3)

**Features:**
- Configurable intervals per check
- Timeout handling with `Promise.race`
- **Threshold-based status transitions:** consecutive failures → degraded → unhealthy; consecutive successes → healthy
- Deep health check endpoint that forces all checks simultaneously
- Liveness, readiness, and detailed health endpoints
- Health events wired to status page component updates

**HA App:** `apps/ha/src/services/health-check.ts` (685 lines)

- DB primary/replica/standby checks
- Redis check
- Memory (process + OS) check
- Disk usage (via `df`)
- 7 service endpoint checks (api, mta, worker, tracking, analytics, billing, devex)
- Replication lag via WAL LSN diff
- Cluster health publishing to Redis

### Status Page

**Source:** `apps/ops/src/status/page.ts` (850 lines)

**Components:** Web App, API, Email Sending, Email Tracking, Webhooks, Analytics
**Groups:** Core Services, Email Services, Integrations

**Features:**
- Real-time component status updates (operational, degraded, partial/major outage, maintenance)
- Group status = worst component status
- **Incident management:** investigating → identified → monitoring → resolved
- **Maintenance windows:** scheduled → in_progress → completed | cancelled
- **Subscriber notifications:** Email notifications for component degradation, incidents, maintenance
- Subscriber component filtering (subscribe to specific components)
- **Uptime calculation:** daily, weekly, monthly percentages
- **Postgres persistence** with in-memory L1 cache + write-through on every mutation (FIX-500-155)

### Incident Management

**Source:** `apps/ops/src/incidents/manager.ts` (688 lines)

**Severity levels:** critical, high, medium, low, sev1–sev4
**Status flow:** investigating → identified → monitoring → resolved

**Features:**
- **Automatic incident creation** from critical alerts
- **Incident roles:** commander, communication, technical, scribe
- **Timeline tracking:** Every status change, severity change, role assignment, note, and communication is recorded
- **Slack channel creation** per incident (`inc-<id>`)
- **Post-mortem workflow:**
  - Auto-created for high/critical incidents
  - Due within 5 days
  - Status: pending → in_progress → completed
  - Root cause analysis, contributing factors, action items, lessons learned
  - Action items tracked with assignees and due dates
  - Overdue post-mortem detection
- **Statistics:** total incidents, MTTR (Mean Time To Resolve), MTTA (Mean Time To Acknowledge), by severity
- **Broadcasting:** Multi-channel updates (Slack, email, status page)
- **Full export** for reporting
- Memory management: bounded history (5K), bounded post-mortems (1K), maps cleaned on resolution (MEM-009)

### Unified Operations Dashboard

**Source:** `apps/ops/src/routes.ts` — `/dashboard` endpoint

Aggregates in a single API call:
- Health report (deep check)
- SLO statuses (at-risk, breached counts)
- Active alerts (by severity)
- Active incidents (by severity)
- Overall status + uptime

---

## 13. Security Incident Handling

### Risk Scoring

**Source:** `apps/compliance/src/risk/scoring.ts` (869 lines)

**10 weighted risk factors:**
- Weighted scoring with configurable weights
- Risk levels: low, medium, high, critical
- Dynamic sending limits adjusted by risk level
- Reassessment intervals based on current risk
- **Redis NX lock** for preventing concurrent scoring of the same tenant (FIX-500-182)
- Blocklist checking

### Content Scanning

**Source:** `apps/compliance/src/content/scanner.ts` (1,290 lines)

- **Spam detection:** 14 regex rules (all-caps, excessive punctuation, money patterns, urgency words)
- **Phishing detection:** 6 rules including homograph/punycode detection
- **Malware detection:** 16 dangerous file extensions blocked
- **Policy compliance** checking
- **OCR** via tesseract.js for image text extraction and scanning
- **Verdicts:** clean, suspicious, blocked

### Cross-Tenant Security

**Source:** `apps/isolation/src/services/data-isolation.ts`

- Cross-tenant access attempts generate immediate Redis security alerts
- Full audit trail of access attempts with source workspace, target workspace, resource ID
- Query validation blocks dangerous SQL patterns

---

## 14. Abuse Detection & Content Scanning

The compliance app's content scanner performs multi-layered abuse detection:

1. **Pre-send scanning** with configurable spam score threshold
2. **URL extraction and validation** against known phishing domains
3. **Attachment scanning** against dangerous extension blacklist
4. **Image OCR** to detect text-based spam in images
5. **Homograph attack detection** in URLs (IDN/punycode)
6. **Policy compliance** checking against custom rules

Scan results include a numeric spam score, matched rules, and a final verdict of `clean`, `suspicious`, or `blocked`.

---

## 15. IP Warmup & Deliverability

### Source: `apps/ops/src/warmup/manager.ts` (330 lines)

**ISP-specific warmup schedules:**

| ISP | Day 1 | Day 7 | Day 14 | Max |
|---|---|---|---|---|
| Gmail | 50 | 2,500 | 20,000 | 30,000 |
| Microsoft | 100 | 5,000 | 50,000 | 50,000 |
| Yahoo | 50 | 2,500 | 20,000 | 20,000 |
| Apple | 75 | 4,000 | 30,000 | 30,000 |
| Default | 100 | 5,000 | 50,000 | 100,000 |

**Daily advancement logic:**
- Advances warmup day only if IP utilized ≥ 75% of daily limit
- Below threshold: warmup day stays the same (slows ramp)
- Daily counters reset at midnight UTC
- Redis counters cleaned for previous day

**Safety:**
- `FOR UPDATE` row lock to prevent TOCTOU race between concurrent cron instances (FIX-500-040)
- Full transaction wrapping with rollback on failure

**API endpoints:**
- View schedules, pool status, per-IP status
- Start/pause/reset warmup per IP
- Manual day override (for recovery scenarios)
- Trigger daily advancement (for cron or manual)

---

## 16. Trust Center & Transparency

### Source: `apps/ops/src/trust/center.ts` (896 lines)

**Public trust center with:**

**Certifications:**
- SOC 2 Type II
- ISO 27001:2022
- GDPR Compliance
- CCPA Compliance
- HIPAA BAA Available

**16 Security Controls** across 7 categories:
- Data Encryption (TLS 1.3 transit, AES-256-GCM rest, HSM key management)
- Authentication (MFA with TOTP/WebAuthn, SSO with SAML/OIDC, RBAC)
- Monitoring (audit logging, 24/7 security monitoring)
- Infrastructure (SOC 2 cloud hosting, network segmentation/WAF/DDoS protection)
- Vulnerability Management (automated scanning, annual pen testing)
- Incident Response (documented plan, regular testing)
- Business Continuity (multi-region DR with tested failover)
- Data Management (configurable retention, data portability)

**Legal Documents:**
- Privacy Policy (v3.0)
- Terms of Service (v3.0)
- Data Processing Agreement (v2.0)
- Security Whitepaper (v2.1)
- Compliance Guide (v1.5)
- Acceptable Use Policy (v2.0)
- Service Level Agreement (v2.0)
- Sub-processor List

**Sub-processors declared:**
- Hetzner (cloud server hosting — Cloud ARM, S3 object storage, EU)
- Zone.ee (DNS registrar — EU, Estonia)
- AWS SES eu-west-1 (fallback email delivery, transit only — no data storage)
- Stripe (payment processing, EU)
- Sentry (error monitoring)

**10 Data Practices** in 5 categories:
- Data Collection (minimal, consent-based)
- Data Storage (encrypted, regional)
- Data Retention (configurable, secure deletion)
- Data Access (limited, audited)
- Data Rights (export, deletion)

**10 FAQ entries** covering security, compliance, data, access, and incident response

**Persistence:** Postgres-backed with in-memory L1 cache + write-through (FIX-500-156)

---

## 17. Security Hardening & Bug Fixes

The codebase contains extensive security hardening, documented via FIX-XXX ticket references:

### Concurrency & Race Conditions
| Fix | Description | Location |
|---|---|---|
| FIX-500-040 | `FOR UPDATE` row lock for IP warmup TOCTOU | warmup/manager.ts |
| FIX-500-182 | Redis NX lock for concurrent risk scoring | compliance/risk |
| FIX-500-183 | Redis SET NX + Lua delete for failover lock | ha/failover.ts |
| FIX-500-336 | Fencing tokens for stale operation prevention | ha/failover.ts |
| FIX-500-421 | Token bucket TOCTOU race noted (TODO) | isolation/rate-limit |
| FIX-500-425 | Advisory lock for encryption key rotation | isolation/encryption |
| AUDIT-001 | Advisory lock + SERIALIZABLE for hash chain | isolation/audit |

### SQL Injection Prevention
| Fix | Description |
|---|---|
| FIX-500-271/272 | Whitelisted aggregation functions and intervals in metrics |
| FIX-500-343 | SQL identifier sanitization in isolation queries |
| FIX-500-334 | Safe label parsing using indexOf instead of split |
| HA app | `sanitizeIdentifier`, `quoteIdentifier` functions |

### Memory Management
| Fix | Description |
|---|---|
| FIX-500-326 | MAX_DATA_STORE_KEYS = 100K eviction for metrics |
| FIX-500-327/328 | splice() for in-place array trimming |
| FIX-500-332 | setMaxListeners(50) across all EventEmitters |
| FIX-500-424 | Redis maxListeners set to 50 |
| MEM-009 | Map cleanup on incident resolution |

### Connection & Resource Safety
| Fix | Description |
|---|---|
| CONN-002 | Pool cleanup on replication init failure |
| FIX-500-185 | WAL archive partial-file safety (stat, rename, cleanup) |
| FIX-500-331 | timer.unref() to not block process exit |
| FIX-500-333 | Fallback when no health check handler registered |

### Authentication & Authorization
| Fix | Description |
|---|---|
| FIX-500-019 | JWKS caching with auto-refresh |
| FIX-500-025 | Auth middleware for HA /api/* and /internal/* |
| FIX-500-026 | Auth middleware for ops /api/* |
| FIX-500-500 | Internal auth required for HA sensitive ops |
| SOC2-001 | 30-minute session timeout |
| SOC2-002 | Signing key required in all environments |

### Data Integrity
| Fix | Description |
|---|---|
| C-062 | SCAN instead of KEYS for Redis iteration |
| E-175 | Post-backup checksum verification |
| FIX-500-241 | Bounded failover history (max 1000) |
| FIX-500-337 | Region validation (max 20, regex, dedup) |
| FIX-500-339 | Production backup encryption mandatory |
| FIX-500-340 | Circuit breaker Redis persistence with graceful degradation |
| FIX-500-418 | SHA-256 hashed cache keys in compliance routes |
| G-219 | Alert threshold/value validation |

---

## 18. Identified Gaps & Recommendations

### Open Issues Noted in Code

1. **FIX-500-421 (TODO):** Token bucket rate limiter has a TOCTOU race condition between read and decrement. Should be replaced with an atomic Lua script (the sliding window implementation already uses Lua correctly).

2. **Health check handlers (FIX-500-333):** When no external handler is registered for database, Redis, TCP, or storage checks, the system assumes healthy. In production, these handlers *must* be wired up or the health checks are meaningless.

3. **Timing-safe comparison inconsistency:** The compliance app uses timing-safe comparison for bearer tokens, but the enterprise, HA, and ops apps use plain string equality (`apiKey !== expectedKey`). All auth comparisons should use `crypto.timingSafeEqual`.

4. **Status page DB writes use `.catch(() => {})`:** All Postgres write-through operations in the status page and trust center silently swallow errors. While this prevents crashes, it could lead to silent data loss. Consider logging failures at minimum.

### Recommendations

1. **Centralize authentication middleware** — Each app implements its own auth pattern. A shared middleware from `@apexmail/lib` would reduce inconsistency and ensure timing-safe comparisons everywhere.

2. **Automate secret rotation notifications** — The secrets manager rotates automatically but doesn't appear to notify dependent services. Consider adding a pub/sub or webhook notification on rotation events.

3. **Add backup restore testing** — The chaos engineering framework exists but doesn't appear to include automated backup restore verification. Consider scheduling periodic restore drills.

4. **Rate limit the trust center / status page public endpoints** — The `/trust` and `/status` endpoints have no rate limiting or caching, making them potential targets for scraping or DoS.

5. **Implement log rotation for in-memory stores** — Several services (tracing, metrics, alerts) use in-memory arrays with max-size bounds. Under heavy load, the constant allocation and splice operations could cause GC pressure. Consider circular buffers.

6. **Add encryption at rest for Redis** — While PostgreSQL data is encrypted via AES-256-GCM, Redis appears to store sensitive data (rate limit tokens, audit events, security alerts) without encryption. Consider TLS for Redis connections and/or application-level encryption for sensitive Redis values.

---

*Report covers ~30,000+ lines of source code across 6 applications, 50+ source files.*
