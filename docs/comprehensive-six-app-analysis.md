# ApexMail — Comprehensive Six-App Analysis Report

> **Scope**: `apps/analytics`, `apps/devex`, `apps/edge-cases`, `apps/sales-autopilot`, `apps/testing`, `apps/ai` (excluding `ai/src/training/`)  
> **Generated from**: Full source code review of every `.ts` / `.js` file in each app  
> **Tech stack (shared)**: TypeScript · Hono · PostgreSQL · Redis · Zod

---

## Table of Contents

1. [Analytics App](#1-analytics-app)
2. [DevEx App](#2-devex-app)
3. [Edge-Cases App](#3-edge-cases-app)
4. [Sales-Autopilot App](#4-sales-autopilot-app)
5. [Testing App](#5-testing-app)
6. [AI App](#6-ai-app)
7. [Cross-Cutting Observations](#7-cross-cutting-observations)

---

## 1. Analytics App

**Port**: N/A (library, consumed by other services)  
**Dependencies**: `duckdb`, `parquet-wasm`, `ioredis`, `pg`, `zod`  
**Source files**: 13 TypeScript modules (~6,000 lines total)

### 1.1 Architecture Overview

Analytics is a **dual-storage OLAP engine** that ingests email lifecycle events into PostgreSQL ("hot") and compacts them into Parquet files ("cold") for DuckDB-powered queries. A reconciliation layer verifies exact-once processing integrity.

### 1.2 Metrics Tracked

| Category | Metrics |
|----------|---------|
| **Delivery** | Sends, deliveries, deferrals, bounces (hard/soft/admin/undetermined), rejections |
| **Engagement** | Opens (unique/total), clicks (unique/total), replies, forwards |
| **Reputation** | Spam complaints, unsubscribes, complaint rate, spam trap hits |
| **Revenue** | Conversions, conversion rate, revenue per email |
| **Inbox** | Inbox/spam/promotions/social/missing placement per provider |
| **Behavioral** | Reply sentiment, auto-reply classification, bot vs. human opens |

### 1.3 Service Catalog

#### Bot Detection (`bot-detection.ts` — 405 lines)
- **5 detection methods**: user-agent analysis (30+ bot patterns), timing analysis (<1s = 35 points), IP reputation (known bot IP ranges), click velocity (3+ clicks in 5s window), header analysis.
- Scoring: 0–100; ≥50 = bot. `BotType` enum: `SECURITY_SCANNER`, `LINK_PREFETCH`, `EMAIL_GATEWAY`, `SPAM_FILTER`, `CRAWLER`, `UNKNOWN`.
- Cache capped at 50K entries (FIX C-095 — prevents unbounded memory growth).

#### Campaign Autopilot (`campaign-autopilot.ts` — 661 lines)
- **Thompson Sampling** (Beta–Bernoulli Bandit) for template optimization.
- Manages `BanditState` with arms, tracks impressions/conversions, and transitions through phases: `exploration → exploitation → converged`.
- `CONVERGENCE_THRESHOLD = 0.95`, `MIN_IMPRESSIONS = 50`.
- Generates `OptimizationReport` with credible intervals, probability of best, expected regret, and lift calculations.

#### Churn Prediction (`churn-prediction.ts` — 583 lines)
- **RFM-inspired scoring** predicting tenant/recipient churn.
- Feature weights: `engagementDecay 0.25`, `recencyPenalty 0.20`, `complaintSignal 0.20`, `unsubscribeSignal 0.15`, `bounceSignal 0.10`, `frequencyDrop 0.10`.
- Risk thresholds: critical complaint rate 0.3%, high bounce 5%, inactive 90 days = critical tier.
- Outputs: `RiskTier` (critical/high/medium/low/healthy), predicted churn date, engagement trend line.

#### Compaction Worker (`compaction.ts` — 463 lines)
- Converts hot PostgreSQL data → cold **Parquet files** grouped by tenant and date.
- Distributed locking via Redis `SET NX EX` to prevent concurrent compaction.
- SHA-256 checksums per file for integrity verification.
- Configurable retention: hot 90 days, cold 2 years. Batch size default 10K rows.

#### Engagement Trust (`engagement-trust.ts` — 463 lines)
- **Trust Equation**: `Trust = (Credibility + Reliability + Intimacy) / Self-Orientation`.
- Component weights: Credibility 0.30, Reliability 0.30, Intimacy 0.25.
- Credibility derived from open/click/spam rates; Reliability from preference compliance and relationship duration.
- Outputs: Trust score, grade (A–F), risk level, actionable recommendations.

#### Inbox Placement (`inbox-placement.ts` — 689 lines)
- Seed-list testing across **8+ email providers**: Gmail, Outlook, Yahoo, AOL, iCloud, ProtonMail, Zoho, GMX.
- Tracks `PlacementTestResult`: inbox, spam, promotions, social, missing per provider.
- Industry benchmarks: transactional 95–99%, marketing 85–95%.
- Generates aggregate `PlacementSummary` with per-provider inbox rates and recommendations.

#### Query Engine (`query-engine.ts` — 568 lines)
- **DuckDB** for cold OLAP queries + PostgreSQL for hot data.
- Query types: time series (hour/day/week/month), dimension aggregation (event_type, recipient_domain, bounce_type, link_id), campaign performance dashboard, funnel analysis, tenant dashboard with rate calculations.

#### Reconciliation Worker (`reconciliation.ts` — 401 lines)
- Verifies **exact-once event processing** by cross-referencing messages with events.
- Detects: missing events, multiple terminal states, orphaned events.
- Stores reconciliation results with duration metrics and discrepancy counts.

#### Reply Tracking (`reply-tracking.ts` — 386 lines)
- Tracks reply rates as a primary KPI.
- Auto-reply detection via headers (`Auto-Submitted`, `X-Auto-Response-Suppress`, `Precedence`) and 18+ content patterns.
- `ReplySentiment` enum: `POSITIVE`, `NEGATIVE`, `NEUTRAL`, `INQUIRY`, `UNSUBSCRIBE_REQUEST`, `OUT_OF_OFFICE`.
- Cache capped at 50K (FIX C-095).

#### Send-Time Optimizer (`send-time-optimizer.ts` — 560 lines)
- **Bayesian averaging** with global priors; hour priors peak at 10 AM (0.11), day priors peak Tuesday (0.18).
- Confidence thresholds: high = 50 samples, medium = 20.
- Builds per-recipient profiles from engagement history.
- Batch optimization with concurrency limit of 50.

#### Subject-Line Analyzer (`subject-line-analyzer.ts` — 567 lines)
- **NLP tokenization** (unigrams/bigrams) categorised into: urgency, exclusivity, benefit, curiosity, social_proof, personalization, question, number, emoji.
- Spam-token detection (20+ trigger words).
- Scores: overall, length, urgency, personalization, clarity, `spamRisk`.
- Optimal length: 30–50 characters.

---

## 2. DevEx App

**Port**: 4200  
**Dependencies**: `hono`, `ioredis`, `pg`, `zod`, `commander`, `chalk`, `openapi3-ts`  
**Source files**: 8 TypeScript modules (~8,500 lines total)

### 2.1 Architecture Overview

DevEx is the **developer experience portal** providing API versioning, an OpenAPI spec generator, SDK generation for 7 languages, a sandboxed email testing environment, webhook management, and CLI tool scaffolding.

### 2.2 API Versioning (`api-versioning.ts` — 454 lines)

- **Date-based versioning** (YYYY-MM format): 5 versions defined (`2022-10` through `2024-01`).
- Current version: `2024-01`; Supported: `2023-10`, `2023-06`; Deprecated: `2023-01`, `2022-10`.
- Hono middleware adds deprecation headers (`Deprecation`, `Sunset`, `Link`).
- Version transformers apply request/response mappings between API versions.
- Returns **410 Gone** for sunset versions.

### 2.3 OpenAPI Generator (`openapi-generator.ts` — 1,947 lines)

- Full **OpenAPI 3.1** spec generation covering all API endpoints:
  - `/emails` — send, batch, get, list
  - `/domains` — CRUD + verify + DNS records
  - `/webhooks` — CRUD + test delivery
  - `/templates` — CRUD + render preview
  - `/analytics` — overview, time-series, aggregation
- Security schemes: `BearerAuth`, `ApiKeyAuth`.
- Component definitions: `Email`, `Domain`, `Template`, `Webhook` schemas with full JSON Schema types.

### 2.4 SDK Generator (`sdk-generator.ts` — 3,204 lines)

Generates complete SDK packages for **7 languages**:

| Language | Package Manager | Key Files Generated |
|----------|----------------|---------------------|
| TypeScript | npm | `package.json`, client, resources, types, errors, README |
| Python | pip | `setup.py`, client, resources, exceptions, README |
| Ruby | gem | `gemspec`, client, resources, errors, README |
| Go | `go get` | `go.mod`, client, resources, errors, README |
| PHP | Composer | `composer.json`, client, resources, exceptions, README |
| Java | Maven | `pom.xml`, client, resources, exceptions, README |
| C# | NuGet | `.csproj`, client, resources, exceptions, README |

Each SDK includes: type-safe client, resource modules (emails, domains, webhooks, templates, analytics), error handling, retry logic, and install instructions.

### 2.5 Sandbox (`sandbox.ts` — 1,155 lines)

- **4 modes**: `CAPTURE` (no send), `SIMULATE` (mock responses), `FORWARD` (test inbox), `REPLAY` (recorded events).
- Configurable bounce/complaint rates and delays for simulation mode.
- Captures full email objects with attachments; max 10K captures per sandbox, 1K environments.
- Database-backed with in-memory cache for fast lookups.

### 2.6 Webhooks (`webhooks.ts` — 960 lines)

- **HMAC-SHA256 signatures** on all webhook payloads.
- Exponential backoff retry: `1m → 5m → 30m → 2h → 6h → 24h` (6 max retries).
- **SSRF protection**: blocks private IP ranges (IPv4/IPv6), performs DNS resolution checks.
- 13 email lifecycle events + account/billing/domain/API key events.
- Rate limiting per endpoint.

### 2.7 CLI Tool (`cli-tool.ts` — 767 lines)

Scaffolds the `apexmail` CLI with **11 commands**: `configure`, `send`, `domains`, `templates`, `webhooks`, `apikeys`, `analytics`, `email`, `validate`, `test`, `logs`. Generates full project scaffolding (package.json, tsconfig, src files).

---

## 3. Edge-Cases App

**Port**: 4600  
**Dependencies**: `hono`, `pg`, `ioredis`, `uuid`, `mime-types`, `iconv-lite`, `punycode`, `mailparser`, `ical-generator`, `node-clamav`, `nodemailer`  
**Source files**: 7 TypeScript modules (~3,500 lines total)

### 3.1 Architecture Overview

Handles **protocol-level edge cases** in email delivery: internationalized addresses (RFC 6531 EAI), attachment security scanning, calendar invite generation (RFC 5545), and SMTP delivery response parsing.

### 3.2 EAI (Email Address Internationalization) (`eai.ts` — 521 lines)

- Full **RFC 6531** compliance for internationalized email addresses.
- **Unicode NFC normalization** on all input.
- Punycode domain conversion for legacy SMTP interop.
- Local part validation: 64-char limit, no consecutive dots, valid charset enforcement.
- Domain validation: 255-char limit, per-label length checks, TLD verification.
- MX record verification with Redis cache for performance.
- SMTPUTF8 capability detection for downstream servers.
- Common typo checking and suggestions.

### 3.3 Attachment Security (`attachment.ts` — 534 lines)

- **ClamAV virus scanning** via INSTREAM protocol.
- **Magic byte detection** for PDF, ZIP, JPEG, PNG, GIF, Office XML — prevents MIME spoofing.
- Double extension detection (e.g., `file.pdf.exe`).
- Encrypted content detection (password-protected ZIPs/PDFs).
- Blocked extensions: `.exe`, `.bat`, `.cmd`, `.scr`, `.pif`, `.com`, `.js`, `.vbs`, `.wsf`, `.msi`.
- **Critical security rule**: scan failures always return `isClean: false` — never assumes clean on error.
- Base64 overhead calculation for accurate size estimation.
- Limits: 25 MB single file, 35 MB total, 20 max files per message.

### 3.4 Calendar Invites (`calendar.ts` — 787 lines)

- RFC 5545 **ICS content generation** with 5 MIME methods: `REQUEST`, `REPLY`, `CANCEL`, `REFRESH`, `COUNTER`.
- Timezone component support for proper cross-timezone scheduling.
- Recurrence rules: `DAILY`, `WEEKLY`, `MONTHLY`, `YEARLY` with `byDay`, `byMonth`, `byMonthDay`.
- Attendee roles and participation status tracking.
- HTML preview with styled invite card for email clients.
- **Security**: URL scheme validation prevents `javascript:` injection (FIX-500-032).

### 3.5 Delivery Handling (`delivery.ts` — 660 lines)

- **SMTP enhanced status code parsing** (e.g., `4.2.1`, `5.1.1`).
- Greylisting detection (9 patterns) and rate-limit detection (7 patterns).
- Retry scheduling with **exponential backoff** and greylist-specific delays.
- **Email loop detection**: hop counting (max 25) + repeated host detection (max 30 Received headers).
- Auto-responder classification: `OOO/vacation`, `bounce`, `notification`, `system` — with confidence scoring.
- MX record resolution with failover ordering.
- IP/CIDR validation (FIX-500-408).

---

## 4. Sales-Autopilot App

**Port**: 3010 (Control Plane service)  
**Dependencies**: `hono`, `pg`, `ioredis`, `cheerio`, `zod`, `uuid`  
**Source files**: ~25 TypeScript modules (~12,000+ lines total)

### 4.1 Architecture Overview

Sales-Autopilot is a **full-stack outbound sales automation platform** with lead discovery/enrichment, CRM pipeline management, drip campaign orchestration, multi-stage Thompson Sampling for A/B testing, reply classification, demo scheduling, and promotional content injection. The app operates as a Control Plane-only service — customer API keys are explicitly blocked.

### 4.2 Lead Discovery & Enrichment

#### Company Enrichment (`enrichment/company.ts` — 525 lines)
- Website scraping with **Cheerio** for: meta descriptions, social profiles (LinkedIn/Twitter/Facebook/GitHub), keywords.
- **Technology detection**: 30+ patterns including React/Vue/Angular, WordPress/Shopify, Google Analytics/Mixpanel/Segment, HubSpot/Intercom, Stripe/PayPal, AWS/Cloudflare.
- 24-hour in-memory cache. Respects `robots.txt` and configurable rate limits (30 req/min default).

#### Lead Scoring (`enrichment/scoring.ts` — 474 lines)
- **4-dimensional scoring engine**:
  - **Firmographic** (40%): employee range multipliers, industry multipliers (SaaS 1.5×), technology bonuses (Salesforce +15), location bonuses.
  - **Engagement** (30%): email opened +5, clicked +15, replied +25, demo requested +50.
  - **Behavior** (20%): recent activity bonus, frequency multiplier, stage progress.
  - **Timing** (10%): 30-day decay, 7-day recency boost 1.3×.

### 4.3 CRM Pipeline (`crm/pipeline.ts` — 1,077 lines)

- **7-stage pipeline**: Prospect → Outreach → Engaged → Demo Scheduled → Proposal → Negotiation → Closed Won/Lost.
- Lead CRUD with full activity recording on stage transitions.
- Task management: call, email, meeting, follow_up, research.
- Complex query filtering, pipeline statistics, follow-up detection, rotten lead identification.

### 4.4 Drip Campaigns (`campaigns/drip-engine.ts` — 1,308 lines)

- Core campaign engine with **in-memory Maps + PostgreSQL write-through** via `CampaignRepository`.
- Composite-key dedup index for O(1) enrollment lookup.
- Secondary indexes by tenant and lead for fast queries.
- Periodic eviction of terminal enrollments (every 10 min).
- Cache hydration from database on startup.
- Step processing with conditional logic (open/click/reply triggers, time delays).

### 4.5 Multi-Stage Thompson Sampling (`campaigns/bandits.ts` — 612 lines)

- **3-stage optimization pipeline**:
  1. Subject line → optimizes for open rate
  2. Value proposition → optimizes for reply/meeting rate
  3. CTA → optimizes for click/intent rate
- Weighted soft updates: `positive_reply: α+2.5`, `spam: β+10.0`, `no_response: β+0.45`.
- **Hierarchical priors**: global → industry → arm level.
- **Catastrophic exploration cap**: 5% max for high-negative arms.
- Decay-toward-prior to prevent stale arms from dominating.
- Per-ICP bandit pools for segment-specific optimization.

### 4.6 Cadence Governor (`campaigns/cadence-governor.ts` — 413 lines)

- Protects leads from over-contacting: max 3 touches/7 days, 5 touches/14 days.
- **Stop signals**: reply, bounce, complaint, unsubscribe → immediate halt.
- Send window enforcement: 9 AM–4 PM local time.
- Timezone inference from country codes (20+ countries mapped).
- Database persistence of touch history.

### 4.7 Reply Classification (`inbox/sentinel.ts` — 572 lines)

- **9 reply categories**: `out_of_office`, `bounce`, `unsubscribe`, `not_interested`, `interested`, `meeting_request`, `question`, `objection`, `referral`.
- Pattern-based with priority ranking.
- Sentiment analysis with positive/negative word sets.
- Generates `SuggestedAction` based on classification result.

### 4.8 Demo Scheduling (`calendar/scheduler.ts` — 768 lines)

- Slot management with user preferences: available days/hours, buffer times, max bookings/day, minimum notice, max advance days.
- Write-through cache to PostgreSQL.
- Periodic eviction of expired slots (every 5 min).
- Defaults: 30-min slots, Mon–Fri 9–17, `Europe/Tallinn`, 24h min notice, 30-day max advance.

### 4.9 Promo Injection (`ads/injection.ts` — 709 lines)

- **Promo types**: banner, text_link, cta_button, signature, ps_line.
- **Placements**: header, footer, inline, sidebar.
- Targeting by industry, company size, location, lead stage.
- Day-of-week scheduling with time windows.
- Stats tracking: impressions, clicks, conversions.
- Database-backed with write-through cache and tenant secondary index.

### 4.10 Authentication (`middleware/auth.ts` — 351 lines)

- Control Plane auth with **HMAC-SHA256** session token verification (timing-safe comparison).
- API key validation.
- IP whitelisting in production.
- **Explicit customer key blocking**: rejects `am_live_*` and `am_test_*` prefixed keys to ensure only Control Plane access.

---

## 5. Testing App

**Dependencies**: `@playwright/test`, `vitest`, `@faker-js/faker`, `axe-core`, `axe-playwright`, `c8`, `clinic`, `fast-check`, `lighthouse`, `msw`, `k6`, `chalk`, `commander`, `zod`  
**Source files**: 50+ test files and infrastructure modules

### 5.1 Architecture Overview

The testing app is a **multi-layer test infrastructure** covering unit tests, E2E browser tests, visual regression, accessibility, chaos engineering, performance benchmarking, and load testing. It includes 35+ checklist test suites for systematic bug detection across 18 project phases.

### 5.2 Unit Testing (Vitest)

**Config** (`vitest.config.ts`):
- Node environment, **V8 coverage provider**.
- Coverage thresholds: **80% statements, 80% functions, 80% lines, 75% branches**.
- Excludes E2E, a11y, and visual tests from unit runs.
- Reporters: verbose, HTML, JSON.
- Type checking enabled via `tsc`.

**Setup** (`setup.ts`):
- Comprehensive **Redis mock** (all commands: `get`, `set`, `del`, `hget`, `hset`, `expire`, `ttl`, `zadd`, `zrange`, `pipeline`, etc.).
- Environment variables for test database configuration.
- Custom matchers: `toBeWithinRange(min, max)`, `toContainObject(expected)`.

### 5.3 E2E Testing (Playwright)

**Config** (`playwright.config.ts`):
- **6 browser projects**: setup (auth), Chromium, Firefox, WebKit, Mobile Chrome, Mobile Safari.
- 60s timeout; screenshot on failure; video on retry; trace on retry.
- Reporters: HTML, JSON, JUnit, list.
- Visual regression: `maxDiffPixels: 100`, `threshold: 0.3`.

**Fixtures** (`e2e/fixtures.ts`):
- Page Object Model: `LoginPage`, `DashboardPage`, `CampaignsPage`, `CampaignEditorPage`, `ContactsPage`, `SettingsPage`.
- Auto-authenticated page fixtures (`authenticatedPage`, `adminPage`).
- Test data generators: emails, campaign names, list names, subject lines.
- Test tags: `@smoke`, `@regression`, `@critical`, `@slow`, `@flaky`, `@mobile`, `@a11y`.

### 5.4 Visual Regression (`visual/visual.spec.ts` — 499 lines)

- **4 viewport sizes**: desktop (1920×1080), laptop (1440×900), tablet (768×1024), mobile (375×667).
- **2 themes**: light and dark.
- Tests for: login page (all viewports × themes), validation states, loading states, dashboard (metrics cards, charts), campaigns (empty state, list, editor, preview modal), contacts (list, add dialog, detail view), settings pages.
- Reduced motion emulation for consistent snapshots.

### 5.5 Accessibility Testing (`a11y/accessibility.spec.ts` — 493 lines)

- **axe-core** integration via `axe-playwright`.
- WCAG compliance levels: **WCAG 2.0 A/AA + WCAG 2.1 A/AA**.
- Tests 11 pages: Login, Sign Up, Forgot Password, Dashboard, Campaigns, Campaign Editor, Contacts, Contact Lists, Settings, Team Settings, Billing.
- **Keyboard navigation**: tab order, form submission with Enter, dashboard navigation, modal focus trapping, Escape to close.
- **Screen reader**: heading hierarchy (single h1), alt text verification, form labels, ARIA landmarks, live regions, error announcements, interactive element roles.
- **Color contrast**: text contrast ratios, focus indicators.

### 5.6 Chaos Engineering (`chaos/` — 2 files, ~1,200 lines)

**Experiment Types** (12 categories):
| Category | Description |
|----------|-------------|
| `network-latency` | Artificial latency injection via tc/toxiproxy |
| `network-partition` | Simulated iptables partition between services |
| `network-packet-loss` | Packet loss injection |
| `cpu-stress` | CPU contention simulation |
| `memory-stress` | Memory pressure testing |
| `disk-io-stress` | I/O saturation |
| `service-kill` | Process termination (SIGKILL/SIGTERM) |
| `dns-failure` | DNS resolution failures |
| `http-error` | Injected HTTP error responses |
| `database-failure` | PostgreSQL failure simulation |
| `cache-failure` | Redis failure simulation |
| `queue-failure` | Message queue failure |

**Runner** (`chaos/runner.ts` — 568 lines):
- Baseline health checks before experiments.
- Cooldown periods between experiments.
- Post-experiment health verification + auto-recovery.
- Assertion-based validation (latency p99 < 5s, error rate < 5%, availability ≥ 95%).
- Dry-run mode for safe testing.
- Alert webhook integration on failure.

### 5.7 Performance Testing (`performance/` — 2 files)

**Runner** (`performance/runner.ts` — 616 lines):
- Chromium-based via Playwright with CDP access.
- Metrics collected: **LCP, FID, CLS, TTFB, FCP, TTI, TBT, Speed Index**, DOM content loaded, resource count/size, JS heap size, DOM nodes.
- Network throttling presets: 4G, 3G, slow 3G, 2G.
- CPU throttling support.
- Warm-up iterations + configurable test iterations with variance calculation.

**Marketing Performance** (`performance/marketing-perf.ts`):
- Tests Home, Pricing, Features pages.
- Relaxed thresholds for local dev: LCP 4s, FCP 3s, TTFB 1.2s, CLS 0.2.

### 5.8 Load Testing (k6)

**Scenarios** (`load/scenarios.js` — 531 lines):
| Scenario | Pattern | Details |
|----------|---------|---------|
| **Smoke** | 1 VU, 1 min | Basic functionality validation |
| **Load** | Ramp 0→50 VUs | 2m ramp-up, 5m steady, 2m ramp-down |
| **Stress** | Ramp 0→300 VUs | Progressive escalation: 100→200→300 |
| **Spike** | 10→500 VUs | Two sudden spikes with 30s valleys |
| **Soak** | 50 VUs, 30 min | Extended run for memory leak detection |
| **Breakpoint** | 10→600 req/s | Ramp arrival rate to find system limits |

**Thresholds**:
- `http_req_duration`: p95 < 500ms, p99 < 1000ms
- `http_req_failed`: rate < 1%
- `login_duration`: p95 < 1000ms
- `campaign_create_duration`: p95 < 2000ms
- `contact_search_duration`: p95 < 500ms

**Custom metrics**: error rate, login duration, campaign creation time, contact search time, total API calls.

### 5.9 Checklist Tests

35 test suites covering phases 1–18 of systematic quality assurance:
- `phase1-foundations.test.ts` through `phase18-comprehensive.test.ts`
- `bug-detection.test.ts`, `deep-bug-detection.test.ts`
- `infrastructure-risk.test.ts`, `operational-risk.test.ts`, `runtime-risk.test.ts`
- `functional-runtime.test.ts`
- 7 batch fix verification suites (`batch2-fixes.test.ts` through `batch7-fixes.test.ts`)

---

## 6. AI App

**Port**: 3012  
**Dependencies**: `@huggingface/transformers`, `@anthropic-ai/sdk`, `natural`, `ml-matrix`, `hono`, `ioredis`, `pg`, `zod`  
**Source files**: ~20 TypeScript modules in `src/` (~8,000+ lines, excluding `training/`)

### 6.1 Architecture Overview

The AI app is an **AI Intelligence Suite** providing LLM inference via a **llama.cpp server sidecar** (OpenAI-compatible API), a unified conversational/command assistant, content generation, sentiment analysis, send-time optimization, predictive analytics, multi-armed bandits, and vector similarity search. It runs as a standalone Hono HTTP service with per-tenant rate limiting, request ID tracing, and model lifecycle management.

**Inference architecture (Option A — llama-server)**:
- `llama-server` (llama.cpp) runs as a sidecar on the VPS, serving **Qwen3.5-8B Q4_K_M GGUF**.
- Exposes an OpenAI-compatible `/v1/chat/completions` endpoint (SSE streaming supported).
- `InferenceEngine` in Node.js is a thin HTTP client — no native `.node` bindings required.
- Drop-in compatible with hosted models (GPT-4o, Claude, etc.) by changing `LLAMA_SERVER_URL`.
- Achieves ~15–30 tok/s on a standard VPS CPU vs ~3–8 tok/s with ONNX Runtime INT8.

### 6.2 Inference Engine (`inference/engine.ts`)

- **llama-server HTTP client** for local, privacy-preserving inference via OpenAI-compatible API.
- Default model: **Qwen3.5-8B** (GGUF Q4_K_M, served by llama.cpp).
- `SimpleTokenizer` retained for token counting / context length estimation (ChatML special tokens).
- Token encoding fix: FIX-500-447 — sorted special tokens by length descending for correct matching.
- Operations: `generate()` (text completion), `chat()` (multi-turn), `embed()` (embeddings), `embedBatch()`, `tokenize()`.
- **Loading lock** (AI-006 FIX): prevents concurrent model loads via promise deduplication.
- Cosine similarity with division-by-zero guard (FIX-500-383).
- Configured via `LLAMA_SERVER_URL` environment variable (default: `http://localhost:8080`).

### 6.3 Embeddings Service (`inference/embeddings.ts` — 653 lines)

- Model: **all-MiniLM-L6-v2** (384-dimensional vectors).
- In-memory vector store with **LRU eviction** (AI-004 FIX), default cap 10K entries.
- LRU tracking via monotonic counter + Map insertion order; counter overflow protection (FIX-500-389).
- **Min-heap search** (FIX-500-086): bounded heap keeps top-K results in O(n log k) instead of O(n log n).
- Batch embedding concurrency limit: 10 concurrent (FIX-500-393).
- Configurable: model path, dimensions, max length, normalization toggle, pooling strategy (mean/cls/max).
- `IterableIterator` return for `getAllVectors()` to avoid copying (FIX-500-388).

### 6.4 Model Lifecycle (`inference/lifecycle.ts` — 480 lines)

Three resilience components:

#### ModelLifecycleManager
- Full lifecycle: loading (with timeout) → warm-up iterations → periodic health checks → graceful shutdown.
- Configurable: warmup iterations, health check interval (30s default), max consecutive errors (5), load timeout (60s).
- Tracks metrics: request count, avg latency, error rate, tokens processed.

#### InferenceCircuitBreaker
- **3-state circuit breaker**: closed → open → half-open.
- Opens after 5 consecutive failures; resets after 30s timeout.
- Half-open allows limited requests; closes after 3 successes.

#### InferenceQueue
- Request queue with configurable max size (100) and timeout (30s).
- Cancellation flag tracking (FIX-500-385).
- Prevents overload when inference engine is under pressure.

### 6.5 Shared Engine Pattern (`inference/index.ts`)

- `getSharedEngine(config?)` factory — deduplicates `InferenceEngine` instances by config hash (model path + name + temperature).
- Prevents redundant model loads across services (FIX-500-099).

### 6.6 Unified Assistant (`assistant/unified.ts` — 1,553 lines)

Replaces separate chatbot and mailbot with a single intelligent assistant providing:
1. **Conversational Q&A** — email marketing expertise
2. **Natural-language commands** — campaigns, lists, contacts
3. **Semi-autonomous backend actions** — billing, account, diagnostics

#### Autonomous Mode
- **Off by default** — Control Plane owner must explicitly enable.
- Starts in **dry-run mode** for safety.
- Design principles (from Anthropic/OpenAI research): least privilege, human-in-the-loop, audit everything, confidence gating, rate limiting, dry-run first, sentiment escalation, transparency.

#### Risk Classification
| Level | Actions |
|-------|---------|
| **Safe** (read-only) | `get_billing_status`, `get_campaign_stats`, `check_api_status`, `account_health_check` |
| **Low** (data exposure) | `verify_domain`, `check_deliverability`, `export_data` |
| **Medium** (create/modify) | `create_campaign`, `create_list`, `create_ab_test`, `schedule_campaign` |
| **High** (high-impact) | `send_campaign`, `import_contacts`, `upgrade_plan` |
| **Critical** (irreversible) | `delete_campaign`, `cancel_subscription`, `process_refund`, `revoke_api_key` |

#### Security Features
- **Role-based access**: viewer → editor → admin → owner hierarchy.
- **Elevated auth actions**: billing changes, API key management, subscription changes require re-verification.
- Input sanitization and **PII redaction**.
- Sentiment-based escalation: negative sentiment score < -0.5 → human handoff.
- Session limits: max 1K sessions, 20 message history, 15-min pending action TTL.
- Proactive outreach templates for 10 trigger events (deliverability drop, bounce spike, quota approaching, etc.).

### 6.7 Action Router (`assistant/actions.ts` — 453 lines)

Routes assistant actions to backend services via **internal API calls**. Handler categories:
- **Campaigns**: create, send, schedule, pause, delete, stats, analyze, A/B test
- **Contacts**: add, remove, import
- **Lists**: create, delete, segment
- **Billing**: status, history, refund, upgrade, downgrade, cancel
- **Domains**: verify, deliverability, reputation, bounces, API keys, status, health
- **Data**: export, subject generation, template retrieval

All handlers support **dry-run mode** for safe testing. Service-to-service auth via Bearer token with configurable timeout (10s).

### 6.8 Content Generator (`content/generator.ts` — 715 lines)

- AI-powered content generation for 7 content types: `subject_line`, `preheader`, `email_body`, `cta`, `product_description`, `social_proof`, `ps_line`.
- **Subject line patterns** by category: urgency, curiosity, benefit, personalized, question, listicle, announcement.
- CTA patterns: action, urgency, benefit, soft.
- Fisher-Yates shuffle for variety (FIX-500-382 — replaces biased `sort(() => Math.random() - 0.5)`).
- Content analysis: readability score, spam score, word count, engagement predictions.
- Personalization token support (`{{firstName}}`, etc.).
- Optimal subject length: ≤60 characters.

### 6.9 Sentiment Analysis (`content/sentiment.ts` — 608 lines)

- **AFINN lexicon** (curated subset for email marketing, ~100 words, scores -5 to +5).
- **NRC emotion lexicon**: 8 emotions — joy, sadness, anger, fear, surprise, trust, anticipation, disgust.
- **Negation handling**: 25+ negation words; 3-word negation window; flips and reduces score by 0.75×.
- **Intensifiers** (very 1.5×, extremely 1.8×) and **diminishers** (somewhat 0.7×, barely 0.4×).
- Analysis modes: document-level, sentence-level, aspect-based.
- Custom lexicon extension via `addCustomWords()`.
- Spam score calculation for email content.
- Naive Bayes classifier for document-level backup.

### 6.10 Multi-Armed Bandits (`bandits/`)

#### Thompson Sampling (`thompson.ts` — 563 lines)
- **Beta–Bernoulli bandit** for binary outcomes (open/no-open, click/no-click).
- Beta distribution sampling via Gamma (Marsaglia–Tsang method) + Box-Muller normal.
- Numerical safety: validates α/β > 0, fallback on infinite loop (FIX-500-386), division-by-zero guards.
- Time-based decay: configurable decay factor (0.95) and window (7 days).
- Arm pruning by minimum pulls and max age (30 days).
- `getProbabilityBest()`: Monte Carlo simulation (1K samples, async with event-loop yields every 500 iterations — FIX-500-089).
- Significant winner detection at configurable threshold (default 0.95).
- Factory functions: `createSubjectLineOptimizer()`, `createSendTimeOptimizer()`, `createContentOptimizer()`.

#### UCB Bandit (`ucb.ts` — 490 lines)
- **UCB1 algorithm**: `mean + √(2 · ln(total_pulls) / arm_pulls)`.
- Deterministic (no randomness) — preferred when reproducibility matters.
- Also includes: **UCB-Tuned** (variance-aware) and **Epsilon-Greedy** baseline.

### 6.11 Predictive Analytics (`analytics/predictor.ts` — 1,170 lines)

- **7 prediction types**: open rate, click rate, conversion rate, unsubscribe rate, churn risk, revenue, best time.
- Linear regression with baseline coefficients refined from historical data.
- Factor analysis: send time (hour-of-day curve), day-of-week, subject length, list size, personalization.
- **Audience segmentation** (6 strategies): engagement, recency, frequency, RFM, lifecycle, behavioral.
- **A/B test analysis**: z-test for statistical significance, lift calculation, sample size recommendations.
- Memory caps: 100K historical records, 50K subscribers (FIX-500-398).
- Model update skipped when insufficient data (FIX-500-397).
- Coefficient cloning before mutation (AI-003 FIX).

### 6.12 Send-Time Optimization (`sto/`)

#### STOOptimizer (`optimizer.ts` — 890 lines)
- Engagement pattern analysis per subscriber: preferred hours (top 3), preferred days (top 2), avg response time.
- Per-list heatmaps: 7×24 grid of engagement scores with peak hours/days.
- Engagement prediction for specific send times based on similar historical time slots.
- **Redis persistence**: sorted sets with timestamp scores, auto-expire, rank-based trimming.
- Memory caps: 10K patterns per subscriber, 50K subscribers.
- Pipeline-based Redis cleanup (FIX-500-396).

#### STOCache (`cache.ts` — 445 lines)
- **Redis-backed persistent cache** for engagement patterns and computed recommendations.
- Batch operations via Redis pipelines for efficiency.
- Configurable TTLs: patterns 30 days, recommendations 24 hours.
- Per-subscriber and per-list pattern limits.

### 6.13 HTTP API Endpoints

The AI service exposes **18 HTTP endpoints** via Hono:

| Route | Method | Description |
|-------|--------|-------------|
| `/health` | GET | Health check with readiness status |
| `/ready` | GET | Readiness probe |
| `/api/inference/generate` | POST | Text completion |
| `/api/inference/chat` | POST | Multi-turn chat |
| `/api/inference/embed` | POST | Single text embedding |
| `/api/inference/embed/batch` | POST | Batch embeddings (max 100) |
| `/api/inference/tokenize` | POST | Token counting |
| `/api/inference/model` | GET | Model info |
| `/api/assistant/session` | POST | Start session |
| `/api/assistant/message` | POST | Send message (chat + commands + actions) |
| `/api/assistant/confirm/:id` | POST | Confirm pending action |
| `/api/assistant/intent` | POST | Quick intent detection |
| `/api/assistant/actions` | GET | List available actions |
| `/api/sto/optimize` | POST | Get optimal send times |
| `/api/content/generate` | POST | Generate content |
| `/api/content/subject-lines` | POST | Generate subject lines |
| `/api/analytics/predict` | POST | Make predictions |
| `/api/analytics/segment` | POST | Segment audience |
| `/api/analytics/ab-test` | POST | Analyze A/B test |
| `/api/vectors/search` | POST | Semantic vector search |

### 6.14 Infrastructure Features

- **Per-tenant rate limiting**: 60 req/min per tenant, in-memory (production: Redis-backed).
- **Request ID propagation**: X-Request-ID header for distributed tracing.
- **Body size limit**: 1 MB max (FIX-500-394).
- **Graceful shutdown**: signal handlers + cleanup callbacks.
- **Degraded mode**: if warm-up fails, starts with `initFailed = true` and `/health` returns 503.

---

## 7. Cross-Cutting Observations

### 7.1 Security Fixes (FIX-500-xxx Series)

The codebase contains extensive security hardening documented via `FIX-500-*` codes:

| Code | Fix Description |
|------|-----------------|
| FIX-500-017 | Try-catch on `JSON.parse` for AI_MODELS env variable |
| FIX-500-032 | JavaScript URL injection prevention in ICS calendar links |
| FIX-500-085 | `startsWith` with offset instead of `slice()` per iteration (perf) |
| FIX-500-086 | Bounded min-heap for vector search instead of full sort |
| FIX-500-088 | Map delete+re-insert for correct LRU ordering |
| FIX-500-089 | Async Monte Carlo with event-loop yields to prevent blocking |
| FIX-500-099 | Shared InferenceEngine instances to prevent redundant model loads |
| FIX-500-130 | Documented missing RedisPatternStore module |
| FIX-500-131 | Canonical singleton for SentimentAnalyzer |
| FIX-500-190 | Robust ESM/CJS entry point detection |
| FIX-500-232 | `.unref()` on intervals to allow graceful process exit |
| FIX-500-382 | Fisher-Yates shuffle replacing biased `sort(random)` |
| FIX-500-383 | Division-by-zero guard in cosine similarity |
| FIX-500-385 | Cancellation flag tracking in InferenceQueue |
| FIX-500-386 | Max iteration cap in Gamma distribution sampler |
| FIX-500-388 | IterableIterator return to avoid copying vector store |
| FIX-500-389 | Counter overflow protection in LRU access tracking |
| FIX-500-392 | Unhealthy status reporting when initialization fails |
| FIX-500-393 | Batch embedding concurrency limit (10) |
| FIX-500-394 | Body size limit (1 MB) to prevent DoS |
| FIX-500-395 | Fixed double-s typo in `storePatternsBatch` |
| FIX-500-396 | Pipeline-based Redis key deletion for efficiency |
| FIX-500-397 | Don't update model timestamp when training is skipped |
| FIX-500-398 | Hard caps on in-memory data arrays to prevent unbounded growth |
| FIX-500-408 | IP/CIDR validation in delivery service |
| FIX-500-447 | Sort special tokens by length descending for correct matching |
| C-095 | 50K cache cap on bot detection and reply tracking |
| AI-003 | Clone coefficients before mutation |
| AI-004 | LRU eviction for vector store |
| AI-006 | Loading lock to prevent concurrent model loads |
| AI-007 | Per-tenant rate limiting |
| AI-008/009 | Request ID propagation and error tracing |

### 7.2 Shared Patterns

- **Framework**: All HTTP services use **Hono** with consistent middleware (CORS, logger, timing, compress, secureHeaders).
- **Validation**: **Zod** schemas for all configuration and request bodies.
- **Storage**: PostgreSQL for persistence, Redis for caching/locking/pub-sub.
- **Memory management**: Hard caps on all in-memory collections (50K cache entries, 100K historical records, 10K vector store).
- **Resilience**: Circuit breakers, exponential backoff, graceful degradation, distributed locking.
- **Observability**: Structured JSON logging, request IDs, health endpoints, metrics tracking.

### 7.3 Algorithm Summary

| Algorithm | App | Use Case |
|-----------|-----|----------|
| Thompson Sampling (Beta–Bernoulli) | Analytics, Sales-Autopilot, AI | Template/subject/CTA optimization |
| UCB1 / UCB-Tuned | AI | Deterministic A/B testing |
| Epsilon-Greedy | AI | Baseline exploration-exploitation |
| Bayesian Averaging | Analytics | Send-time optimization |
| AFINN + NRC Lexicon | AI | Sentiment + emotion analysis |
| RFM Scoring | Analytics | Churn prediction |
| Trust Equation | Analytics | Engagement trust scoring |
| Linear Regression | AI | Open/click/conversion rate prediction |
| Z-test | AI | A/B test statistical significance |
| Cosine Similarity + Min-Heap | AI | Vector similarity search |
| Fisher-Yates Shuffle | AI | Unbiased content pattern selection |
| Marsaglia-Tsang + Box-Muller | AI | Gamma/Normal distribution sampling |

### 7.4 Port Allocation

| Port | Service |
|------|---------|
| 3000 | Customer Console (web) |
| 3001 | Customer API |
| 3010 | Sales Autopilot (Control Plane) |
| 3011 | Compliance |
| 3012 | AI Intelligence Suite |
| 3020 | Control Plane UI |
| 4200 | DevEx Portal |
| 4600 | Edge Cases |
