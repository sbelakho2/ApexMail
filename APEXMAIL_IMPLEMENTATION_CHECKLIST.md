# ApexMail — Implementation Checklist & Verification Standard

**Owner:** Bel Consulting OÜ  

**Domain:** [apexmail.ee](https://apexmail.ee)  

**Reference System:** [ApexMediation](https://apexmediation.ee) (Visual cues)  

**Version:** v11-Complete (Full Enterprise + Inbound + Templates + Validation + Engagement)  

**Philosophy:** Core deliverability runs with zero paid SaaS required; integrations are optional, adapter-based, and replaceable.

---

## 🛑 Critical Success Factors (Non-Negotiables)

- [ ] **No Paid SaaS Dependencies (Core Mailplane):** The core send pipeline (API → queue → MTA → tracking endpoints → suppression) must run entirely on commodity hardware/Linux with 0 paid API keys.
  - **Evidence Required:** Runbook proving `CORE_ONLY=true` deploy works end-to-end (send, bounce, suppress, unsubscribe, tracking) with 0 paid integrations configured.

- [ ] **Optional Integrations Must Be Pluggable:** Any non-core integration (billing, enterprise IdP, chat tools, lead enrichment, etc.) must be behind an adapter and fully disable-able.
  - **Billing Policy:** If billing is enabled, it is **Stripe-only** (single provider, no alternative payment rails).
  - **Evidence Required:** Core tests pass with billing disabled; billing E2E passes using Stripe test mode + webhook signature verification.

- [ ] **Crisis-Proof Operations:** No empty DBs, no log explosions, no silent data loss.
  - **Evidence Required:** "Chaos Suite" pass report showing recovery from DB loss, disk saturation, and key rotation.

- [ ] **Data Sovereignty & Verification:** All critical events must be cryptographically signed and verifiable (Pattern: ApexMediation Signed Logs).
  - **Evidence Required:** Verification tool able to validate the cryptographic chain of a daily log snapshot.

- [ ] **CAN-SPAM / CASL / ePrivacy Baseline:** Physical address required, one-click unsubscribe enforced, transactional vs marketing distinction.
  - **Evidence Required:** Template linter rejecting emails without `List-Unsubscribe-Post` header or missing physical address.

- [ ] **Transactional vs Marketing Classification:** API requires explicit `type: transactional | marketing` flag. Marketing emails MUST have unsubscribe; transactional emails exempt but audited for abuse.
  - **Evidence Required:** Send with `type: marketing` and no unsubscribe -> 400 "Marketing emails require unsubscribe"; Send `type: transactional` for promotional content -> Flagged in abuse review queue.

- [ ] **Bounce & Suppression Pipeline:** Hard bounces immediately suppressed; no repeat sends to dead addresses.
  - **Evidence Required:** Integration test showing suppressed address returns `400 Recipient Suppressed` on second send attempt.

---

## Phase 1: Foundations (Repo, Standards, Determinism)

*Goal: Create a codebase and process that cannot drift into an unmaintainable state.*

### 1.1 Repository & Structure

- [ ] **Establish Monorepo Structure**
  - **Implementation:** Create distinct boundaries: `/api`, `/worker`, `/mta` (Postfix config), `/web` (Next.js 14 App Router), `/ops`, `/sales-autopilot`, `/docs`.

  - **Evidence Required:** Directory tree listing matching architecture diagram.

- [ ] **Define Internal Dependency Policy**
  - **Implementation:** "Thin Interface" pattern. Wrap all 3rd party libs (logging, storage, crypto) in internal interfaces.

  - **Evidence Required:** Code review of `lib/` directory showing wrappers for all external dependencies.

- [ ] **Implement Toolchain Pinning**
  - **Implementation:** Create `tools/bootstrap.sh` to install exact versions of Node, Go, Rust, etc., to `./.toolchain/`. Store checksums.

  - **Evidence Required:** Execution log of `./tools/bootstrap.sh` on a clean, network-isolated container.

### 1.2 Deterministic Build Pipeline

- [ ] **Create Self-Hosted CI Runner**
  - **Implementation:** standard Linux runner (e.g., Drone/Woodpecker or self-hosted GitHub Actions runner) with reproducible containers.

  - **Evidence Required:** Diff capability showing two builds from the same commit produce identical binary hashes.

- [ ] **Implement SBOM Generation**
  - **Implementation:** Integrate CycloneDX generation in the build process.

  - **Evidence Required:** Generated `sbom.json` for the core binary.

### 1.3 Documentation & Architecture

- [ ] **Create Architecture Decision Records (ADR) System**
  - **Implementation:** `/docs/adr/XXXX-title.md` structure.

  - **Evidence Required:** ADR 001 (Database Choice), ADR 002 (MTA Stack), ADR 003 (Sales Autopilot) committed.

- [ ] **Implement "Docs as Code" System (Shared Design)**
  - **Implementation:** Static site generator building from `/docs`. Must use the same Tailwind config and Design tokens as the main app for seamless transition.
  - **Evidence Required:** User navigates from App to Docs -> Header and Fonts remain identical (no visual context switch).

### 1.4 Hard Quality Gates

- [ ] **Implement Ghost Function Detection**
  - **Implementation:** `tsc --noEmit`, eslint `no-unused-vars`, dead code elimination analysis.

  - **Evidence Required:** CI failure log when an unused export is introduced.

- [ ] **Implement Runtime Route Mapping**
  - **Implementation:** Test script that enumerates all API endpoints and verifies handlers exist (not 404).

  - **Evidence Required:** Automated test report listing all 100% mapped routes.

### 1.5 The "Bus Factor" Protocol (Owner Security)

- [ ] **Implement "Dead Man's Switch"**
  - **Implementation:** If Owner doesn't authenticate for 30 days, system enters "Read-Only/Preservation" mode and emails contingency contact.

  - **Evidence Required:** Time-travel test: Set last_login = -31d -> System changes state -> Email sent.

- [ ] **Implement "Break Glass" Access Logging**
  - **Implementation:** Admin SSH/DB access requires specific generic-user + MFAToken. All sessions recorded `asciinema` style.

  - **Evidence Required:** Playback of a "Break Glass" session from the audit log.

### 1.6 The "Zero-Day" Active Defense (Foresight)

- [ ] **Implement Database Honeytokens**
  - **Implementation:** Insert fake rows (e.g., `user_id="admin-alert"`) that trigger immediate alerts via self-hosted alerting (Prometheus Alertmanager → email) if `SELECT`ed.

  - **Evidence Required:** `SELECT * FROM users` -> Alarm fires within 10 seconds.

- [ ] **Implement Codebase Canary Tokens**
  - **Implementation:** Seed unique canary strings (not matching real cloud key formats) into controlled files/config and monitor logs/egress for any appearance; alert via self-hosted alerting on detection.

  - **Evidence Required:** Canary string placed in `ops/canary_tokens.txt` -> simulated leak (emit canary to logs) -> alert received within 10 seconds.

---

## Phase 2: Data Layer (Postgres, Migrations, Safety)

*Goal: Never-Empty-DB guarantees, automated safety.*

### 2.1 Database Setup & Migrations

- [ ] **Configure Connection Pooling**
  - **Implementation:** PgBouncer in transaction mode. Max 100 connections to Postgres. Pool size per service: API=20, Worker=30, MTA=10. Connection timeout: 5s. Idle timeout: 10 minutes.

  - **Evidence Required:** Under load: `pg_stat_activity` shows ≤100 connections; Service logs show pool exhaustion warning at configured limit; Idle connections released after 10 minutes.

- [ ] **Build Custom Migration Engine**
  - **Implementation:** Tool in `/tools/migrate/` supporting: Advisory Locks, Checksums, Dry-Run, Audit Table.

  - **Evidence Required:** Log output showing a successful migration apply with locking and audit record creation.

- [ ] **Implement Startup Schema Gate**
  - **Implementation:** API service must calculate a "Schema Fingerprint" (tables + columns + indexes) at startup. If mismatch -> 503.

  - **Evidence Required:** Integration test showing API refusing to start when a required specific index is missing.

### 2.2 Data Retention & Partitioning

- [ ] **Configure Postgres Partitioning**
  - **Implementation:** `CREATE TABLE ... PARTITION BY RANGE` for `event_log_hot`.

  - **Evidence Required:** SQL Inspection showing active partitions for the current date range.

- [ ] **Implement Postgres Temporal Tables (System-Versioned)**
  - **Implementation:** Use `pg_temporal` or history tables triggers for critical entities (`users`, `domains`, `api_keys`).

  - **Evidence Required:** Update user row -> `SELECT * FROM users_history` shows previous state with timestamp range.

- [ ] **Implement Rolling Window Policy**
  - **Implementation:** Automated job to detach old partitions after 90 days (move to Phase 5 cold store).

  - **Evidence Required:** Test confirming data older than retention policy is no longer in the *hot* table.

### 2.3 Disaster Recovery

- [ ] **Automate Backup & PITR**
  - **Implementation:** `pg_basebackup` + WAL archiving to mounted volume + offsite copy via `restic`.

  - **Evidence Required:** Log from a successful restore operation to a staging DB including duration metrics.

- [ ] **Implement "Never-Empty" Tests**
  - **Implementation:** Integration test: Boot clean DB -> Apply Migrations -> Verify Fingerprint -> Run Login.

  - **Evidence Required:** Pass result of the `test_boot_from_scratch` suite.

---

## Phase 3: Core Email Data Plane (API, Idempotency, Queues)

*Goal: Reliable high-volume ingestion without external brokers.*

### 3.1 Idempotency & Ingestion

- [ ] **Implement Idempotency Key Middleware**
  - **Implementation:** `outbox_messages` table with unique constraint on `(customer_id, idempotency_key)`.

  - **Evidence Required:** "Torture Test" result: 10k concurrent requests with same key result in exactly 1 write and 9999 "202 Accepted" replays.

- [ ] **Implement Transactional Outbox**
  - **Implementation:** API writes payload + recipients to DB in ONE transaction. Generate RFC 5322-compliant `Message-ID` header (`<{uuid}@apexmail.ee>`) at ingestion time for threading/deduplication.

  - **Evidence Required:** Code review confirming no side effects (like queue pushes) happen outside the DB transaction; Received email shows valid `Message-ID` header matching UUID format.

### 3.2 Internal Worker Queue

- [ ] **Implement Postgres-Backed Queue Leasing**
  - **Implementation:** `SELECT ... FOR UPDATE SKIP LOCKED` pattern for worker tasks. Visibility timeout: 5 minutes. If worker crashes, job auto-released after timeout. Dead-letter after 3 failed attempts.

  - **Evidence Required:** Load test metrics showing high throughput without lock contention errors; Kill worker mid-task -> Job reappears after 5 minutes -> Picked up by another worker; Job fails 3 times -> Moved to dead-letter queue.

- [ ] **Implement Backpressure Mechanisms**
  - **Implementation:** Per-tenant rate limiters; Global concurrency caps returning `429 Too Many Requests`.
  - **Evidence Required:** Graph showing API returning 429s precisely when limits are exceeded.

- [ ] **Implement Fair Queue Scheduling (Anti-Starvation)**
  - **Implementation:** Weighted fair queuing across tenants. No single tenant can consume >30% of worker capacity. Round-robin with priority boost for low-volume tenants.
  - **Evidence Required:** Large tenant floods queue -> Small tenant's emails still processed within SLA; Latency graph shows bounded delay for all tenants.

### 3.2.1 Priority Traffic Shaping

- [ ] **Implement "Fast Lane" Pattern Classification**
  - **Implementation:** Middleware detecting patterns (Subject: "Your code", "Reset"; Headers `X-Priority: high`) -> Routes to `queue_high_priority`.

  - **Evidence Required:** Inject 10k bulk + 1 transactional -> Log timestamp shows transaction processed before bulk completion.

### 3.3 Recipient Validation & Hygiene

- [ ] **Implement Real-Time Email Validation**
  - **Implementation:** Syntax check (RFC 5322), MX record lookup, disposable email detection (local blocklist), role-based filtering (`info@`, `admin@`).

  - **Evidence Required:** `test@mailinator.com` -> Rejected as disposable; `invalid@@bad` -> Rejected as syntax error.

- [ ] **Implement Reply-To Domain Validation**
  - **Implementation:** `reply_to` address must use a verified domain OR match the `from` domain. Prevent spoofing unrelated domains. Warn if reply-to domain has no MX record.

  - **Evidence Required:** Reply-to with unverified domain -> 400 "Reply-To domain not verified"; Reply-to matching from domain -> Allowed; Reply-to with no MX -> Warning logged but allowed.

- [ ] **Implement "Risky Address" Scoring**
  - **Implementation:** Score recipients based on: domain age, MX quality, past bounce history. Block or warn above threshold.
  - **Evidence Required:** Send to known spamtrap domain -> API returns 400 with "High-risk recipient" warning.

- [ ] **Implement Recipient Deduplication**
  - **Implementation:** Within a single API request, dedupe recipients by normalized email (lowercase, trim). Return warning if duplicates detected. Configurable: `dedupe: true` (default) or `dedupe: false`.
  - **Evidence Required:** Send to `["a@b.com", "A@B.com", "a@b.com "]` -> Single email sent; Response includes `"duplicates_removed": 2`.

- [ ] **Implement List Hygiene Service**
  - **Implementation:** Bulk validation endpoint `POST /v1/validate/list`. Returns clean/risky/invalid counts + downloadable results.

  - **Evidence Required:** Upload 10K addresses -> Report shows 8.5K clean, 1K risky, 500 invalid in <30 seconds.

### 3.4 Template & Rendering Engine

- [ ] **Implement Template Storage & Versioning**
  - **Implementation:** Templates stored in DB with version history. Rollback capability. Variables schema validation.
  - **Evidence Required:** Create template v1 -> Update to v2 -> Rollback to v1 -> Email renders with v1 content.

- [ ] **Implement Template Inheritance (Layouts)**
  - **Implementation:** Support `extends: base_layout` to inherit header/footer from parent template. Child templates override `{{block content}}`. Changes to base propagate to all children.
  - **Evidence Required:** Update footer in base template -> All child templates reflect change immediately; Child can override specific block without affecting siblings.

- [ ] **Implement MJML/HTML Rendering Pipeline**
  - **Implementation:** Accept MJML or raw HTML. Server-side render to inline-CSS HTML for max compatibility. Support `@media (prefers-color-scheme: dark)` styles for dark mode email clients.
  - **Evidence Required:** MJML input -> Output renders identically in Gmail, Outlook, Apple Mail (screenshot comparison); Dark mode toggle in Apple Mail -> Email switches to dark palette.

- [ ] **Implement Smart Plain-Text Generation**
  - **Implementation:** Auto-generate optimized `text/plain` part from HTML if not provided. Strip tables, format links as `[Text](Url)`, preserve hierarchy.
  - **Evidence Required:** Send HTML-only email -> Received payload contains readable plain-text alternative.

- [ ] **Implement Dynamic Variable Injection**
  - **Implementation:** Handlebars-style `{{user.name}}` with strict mode (fail on missing vars, not silent empty).

  - **Evidence Required:** Send with missing `user.name` -> API returns 400 "Missing required variable".

- [ ] **Implement Template Linting & Spam Check**
  - **Implementation:** Pre-send validator for broken links, missing unsubscribe, and SpamAssassin scoring.

  - **Evidence Required:** Template with missing unsubscribe -> Blocked with explicit error reason.

- [ ] **Implement "Preview & Test Send"**
  - **Implementation:** API endpoint to render template with sample data and send to test address without metering.

  - **Evidence Required:** Preview call -> Returns rendered HTML + sends to sandbox inbox.

- [ ] **Implement Scheduled Send**
  - **Implementation:** `send_at` parameter (ISO 8601 timestamp, max 7 days in future). Store in `scheduled_messages` table. Worker picks up at scheduled time ± 60 seconds. Cancellation endpoint `DELETE /v1/messages/{id}/schedule`.

  - **Evidence Required:** Schedule email for +1 hour -> Message not sent immediately; After 1 hour -> Message delivered; Cancel before send_at -> Message never sent.

- [ ] **Implement A/B Testing Framework**
  - **Implementation:** Split traffic by percentage. Track variant performance (open/click/convert). Auto-promote winner after statistical significance. Minimum sample size enforced (default: 100 per variant) before winner declaration.

  - **Evidence Required:** Create A/B test (Subject A vs B, 50/50 split) -> After 1000 sends -> Dashboard shows "Variant B: +12% open rate, p<0.05"; Test with only 50 sends -> Status shows "Insufficient data" (no winner declared).

- [ ] **Implement Template Analytics**
  - **Implementation:** Per-template metrics: sends, opens, clicks, bounces, unsubscribes. Trend over time.

  - **Evidence Required:** API `GET /v1/templates/{id}/stats` returns JSON with `opens`, `clicks`, `bounces` counts; E2E test: send 100 emails -> open 50 -> stats return `open_rate: 50%`.

---

## Phase 4: MTA Stack (Self-Hosted, Deliverability)

*Goal: Deliver at scale with complete control. Extreme foresight for reputation.*

### 4.1 MTA Architecture

- [ ] **Deploy Postfix Outbound Cluster**
  - **Implementation:** Custom Postfix config for high-volume outbound; Per-IP queues; TLS 1.2+ enforcement (`smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1`); Opportunistic DANE support.

  - **Evidence Required:** `postconf -n` dump showing adjusted `default_destination_concurrency_limit` and `smtp_connection_cache_on_demand`; SSL Labs-style check confirms TLS 1.2+ only; Connection attempt with TLS 1.0 rejected.

- [ ] **Implement Smart IP Pooling**
  - **Implementation:**  Logic to route "Growth" tenants to shared IPs `pool_shared` and "Scale" tenants to `pool_dedicated`.
  - **Evidence Required:** Headers showing different source IPs for different tiers.

- [ ] **Implement IPv6 Dual-Stack Sending**
  - **Implementation:** Configure Postfix for IPv4/IPv6 dual-stack. Prefer IPv6 when destination MX supports it. Fall back to IPv4 on connection failure.
  - **Evidence Required:** Delivery to Gmail shows IPv6 source in `Received` header; IPv6-only destination delivers successfully.

### 4.1.1 Domain Verification & Onboarding

- [ ] **Implement Tenant Onboarding Wizard**
  - **Implementation:** Step-by-step checklist: 1) Verify domain, 2) Add DKIM/SPF/DMARC, 3) Send test email, 4) Configure webhooks, 5) Enable production mode. Progress persisted. "Skip" allowed but shows warnings.

  - **Evidence Required:** New tenant -> Dashboard shows "Setup: 2/5 Complete" -> Complete all steps -> Banner removed; Skip domain verification -> Warning badge persists on dashboard.

- [ ] **Implement Domain Ownership Verification**
  - **Implementation:** Generate unique TXT record `apexmail-verify=abc123`. Poll DNS until verified or timeout (72 hours max). Auto-expire unverified domains after timeout with email notification.

  - **Evidence Required:** Add domain -> System shows "Pending" -> Add TXT record -> Status changes to "Verified" within 5 minutes; Domain not verified after 72h -> Status changes to "Expired", email sent, domain removed from active list.

- [ ] **Implement Automated DNS Health Checks**
  - **Implementation:** Continuous monitoring of SPF, DKIM, DMARC, MX records. Alert on misconfiguration.

  - **Evidence Required:** Remove DKIM record -> Dashboard shows "DKIM: ❌ Missing" within 1 hour -> Alert email sent.

- [ ] **Implement "DNS Wizard" Setup Guide**
  - **Implementation:** Copy-paste ready DNS records for all major registrars (Cloudflare, GoDaddy, Namecheap).

  - **Evidence Required:** Screenshot of setup wizard showing provider-specific instructions.

### 4.2 Authentication & Compliance

- [ ] **Implement Automated DKIM Rotation**
  - **Implementation:** Weekly automated rotation of DKIM keys; old keys valid for 7 days grace period. Selector naming convention: `apexmail{YYYYWW}` (e.g., `apexmail202605`) for predictable rotation coordination.

  - **Evidence Required:** CI test verifying both current and previous private keys can sign messages; DNS shows both `apexmail202605._domainkey` and `apexmail202604._domainkey` during grace period.

- [ ] **Implement DMARC Policy & Reporting (RUA/RUF)**
  - **Implementation:** Provide guided DMARC record creation with report ingestion pipeline and alignment checks.

  - **Evidence Required:** DMARC aggregate report parsed -> Dashboard shows pass/fail by source.

- [ ] **Implement Feedback Loop (FBL) Processor**
  - **Implementation:** Ingest ARF (Abuse Reporting Format) emails; auto-unsubscribe complainers.

  - **Evidence Required:** Integration test: Pipe sample ARF email -> Confirm recipient added to `suppression_list`.

### 4.2.1 Advanced Email Authentication (Differentiators)

- [ ] **Implement MTA-STS (Strict Transport Security)**
  - **Implementation:** Host `/.well-known/mta-sts.txt` policy file; add `_mta-sts` DNS TXT record. Enforce TLS on inbound.

  - **Evidence Required:** `mta-sts-validator` passing for all customer domains; SMTP connection logs showing rejected non-TLS connections.

- [ ] **Implement TLS-RPT (SMTP TLS Reporting, RFC 8460)**
  - **Implementation:** Publish `_smtp._tls` TXT record and host TLS-RPT ingest endpoint. Parse reports and surface failures by receiving domain.

  - **Evidence Required:** Inject a simulated TLS failure -> TLS-RPT report ingested -> Dashboard shows impacted domains and error category.

- [ ] **Implement BIMI (Brand Indicators)**
  - **Implementation:** Support customer BIMI records; validate SVG logos; cache VMC certificates.

  - **Evidence Required:** Test email to Gmail showing customer logo in inbox (screenshot).

- [ ] **Implement ARC (Authenticated Received Chain)**
  - **Implementation:** Sign outbound with `ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results` headers.

  - **Evidence Required:** ARC validation tool confirming valid chain on forwarded message.

- [ ] **Implement List-Unsubscribe-Post (RFC 8058)**
  - **Implementation:** All marketing emails include `List-Unsubscribe: <mailto:...>, <https://...>` AND `List-Unsubscribe-Post: List-Unsubscribe=One-Click`.

  - **Evidence Required:** Gmail/Yahoo showing "Unsubscribe" button in header; one-click triggers instant suppression.

### 4.3 Warm-Up & Reputation Management

*Dependency: Requires at least one verified domain (Phase 4.1.1) before warm-up can begin.*

- [ ] **Implement Automated Warm-Up Scheduler**
  - **Implementation:** Geometric progression logic (e.g., Day 1: 50, Day 2: 100, Day 3: 200). Auto-throttle if bounces > 1%.
  - **Refinement:** "Pause & Heal" Logic. If error rate > 3%, pause for 24h, then revert to *previous* day's volume. Do not simply maintain current volume.
  - **Evidence Required:** Simulator run: Day 5 (error spike) -> Day 6 (Paused) -> Day 7 (Resumes at Day 4 volume).

- [ ] **Implement "Pre-Flight" Reputation Checks**
  - **Implementation:** Check destination against local cache of RBLs (Real-time Blackhole Lists) before attempting delivery.

  - **Evidence Required:** Log entry showing "Deferred: Target IP listed on Spamhaus" (simulated).

- [ ] **Implement IP Reputation Dashboard**
  - **Implementation:** (Optional Integration) Fetch data from Google Postmaster Tools API and Microsoft SNDS when credentials configured. Gracefully degrade to "No external data" when disabled. Display reputation score per IP.
  - **Evidence Required:** With credentials: Dashboard shows reputation trend graph per IP. Without credentials: Dashboard shows "External reputation data not configured" with internal bounce/complaint rate only.

- [ ] **Implement Seed List Testing**
  - **Implementation:** Maintain test accounts at major ISPs (Gmail, Outlook, Yahoo). Before production campaign, send to seed list and verify inbox placement. Surface "Inbox/Spam/Missing" results.
  - **Evidence Required:** New campaign -> "Test Deliverability" button -> Results show "Gmail: Inbox, Outlook: Spam, Yahoo: Inbox" within 5 minutes.

### 4.4 Bounce Classification & Suppression (Critical)

- [ ] **Implement VERP (Variable Envelope Return Path)**
  - **Implementation:** Encode recipient in return-path: `bounce+user=domain.com@apexmail.ee` for tracking.

  - **Evidence Required:** DSN received -> Original recipient correctly extracted and logged.

- [ ] **Implement Bounce Classification Engine**
  - **Implementation:** Regex + ML classifier for: Hard (550 user unknown), Soft (450 mailbox busy), Block (5.7.1 policy), Auto-Reply (OOO).
  - **Evidence Required:** Classification accuracy report: >98% on 1000-sample bounce corpus.

- [ ] **Implement Delayed Bounce Correlation**
  - **Implementation:** Handle DSNs arriving hours/days after send. Correlate via `Message-ID` or VERP. Update message status retroactively. Alert if delayed bounce rate spikes.
  - **Evidence Required:** Send email -> DSN arrives 6 hours later -> Message status updated to "bounced"; Dashboard shows "Delayed Bounce" indicator.

- [ ] **Implement Suppression List Sync**
  - **Implementation:** Real-time suppression propagation to all MTA nodes via Redis pub/sub.

  - **Evidence Required:** Latency test: Suppress address -> Rejection on all nodes < 100ms.

- [ ] **Implement Suppression List Import/Export**
  - **Implementation:** Bulk import via CSV (`POST /v1/suppressions/import`). Bulk export for migration. Support categories: hard_bounce, complaint, unsubscribe, manual. Dedupe on import.
  - **Evidence Required:** Import 10K addresses -> All appear in suppression list; Re-import same file -> No duplicates; Export -> CSV matches imported data.

- [ ] **Implement Category-Based Unsubscribe**
  - **Implementation:** Support unsubscribe categories (e.g., `marketing`, `product_updates`, `newsletters`). Recipients can opt-out of specific categories while remaining subscribed to others.
  - **Evidence Required:** Unsubscribe from "newsletters" -> Still receives "product_updates"; Full unsubscribe -> All categories suppressed.

- [ ] **Implement Hosted Preference Center**
  - **Implementation:** White-label hosted page (`preferences.apexmail.ee/{tenant}/{token}`) where recipients manage their subscription categories. Supports custom tracking domains.
  - **Evidence Required:** Recipient clicks "Manage Preferences" -> Sees category checkboxes -> Saves -> Database reflects choices immediately.

- [ ] **Implement Per-Domain Rate Limiting**
  - **Implementation:** Adaptive limits per MX (Gmail: 100/min, Outlook: 50/min). Backoff on 4XX responses.

  - **Evidence Required:** Metrics showing automatic throttle-down when Gmail returns 421.

- [ ] **Capture Raw SMTP Responses**
  - **Implementation:** Store raw `smtp_reply` text and enhanced status codes for each delivery attempt.

  - **Evidence Required:** Delivery log shows full 5XX/4XX response for a blocked send.

- [ ] **Expose Deliverability Diagnostics UI**
  - **Implementation:** Customer view with last 100 SMTP responses, top block reasons, and remediation hints.

  - **Evidence Required:** Screenshot showing "Top Block Reason: 5.7.1 Policy" with remediation checklist.

### 4.4.1 Reputation Circuit Breaker (The "Airbag")

- [ ] **Implement Sliding Window Error Monitor**
  - **Implementation:** Redis `INCR` counter for bounces/complaints (10-minute window). If Rate > 3%, trigger `PAUSE_QUEUE`.

  - **Evidence Required:** Test Bench: Inject 5 consecutive hard bounces -> System state changes to "PAUSED (Protection)" -> Admin alerted.

---

## Phase 5: Analytics & Cold Storage (High Volume)

*Goal: Millions of events/day, exactly-once, cheap storage.*

### 5.1 Event Ingestion

- [ ] **Implement Immutable Event Log**
  - **Implementation:** Append-only architecture. `event_id` constructed deterministically `hash(message_id + type + time)` to dedupe.

  - **Evidence Required:** SQL permissions check showing `DELETE` is disabled for application users.

- [ ] **Implement Exact-Once Reconciliation**
  - **Implementation:** Nightly job comparing `outbox_recipients` vs `event_log` counts.

  - **Evidence Required:** Reconciliation report showing 0 discrepancy on a 1M message dataset.

- [ ] **Deploy ClickHouse/DuckDB for Real-time Analytics**
  - **Implementation:** Use self-hosted ClickHouse (preferred) or embedded DuckDB as the OLAP engine. Sync from Postgres via CDC or batch ETL.

  - **Evidence Required:** Sub-second query response on "Last 30 days open rate" aggregation over 10M rows.

### 5.1.1 Engagement Tracking Infrastructure

- [ ] **Implement Open Tracking Pixel**
  - **Implementation:** Inject invisible 1x1 GIF with unique URL `https://t.apexmail.ee/o/{message_id}`. Log on request. Cache-bust headers. CORS: `Access-Control-Allow-Origin: *` for pixel endpoint (no credentials).

  - **Evidence Required:** Open email in Gmail -> Pixel request logged -> Dashboard shows "Opened" within 5 seconds; Browser console shows no CORS errors on pixel load.

- [ ] **Implement Click Tracking**
  - **Implementation:** Rewrite URLs through `https://t.apexmail.ee/c/{link_id}?r={original_url}`. 302 redirect after logging.
  - **Evidence Required:** Click link -> Redirect latency <50ms; Original destination reached; Click logged with timestamp.

- [ ] **Implement Custom Tracking Domains**
  - **Implementation:** Allow tenants to CNAME their own domain (e.g., `links.customer.com`) to ApexMail tracking. Auto-provision TLS certificates via ACME. Validate CNAME before activation.
  - **Evidence Required:** Customer configures `track.example.com` -> Clicks rewrite to `https://track.example.com/c/...` -> TLS valid; Branded domain appears in email source.

- [ ] **Implement Unsubscribe Tracking**
  - **Implementation:** Handle `List-Unsubscribe-Post` webhooks. Immediately add to suppression list. Fire customer webhook.

  - **Evidence Required:** One-click unsubscribe in Gmail -> Recipient suppressed within 1 second -> Customer webhook received.

- [ ] **Implement Engagement Scoring**
  - **Implementation:** Per-recipient engagement score based on opens, clicks, recency, bounce history, and complaint history. Surface "Cold" contacts for re-engagement or pruning. Flag "Risky" contacts with high bounce/complaint rates.

  - **Evidence Required:** Dashboard showing recipient with "Engagement: Low (no opens in 90 days)" warning; Recipient with prior hard bounce shows "Risk: High" badge.

### 5.2 Cold Storage Engine

- [ ] **Implement Parquet Compaction Worker**
  - **Implementation:** Worker converts daily Postgres partitions -> local Parquet files -> S3-compatible object storage (MinIO) or encrypted offsite volume.

  - **Evidence Required:** `parquet-tools cat` output of a generated file matching the source DB data.

- [ ] **Implement Embedded Query Engine (DuckDB)**
  - **Implementation:** Vendor DuckDB (no external binary) to query cold Parquet files via API.

  - **Evidence Required:** Query latency benchmark: < 500ms for aggregation over 10M rows.

### 5.3 Inbound Email Processing

- [ ] **Implement Inbound MX & SMTP Server**
  - **Implementation:** Postfix inbound on dedicated subdomain (`inbound.apexmail.ee`). Parse and webhook to customer endpoint.

  - **Evidence Required:** Send email to `webhook-test@tenant.inbound.apexmail.ee` -> Customer webhook receives JSON payload.

- [ ] **Implement Reply Tracking**
  - **Implementation:** VERP-style reply address `reply+{message_id}@inbound.apexmail.ee`. Match replies to original sends.

  - **Evidence Required:** Original send -> Reply received -> Dashboard shows "1 Reply" linked to original message.

- [ ] **Implement Spam/Virus Filtering (Inbound)**
  - **Implementation:** SpamAssassin + ClamAV on inbound. Score threshold configurable per tenant.

  - **Evidence Required:** Send GTUBE test string -> Marked as spam; Send EICAR test file -> Quarantined.

- [ ] **Implement Inbound Authentication Verification**
  - **Implementation:** Verify SPF, DKIM, DMARC on all inbound. Include `Authentication-Results` header. Surface in webhook payload.

  - **Evidence Required:** Receive email failing DKIM -> Webhook payload shows `"dkim": "fail"` -> Dashboard shows warning icon.

- [ ] **Implement Inbound Rate Limiting**
  - **Implementation:** Per-tenant inbound rate limits. Reject with 421 when exceeded. Protect against inbound flooding attacks.

  - **Evidence Required:** 1000 emails/min to single tenant -> After limit, SMTP returns 421 "Rate limit exceeded".

---

## Phase 6: Sales Autopilot & CRM (For Control Plane)

*Goal: Automated growth using the platform itself. Inspired by Ad-Project "Autopilot".*

### 6.1 Lead Generation & Enrichment

- [ ] **Implement "SaaS Hunter" Scraper for Control Plane**
  - **Implementation:** Worker that scans **publicly listed** SaaS directories (e.g., ProductHunt, G2 public pages) and checks DNS for `spf.protection.outlook.com` or `_spf.google.com`. Respects `robots.txt`. No private data scraped. Internal use only (lead gen for Owner, not exposed to customers).

  - **Evidence Required:** Sample CSV export of 100 potential leads with verified MX records; Log confirms `robots.txt` was checked before each domain scan.

- [ ] **Implement Company Enrichment**
  - **Implementation:** Fetch public metadata (meta tags, logo, checking for "Careers" page) to score lead viability.

  - **Evidence Required:** JSON object for a test domain populated with Title, Description, and Tech Stack signals.

### 6.2 Outreach Automation

- [ ] **Implement Drip Campaign Engine**
  - **Implementation:** Sequence builder (Email 1 -> Wait 3 Days -> Email 2). Uses ApexMail API to send.

  - **Evidence Required:** Integration test: Email 1 sent at T -> Email 2 sent at T + 72h ± 5 minutes (jitter tolerance); sequence state persisted across worker restarts.

- [ ] **Implement "Inbox Sentinel"**
  - **Implementation:** Monitor reply-to mailbox. Detect "Out of Office" (ignore) vs "Interested" (notify admin).

  - **Evidence Required:** Unit test classifying 50 sample replies (positive, negative, OOO) correctly.

### 6.3 Internal Control Plane CRM Dashboard

- [ ] **Implement "Pipeline View"**
  - **Implementation:** Kanban board in Dashboard (Leads -> Contacted -> Demo -> Won).

  - **Evidence Required:** Screenshot of the pipeline view with 50+ loads.

- [ ] **Implement Automated Demo Scheduling**
  - **Implementation:** Link tracking in emails; "Book Demo" calendar integration (e.g., Cal.com self-hosted or simple slot picker).

  - **Evidence Required:** E2E flow: Click link -> Book Slot -> Calendar Event Created.

### 6.4 Internal Cross-Promotion & Ad Injection (Monetization)

- [ ] **Implement Dynamic Ad Slots**
  - **Implementation:** Template tag `{{promo_block}}` resolved by decision engine (Cross-sell own products or 3rd party).

  - **Evidence Required:** Transactional receipt email renders with a targeted "Upgrade to Pro" banner injected.

- [ ] **Implement Affiliate Link Auto-Wrapper**
  - **Implementation:** Middleware that rewrites specific external domains (e.g., `digitalocean.com`) to add `?ref=code` automatically.

  - **Evidence Required:** Send email with raw link -> Received email contains affiliate-tagged link.

---

## Phase 6.5: Security, Compliance & Owner Control Plane (Restored & Enhanced)

*Goal: Prevent abuse, verifiable security, and automated Estonian/EU bureaucratic compliance.*

### 6.5.1 Abuse Prevention

- [ ] **Implement Tenant Risk Scoring**
  - **Implementation:** Heuristic engine (signup email domain, volume ramp, content scanning).

  - **Evidence Required:** Test showing immediate suspension/throttling when "risk score" crosses threshold.

- [ ] **Implement Content Scanning**
  - **Implementation:** Regex/heuristic content checks before spooling.
  - **Add-On:** OCR (Tesseract/EasyOCR) for image-heavy emails. Detect text embedded in images to bypass filters.
  - **Evidence Required:** Email with spam text hidden in JPG -> Blocked by "Image Content Filter".

### 6.5.2 Immutable Audit & Secrets

- [ ] **Implement Signed Audit Logs**
  - **Implementation:** Hash-chaining (Merkle tree-like) for audit logs. `hash(prev_hash + row)`.

  - **Evidence Required:** Verification script that detects tampering if a single row is modified in the DB.

- [ ] **Implement Secret Management (No Vault)**
  - **Implementation:** OS Keyring or Encrypted file at rest; Environment injection at runtime.

  - **Evidence Required:** Boot logs showing no secrets printed; Dump of environment showing secrets present only in memory.

### 6.5.3 Owner Control Plane (Compliance & Bureaucracy)

- [ ] **Implement "Compliance Admin" Dashboard (High-Fidelity)**
  - **Implementation:** Super-Admin view must use the *same* polished Design System as the customer console. No "ugly admin" interfaces. Shows all active DPAs, ROPA logs, and "Sudo" access logs.
  - **Evidence Required:** Screenshot of the Admin View indistinguishable in quality from the main product; List of signed DPAs presented in "Glassmorphism" cards.

- [ ] **Implement Control Plane Theme Lock (ApexMediation Parity)**
  - **Implementation:** Control plane inherits identical design tokens, typography, and layout grid from the public console. No separate admin theme allowed.
  - **Evidence Required:** Token audit showing single source of truth; side-by-side comparison of Control Plane and Console pages with identical spacing, type, and color system.

- [ ] **Implement Automated DPA & Estonian Legal Wrapper**
  - **Implementation:** Auto-generate PDF Data Processing Agreements with Bel Consulting OÜ signatures. Support Estonian E-Invoice standard (XML) for B2B.

  - **Evidence Required:** Generated PDF showing correct "Data Controller" (Customer) vs "Data Processor" (Bel Consulting) roles, matching Ad-Project standards.

- [ ] **Implement "Right-to-be-Forgotten" Cascade**
  - **Implementation:** Single-API call `DELETE /v1/gdpr/forget/{userId}` that triggers scrubbing from Hot Data, Cold Parquet (via re-write), and backup logs.
  - **Safeguard:** "Legal Hold" Mode. If `tenant.legal_hold = true`, DELETE requests are acknowledged (`202 Accepted`) but *suppressed/delayed* indefinitely until hold is lifted.
  - **Evidence Required:** legal_hold=true -> Delete API called -> Data REMAINS in DB; Hold released -> Data purged.

### 6.5.4 GDPR/Estonian Compliance Automation (Ad-Project+)

- [ ] **Implement Consent Ledger (Source of Truth)**
  - **Implementation:** Store consent timestamp, IP, method, and exact checkbox text per recipient. Immutable append-only ledger.

  - **Evidence Required:** DSAR export shows consent history with cryptographic proof hash.

- [ ] **Implement Consent Withdrawal & Do-Not-Contact Ledger**
  - **Implementation:** Store withdrawal timestamp/source (one-click unsubscribe, manual admin action, webhook). Enforce immediate suppression without deleting historical proof.

  - **Evidence Required:** Recipient clicks one-click unsubscribe -> `suppression_list` updated within 1 second; DSAR export shows both consent grant and withdrawal events.

- [ ] **Implement DSAR Workflow (Export/Rectify/Delete)**
  - **Implementation:** One-click DSAR runbook that generates data export, schedules deletion, and logs completion within 30 days.

  - **Evidence Required:** DSAR test: request -> export ZIP -> delete -> signed completion record.

- [ ] **Implement ROPA Auto-Generation**
  - **Implementation:** Auto-create Records of Processing Activities from live data flows and job definitions.

  - **Evidence Required:** ROPA export listing each processing activity with purpose, retention, legal basis.

- [ ] **Implement Sub-Processor Registry**
  - **Implementation:** Versioned list of all subprocessors, change notifications, and acceptance logs.

  - **Evidence Required:** Change log showing customer notification and acknowledgment timestamp.

- [ ] **Implement Estonian Data Residency Toggle**
  - **Implementation:** Per-tenant flag forcing storage/processing in EU/EE region only (hard fail if not available).

  - **Evidence Required:** Tenant in EU-only mode -> attempted US storage write rejected.

- [ ] **Implement Per-Tenant Retention Schedules**
  - **Implementation:** Configurable retention for logs and message bodies (e.g., 30d, 90d, 1y). Enforce via automated purge.

  - **Evidence Required:** Retention set to 30d -> Data older than 30d removed in nightly job.

### 6.5.5 Owner Control Plane Governance (Full Control)

- [ ] **Implement Policy-as-Code Guardrails**
  - **Implementation:** YAML policies for send limits, content rules, and approval requirements; enforced at API boundary.

  - **Evidence Required:** Policy update -> immediate enforcement without deploy; audit log shows policy change.

- [ ] **Implement API Key Scopes & Rotation**
  - **Implementation:** Scoped keys (`send`, `templates`, `webhooks`). Mandatory rotation policy with expiry reminders.

  - **Evidence Required:** Expired key -> 401 with `X-Key-Expired`; rotation audit log entry created.

- [ ] **Implement MFA for High-Risk Actions**
  - **Implementation:** Require TOTP/WebAuthn confirmation for: API key creation, domain deletion, billing changes, SSO config changes. Rate-limit failed MFA attempts.

  - **Evidence Required:** Attempt to create API key without MFA -> 403 "MFA required"; Successful MFA -> Action proceeds; 5 failed MFA attempts -> 15-minute lockout.

- [ ] **Implement Emergency Key Revocation**
  - **Implementation:** One-click revoke all keys for tenant; revoke propagates to all services in <60s.

  - **Evidence Required:** Revoke event -> All API calls return 401 within 60s.

- [ ] **Implement Sudo Access Workflow**
  - **Implementation:** Time-boxed privileged access with justification, approval, and auto-expiry.

  - **Evidence Required:** Access request -> approval -> auto-revoke after 60 minutes.

- [ ] **Implement Compliance Calendar**
  - **Implementation:** Track DPA expirations, DPIA review dates, and legal document renewals.

  - **Evidence Required:** Calendar view with upcoming deadlines + automated reminder emails.

- [ ] **Implement Signed Audit Export for Customers**
  - **Implementation:** One-click export of access logs and delivery logs with cryptographic signatures.

  - **Evidence Required:** Customer verifies export signature with provided CLI tool.

- [ ] **Implement Global Kill Switch**
  - **Implementation:** Owner can freeze a tenant instantly (stop sends, block API, queue retained).

  - **Evidence Required:** Toggle kill switch -> all API calls return 423 Locked within 5 seconds.

### 6.5.6 Strategic Compliance (Estonia & Ad-Tech)

- [ ] **Implement Estonian E-Invoice (EVS 923 / EN 16931)**
  - **Implementation:** Generator for compliant XML v1.2. Integration with `e-arveldaja` API or PEPPOL access point.

  - **Evidence Required:** Generated XML passes `Maksu- ja Tolliamet` validator; B2G invoice successfully accepted.

- [ ] **Implement QES Digital Signatures (Smart-ID/Mobile-ID)**
  - **Implementation:** Integration with SK ID Solutions (`SK.ee`) API. Create valid `.asice` containers for B2B contracts.

  - **Evidence Required:** Contract signing flow: User creates Smart-ID signature -> System produces valid ASiC-E container verifiable by `DigiDoc4`.

- [ ] **Implement Crypto/AML Foundations (RAB-Ready)**
  - **Implementation:** Immutable "KYC Audit Log" linking to verify providers (Veriff). PEP/Sanctions list cache.

  - **Evidence Required:** Audit trail showing "User X screened against EU Sanctions List v2026.01.31 - Clean".

- [ ] **Implement IAB TCF v2.2 (Ad-Project Standards)**
  - **Implementation:** Parse and store TC Strings (Transparency & Consent). Pass `Global Privacy Platform` (GPP) signals in tracking pixels.

  - **Evidence Required:** Test suite: Inject TC String -> Verify consent signal controls pixel firing.

---

## Phase 7: Product UX & Design System (Ad-Project Adapted)

*Goal: Polished, accessible, consistent UI. Matches ApexMediation standards.*

### 7.1 Design System Implementation

- [ ] **Implement Accessibility (WCAG 2.1 AA) Compliance**
  - **Implementation:** All UI components pass axe-core audit. Keyboard navigation for all actions. ARIA labels on interactive elements. Color contrast ratio ≥ 4.5:1.

  - **Evidence Required:** Lighthouse accessibility score ≥ 95; axe-core CI check passes with 0 violations; Tab-key navigation demo through full send flow.

- [ ] **Adopt Shadcn/UI + Tailwind**
  - **Implementation:** Copy `components/ui` from reference. Enforce specific `branding` colors in `tailwind.config.ts`.

  - **Evidence Required:** Component gallery page (`/design`) showcasing Buttons, Inputs, Cards in Apex colors.

- [ ] **Implement ApexMediation Design Tokens (Single Source of Truth)**
  - **Implementation:** Centralized tokens for color, spacing, radii, elevation, blur, and typography scale. Used by Console, Control Plane, Docs, and Marketing pages.
  - **Evidence Required:** Token manifest file with references across all surfaces; diff shows no divergent token values.

- [ ] **Implement Typography & Iconography System**
  - **Implementation:** Inter-based type scale (display → caption), consistent letter spacing, and an icon set aligned with ApexMediation visual language.
  - **Evidence Required:** Typography showcase page showing headings, body, captions; icon catalog visible in `/design`.

- [ ] **Implement "Glassmorphism" Dashboard (ApexMediation Identity)**
  - **Implementation:** Strict adherence to ApexMediation.ee visual standards: high-transparency glass panels, subtle border gradients, Inter font, and "Deep Space" dark mode background.
  - **Performance Guard:** Implement "Bundle Budget" (<150KB Initial load) and CSS containment to ensure glass blur doesn't cause repaint lag.
  - **Evidence Required:** Lighthouse Performance Score > 90 on Dashboard; scrolling 1000 items with blur enabled maintains 60fps.

- [ ] **Implement Command Palette Navigation**
  - **Implementation:** `Cmd+K` global menu for rapid navigation (e.g., "Go to Templates", "Search User"). Matches the precision feel of the reference system.
  - **Evidence Required:** Press `Cmd+K` -> Menu opens < 50ms -> Type "Billing" -> Navigates to Billing.

- [ ] **Implement "Trust-First" UI Interactions**
  - **Implementation:** "Consequence Modals" for destructive actions. Clear visualization of costs before confirmation.
  - **Evidence Required:** Delete Domain -> Modal shows "This will stop 5 active campaigns" with specific red visuals.

- [ ] **Implement Motion & Micro-Interaction Guidelines**
  - **Implementation:** Subtle motion on hover/focus, loading skeletons, and blur transitions consistent with ApexMediation. Respect `prefers-reduced-motion`.
  - **Evidence Required:** Motion audit showing all interactive components have consistent timings; reduced-motion disables animations.

- [ ] **Implement Density Modes (Comfortable/Compact)**
  - **Implementation:** User-selectable density for tables and dashboards. Default mirrors ApexMediation layout density.
  - **Evidence Required:** Toggle between modes -> row height and padding change without layout breakage.

### 7.2 Web Application Structure

- [ ] **Next.js 14 App Router Migration**
  - **Implementation:** Use React Server Components (RSC) for data fetching. minimize client-side JS.

  - **Evidence Required:** Network tab screenshot showing 0 JSON API calls on initial page load (all server-rendered).

- [ ] **Real-Time Updates via SSE**
  - **Implementation:** Server-Sent Events for log streaming (no WebSockets if possible, for simplicity).

  - **Evidence Required:** Video showing logs appearing in the UI < 1s after ingestion.

### 7.3 Enterprise & Agency Portals

- [ ] **Implement "Master Account" Switcher**
  - **Implementation:** User-switcher dropdown for Agency Admins to "Impersonate" sub-accounts (with audit trail).

  - **Evidence Required:** Select Client A -> View changes to Client A context -> Send test email -> Logged as Client A (by Admin).

- [ ] **Implement Audit Log Viewer (Customer Facing)**
  - **Implementation:** Read-only view of `audit_logs` for "Enterprise" role users.

  - **Evidence Required:** User changes API Key -> "Security Log" page shows "User X rotated Key Y from IP Z".

---

## Phase 8: AI-Powered Intelligence Suite (Production-Grade)

*Goal: State-of-the-art AI running entirely on CPU (Hetzner ARM64), using ONNX Runtime for maximum performance, fine-tuned for email operations, with zero external API dependencies.*

**Hardware Target:** Hetzner CAX41 (16 ARM64 cores, 32GB RAM) or equivalent. All models must achieve <300ms p95 latency for interactive use cases.

**Runtime:** ONNX Runtime 1.17+ with ARM64 optimizations (MLAS backend). All models quantized to INT8/INT4 with ONNX Runtime quantization tools.

### 8.1 ONNX Runtime Infrastructure & Model Serving

- [ ] **Deploy ONNX Runtime GenAI Inference Server (ARM64-Optimized)**
  - **Implementation:** Deploy `onnxruntime-genai` server with ARM64 MLAS optimizations:
    - Build with `--use_mlas --enable_lto --minimal_build`
    - Thread pool: 12 threads (reserve 4 cores for system)
    - Memory arena: Pre-allocated 16GB, prevent fragmentation
    - Session options: `graph_optimization_level=ORT_ENABLE_ALL`, `enable_mem_pattern=True`
    - Execution provider priority: `[CPUExecutionProvider]` with ARM NEON
  - **Primary Model:** Microsoft Phi-3.5-mini-instruct-onnx (3.8B params, INT4 AWQ, ~2.1GB)
    - Source: `huggingface.co/microsoft/Phi-3.5-mini-instruct-onnx`
    - Why: State-of-the-art instruction following at <4B, 128K context, native ONNX support, MIT license
    - Quality: Outperforms Llama-3-8B on most benchmarks despite smaller size
  - **Evidence Required:**
    - Benchmark: >25 tokens/sec generation on CAX41 (faster than llama.cpp due to ONNX optimizations)
    - Load test: 15 concurrent requests, p95 latency <600ms, 0 OOM errors over 24h
    - Memory profile: RSS stable at <8GB under sustained load

- [ ] **Deploy Phi-3-medium-128k-instruct (Fallback for Complex Tasks)**
  - **Implementation:** Secondary model for complex reasoning tasks requiring higher quality:
    - Model: `microsoft/Phi-3-medium-128k-instruct-onnx` (14B params, INT4 quantized, ~7.5GB)
    - Use case: Complex email analysis, multi-step reasoning, detailed explanations
    - Routing: Intent classifier routes complex queries to medium model
  - **Evidence Required:**
    - Quality benchmark: >90% accuracy on ApexMail reasoning test suite (vs 82% for mini)
    - Latency: <2s for typical response (acceptable for async/complex tasks)

- [ ] **Implement Model Router with Quality-Latency Tradeoff**
  - **Implementation:** Intelligent routing based on query complexity:
    - **Simple queries** (FAQ, status checks): Phi-3.5-mini (<300ms)
    - **Medium queries** (troubleshooting, explanations): Phi-3.5-mini with longer context
    - **Complex queries** (debugging, multi-step analysis): Phi-3-medium (<2s)
    - Complexity detection via lightweight DeBERTa classifier (<10ms overhead)
  - **Evidence Required:**
    - Routing accuracy: 95%+ queries correctly routed (validated on 1K labeled samples)
    - Latency budget met: 90%+ of responses within target latency for their complexity tier

- [ ] **Implement ONNX Model Hot-Swap & A/B Versioning**
  - **Implementation:** Zero-downtime model updates:
    - Model registry in Postgres: version, sha256, ONNX opset, quantization method, benchmark scores
    - Warm model loading: Pre-load new model in separate session before swap
    - Traffic splitting: Gradual rollout 5% → 25% → 50% → 100% with automatic rollback on quality regression
    - Health checks: Latency p99, error rate, output quality score (via small eval set)
  - **Evidence Required:**
    - Swap latency: <100ms to switch traffic (no dropped requests)
    - Automatic rollback triggers within 60s if error rate >1% or latency >2x baseline

- [ ] **Implement Continuous Batching with ONNX Runtime**
  - **Implementation:** Custom batching layer for throughput optimization:
    - Dynamic batching: Accumulate requests for 10ms, batch inference
    - KV-cache reuse: Share computed attention across similar prompt prefixes
    - Async generation: Stream tokens via Server-Sent Events
  - **Evidence Required:**
    - Throughput: 3x improvement over sequential processing at 50%+ utilization
    - First-token latency: <150ms p95 (streaming responsiveness)

### 8.2 Fine-Tuned Email Domain Expert (ONNX Native)

- [ ] **Create ApexMail Expert Training Dataset (100K+ Examples)**
  - **Implementation:** Curate high-quality training dataset:
    - **Public Technical Sources:**
      - Stack Overflow: `[email-deliverability]`, `[dkim]`, `[spf]`, `[dmarc]`, `[smtp]` tags (~20K Q&A pairs)
      - Postfix/Exim/Sendmail mailing lists (public archives, ~60K threads → 30K high-quality pairs)
      - RFC documentation converted to Q&A (RFC 5321, 5322, 6376, 7208, 7489) (~2K pairs)
      - Email-on-Acid, Litmus blog technical articles (~3K examples)
    - **Synthetic High-Quality Examples:**
      - GPT-4 Turbo generated edge cases with human verification (~10K)
      - Claude-3 generated troubleshooting scenarios (~10K)
      - Multi-turn conversation synthesis for support flows (~15K)
    - **ApexMail Proprietary:**
      - Internal runbooks and documentation (~1K)
      - Anonymized support ticket resolutions (~5K)
  - **Dataset Format:** ShareGPT/OpenAI format with `messages` array, supports multi-turn
  - **Quality Control:**
    - Deduplication via MinHash (Jaccard >0.8 = duplicate)
    - Quality filtering via perplexity scoring (remove outliers)
    - Human audit: 1K random samples, >97% accuracy requirement
  - **Evidence Required:**
    - Final dataset: >100K examples, <5% duplicate rate
    - Topic distribution: Balanced across DKIM/SPF/DMARC/Bounce/Deliverability/SMTP
    - Quality audit report with inter-annotator agreement >0.9 (Cohen's kappa)

- [ ] **Fine-Tune Phi-3.5-mini on Email Domain (LoRA → ONNX Export)**
  - **Implementation:** Domain adaptation with LoRA, export to ONNX:
    - **Base Model:** `microsoft/Phi-3.5-mini-instruct`
    - **LoRA Config:** r=128, alpha=256, dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    - **Training:**
      - Epochs: 2 (avoid overfitting on domain data)
      - Batch size: 8, gradient accumulation: 4
      - Learning rate: 1e-4 (cosine decay with warmup)
      - Hardware: Single A100 80GB or 2x A100 40GB (cloud burst)
    - **Export Pipeline:**
      1. Merge LoRA weights into base model
      2. Export to ONNX via `optimum` library
      3. Quantize to INT4 AWQ using ONNX Runtime quantization tools
      4. Validate: Output quality matches FP16 within 2% on eval set
  - **Evidence Required:**
    - Training loss: Smooth convergence, final loss <0.8
    - Eval metrics: ROUGE-L >0.78, BERTScore >0.88 on holdout (improvement over base)
    - Human eval: Blind A/B test, fine-tuned preferred 85%+ (n=200 comparisons)
    - ONNX export validation: Bit-exact outputs for 100 test prompts

- [ ] **Implement Structured Output via Guided Generation (ONNX)**
  - **Implementation:** Constrained decoding using `outlines` library with ONNX backend:
    - **JSON Schema Enforcement:** Define Pydantic models, compile to FSM for constrained generation
    - **Schemas:**
      ```python
      class IntentClassification(BaseModel):
          intent: Literal["setup_help", "troubleshoot", "billing", "feature_request", "escalate"]
          confidence: float = Field(ge=0, le=1)
          entities: dict[str, str]
      
      class SupportResponse(BaseModel):
          thinking: str  # Chain-of-thought (hidden from user)
          answer: str
          sources: list[str]
          escalate: bool
          follow_up_questions: list[str]
      ```
    - **Inference:** Compile schema once, reuse FSM for all requests (zero overhead after warmup)
  - **Evidence Required:**
    - Schema compliance: 100% valid JSON across 50K test queries (guaranteed by FSM)
    - Quality: No degradation vs unconstrained generation (same eval scores)
    - Latency overhead: <5% vs unconstrained generation

### 8.3 Intelligent Customer Support Chatbot (Production-Grade)

*The core conversational AI for real-time customer support via web widget, API, and dashboard.*

- [ ] **Implement Multi-Turn Conversation Engine**
  - **Implementation:** Stateful conversation manager with context windowing:
    - **Conversation State:**
      ```typescript
      interface ConversationState {
        id: string;
        tenant_id: string;
        user_id?: string;
        turns: Turn[];           // Full conversation history
        context_window: Turn[];  // Last N turns sent to model
        detected_intents: Intent[];
        entities: Map<string, string>;
        sentiment_score: number;
        escalation_risk: number;
        created_at: Date;
        last_activity: Date;
      }
      ```
    - **Context Management:**
      - Sliding window: Last 8 turns (user + assistant) + system prompt
      - Long-term memory: Key facts extracted and persisted (e.g., "User has 3 domains configured")
      - Context compression: Summarize older turns when approaching token limit
    - **Session Handling:**
      - Redis-backed sessions (TTL: 30 minutes of inactivity)
      - Seamless resume: User returns → full context restored
      - Cross-device: Session linked to user_id if authenticated
  - **Evidence Required:**
    - Context coherence: Bot correctly references information from 5+ turns ago in 95%+ of cases
    - Session resume: 100% of resumed sessions have full context
    - Latency: Session lookup <5ms (Redis)

- [ ] **Implement Intent-Aware Response Generation Pipeline**
  - **Implementation:** Multi-stage pipeline for high-quality responses:
    - **Stage 1: Intent Classification (DeBERTa, <15ms)**
      - 25 intent categories specific to email platform support
      - Multi-label (user can have multiple intents)
      - Confidence threshold: >0.7 for primary intent
    - **Stage 2: Entity Extraction (NER, <10ms)**
      - Domain names, email addresses, error codes, timestamps
      - Template variables, API endpoints
      - Custom entities: "bounce type", "DKIM selector", "SPF mechanism"
    - **Stage 3: Knowledge Retrieval (if needed, <50ms)**
      - Query internal documentation based on intent + entities
      - Return top 3 relevant passages for grounding
    - **Stage 4: Response Generation (Phi-3.5, <400ms)**
      - System prompt with retrieved context
      - User query with conversation history
      - Structured output (answer + follow-ups + confidence)
    - **Stage 5: Post-Processing (<30ms)**
      - Safety validation (already covered in 8.4)
      - Formatting (markdown, code blocks)
      - Action extraction (if bot suggests actions)
  - **Evidence Required:**
    - End-to-end latency: <600ms p95 for typical query
    - Intent accuracy: >94% on held-out test set
    - Response relevance: >90% rated "relevant" by human evaluators

- [ ] **Implement Proactive Assistance System**
  - **Implementation:** Bot initiates helpful suggestions based on context:
    - **Triggers:**
      - User views error page → "I see you're looking at a bounce report. Need help understanding it?"
      - DKIM setup incomplete → "Your domain setup is 80% complete. Want me to guide you through DKIM?"
      - High bounce rate detected → Proactive alert with diagnosis
      - New feature released → Contextual introduction
    - **Personalization:**
      - Track user expertise level (beginner/intermediate/expert)
      - Adjust explanation depth accordingly
      - Remember past interactions ("Last time you asked about SPF...")
    - **Timing:**
      - Debounce: Max 1 proactive message per 10 minutes
      - Relevance scoring: Only trigger if confidence >0.8
      - User preference: "Don't show tips" option
  - **Evidence Required:**
    - Engagement: 40%+ of proactive messages receive a response
    - Helpfulness: 75%+ rated helpful (thumbs up)
    - Non-intrusive: <5% of users disable proactive tips

- [ ] **Implement Tool-Augmented Responses (Function Calling)**
  - **Implementation:** Bot can execute actions on behalf of user (with confirmation):
    - **Available Tools:**
      ```python
      class BotTools:
          async def check_domain_dns(self, domain: str) -> DNSCheckResult
          async def validate_dkim_record(self, domain: str, selector: str) -> DKIMResult
          async def check_spf_record(self, domain: str) -> SPFResult
          async def analyze_bounce(self, message_id: str) -> BounceAnalysis
          async def get_sending_stats(self, domain: str, days: int) -> Stats
          async def check_blacklist_status(self, ip_or_domain: str) -> BlacklistResult
          async def generate_dns_records(self, domain: str) -> DNSRecords
          async def test_email_rendering(self, template_id: str) -> RenderResult
          async def create_support_ticket(self, summary: str, priority: str) -> Ticket
      ```
    - **Execution Flow:**
      1. Model decides tool is needed (structured output)
      2. Display tool call to user with explanation
      3. Execute tool (with rate limiting)
      4. Stream result back to model
      5. Model generates final response incorporating result
    - **Safety:**
      - Read-only tools: No confirmation needed
      - Write tools (create ticket): Require explicit user confirmation
      - Rate limiting: Max 5 tool calls per conversation
  - **Evidence Required:**
    - Tool accuracy: Correct tool selected 95%+ of the time
    - Execution success: 99%+ of tool calls complete successfully
    - User satisfaction: Tool-assisted responses rated higher than non-tool

- [ ] **Implement Real-Time Typing Indicators & Streaming**
  - **Implementation:** Responsive UX with streaming responses:
    - **Typing Indicator:** Show while model is generating
    - **Token Streaming:** Stream tokens via WebSocket/SSE as generated
    - **Chunked Display:** Group tokens into words before display (smoother)
    - **Cancellation:** User can interrupt generation (stop button)
    - **Partial Recovery:** If generation fails mid-stream, show partial + error
  - **Evidence Required:**
    - Time to first token: <200ms p95
    - Stream reliability: <0.1% dropped connections
    - Perceived latency: User survey shows "fast" rating >85%

- [ ] **Implement Chatbot Widget (Embeddable)**
  - **Implementation:** Lightweight, customizable chat widget:
    - **Technical:**
      - Bundle size: <50KB gzipped (lazy load conversation history)
      - Framework-agnostic: Vanilla JS, works with React/Vue/Angular
      - Shadow DOM: Isolated styles, no conflicts
      - Accessibility: WCAG 2.1 AA compliant
    - **Features:**
      - Persistent position (bottom-right, configurable)
      - Minimize/maximize with animation
      - Unread message badge
      - File upload (screenshots, logs)
      - Code block rendering with syntax highlighting
      - Link previews for documentation
    - **Customization:**
      - Brand colors, logo, welcome message
      - Custom CSS injection
      - Position and size
      - Business hours display
  - **Evidence Required:**
    - Lighthouse performance: >90
    - Load time: <500ms to interactive
    - Cross-browser: Chrome, Firefox, Safari, Edge (latest 2 versions)

### 8.4 Intelligent Email Mailbot (Automated Email Support)

*AI-powered email responder for support@, help@, and inbound ticket emails.*

- [ ] **Implement Inbound Email Processing Pipeline**
  - **Implementation:** Process incoming support emails automatically:
    - **Ingestion:**
      - Webhook from email provider (SendGrid, Postmark inbound)
      - Parse: Subject, body (plain + HTML), attachments, headers
      - Extract: Sender, in-reply-to (threading), references
    - **Preprocessing:**
      - Strip signatures (ML-based signature detection)
      - Remove quoted replies (keep only new content)
      - Extract inline images, attachments metadata
      - Language detection (support EN, ES, FR, DE, PT)
    - **Threading:**
      - Match to existing conversation via Message-ID/References
      - Create new conversation if no match
      - Link to user account if sender email matches
  - **Evidence Required:**
    - Parsing accuracy: 99%+ of emails correctly parsed
    - Threading accuracy: 98%+ correctly threaded
    - Processing latency: <2s from receipt to processed

- [ ] **Implement Email-Specific Intent Classification**
  - **Implementation:** Fine-tuned classifier for email support intents:
    - **Email-Specific Intents:**
      - `auto_reply_ooo`: Out of office (don't respond)
      - `auto_reply_receipt`: Delivery receipt (don't respond)
      - `unsubscribe_request`: Handle via unsubscribe system
      - `spam_report`: Log and suppress sender
      - `forwarded_bounce`: Extract original bounce, analyze
      - `question_technical`: Technical support question
      - `question_billing`: Billing inquiry
      - `bug_report`: Product bug report
      - `feature_request`: Feature suggestion
      - `complaint`: Unhappy customer (escalate)
      - `praise`: Positive feedback (log, respond warmly)
      - `vendor_pitch`: Sales email (ignore)
    - **Routing:**
      - `auto_reply_*`, `vendor_pitch` → No response, log only
      - `unsubscribe_request` → Automated unsubscribe flow
      - `complaint` → Immediate escalation to human
      - Others → AI response with confidence check
  - **Evidence Required:**
    - Classification accuracy: >97% on email-specific intents
    - False positive rate for "no response" categories: <0.5%
    - Complaint detection: 100% (never miss unhappy customer)

- [ ] **Implement AI Email Response Generator**
  - **Implementation:** Generate professional email responses:
    - **Tone Calibration:**
      - Analyze sender's tone (formal/casual/frustrated)
      - Match response formality level
      - Extra empathy for frustrated senders
    - **Response Structure:**
      ```
      Subject: Re: {original_subject}
      
      Hi {first_name},
      
      {acknowledgment of their question}
      
      {detailed answer with steps if applicable}
      
      {offer for follow-up}
      
      Best regards,
      {bot_name} (AI Assistant)
      ApexMail Support Team
      
      ---
      This response was generated by AI. Reply to continue the conversation 
      or request human support at any time.
      ```
    - **Quality Checks:**
      - Minimum response length (no one-liners for complex questions)
      - Maximum length (respect inbox, <500 words)
      - No hallucinated links or features
      - Spell check + grammar validation
  - **Evidence Required:**
    - Response quality: 85%+ rated "helpful" by recipients
    - Tone matching: 90%+ appropriate formality level
    - Grammar/spelling: 0 errors in 1000 responses

- [ ] **Implement Smart Auto-Reply Policies**
  - **Implementation:** Configurable automation levels:
    - **Level 1 - Draft Only:**
      - AI generates draft, human reviews before send
      - For: New customers, high-value accounts, complex issues
    - **Level 2 - Send with Delay:**
      - AI response sent after 5-minute delay (allow human override)
      - For: Standard questions with high confidence
    - **Level 3 - Instant Reply:**
      - Immediate AI response for simple questions
      - For: FAQ-type questions, status checks
    - **Confidence Thresholds:**
      - >0.9 confidence: Level 3 eligible
      - 0.7-0.9: Level 2 eligible
      - <0.7: Level 1 only (human review required)
    - **Tenant Configuration:**
      - Per-tenant automation level preference
      - Business hours vs after-hours policies
      - VIP customer overrides
  - **Evidence Required:**
    - Automation rate: 60%+ of emails handled without human intervention
    - Accuracy at each level: Level 3 >95%, Level 2 >90%, Level 1 N/A
    - Response time: Level 3 <30s, Level 2 <5min, Level 1 <1hr (SLA)

- [ ] **Implement Email Conversation Threading & History**
  - **Implementation:** Full email thread management:
    - **Thread View:**
      - Chronological display of all emails in thread
      - AI responses clearly marked
      - Human agent responses distinguished
      - Internal notes (not sent to customer)
    - **Context Passing:**
      - Full thread context passed to AI (with summarization for long threads)
      - Previous resolution attempts noted
      - Related tickets linked
    - **Handoff:**
      - Seamless handoff to human agent with full context
      - Agent can take over mid-thread
      - AI can resume if agent marks resolved
  - **Evidence Required:**
    - Thread accuracy: 99%+ emails correctly grouped
    - Context quality: Agents rate context "complete" in 95%+ of handoffs
    - Handoff latency: <30s from escalation to agent notification

- [ ] **Implement Mailbot Performance Analytics**
  - **Implementation:** Comprehensive metrics for email AI:
    - **Volume Metrics:**
      - Emails received, processed, responded (by AI vs human)
      - Automation rate by category
      - Response time distribution
    - **Quality Metrics:**
      - Customer reply rate (follow-up = potentially unresolved)
      - Escalation rate
      - Resolution rate (thread closed after AI response)
      - Customer satisfaction (survey after resolution)
    - **Operational Metrics:**
      - Processing latency
      - Model confidence distribution
      - Error rates
    - **Improvement Signals:**
      - Low-confidence categories (need more training data)
      - High-escalation intents (need better responses)
      - Common follow-up questions (improve initial response)
  - **Evidence Required:**
    - Dashboard with all metrics, filterable by time/tenant/category
    - Automated weekly report with trends
    - Alert on anomalies (e.g., escalation rate spike)

### 8.5 Multi-Stage Safety & Guardrails (ONNX-Optimized Pipeline)

- [ ] **Deploy ONNX-Optimized Safety Model Stack**
  - **Implementation:** All safety models run via ONNX Runtime for consistent, fast inference:
    - **Model 1:** `microsoft/deberta-v3-large` (304M params, INT8) - Intent & injection detection
    - **Model 2:** `unitary/toxic-bert` (110M params, INT8) - Toxicity detection
    - **Model 3:** `BAAI/bge-base-en-v1.5` (110M params, INT8) - Semantic similarity for OOD detection
    - All models: Quantized to INT8 via ONNX Runtime quantization, ARM64 optimized
    - Session sharing: Single ONNX session pool, models loaded at startup
  - **Evidence Required:**
    - Combined safety pipeline latency: <50ms p95 for all checks
    - Memory footprint: <2GB for entire safety stack

- [ ] **Implement Input Sanitization Layer (Pre-LLM)**
  - **Implementation:** Fast regex + classifier pipeline before LLM invocation:
    1. **Unicode Normalization:** NFC normalization, strip zero-width chars, confusable detection (ICU)
    2. **Injection Pattern Detection:** Compiled regex for known patterns + ML classifier backup
    3. **Content Policy Filter:** PII detection (email, phone, SSN, credit card patterns)
    4. **Length Guards:** Reject inputs >4K tokens (DoS prevention)
  - **Evidence Required:**
    - Latency: <3ms p99 for sanitization layer
    - Detection rate: 100% on OWASP LLM Top 10 injection patterns
    - False positive rate: <0.05% on legitimate support queries

- [ ] **Deploy DeBERTa-v3-large Prompt Injection Classifier (ONNX)**
  - **Implementation:** Fine-tuned on comprehensive injection dataset:
    - **Base:** `microsoft/deberta-v3-large` (304M params) - highest quality encoder
    - **Training Data:**
      - [Lakera Gandalf dataset](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) (~10K examples)
      - [PromptInject](https://github.com/agencyenterprise/PromptInject) (~5K examples)
      - [JailbreakBench](https://jailbreakbench.github.io/) (~2K examples)
      - Custom ApexMail adversarial examples (~3K, red-team generated)
      - Negative examples: Clean support queries (~50K)
    - **Output:** Binary `safe` / `injection_attempt` with calibrated probability
    - **Export:** ONNX INT8 quantized (~150MB)
  - **Evidence Required:**
    - Accuracy: >99.5% on held-out test set (higher than smaller models)
    - Latency: <15ms p95 (ONNX INT8 optimized)
    - Red team: 0 bypasses in 2000 novel adversarial attempts (documented vectors)
    - False positive rate: <0.01% on clean queries

- [ ] **Implement Multi-Layer Output Validation (Post-LLM)**
  - **Implementation:** Comprehensive output checking pipeline:
    1. **Factual Grounding Check:**
       - Extract claims via lightweight NER
       - Verify against ApexMail knowledge base (exact + fuzzy match)
       - Flag ungrounded claims with confidence <0.8
    2. **Confidence Calibration:**
       - Analyze token logprobs from ONNX GenAI
       - Flag responses with mean probability <0.6 or high variance
       - Trigger human review for low-confidence responses
    3. **Toxicity Filter (ONNX):**
       - `unitary/toxic-bert` INT8 model
       - Block if any toxicity category >0.7
       - Log near-misses (0.5-0.7) for review
    4. **PII Leakage Scanner:**
       - Regex patterns for emails, API keys, internal URLs, customer data
       - Named entity recognition for person/org names
       - Redact or block based on sensitivity
    5. **Consistency Check:**
       - Compare response to previous turns for contradictions
       - Flag if semantic similarity to contradictory statement >0.8
  - **Evidence Required:**
    - Hallucination detection: 97%+ catch rate on synthetic test set (500 fabricated facts)
    - Toxicity: 0 toxic responses in 25K adversarial test queries
    - PII leakage: 0 internal data exposed in 100K response audit
    - Latency: <30ms for full output validation pipeline

- [ ] **Implement Intent-Based Deterministic Responses**
  - **Implementation:** Route sensitive topics to hard-coded templates (zero LLM involvement):
    - **Detection:** DeBERTa-v3-large multi-class intent classifier (fine-tuned)
    - **Sensitive Intents:**
      - `billing_dispute` → Template: "I understand billing concerns are important. I'm connecting you with our billing specialist who can review your account. Ticket #{{id}} created."
      - `legal_request` → Template: "For legal matters, please contact legal@apexmail.ee or visit our Legal page at /legal. I cannot provide legal advice."
      - `account_deletion` → Template: "You can delete your account via Settings → Account → Delete Account, or visit our GDPR portal at /gdpr. This action is irreversible."
      - `refund_request` → Template: [Exact refund policy from docs, no generation]
      - `security_concern` → Template: Immediate escalation + security team notification
    - **Fallback:** If intent confidence <0.9, use LLM but with extra guardrails
  - **Evidence Required:**
    - Intent classifier accuracy: >98% on sensitive categories
    - 100% template usage for high-confidence sensitive intents
    - Audit log: Template ID + intent confidence for every templated response

- [ ] **Implement Adaptive Human Escalation System**
  - **Implementation:** Multi-signal escalation with configurable thresholds:
    - **Automatic Escalation Triggers:**
      - Model confidence <0.5 on response tokens
      - User sentiment score <-0.5 (tracked across conversation)
      - Explicit keywords: "human", "agent", "manager", "supervisor", "speak to someone"
      - Conversation loop: Same intent detected 3+ times
      - Safety filter near-miss: Any safety score in 0.6-0.8 range
      - Out-of-distribution: Query embedding >2σ from training distribution centroid
    - **Escalation Quality:**
      - Full conversation transcript with timestamps
      - AI's understanding summary (generated by model)
      - Detected intent history
      - Suggested resolution (if available)
      - Confidence scores for each turn
    - **Routing:** Priority queue based on sentiment + wait time
  - **Evidence Required:**
    - Escalation latency: Ticket created in <5s with full context
    - Human agent satisfaction: >92% find AI context "helpful" (survey)
    - Escalation rate: 8-12% of conversations (calibrated to balance coverage vs efficiency)

### 8.6 Send Time Optimization (Production ML Pipeline)

- [ ] **Build Real-Time Recipient Engagement Feature Store**
  - **Implementation:** High-performance feature store with Postgres + Redis:
    - **Per-Recipient Features (Redis, hot):**
      - `hourly_open_prob[24]`: Open probability by hour (UTC), exponential decay (τ=30 days)
      - `dow_multiplier[7]`: Day-of-week engagement modifier
      - `timezone`: Inferred from open IP geolocation (MaxMind), confidence score
      - `last_engagement`: Timestamp + type (open/click/reply)
      - `engagement_velocity`: 7-day trend (improving/declining/stable)
      - `device_preference`: Mobile vs desktop ratio
      - `avg_response_time`: Mean time to open after delivery
    - **Aggregate Features (Postgres, materialized views):**
      - Sender reputation by domain
      - Template performance by category
      - Industry benchmarks
    - **Update Pipeline:**
      - Streaming via Postgres NOTIFY on `event_log` inserts
      - Redis update latency: <500ms from event
      - Batch refresh: Hourly for aggregate features
  - **Evidence Required:**
    - Feature freshness: <1s from event to Redis update
    - Coverage: >85% of active recipients with 14+ days of engagement data
    - Storage: <150 bytes per recipient (Redis), <1KB with history (Postgres)

- [ ] **Train XGBoost Send Time Prediction Model (ONNX Export)**
  - **Implementation:** Gradient boosting model for optimal send time:
    - **Model:** XGBoost with ONNX export via `onnxmltools`
    - **Features (40+):**
      - Recipient: All engagement features from store
      - Email: template_id, subject_length, has_emoji, personalization_count, attachment_count, is_transactional
      - Temporal: Current hour, day_of_week, is_holiday, days_since_last_send
      - Sender: Historical open rate, domain reputation score
    - **Target:** Binary open within 24h
    - **Training:**
      - Data: 90-day rolling window, ~10M send records
      - Split: Time-based 80/10/10 (train on older, test on recent)
      - Hyperparameters: Optuna with 200 trials, optimizing AUC-PR (handles class imbalance)
    - **Export:** ONNX format, quantized to FP16 (~2MB)
  - **Evidence Required:**
    - Offline: AUC-ROC >0.74, AUC-PR >0.45, lift@10% >2.5x vs random
    - Online A/B: +15% open rate vs immediate send (p<0.01, n>100K per arm, 4-week test)
    - Calibration: Brier score <0.18, reliability diagram shows good calibration
    - Inference: <5ms per prediction (ONNX optimized)

- [ ] **Implement Multi-Armed Bandit for Exploration-Exploitation**
  - **Implementation:** Thompson Sampling for continuous learning:
    - **Problem:** Pure exploitation misses changing preferences
    - **Solution:** Thompson Sampling with Beta posteriors per (recipient_cluster, hour) pair
    - **Exploration rate:** 10% of sends explore non-optimal times
    - **Clustering:** K-means on engagement patterns (K=50 clusters)
    - **Update:** Posterior updated on each open/no-open observation
  - **Evidence Required:**
    - Regret analysis: Cumulative regret grows sub-linearly (√T)
    - Adaptation: Model detects preference shifts within 2 weeks
    - A/B: Bandit outperforms static model by >3% after 8 weeks

- [ ] **Implement Predictive Send Queue with Guarantees**
  - **Implementation:** Distributed queue for optimized delivery:
    - **Flow:**
      1. Email received with `optimize_send_time: true`
      2. Query XGBoost model for optimal hour (returns probability distribution)
      3. Sample send time from distribution (respects uncertainty)
      4. Store in `scheduled_sends` table with `optimal_send_at`
      5. Worker polls for due emails, sends with ±10min jitter
    - **Constraints:**
      - Tenant blackout windows (configurable)
      - Max delay: 24h (configurable per tenant)
      - Recipient timezone awareness
      - Volume smoothing: Spread sends to avoid spike detection
    - **Reliability:**
      - Exactly-once delivery guarantee (idempotency keys)
      - Dead letter queue for failed predictions
      - Fallback: Immediate send if model unavailable
  - **Evidence Required:**
    - Queue latency: <50ms to enqueue
    - Delivery accuracy: 97% within ±15min of predicted optimal
    - Throughput: 500K scheduled sends/hour per worker
    - Reliability: 0 dropped emails in 30-day soak test

- [ ] **Implement Automated Model Retraining Pipeline (MLOps)**
  - **Implementation:** Weekly retraining with quality gates:
    - **Schedule:** Every Sunday 02:00 UTC
    - **Pipeline:**
      1. Export features + labels for past 90 days
      2. Train new XGBoost model (same hyperparameters)
      3. Evaluate on held-out week (most recent)
      4. Compare to production model on same eval set
      5. If AUC improves >0.3%, promote to shadow
      6. Shadow serves 5% traffic for 48h
      7. If shadow metrics match/exceed, promote to primary
    - **Monitoring:**
      - Model staleness alert: >14 days without successful update
      - Performance degradation: AUC drops >3% → alert + auto-rollback
      - Data drift detection: Feature distribution shifts (PSI >0.1)
  - **Evidence Required:**
    - Retraining success rate: >98% of weekly runs complete
    - Auto-rollback: Triggered 0 times in 6-month period (good model quality)
    - Continuous improvement: AUC trending upward over 6 months

### 8.7 Subject Line Intelligence (ONNX-Powered)

- [ ] **Train DeBERTa-v3-large Subject Line Effectiveness Model (ONNX)**
  - **Implementation:** State-of-the-art transformer for subject line scoring:
    - **Base:** `microsoft/deberta-v3-large` (304M params) - best encoder quality
    - **Training Data (1M+ examples):**
      - [Mailchimp benchmark data](https://mailchimp.com/resources/email-marketing-benchmarks/) (industry rates by sector)
      - [Kaggle Email Campaign datasets](https://www.kaggle.com/) (~200K labeled examples)
      - Public newsletter archives with engagement metrics (~300K)
      - Synthetic augmentation: GPT-4 paraphrasing + back-translation (~500K)
    - **Architecture:**
      - DeBERTa encoder → Mean pooling → MLP head (256 → 128 → 4)
      - Multi-task: Regression (open rate) + Classification (quartile bucket)
    - **Labels:** Normalized open rates (0-100 scale, industry-adjusted)
    - **Export:** ONNX INT8 quantized (~150MB), <40ms inference
  - **Evidence Required:**
    - Correlation: Spearman ρ >0.55 with actual open rates (holdout)
    - Classification accuracy: >70% quartile prediction
    - Cross-industry generalization: Tested on 5 different industries
    - Latency: <35ms p95 (ONNX INT8)

- [ ] **Implement Subject Line Feature Analyzer**
  - **Implementation:** Comprehensive analysis beyond ML score:
    - **Structural Features:**
      - Length score (optimal: 30-50 chars for mobile)
      - Word count (optimal: 4-8 words)
      - Preview text alignment
    - **Engagement Signals:**
      - Personalization detection (`{{name}}`, `{{company}}`)
      - Urgency indicators (deadline words, numbers)
      - Curiosity gap patterns (questions, incomplete statements)
      - Emoji presence + sentiment match
    - **Risk Factors:**
      - Spam trigger words (weighted by severity)
      - ALL CAPS percentage
      - Excessive punctuation
      - Misleading patterns (RE:, FW: when not reply)
    - **Competitive Intelligence:**
      - Compare to top-performing subjects in same category
      - Industry benchmark percentile
  - **Evidence Required:**
    - Feature accuracy: Manual validation of 500 subjects, >95% correct feature detection
    - Actionable feedback: Each feature has specific improvement suggestion

- [ ] **Implement Phi-3.5 Subject Line Generator (ONNX)**
  - **Implementation:** High-quality variant generation with constraints:
    - **Model:** Fine-tuned Phi-3.5-mini on subject line generation task
    - **Training Data:**
      - High-performing subject lines (top 10% open rates) paired with email context
      - Style variations: urgency, curiosity, benefit, social proof
      - ~50K examples with human-validated quality
    - **Generation Pipeline:**
      1. Analyze original subject + email body context
      2. Generate 5 variants using different strategies:
         - `urgency`: Time-sensitive framing
         - `curiosity`: Open loop / question
         - `benefit`: Clear value proposition
         - `social_proof`: Numbers, testimonials
         - `personalized`: Heavy personalization
      3. Score all variants with effectiveness model
      4. Return top 3 that score higher than original
    - **Constraints:**
      - Max 60 chars (mobile-friendly)
      - Preserve key entities from original
      - No clickbait (trained to avoid)
      - Brand voice consistency (configurable tone)
  - **Evidence Required:**
    - Quality: 80%+ of variants score higher than original
    - Diversity: Cosine similarity <0.7 between variant pairs
    - Speed: <800ms for 5 variants (ONNX Phi-3.5-mini)
    - Human eval: 75%+ of variants rated "as good or better" than original

- [ ] **Implement Real-Time Subject Line API**
  - **Implementation:** API endpoint `POST /v1/subject/analyze`:
    - **Request:**
      ```json
      {
        "subject": "Your weekly newsletter",
        "body_preview": "First 500 chars of email body...",
        "industry": "saas",
        "generate_variants": true
      }
      ```
    - **Response:**
      ```json
      {
        "score": 68,
        "percentile": 45,
        "grade": "C+",
        "factors": {
          "length": {"score": 90, "value": 22, "feedback": "Good length for mobile"},
          "personalization": {"score": 40, "feedback": "Add {{name}} for +8% open rate"},
          "urgency": {"score": 30, "feedback": "No time-sensitive elements detected"},
          "curiosity": {"score": 55, "feedback": "Moderate curiosity appeal"},
          "spam_risk": {"score": 95, "feedback": "Low spam trigger risk"}
        },
        "variants": [
          {"text": "{{name}}, your weekly insights (3 trends inside)", "score": 82, "strategy": "curiosity"},
          {"text": "📊 This week's must-see metrics for {{company}}", "score": 79, "strategy": "benefit"},
          {"text": "{{name}}: Don't miss these updates (expires Friday)", "score": 77, "strategy": "urgency"}
        ],
        "benchmark": {
          "industry_avg": 62,
          "top_10_pct": 78
        }
      }
      ```
  - **Evidence Required:**
    - API latency: <150ms p95 without variants, <500ms with variants
    - Availability: 99.9% uptime
    - Usage: 50%+ of marketing emails analyzed before send (tracked)

### 8.8 Intelligent Bounce & Deliverability Analysis (ONNX)

- [ ] **Train BGE-large Bounce Classifier (ONNX)**
  - **Implementation:** High-accuracy bounce classification:
    - **Base:** `BAAI/bge-large-en-v1.5` (335M params) - best embedding quality
    - **Architecture:** BGE encoder → Classification head (10 classes)
    - **Training Data:**
      - 500K+ labeled SMTP responses (anonymized production data)
      - Public bounce message datasets
      - Synthetic examples for rare categories
    - **Classes (hierarchical):**
      - `hard.invalid_mailbox`: Mailbox doesn't exist (550 5.1.1)
      - `hard.invalid_domain`: Domain doesn't exist (550 5.1.2)
      - `hard.policy_permanent`: Permanent policy rejection
      - `soft.mailbox_full`: Over quota (452 4.2.2)
      - `soft.temp_failure`: Temporary failure, retry later
      - `soft.greylisting`: Initial rejection, retry expected
      - `block.spam`: Classified as spam
      - `block.reputation`: IP/domain blacklisted
      - `block.dmarc`: DMARC policy failure
      - `block.content`: Content-based rejection
    - **Export:** ONNX INT8 (~170MB)
  - **Evidence Required:**
    - Accuracy: >99% on held-out test (5K manually labeled)
    - Per-class F1: >0.95 for all classes
    - Latency: <8ms per classification
    - Coverage: 99.99% of bounces classified (fallback: regex patterns)

- [ ] **Implement Real-Time Deliverability Health Score**
  - **Implementation:** Composite score tracking sender health:
    - **Components:**
      - Bounce rate (weighted by type)
      - Complaint rate (FBL data)
      - Engagement metrics (opens, clicks, replies)
      - Authentication pass rate (SPF, DKIM, DMARC)
      - Blacklist presence check
    - **Calculation:** Weighted moving average, updated per-send
    - **Alerts:**
      - Score <70: Warning notification
      - Score <50: Automatic sending pause (configurable)
      - Sudden drop >15 points: Immediate alert
  - **Evidence Required:**
    - Score correlation: >0.7 with actual inbox placement rate (seed testing)
    - Alert accuracy: 95%+ of alerts correspond to real deliverability issues

- [ ] **Implement Isolation Forest Anomaly Detection (ONNX)**
  - **Implementation:** Detect unusual bounce patterns:
    - **Model:** Isolation Forest with ONNX export
    - **Features:**
      - Bounce rate by category (10-element vector)
      - Bounce rate by receiving domain (top 50)
      - Hourly pattern deviation
      - Template-specific bounce rates
    - **Training:** Fit on 60 days of "normal" patterns
    - **Detection:** Anomaly score >0.85 triggers alert
  - **Evidence Required:**
    - Detection: 98%+ of simulated incidents caught within 15 minutes
    - False positive rate: <2 false alerts per week
    - Root cause suggestions: 80%+ accuracy in identifying cause

### 8.9 Email Content Intelligence Suite

- [ ] **Implement Ensemble Spam Score Predictor**
  - **Implementation:** Multi-model ensemble for pre-send spam prediction:
    - **Component 1:** SpamAssassin rules (local, rule-based)
    - **Component 2:** Fine-tuned DeBERTa-v3-base spam classifier (ONNX)
      - Trained on SpamAssassin corpus + Enron ham
      - Binary classification with probability
    - **Component 3:** Heuristic analyzer
      - Link-to-text ratio
      - Image-to-text ratio
      - HTML complexity score
      - Suspicious phrase dictionary
    - **Ensemble:** Stacked model (XGBoost) combining all scores
  - **Evidence Required:**
    - Correlation: >0.75 with actual Gmail/Outlook spam placement
    - Latency: <150ms for full content analysis
    - Actionable: Top 3 specific improvement recommendations

- [ ] **Implement Content Quality Analyzer**
  - **Implementation:** Comprehensive content checking:
    - **Personalization Validation:**
      - All `{{tokens}}` have corresponding data
      - Fallback values for missing data
      - Offensive combination detection (gender/name mismatch)
    - **Link Validation (async):**
      - All URLs reachable (cached, async check)
      - No broken redirect chains
      - UTM parameter validation
    - **Accessibility Check:**
      - Alt text for images
      - Sufficient color contrast
      - Screen reader compatibility
    - **Mobile Rendering Preview:**
      - Width compatibility
      - Font size adequacy
      - Touch target sizes
  - **Evidence Required:**
    - Error catch rate: 100% of missing tokens detected
    - False positive rate: <0.05%
    - Link check latency: <2s for typical email (cached)

### 8.10 AI System Observability & MLOps

- [ ] **Implement Comprehensive Model Monitoring Dashboard**
  - **Implementation:** Grafana + Prometheus for full observability:
    - **Inference Metrics:**
      - Latency histograms (p50, p95, p99) by model
      - Throughput (requests/sec)
      - Token generation rate (for generative models)
      - Batch size distribution
    - **Resource Metrics:**
      - Memory usage by model session
      - CPU utilization per model
      - ONNX Runtime thread pool saturation
    - **Quality Metrics:**
      - Prediction distribution drift
      - Confidence score distribution
      - Safety filter trigger rates
      - User feedback scores (rolling 7-day)
    - **Business Metrics:**
      - STO lift (open rate improvement)
      - Subject line adoption rate
      - Escalation rate trend
  - **Evidence Required:**
    - Dashboard with all metrics, 30-day retention
    - Alert rules for anomalies (documented thresholds)

- [ ] **Implement Feature Store Monitoring**
  - **Implementation:** Track feature freshness and quality:
    - Feature staleness alerts (>1h without update)
    - Feature distribution monitoring (PSI alerts)
    - Missing value rates
    - Join failure rates (feature lookup misses)
  - **Evidence Required:**
    - 99.9% feature availability
    - <0.1% staleness rate during normal operation

- [ ] **Implement Model A/B Testing Framework**
  - **Implementation:** Rigorous experimentation system:
    - **Traffic Splitting:** Deterministic hash on tenant_id + experiment_id
    - **Metrics Collection:** All relevant metrics per variant
    - **Statistical Analysis:**
      - Bayesian inference for early stopping
      - Power analysis for sample size
      - Novelty effect detection (time-series analysis)
    - **Guardrails:** Auto-stop if degradation >threshold
    - **Documentation:** Auto-generated experiment report
  - **Evidence Required:**
    - Run 5+ experiments with documented outcomes
    - Decision framework: Clear criteria for winner selection

- [ ] **Implement Human-in-the-Loop Feedback System**
  - **Implementation:** Continuous learning from user feedback:
    - **Collection:**
      - 👍/👎 on AI support responses
      - Subject line A/B test results
      - Escalation reasons (human agent input)
      - Correction submissions
    - **Processing:**
      - Weekly aggregation of feedback
      - Automated dataset curation (positive examples → training)
      - Negative examples → error analysis
    - **Reporting:**
      - Weekly feedback summary
      - Low-performing response categories
      - Improvement recommendations
  - **Evidence Required:**
    - >25% feedback rate on AI interactions
    - Positive rating trend: >88% after 6 months
    - Monthly model improvements based on feedback

- [ ] **Implement Comprehensive AI Audit Trail**
  - **Implementation:** Full traceability for compliance + debugging:
    - **Logged per Request:**
      - Request ID, timestamp, user/tenant ID
      - Model version + ONNX session ID
      - Full prompt (PII redacted via NER)
      - Inference parameters (temperature, max_tokens, etc.)
      - Raw model output
      - Safety filter decisions (with scores)
      - Final response (post-processing)
      - Latency breakdown (queue, inference, post-processing)
    - **Storage:**
      - Hot: 30 days in Postgres (indexed on request_id, tenant_id, timestamp)
      - Cold: 2 years in S3 (Parquet, partitioned by date)
    - **Query Interface:**
      - Full-text search on prompts/responses
      - Filter by safety flags, latency, model version
      - Replay capability (re-run with current model)
  - **Evidence Required:**
    - Query any request by ID in <1s
    - GDPR Article 22 compliance: Explain any automated decision
    - Replay accuracy: Re-run produces consistent results

---

## Phase 9: Testing & "Perfect Product" Gates

*Goal: Measurable perfection.*

### 9.1 Test Pyramid

- [ ] **Implement End-to-End (E2E) Suite**
  - **Implementation:** Signup -> Domain -> Send -> Verify Delivery -> Invoice.

  - **Evidence Required:** Video recording or trace log of a fully automated E2E run.

- [ ] **Implement Chaos Suite**
  - **Implementation:** Randomly kill pods, saturate disk, rotate keys mid-flight.

  - **Evidence Required:** System recovery logs showing automatic self-healing without manual intervention.

### 9.2 Guardrails

- [ ] **Implement Disk & Resource Guardrails**
  - **Implementation:** Daemon checking disk usage. >85% = Prune Cache. >92% = 503 Safe Mode.

  - **Evidence Required:** "Disk Fill Drill" report showing system gracefully entering safe mode.

- [ ] **Implement Deployment Gates**
  - **Implementation:** Block deploy if Migration Fingerprint fails or E2E fails.

  - **Evidence Required:** CI log showing a blocked deployment due to a failed "Canary" check.

- [ ] **Implement Visual Regression Gates (Console + Control Plane)**
  - **Implementation:** Snapshot testing for critical pages (Dashboard, Templates, Billing, Compliance Admin). Fail CI on pixel diffs beyond threshold.
  - **Evidence Required:** CI run showing failure on unintended UI diff; approved diff updates the baseline.

---

## Phase 10: Operations & SLOs [ApexMediation Alignment]

*Goal: Transparent, high-trust operations.*

### 10.1 Public SLOs

- [ ] **Define and Publish SLIs/SLOs**
  - **Implementation:** Latency < 200ms (p95), Availability 99.9%.

  - **Evidence Required:** Link to `/slo` page showing live graphs vs targets (matching ApexMediation style).

- [ ] **Implement "Signed Log" Verification for Customers**
  - **Implementation:** Feature allowing customers to download a signed proof of their delivery logs.
  - **Evidence Required:** Cryptographic verification tool output validating a customer's log export.

- [ ] **Implement Public "Trust Center" (ApexMediation Style)**
  - **Implementation:** A dedicated `/trust` page showing live uptime, security posture (last audit, compliance checks), and sub-processor status. "Radical Transparency".
  - **Evidence Required:** `/trust` page accessible without login, showing "All Systems Operational" and "Last Security Scan: 2 hours ago".

### 10.2 Maintenance

- [ ] **Create Automated Maintenance Jobs**
  - **Implementation:** Vacuum, Rotation, Cold Storage Compaction.

  - **Evidence Required:** Cron logs showing successful execution of maintenance tasks over 7 days.

- [ ] **Disaster Recovery Game Day**
  - **Implementation:** Full restore from offsite backup to new hardware.

  - **Evidence Required:** RTO (Recovery Time Objective) measurement from the last Game Day (Target: < 2 hours).

---

## Phase 11: Billing, Metering & Monetization

*Goal: Accurate usage tracking, seamless payments, enterprise-ready billing.*

### 11.1 Usage Metering

- [ ] **Implement Idempotent Event Metering**
  - **Implementation:** Meter: emails sent, API calls, webhooks delivered, dedicated IPs. Use event UUIDs for exactly-once counting.

  - **Evidence Required:** Duplicate event injection -> Counter unchanged; Reconciliation report showing 0 discrepancy.

- [ ] **Implement Real-Time Usage Dashboard**
  - **Implementation:** Customer-facing usage graphs (daily/monthly). Show current vs plan limit.
 High-contrast vector charts (Recharts/Visx) matching ApexMediation style.  - **Evidence Required:** Screenshot of dashboard showing usage bar at 75% with projected overage warning.

- [ ] **Implement Usage Alerts**
  - **Implementation:** Email notifications at 50%, 80%, 100% of plan limit. Configurable thresholds.

  - **Evidence Required:** Test tenant hitting 80% -> Email received within 1 minute.

### 11.2 Billing Infrastructure

- [ ] **Implement Plan Management**
  - **Implementation:** CRUD for pricing tiers (Starter: 10K/mo, Growth: 100K/mo, Scale: 1M/mo). Feature flags per plan.

  - **Evidence Required:** Admin UI showing plan editor with feature toggles (dedicated IP, API access, etc.).

- [ ] **Implement "Infrastructure Pricing" Engine**
  - **Implementation:** Support for non-CPM line items: "Dedicated Instance Fee", "Throughput Reservation (emails/sec)", "SLA Premium".

  - **Evidence Required:** Invoice generated with "$3,000 Platform Fee" + "$500 Reserved Capacity" (independent of volume).

- [ ] **Implement Proration Engine**
  - **Implementation:** Mid-cycle upgrade/downgrade calculated correctly. Credit remaining days, charge new rate.

  - **Evidence Required:** Test: Upgrade on day 15 of 30-day cycle -> Invoice shows correct prorated amounts.

- [ ] **Implement Invoice Generation**
  - **Implementation:** PDF invoices with line items, VAT (Estonian 22%), adjustments. Estonian e-Invoice XML export.

  - **Evidence Required:** Generated invoice PDF matching Estonian tax authority format; XML validates against e-Invoice schema.

- [ ] **Implement Payment Processing**
  - **Implementation:** Stripe-only billing via Stripe Billing + webhooks. Use Stripe as the system of record for: customers, subscriptions, invoices, payments, refunds.

  - **Implementation:**
    - Create Stripe `Customer` per tenant.
    - Create Stripe `Subscription` per plan (usage-based or tiered if desired).
    - Use Stripe `Checkout Session` for initial payment method capture.
    - Verify webhook signatures (`Stripe-Signature`) and process events idempotently.
    - Maintain an internal mirror table keyed by Stripe IDs for fast reads and audits.

  - **Evidence Required:** E2E (Stripe test mode): checkout -> subscription active -> invoice paid -> entitlement flags update within 60 seconds.

  - **Evidence Required:** Webhook replay test: replay the same event twice -> internal state changes exactly once.

- [ ] **Implement Dunning Sequence**
  - **Implementation:** Failed payment retry: Day 1, 3, 7, 14. Soft-suspend at Day 7 (queue but don't send). Hard-suspend at Day 21. Grace period: queued messages retained for 7 days after hard-suspend, then purged with notification.

  - **Evidence Required:** Timeline log showing correct state transitions during simulated payment failure; Queued messages during soft-suspend -> Payment resolved -> Messages sent; Hard-suspend + 8 days -> Queued messages purged, tenant notified.

- [ ] **Implement Refund & Credit System**
  - **Implementation:** Stripe-only refunds and credits. Support Stripe `Refund` and (if needed) Stripe `Credit Note` flows; mirror results internally.

  - **Evidence Required:** Create refund in test mode -> Stripe emits refund events -> internal invoice status and customer balance reflect the refund.

- [ ] **Implement SLA Credit Automation**
  - **Implementation:** When uptime SLO breached, automatically calculate and apply service credit per contract terms.

  - **Evidence Required:** SLO breach detected (99.8% vs 99.9% target) -> Credit memo auto-generated -> Customer notified.

### 11.3 Enterprise Billing

- [ ] **Implement Contract Management**
  - **Implementation:** Custom pricing, committed volumes, annual prepay discounts, SLA credits.

  - **Evidence Required:** Contract PDF with custom terms; Credit auto-applied when SLO breached.

- [ ] **Implement Purchase Order Support**
  - **Implementation:** PO reference field on invoices. Net-30/60 payment terms.

  - **Evidence Required:** Invoice showing PO number; Payment due date = Invoice date + 30 days.

### 11.4 Revenue Optimization & Growth

- [ ] **Implement "Powered by ApexMail" Viral Loop**
  - **Implementation:** Injects "Powered by ApexMail" footer in all Free Tier emails. Tracking link with UTM attribution.

  - **Evidence Required:** Click on footer -> Lands on Sign-up page -> Attribution recorded in cookie.

- [ ] **Implement "Cost Circuits" (Margin Protection)**
  - **Implementation:** Real-time calculation of (object storage cost + bandwidth) per tenant. If Cost > Revenue, trigger alert/throttle.

  - **Evidence Required:** "Expensive Tenant" simulation -> Alert fired when margin drops below 20%.

- [ ] **Implement Pre-Paid "Wallet" System**
  - **Implementation:** Account balance ledger. Crypto-friendly top-up capability (manual manual flow initially).

  - **Evidence Required:** Balance reaches 0 -> Outbound sending paused immediately (synchronous check).

---

## Phase 12: Developer Experience (DX)

*Goal: Best-in-class API, SDKs, and developer tooling.*

### 12.1 API Excellence

- [ ] **Implement API Versioning**
  - **Implementation:** URL versioning (`/v1/`). 12-month deprecation policy. Sunset header on deprecated endpoints.

  - **Evidence Required:** `/v1/send` and `/v2/send` both functional; v1 returns `Sunset: <date>` header.

- [ ] **Implement Idempotency Keys**
  - **Implementation:** `Idempotency-Key` header support. Store result for 24h. Replay on duplicate key.

  - **Evidence Required:** Same key twice -> Same response, single database write.

- [ ] **Implement Request Tracing**
  - **Implementation:** Return `X-Request-ID` in all responses. Searchable in logs for support.

  - **Evidence Required:** Support workflow: Customer provides request ID -> Operator finds full trace in 30s.

- [ ] **Implement Rate Limit Headers**
  - **Implementation:** `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` on all responses.

  - **Evidence Required:** Client SDK correctly pausing when `Remaining: 0`.

- [ ] **Implement Bulk Send Endpoint**
  - **Implementation:** `POST /v1/send/batch` accepting up to 1000 recipients. Single API call, single response.
  - **Evidence Required:** Benchmark: 1000 emails via batch vs 1000 individual calls -> 10x latency improvement.

- [ ] **Implement Cursor-Based Pagination**
  - **Implementation:** All list endpoints use cursor pagination (`?cursor=xxx&limit=100`). Return `next_cursor` in response. No offset-based pagination (performance cliff).
  - **Evidence Required:** List 10M messages -> Consistent <100ms response time regardless of page depth; `next_cursor` allows resumption after interruption.

### 12.2 Webhooks

- [ ] **Implement Webhook Signatures**
  - **Implementation:** HMAC-SHA256 signature in `X-ApexMail-Signature`. Include timestamp to prevent replay.

  - **Evidence Required:** Signature verification code sample in docs; Replay attack blocked after 5 min.

- [ ] **Implement Webhook Retry with Backoff**
  - **Implementation:** Exponential backoff: 1s, 2s, 4s, 8s... up to 24 hours. Dead-letter after 72h. Connection timeout: 10s. Response timeout: 30s. Circuit breaker: disable webhook after 10 consecutive failures, require manual re-enable.

  - **Evidence Required:** Webhook log showing retry timestamps matching exponential schedule; Slow endpoint (35s response) -> Timeout logged -> Retry scheduled; 10 consecutive failures -> Webhook status "Disabled (circuit open)".

- [ ] **Implement Webhook Logs & Replay**
  - **Implementation:** Searchable history of payloads and responses. Manual "Replay" button in UI.

  - **Evidence Required:** Screenshot: Failed webhook -> Click replay -> Success.

- [ ] **Implement Event Types**
  - **Implementation:** Granular subscription: `delivered`, `bounced`, `opened`, `clicked`, `complained`, `unsubscribed`.

  - **Evidence Required:** Tenant subscribed only to `bounced` -> Only receives bounce webhooks.

### 12.3 SDKs & Tooling

- [ ] **Publish OpenAPI Specification**
  - **Implementation:** OpenAPI 3.0 spec at `/openapi.json`. Auto-generate from code annotations.
  - **Add-On:** Publish Zod / Pydantic / Go Struct definitions to a separate `@apexmail/types` package for developer convenience.
  - **Evidence Required:** `import { SendRequest } from '@apexmail/types'` functional in a user's TS project.

- [ ] **Create Official SDKs (Automated Pipeline)**
  - **Implementation:** Use `openapi-generator-cli` or `fern` to auto-generate SDKs for Node.js, Python, Go, and Java on every API release.

  - **Evidence Required:** CI/CD pipeline log shows SDK generation + tests + publish (npm, PyPI) tagged with API version; `npm install @apexmail/sdk` works and can send in 5 lines of code.

- [ ] **Create CLI Tool**
  - **Implementation:** `apexmail send --to=user@example.com --subject="Test" --body="Hello"`.

  - **Evidence Required:** CLI demo video showing send, status check, and log tail.

- [ ] **Implement Sandbox Mode**
  - **Implementation:** API key flag `sandbox: true`. Full functionality, no actual sending. Emails captured for inspection. Webhooks fire to a "Sandbox Webhook Log" instead of customer endpoint.

  - **Evidence Required:** Sandbox send -> Email appears in "Test Inbox" UI, not delivered externally; Webhook event logged in "Sandbox Webhook Log" with full payload visible in dashboard.

- [ ] **Implement Email Preview API**
  - **Implementation:** `POST /v1/preview` -> Render template with variables, return HTML + plaintext + screenshot.

  - **Evidence Required:** Preview response includes rendered HTML and base64 PNG screenshot.

- [ ] **Implement Local Mock Server**
  - **Implementation:** `npx @apexmail/mock-server` spins up local API that mimics production. Captures all requests for inspection.

  - **Evidence Required:** Developer runs mock server -> SDK sends email -> Mock captures payload -> No external network call made.

- [ ] **Implement Postman/Insomnia Collection**
  - **Implementation:** One-click import collection with all endpoints, example requests, and environment variables.

  - **Evidence Required:** Import collection -> Run "Send Email" request -> Success response with all fields documented.

---

## Phase 13: High Availability & Disaster Recovery

*Goal: 99.9%+ uptime, <15 min RTO, <1 min RPO.*

### 13.1 Multi-Region Architecture

- [ ] **Implement Active-Passive Database Replication**
  - **Implementation:** Postgres streaming replication to secondary region. Automatic failover via Patroni.

  - **Evidence Required:** Failover drill: Kill primary -> Secondary promoted in <30s -> API continues serving.

- [ ] **Implement Queue Replication**
  - **Implementation:** Postgres-backed queue with replication. No message loss on region failure.

  - **Evidence Required:** Kill primary region mid-flight -> Messages delivered from secondary.

- [ ] **Implement DNS-Based Failover**
  - **Implementation:** Health-checked DNS (self-hosted PowerDNS or any DNS provider). Automatic failover on region health check failure.

  - **Evidence Required:** DNS TTL 60s; Failover observed within 2 minutes of simulated outage.

### 13.2 Graceful Degradation

- [ ] **Implement Read-Only Mode**
  - **Implementation:** If DB write fails, queue to local disk. Drain when DB recovers.

  - **Evidence Required:** DB disconnect -> API returns 202 Accepted -> Emails sent after recovery.

- [ ] **Implement Feature Flags for Load Shedding**
  - **Implementation:** Disable non-critical features (tracking pixels, webhooks) under extreme load.

  - **Evidence Required:** Load test: 10x normal traffic -> Tracking disabled, core delivery continues.

- [ ] **Implement Circuit Breakers**
  - **Implementation:** Per-MX circuit breakers. Open on 50% failure rate. Half-open after 60s.

  - **Evidence Required:** Gmail MX returning 421 -> Circuit opens -> No further attempts for 60s.

### 13.3 Backup & Recovery

- [ ] **Implement Continuous WAL Archiving**
  - **Implementation:** WAL shipped to object storage every 60s. Point-in-time recovery to any second.

  - **Evidence Required:** PITR test: Restore to timestamp 5 minutes ago -> Data matches.

- [ ] **Implement Offsite Backup Verification**
  - **Implementation:** Daily automated restore to isolated environment. Schema + sample data validation.

  - **Evidence Required:** Daily backup verification report showing successful restore for last 30 days.

- [ ] **Implement Backup Encryption (At Rest & In Transit)**
  - **Implementation:** AES-256 encryption for all backups. Key stored separately from data (OS keyring or HSM). TLS for WAL shipping. Support key rotation without re-encrypting old backups (store key version metadata).

  - **Evidence Required:** Backup file inspection shows encrypted blob; Restore fails without correct key; Key rotation test: rotate key -> new backup uses new key -> old backup still restorable with old key (retrieved via version metadata).

- [ ] **Implement Immutable Backup Retention**
  - **Implementation:** Object lock / WORM compliance for backup storage. Prevent deletion even by admin for retention period.

  - **Evidence Required:** Attempt to delete 7-day-old backup -> Operation denied; Backup older than retention -> Auto-deleted.

---

## Phase 14: Observability & Distributed Tracing

*Goal: Full visibility into the email pipeline. Debug any issue in <5 minutes.*

### 14.1 OpenTelemetry Integration

- [ ] **Implement Trace Context Propagation**
  - **Implementation:** W3C Trace Context through async queues. Span per stage: accept→render→queue→send→deliver.

  - **Evidence Required:** Jaeger/Tempo trace showing full journey of single email from API to delivery.

- [ ] **Implement Custom Metrics**
  - **Implementation:** Prometheus metrics: `emails_sent_total{tenant,status}`, `bounce_rate{tenant,type}`, `delivery_latency_seconds{p50,p95,p99}`.

  - **Evidence Required:** Grafana dashboard showing all SLI metrics with 7-day history.

- [ ] **Implement Structured Logging**
  - **Implementation:** JSON logs with consistent schema. Fields: `trace_id`, `tenant_id`, `message_id`, `stage`, `duration_ms`.

  - **Evidence Required:** Log query: `trace_id=X` returns ordered logs from all services for that request.

- [ ] **Implement "Live Topology" Visualization**
  - **Implementation:** Real-time visual map of the infrastructure (MTA nodes, Queues, DBs) with traffic flow animations (Particle UI). Align with ApexMediation's "technological transparency" aesthetic.
  - **Evidence Required:** Visualization in Admin Dashboard showing active traffic flowing from API -> Queue -> MTA nodes.

### 14.2 Alerting & Incident Response

- [ ] **Implement SLO-Based Alerts**
  - **Implementation:** Alert when burn rate exceeds monthly error budget. (e.g., 1% monthly budget burned in 1 hour = page)

  - **Evidence Required:** Alert fired during chaos test; Alertmanager notification delivered to email/Matrix/Mattermost (optional Slack via webhook bridge).

- [ ] **Implement Anomaly Detection**
  - **Implementation:** Baseline bounce rate per tenant. Alert on 3σ deviation.

  - **Evidence Required:** Simulated spam campaign -> Alert: "Tenant X bounce rate 15% (baseline 2%)".

- [ ] **Implement IP Blocklist Monitoring**
  - **Implementation:** Hourly check against Spamhaus, Barracuda, SORBS. Alert on listing.

  - **Evidence Required:** Test IP added to mock blocklist -> Alert within 1 hour.

### 14.2.1 Public Status & Incident Communication

- [ ] **Implement Public Status Page**
  - **Implementation:** Self-hosted status page (e.g., Cachet or custom). Components: API, SMTP, Dashboard, Webhooks. Auto-update from health checks.

  - **Evidence Required:** Simulated API degradation -> Status page shows "API: Degraded" within 2 minutes.

- [ ] **Implement Incident Timeline**
  - **Implementation:** Chronological incident log with updates. RSS feed for subscribers. Post-incident reports (RCA).

  - **Evidence Required:** Major incident -> Timeline shows: Detected -> Investigating -> Mitigated -> Resolved with timestamps.

- [ ] **Implement Maintenance Window Scheduler**
  - **Implementation:** Schedule maintenance with advance notice. Status page shows upcoming maintenance. Email notification to affected tenants.

  - **Evidence Required:** Schedule maintenance for Sunday 3AM -> Status page shows banner 48h in advance -> Tenant receives email.

### 14.3 PII Protection in Logs

- [ ] **Implement Log Redaction**
  - **Implementation:** Auto-redact email bodies, mask addresses in logs (`j***@example.com`).

  - **Evidence Required:** Grep of 7-day logs showing 0 unmasked email addresses.

- [ ] **Implement Audit Log Retention**
  - **Implementation:** Hot (7d) → Warm (30d) → Cold (1y) → Archive/Delete.

  - **Evidence Required:** Storage report showing correct tier distribution.

### 14.3.1 Forensic Render Snapshots (Time-Travel)

- [ ] **Implement Rendered Artifact Storage**
  - **Implementation:** Store GZIP-compressed HTML of sent body in S3/MinIO bucket `artifacts/{date}/{message_id}.html.gz` for 7 days.

  - **Evidence Required:** Fetch message ID from today -> API returns exact HTML; Fetch message ID from 8 days ago -> 404 (Expired).

---

## Phase 15: Multi-Tenant Isolation (Enterprise)

*Goal: True isolation for enterprise customers. Prevent noisy neighbor.*

### 15.1 Resource Isolation

- [ ] **Implement Per-Tenant Rate Limits**
  - **Implementation:** Token bucket per tenant. Configurable burst and sustained rates.

  - **Evidence Required:** Tenant A at limit -> Tenant B unaffected (latency graph comparison).

- [ ] **Implement Per-Tenant Queue Depth Limits**
  - **Implementation:** Max 100K queued messages per tenant. Return 429 when exceeded.

  - **Evidence Required:** Load test: Tenant exceeds limit -> 429 returned, other tenants continue.

- [ ] **Implement Dedicated Egress IPs (Enterprise)**
  - **Implementation:** Enterprise tier gets dedicated sending IPs. IP assigned at onboarding.

  - **Evidence Required:** Two enterprise tenants -> Different `Received` headers showing different source IPs.

### 15.2 Data Isolation

- [ ] **Implement Row-Level Security**
  - **Implementation:** Postgres RLS policies: `CREATE POLICY tenant_isolation ON messages USING (tenant_id = current_setting('app.tenant_id'))`.

  - **Evidence Required:** Pen test report: 0 cross-tenant data access vulnerabilities.

- [ ] **Implement Tenant Data Export**
  - **Implementation:** Full data export (JSON/CSV) for tenant offboarding or GDPR portability.

  - **Evidence Required:** Export -> Import to test DB -> Row counts match.

---

## Phase 16: Edge Cases & Advanced Handling

*Goal: Handle the 1% of emails that cause 90% of support tickets.*

### 16.1 Email Content Edge Cases

- [ ] **Implement Internationalized Email (EAI)**
  - **Implementation:** Support UTF-8 in local-part and domain (RFC 6531). SMTPUTF8 extension negotiation. Normalize Unicode (NFC) on input. Explicit `Content-Type: text/html; charset=utf-8` headers.

  - **Evidence Required:** Email to `用户@例子.中国` delivered successfully; Subject with emoji renders correctly; Body with mixed scripts (Cyrillic + Latin) displays without mojibake.

- [ ] **Implement Attachment Handling**
  - **Implementation:** Virus scan (ClamAV), size limits (25MB per attachment, 35MB total message including encoding overhead), type restrictions (.exe blocked), inline vs attached.

  - **Evidence Required:** Upload .exe -> Rejected; Upload 30MB -> Rejected; Upload 5MB PDF -> Delivered; 25MB attachment + 15MB attachment -> Rejected (exceeds 35MB total).

- [ ] **Implement Email Size Pre-Check**
  - **Implementation:** API validates estimated MIME size before queuing. Return 413 "Payload Too Large" with specific limit. Prevents MTA rejection downstream.

  - **Evidence Required:** API call with 40MB body -> 413 returned before any queue write; Error message shows "Max message size: 35MB".

- [ ] **Implement Calendar Invite Support**
  - **Implementation:** Proper `text/calendar` MIME handling. ICS attachment rendering in preview.

  - **Evidence Required:** Calendar invite email -> Shows "Accept/Decline" buttons in Gmail/Outlook.

### 16.2 Delivery Edge Cases

- [ ] **Implement Greylisting Retry**
  - **Implementation:** Detect 4XX greylisting responses. Retry after 5 minutes (not immediately).

  - **Evidence Required:** Log showing: First attempt 450 -> Retry at +5min -> 250 OK.

- [ ] **Implement Loop Detection**
  - **Implementation:** `Received` header count check. Reject if >25 hops.

  - **Evidence Required:** Simulated loop -> Email rejected with "Too many hops" error.

- [ ] **Implement Auto-Responder Detection**
  - **Implementation:** Classify OOO replies. Don't count as bounce, don't trigger retry.

  - **Evidence Required:** 50 sample auto-replies correctly classified (not bounced, not retried).

- [ ] **Implement MX Failover Logic**
  - **Implementation:** On primary MX failure (timeout or 5XX), automatically try secondary/tertiary MX records in priority order. Log which MX accepted delivery.

  - **Evidence Required:** Mock primary MX to return 421 -> System attempts secondary MX -> Delivery succeeds; Log shows "Delivered via MX priority 20 (backup.example.com)".

---

## Phase 17: Enterprise Infrastructure (The "Whale" Tier)

*Goal: Capture $5k - $50k/mo contracts via compliance, control, and isolation.*

### 17.1 Infrastructure-as-a-Service Models

- [ ] **Implement "ApexMail Private" (Single Tenant)**
  - **Implementation:** Terraform module to deploy a fully isolated `MTA + DB + API` stack into a dedicated VPC or subnet.

  - **Evidence Required:** "Private Deploy" test; 0% resource overlap with public multi-tenant cloud.

- [ ] **Implement BYOIP (Bring Your Own IP)**
  - **Implementation:** Support for binding outbound SMTP interface to customer-owned IP ranges (/24 blocks). Requires customer to delegate reverse DNS and update SPF.

  - **Evidence Required:** Customer-owned IP configured -> Test email shows customer IP in `Received` header; Reverse DNS resolves to customer domain; SPF check passes.

  - **Evidence Required:** Email sent from "Private Tenant" shows `Received: from mail.customer-owned-domain.com [1.2.3.4]` (Customer IP).

- [ ] **Implement "Log Streaming" to Customer S3**
  - **Implementation:** Firehose-style pusher. API accepts customer S3-compatible credentials -> Real-time JSON dump of all events.

  - **Evidence Required:** Send email -> Check customer bucket -> `2026/02/01/log-1.json.gz` appears within 60s.

### 17.2 Agency & Reseller Capabilities

- [ ] **Implement Sub-Account API**
  - **Implementation:** `POST /v1/subaccounts`. Master API Key can manage child accounts, limit their volume, and view their aggregate stats.

  - **Evidence Required:** Agency Account creates "Client A" -> Client A sends email -> Agency dashboard shows "Client A: 1 Sent".

- [ ] **Implement "White-Label" Dashboard**
  - **Implementation:** Ability to CNAME the dashboard (`email.agency.com`), remove ApexMail branding, and inject Agency logo.

  - **Evidence Required:** Login flow via custom domain; all "ApexMail" references replaced by "AgencyName".

### 17.3 Enterprise Governance

- [ ] **Implement Template Approval Workflow**
  - **Implementation:** Enterprise flag `require_template_approval: true`. New/edited templates go to "Pending Approval" state. Designated approvers can approve/reject with comments. Only approved templates can be used for sending.

  - **Evidence Required:** Create template -> Status "Pending" -> Attempt send -> 400 "Template not approved"; Approver approves -> Status "Approved" -> Send succeeds; Audit log shows approver, timestamp, and approval comment.

- [ ] **Implement SSO (SAML/OIDC)**
  - **Implementation:** Default: self-hosted IdP (Keycloak) via SAML/OIDC. Optional enterprise IdPs: Okta/AzureAD. Enforce "SSO Only" login policy for enterprise tenants.

  - **Evidence Required:** Login attempt with password -> Rejected; Login via Okta Simulation -> Success.

- [ ] **Implement HIPAA / BAA Compliance Mode**
  - **Implementation:** "Zero-Retention" flag for message bodies (processed in RAM, never written to disk, only metadata logged).

  - **Evidence Required:** Send Sensitive Email -> Review all DB tables/Logs -> No Subject/Body text found anywhere on disk.

### 17.4 Enterprise Support Infrastructure

- [ ] **Implement Priority Support Queue**
  - **Implementation:** Enterprise tickets routed to dedicated queue. SLA: 1h response, 4h resolution for P1.

  - **Evidence Required:** Enterprise tenant submits P1 ticket -> Response within 1 hour -> SLA timer visible in ticket.

- [ ] **Implement Dedicated Slack/Teams Channel**
  - **Implementation:** Default: Matrix/Mattermost shared channel. Optional: Slack/Teams via a bridge. Two-way sync with ticketing system.

  - **Evidence Required:** Message in Slack -> Ticket created automatically; Ticket update -> Slack notification.

- [ ] **Implement Customer Success Health Dashboard**
  - **Implementation:** Internal view per enterprise: usage trends, support tickets, NPS, renewal risk score.

  - **Evidence Required:** Dashboard showing "Acme Corp: Usage ↓20%, 3 open tickets, Renewal Risk: Medium".

- [ ] **Implement Quarterly Business Review (QBR) Automation**
  - **Implementation:** Auto-generate QBR deck: usage stats, deliverability trends, feature adoption, recommendations.
  - **Evidence Required:** "Generate QBR" button -> PDF with charts and insights ready for customer meeting.

---

## Phase 18: Public Marketing Website (The Sales Machine)

*Goal: Convert developers and CTOs by selling the "Killer Features" directly.*

### 18.1 "Killer Feature" Landing Pages

- [ ] **Implement "Compliance-as-Code" Landing Page**
  - **Implementation:** Dedicated page selling the "Consent Ledger", "Auto-DPA", and "Right-to-be-Forgotten" cascade. Use 3D diagrams of the immutable hash chain.
  - **Hero Copy:** "The First Email API That Keeps You Out of Court."
  - **Visual:** Glass-panel visualization of a "Signed Log" verifying a delivery.

- [ ] **Implement "Private Cloud" Landing Page**
  - **Implementation:** Sell the Single-Tenant Model (Phase 17.1). "Your VPC, Your IP, Our Code."
  - **Interactive Element:** "Latencimeter" comparing Shared Grid (jittery) vs Private Core (flatline).
  - **Call to Action:** "Deploy Private Instance" (Links to Sales/Cal.com).

- [ ] **Implement "Forensic Debugging" Showcase**
  - **Implementation:** Interactive demo of the "Time Travel" render history (Phase 14.3.1). Allow visitors to "scrub" a timeline of a broken email and see code changes.
  - **Hero Copy:** "Stop Guessing. See Exactly What They Saw."

### 18.2 Developer Conversion Tools

- [ ] **Implement "Live API Console" (No Login)**
  - **Implementation:** Integrated REPL on the homepage. tailored `curl` command generator.
  - **Action:** User types "Startups", clicks "Send" -> Real email arrives in their inbox (using cached/rate-limited demo tier).
  - **Evidence Required:** Homepage visitor sends test email in < 10 seconds without credit card.

- [ ] **Implement "Cost vs SendGrid" Calculator**
  - **Implementation:** Slider for "Monthly Volume" + checkboxes for "Dedicated IP", "SSO". Shows ApexMail vs Competitor pricing.
  - **Differentiation:** Highlight "ApexMail Private" flat fee vs CPM scaling of others.
  - **Evidence Required:** Calculator shows accurate pricing breakdowns for volumes from 10K to 1M emails/month.
---

## ⚔️ Competitive Differentiators (The "Killer" Features)

*Why customers will choose ApexMail over SendGrid, Mailchimp, or AWS SES.*

### 1. Automated EU Compliance & Bureaucracy (Phase 6.5)

- **Status Quo:** GDPR compliance is a nightmare of manual PDFs, separate "Consent Management Platforms", and expensive legal audits.
- **ApexMail Advantage:** Native "Consent Ledger" (immutable), auto-generated DPAs, instant "Right-to-be-Forgotten" cascades, and ROPA generation.
- **The Killer Feature:** **Compliance-as-Code**. You are instantly audit-ready for the strictest EU regulators.
- **Quality Gate:** DSAR workflow test + signed audit export verification.

### 2. Cryptographic "Proof of Delivery" (Phase 6.5 + 10.1)

- **Status Quo:** You trust SendGrid's logs. If they say "Delivered" but the user says "Not Received", you have no proof.
- **ApexMail Advantage:** Every log row is cryptographically signed (hash-chain). Customers can verify the integrity of their delivery history.
- **The Killer Feature:** **Verifiable Truth**. Essential for legal/fintech use cases.
- **Quality Gate:** Verification tool detects any tampering in daily signed log snapshot.

### 3. "Active Defense" Security Core (Phase 1.6)

- **Status Quo:** Security is a firewall. If an attacker breaches the DB, they dwell silently for months.
- **ApexMail Advantage:** Native "Honeytokens" (fake users) and "Canary Tokens" (fake config strings) that scream if touched.
- **The Killer Feature:** **Intrusion Awareness**. The system actively hunts for attackers inside itself.
- **Quality Gate:** Canary/honeytoken access triggers alert within 10 seconds.

### 4. True Single-Tenant Vending (Phase 17.1)

- **Status Quo:** "Enterprise" plans usually mean "Priority Support" and a "Static IP" on a shared cluster. Noisy neighbors still affect your API latency.
- **ApexMail Advantage:** "ApexMail Private" deploys a completely isolated replica (VPC, DB, API) via Terraform.
- **The Killer Feature:** **Physical Isolation**. Zero noisy neighbor risk, perfect HIPAA/GDPR alignment.
- **Quality Gate:** "Private Deploy" test shows 0% resource overlap + independent queue/DB.

### 5. Privacy-First "Local" AI (Phase 8)

- **Status Quo:** "AI Writing Assistants" send your customer drafts to OpenAI. Privacy nightmare.
- **ApexMail Advantage:** CPU-only ONNX Runtime models running locally on ARM64. Deeply optimized for privacy and latency.
- **The Killer Feature:** **Air-Gapped Intelligence**. Smart features (Chatbot, Mailbot, STO) without the data leak risk.
- **Quality Gate:** Network-isolated inference test: support answers, STO predictions, and content checks work with outbound network disabled.

### 6. "Priority Pass" Traffic Shaping (Phase 3.2.1)

- **Status Quo:** At high volume, bulk marketing traffic can delay transactional mail (password resets/OTPs).
- **ApexMail Advantage:** Automatic regex-based classification puts transactional mail in a dedicated "Fast Lane" queue, guaranteeing <2s delivery even during heavy bulk loads.
- **The Killer Feature:** **Thundering Herd Immunity**. Your OTPs never wait for your newsletter.
- **Quality Gate:** Flood test: 10k bulk + 1 OTP results in OTP delivered first.

### 7. "The Airbag" Reputation Circuit Breaker (Phase 4.4.1)

- **Status Quo:** Many email providers enforce strict bounce/complaint limits and may suspend sending after repeated violations.
- **ApexMail Advantage:** A local "pre-flight" circuit breaker that pauses your queue *before* you hit the provider's ban limit, alerting you to fix the data first.
- **The Killer Feature:** **Ban-Hammer Insurance**. We stop you from shooting yourself in the foot.
- **Quality Gate:** Sliding-window bounce test automatically pauses queue and requires explicit operator resume.

### 8. Forensic Render History (Phase 14.3.1)

- **Status Quo:** A user says "This email looked broken." You check the template *now*, but variables have changed. You can't reproduce it.
- **ApexMail Advantage:** Option to store the *exact* rendered HTML artifact of every sent email for 7 days.
- **The Killer Feature:** **Time-Travel Debugging**. See exactly what the user saw, pixel-perfect.
- **Quality Gate:** Artifact retrieval returns exact HTML for recent message IDs and expires after retention.

---

## 📊 Checklist Summary & Prioritization Matrix

### Phase Priority (Recommended Order)

| Phase | Priority | Effort | Business Value | Dependencies |

|-------|----------|--------|----------------|--------------|

| 1. Foundations | 🔴 Critical | Medium | Enabler | None |

| 2. Data Layer | 🔴 Critical | Medium | Enabler | Phase 1 |

| 3. Core API | 🔴 Critical | High | Revenue | Phase 2 |

| 4. MTA Stack | 🔴 Critical | High | Revenue | Phase 3 |

| 6.5 Security/Compliance | 🔴 Critical | Medium | Legal | Phase 2 |

| 11. Billing | 🟡 High | High | Revenue | Phase 3 |

| 12. Developer Experience | 🟡 High | Medium | Growth | Phase 3 |

| 5. Analytics | 🟡 High | Medium | Insights | Phase 4 |

| 9. Testing | 🟡 High | Medium | Quality | All |

| 13. High Availability | 🟢 Medium | High | Uptime | Phase 4 |

| 14. Observability | 🟢 Medium | Medium | Ops | Phase 4 |

| 6. Sales Autopilot | 🟢 Medium | High | Growth | Phase 4 |

| 7. UX/Design | 🟢 Medium | Medium | Polish | Phase 3 |

| 17. Enterprise Infra | 🟢 Medium | High | $$$$ | Phase 15 |

| 8. AI Intelligence Suite | 🟡 High | High | Differentiation | Phase 5 |

| 15. Multi-Tenant | 🟡 High | High | Enterprise | Phase 6.5 |

| 16. Edge Cases | 🔵 Low | Medium | Support Reduction | Phase 4 |

| 10. Operations | 🔵 Low | Medium | Trust | Phase 9 |

### Quick Wins (< 1 Day Each, High Impact)

1. ✅ `List-Unsubscribe-Post` header (Gmail/Yahoo compliance)

2. ✅ Rate limit headers on API responses

3. ✅ Idempotency key support

4. ✅ Webhook signatures

5. ✅ OpenAPI spec generation

6. ✅ Bounce classification regex rules

7. ✅ Per-domain rate limiting config

8. ✅ Domain verification TXT record generator

9. ✅ Template variable strict mode

10. ✅ Inbound reply tracking setup

11. ✅ DMARC reporting ingestion (RUA parsing)

12. ✅ Template linting (unsubscribe/link checks)

13. ✅ API key rotation policy

14. ✅ Disposable email blocklist

15. ✅ Open/click tracking pixel implementation

16. ✅ Public status page setup

17. ✅ Postman collection export

18. ✅ Engagement score calculation

### Total Checklist Items

- **Critical (Non-Negotiable):** 7 items
- **Phase 1-10 (Core):** ~95 items
- **Phase 11-17 (Enterprise/Growth):** ~118 items
- **Total:** 220 verification points

### Revenue Tier Mapping

| Tier | Price | Key Unlocks |

|------|-------|-------------|

| Free | $0 | 1K emails/mo, "Powered by" footer, Shared IP |

| Starter | $29/mo | 25K emails, Remove branding, Basic analytics |

| Growth | $99/mo | 100K emails, Dedicated IP warm-up, Webhooks |

| Scale | $299/mo | 500K emails, Dedicated IP, Priority support |

| Enterprise | $999+/mo | Custom volume, SSO, SLA, Dedicated CSM |

| Private | $5K+/mo | Single-tenant, BYOIP, HIPAA, Custom contracts |

---

> **Document Metadata**
> Version: v11-Complete
> Last Updated: 2026-02-01
> Next Review: Before Phase 1 Complete
