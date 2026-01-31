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

## Phase 6: Sales Autopilot & CRM (New Phase)

*Goal: Automated growth using the platform itself. Inspired by Ad-Project "Autopilot".*

### 6.1 Lead Generation & Enrichment

- [ ] **Implement "SaaS Hunter" Scraper**
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

### 6.3 Internal CRM Dashboard

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

## Phase 8: AI Mailbot (Support & Ops)

*Goal: CPU-only, deterministic, safe support agent.*

### 8.1 Agent Architecture

- [ ] **Implement RAG Pipeline**
  - **Implementation:** Ingest docs/runbooks -> Embeddings (local model) -> Vector Store (Postgres `pgvector`).

  - **Evidence Required:** Retrieval accuracy test: Query "How to setup DKIM" returns the exact documentation chunk.

- [ ] **Implement CPU-Only Inference Service**
  - **Implementation:** `llama.cpp` serving a quantized 7B model (e.g., Mistral or Llama-3).

  - **Evidence Required:** Performance metrics showing inference latency < 2s on target CPU hardware.

### 8.2 Safety & Evaluation

- [ ] **Implement Hard Safety Gates**
  - **Implementation:** Classifier to reject prompt injection or off-topic queries.

  - **Evidence Required:** Red-team report showing 100% blockage of known jailbreak prompts.

- [ ] **Implement "Deterministic Mode"**
  - **Implementation:** Fallback to template/tool responses for sensitive topics (billing, legal).

  - **Evidence Required:** Test case showing bot refuses to "invent" a refund policy and quotes the official text instead.

- [ ] **Implement Human Escalation Path**
  - **Implementation:** Confidence threshold trigger. Low confidence or explicit "talk to human" -> Create support ticket + notify on-call.

  - **Evidence Required:** Ask complex billing dispute -> Bot responds "I'm escalating this to our team" -> Ticket created in <30s.

- [ ] **Implement Conversation Handoff**
  - **Implementation:** Full context transfer to human agent. Include conversation history, detected intent, and suggested resolution.

  - **Evidence Required:** Human agent receives ticket with "Summary: User asking about DKIM setup for 3rd domain" + full transcript.

### 8.3 AI Optimization Suite (High ROI)

- [ ] **Implement "Send Time Optimization" (STO)**
  - **Implementation:** Store "Hourly Open Probability" per recipient. Hold non-urgent mail in "Predictive Queue" until window.

  - **Evidence Required:** AB Test: STO group shows +15% open rate vs control group.

- [ ] **Implement Subject Line Scorer**
  - **Implementation:** Pre-send check mechanism using local LLM to score subject lines and suggest 3 variants.

  - **Evidence Required:** User types "Newsletter" -> System suggests "📅 Your Weekly Update (Inside: X, Y, Z)".

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
- **ApexMail Advantage:** CPU-only 7B LLM (Mistral/Llama) running locally.
- **The Killer Feature:** **Air-Gapped Intelligence**. Smart features without the data leak risk.
- **Quality Gate:** Network-isolated inference test: support answers work with outbound network disabled.

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

| 8. AI Mailbot | 🔵 Low | High | Differentiation | Phase 5 |

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
