# ApexMail AI Agent — Exhaustive Training Content Analysis

> **Generated**: 2026-02-19
> **Scope**: Complete audit of ALL repository content vs. 1,067 existing training examples
> **Goal**: Identify every piece of domain knowledge available and every gap in training coverage

---

## Table of Contents

1. [Complete File Inventory](#1-complete-file-inventory)
2. [Pricing & Plan Details (Canonical Source)](#2-pricing--plan-details)
3. [Support Playbooks — Content & Gaps](#3-support-playbooks)
4. [API Documentation — Content & Gaps](#4-api-documentation)
5. [Enterprise Features — Content & Gaps](#5-enterprise-features)
6. [Compliance & Security — Content & Gaps](#6-compliance--security)
7. [User Guide — Content & Gaps](#7-user-guide)
8. [Operations — Content & Gaps](#8-operations)
9. [Tool Contracts — Internal Only](#9-tool-contracts)
10. [Production Code — Action Types Gap](#10-production-code-action-types)
11. [Customer Profile Coverage](#11-customer-profiles)
12. [Error Codes — Complete Reference](#12-error-codes)
13. [Current Context Keys vs. Needed Keys](#13-context-keys)
14. [Priority Gap Summary & Recommendations](#14-priority-recommendations)
15. [Specific New Training Example Proposals](#15-new-example-proposals)

---

## 1. Complete File Inventory

### 1A. Training System (5 files)

| File | Lines | Purpose |
|------|-------|---------|
| `apps/ai/training/prompts_v2.py` | 225 | System prompt, pricing table, 35 tools, behavior rules |
| `apps/ai/training/build_agent.py` | 7,601 | Training data builder (23 sections, ~1,067 examples) |
| `apps/ai/training/test_agent.py` | 2,082 | Test suite (14 categories) |
| `apps/ai/training/customer_profiles.py` | 1,541 | 50+ customer profiles across all plan tiers |
| `data/train_agent.jsonl` | ~2,100 | Built dataset (1,067 examples × ~2x weight) |

### 1B. Support Playbooks (26 files)

| File | Lines | Key Topics |
|------|-------|-----------|
| `a-domain-dns-troubleshooting.md` | 332 | DNS propagation, wrong type, Cloudflare, Squarespace, wildcard |
| `b-dkim-spf-dmarc-correctness.md` | 285 | Selector rotation, body hash, multiple SPF records, alignment |
| `c-sender-identity-alignment.md` | 193 | RFC 5322 From, Reply-To, delegation, plus-addressing |
| `d-api-auth-troubleshooting.md` | 306 | API keys, HMAC-SHA256 webhook verification, idempotency, attachment limits |
| `e-webhooks-events-troubleshooting.md` | 358 | 17 event types, TLS cert, retry schedule (30s timeout, 8 retries/24h) |
| `f-bounces-complaints-suppressions.md` | 350 | Bounce categories, retry schedule (5m→15m→30m→1h→4h), complaint 0.1% |
| `g-deliverability-inbox-placement.md` | 501 | Gmail Promotions tab, URL shortener, tracking domain mismatch |
| `h-templates-rendering-content.md` | 442 | MJML, Handlebars helpers, dark mode, HTML injection, image hosting |
| `ip-allowlist-security-controls.md` | 1,120 | **14 API key scopes**, RBAC (5 roles), IP allowlisting, MFA, audit logs |
| `ip-pools-warmup-infrastructure.md` | 719 | **29-day warmup schedule**, rDNS/PTR, MTA-STS, DANE, TLS-RPT |
| `link-tracking-branding.md` | 856 | Click/open tracking, SSL provisioning, bot detection, List-Unsubscribe RFC 8058 |
| `llm-chatbot-runtime.md` | 495 | **INTERNAL** — AI architecture (agent should NOT learn this) |
| `message-diagnostics-retention.md` | 1,075 | Message lifecycle, retention by plan, SMTP transcript, queue diagnosis |
| `quota-rate-limits-billing.md` | 572 | What counts as a "send", daily limits, burst rates, overage handling |
| `sdk-integration-runtime.md` | 1,049 | Node.js/Python SDK, ESM/CJS, TypeScript, Next.js/Express integration |
| `sending-suspended.md` | 325 | Suspension reasons, remediation, appeal process |
| `webhook-failures.md` | 270 | Redis retry queue, endpoint testing, permanent disable |
| `cmp-compliance-privacy-retention.md` | 516 | GDPR erasure API, CAN-SPAM, CASL, unsubscribe timelines |
| `account-lockout.md` | 298 | Lockout causes, MFA recovery, SSO failures, identity verification |
| `api-errors.md` | 483 | 40+ error codes with SQL diagnosis and resolution |
| `billing-dispute.md` | 317 | Disputes, overage calc, SLA credits, dedicated IP add-on ($49/mo) |
| `bounce-investigation.md` | 270 | Deep bounce investigation, SMTP response codes, ISP patterns |
| `data-export.md` | 349 | GDPR export/erasure, data locations (PG/Redis/S3), CLI tools |
| `deliverability-triage.md` | 296 | ISP-specific troubleshooting, Google Postmaster Tools |
| `domain-verification.md` | 316 | Step-by-step verification walkthrough |
| `performance-degradation.md` | 483 | Latency diagnosis, Prometheus queries, PostgreSQL/Redis diagnostics |

### 1C. API Documentation (14 files)

| File | Lines | Content |
|------|-------|---------|
| `api/authentication.md` | 397 | API keys, JWT (ES256, 1h access/30d refresh), OAuth 2.0 PKCE |
| `api/rate-limits.md` | ~200 | Rate limit headers, exponential backoff, batch endpoints |
| `api/errors.md` | 708 | **40+ error codes** with JSON examples and resolution steps |
| `api/webhooks.md` | 446 | 7 event types with full payloads, HMAC-SHA256 verification |
| `api/sdk-reference.md` | 480 | Node.js/Python SDK methods |
| `api/changelog.md` | — | API versioning history |
| `api/openapi.yaml` | — | OpenAPI spec |
| `api/endpoints/analytics.md` | — | Analytics API |
| `api/endpoints/campaigns.md` | — | Campaign CRUD |
| `api/endpoints/contacts.md` | — | Contact CRUD, CSV import |
| `api/endpoints/domains.md` | — | Domain management |
| `api/endpoints/events.md` | — | Event search/filtering |
| `api/endpoints/messages.md` | — | Message send/status |
| `api/endpoints/templates.md` | — | Template CRUD |

### 1D. Enterprise Documentation (9 files)

| File | Lines | Key Content |
|------|-------|-----------|
| `enterprise/sso.md` | 239 | SAML 2.0, OIDC, 7+ IdPs, auto-provisioning, SCIM |
| `enterprise/sub-accounts.md` | 374 | Hierarchy, API, resource quotas, consolidated billing |
| `enterprise/whitelabel.md` | 360 | Custom domains, UI branding, CSS/JS, SSL provisioning |
| `enterprise/support.md` | 454 | 3 tiers (24h/4h/15min), ticket API, escalation API |
| `enterprise/compliance.md` | 507 | Consent management API, 7 regulations (GDPR/CCPA/HIPAA/CASL/LGPD/PDPA/POPIA) |
| `enterprise/log-streaming.md` | 498 | 8 destinations (S3/BigQuery/Snowflake/Kafka/Kinesis/Elasticsearch/Datadog/webhook) |
| `enterprise/private-cloud.md` | 381 | 4 deployment options, 3 EU regions, from $2,500/mo base |
| `enterprise/qbr.md` | 493 | QBR structure (90min), scheduling API, report sections |
| `enterprise/template-approval.md` | 441 | Multi-stage workflows, role-based approvers, version control |

### 1E. Compliance & Security (7 files)

| File | Lines | Content |
|------|-------|---------|
| `compliance/gdpr-compliance.md` | 340 | Bel Consulting OÜ (16192499), controller vs processor, lawful bases, sub-processor: Hetzner |
| `compliance/data-retention.md` | 183 | Full retention schedule by data type (email 30d, events 90d, billing 7yr) |
| `compliance/acceptable-use-policy.md` | 250 | Prohibited content, consent requirements |
| `compliance/incident-response.md` | 329 | P1–P4 severity, 72h GDPR breach notification |
| `security/data-protection.md` | 281 | AES-256-GCM, TLS 1.3/1.2, per-org encryption keys, tenant isolation |
| `security/email-authentication.md` | 322 | ARC (RFC 8617), MTA-STS (RFC 8461), TLSRPT (RFC 8460), BIMI/VMC |
| `security/compliance.md` | — | Security compliance overview |
| `security/advanced-analytics.md` | — | Analytics security |

### 1F. User Guide (5 files)

| File | Lines | Content |
|------|-------|---------|
| `user-guide/getting-started.md` | 366 | Account setup, domain verification, first email |
| `user-guide/contacts.md` | 434 | Lists, CSV import (25MB/100K), tags, segments, scoring (0-100) |
| `user-guide/inbox-placement-testing.md` | 353 | Seed list testing, benchmarks (transactional 95-99%, marketing 85-95%) |
| `user-guide/glossary.md` | 276 | 30+ definitions: SPF, DKIM, DMARC, ARC, BIMI, MTA-STS, VERP, DSN, FBL, ARF |
| `user-guide/troubleshooting.md` | 559 | Auth errors, rate limiting, spam, domain, webhooks, bounces |

### 1G. Operations (6+ files — INTERNAL, agent knows SLOs only)

| File | Lines | Key Agent-Relevant Content |
|------|-------|--------------------------|
| `operations/slo-management.md` | 313 | **99.9% API availability**, P99 < 500ms, 98% delivery in 5min |
| `operations/monitoring.md` | 546 | Prometheus metrics (internal) |
| `operations/disaster-recovery.md` | 429 | Daily full + 6h incremental backups, PITR, RPO <1min, RTO <15min |
| `operations/on-call.md` | 198 | P1-P4 response SLAs |
| `operations/scaling.md` | — | Scaling procedures |
| `operations/runbooks/incident-response.md` | — | Incident runbook |

### 1H. Tool Contracts (8 files — INTERNAL, never reveal)

| File | Lines | Content |
|------|-------|---------|
| `tool-contracts/ses.md` | 170 | SES as fallback, circuit breaker |
| `tool-contracts/stripe.md` | 227 | EUR pricing (!), subscription lifecycle |
| `tool-contracts/hetzner.md` | 154 | ARM servers, fleet |
| `tool-contracts/hono.md` | — | Web framework |
| `tool-contracts/postgresql.md` | — | Database |
| `tool-contracts/prometheus.md` | — | Monitoring |
| `tool-contracts/redis.md` | — | Cache/queue |
| `tool-contracts/zone-ee.md` | — | Domain registrar |

### 1I. Architecture (8 files — mostly internal)

| File | Key Content |
|------|-----------|
| `architecture/overview.md` | System architecture |
| `architecture/data-flow.md` | Data pipeline |
| `architecture/queue-system.md` | BullMQ queues |
| `architecture/ai-pipeline.md` | AI inference pipeline |
| `architecture/mta-configuration.md` | MTA config |
| `architecture/multi-region.md` | Multi-region setup |
| `architecture/analytics-data-science.md` | Analytics pipeline |
| `architecture/control-plane-isolation.md` | Control plane isolation |

### 1J. Production Code (key files)

| File | Lines | Relevance |
|------|-------|-----------|
| `apps/ai/src/assistant/unified.ts` | 2,105 | **80+ action types** (only 35 in system prompt) |
| `apps/billing/src/services/plans.ts` | 786 | Canonical pricing, PAYG calculation, all feature flags |
| `packages/lib/src/error-codes.ts` | ~80 | 24 standardized API error codes |
| `apps/billing/src/services/dunning.ts` | — | Dunning/payment failure logic |
| `apps/billing/src/services/wallet.ts` | — | PAYG wallet/credits |
| `apps/billing/src/services/sla-credits.ts` | — | SLA credit calculation |

---

## 2. Pricing & Plan Details

### 2A. Canonical Source (`plans.ts`)

| Plan | Monthly | Yearly (~17% off) | Emails/mo | API calls/mo | Domains | Team | Retention |
|------|---------|-------|-----------|--------------|---------|------|-----------|
| Free | $0 | $0 | 1,000 | 10,000 | 1 | 1 | 7 days |
| Starter | $29 | $290 | 25,000 | 250,000 | 3 | 3 | 30 days |
| Pro | $59 | $590 | 50,000 | 500,000 | 5 | 5 | 60 days |
| Growth | $129 | $1,290 | 100,000 | 1,000,000 | 10 | 10 | 90 days |
| Scale | $399 | $3,990 | 500,000 | 5,000,000 | Unlimited | 25 | 365 days |
| Enterprise | $1,299 | $12,990 | 2,000,000 | 20,000,000 | Unlimited | Unlimited | 730 days |
| PAYG | $0 base | — | Unlimited | Unlimited | 3 | 3 | 30 days |

### 2B. PAYG Pricing (from `plans.ts`)

| Volume Tier | Price per Email |
|-------------|----------------|
| 0–10,000 | $0.001 |
| 10,001–100,000 | $0.0008 |
| 100,001–1,000,000 | $0.0005 |
| 1,000,001+ | $0.0003 |

- API: First 100K free, then $0.10/1,000
- Overage on plans: $0.50/1,000 extra emails

### 2C. Feature Matrix (from `plans.ts`)

| Feature | Free | Starter | Pro | Growth | Scale | Enterprise | PAYG |
|---------|------|---------|-----|--------|-------|------------|------|
| Webhooks | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Custom tracking domain | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| A/B testing | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| Dedicated IP | ❌ | ❌ | ❌ | 1 | 3 | 10 | ❌ |
| SSO | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Audit logs | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| Subaccounts | ❌ | ❌ | ❌ | ❌ | ✅ (10) | ✅ (100) | ❌ |
| White-label | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| BYOIP | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| HIPAA/SOC2 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| SLA credit | ❌ | ❌ | ❌ | ❌ | 10% | 25% | ❌ |
| Support level | Community | Email | Email | Priority | Phone | Dedicated | Email |
| Template approval | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| Data export | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Advanced analytics | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Priority onboarding | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Private cloud | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |

### 2D. 🔴 CRITICAL: Pricing Discrepancies Across Sources

| Source | Starter emails | Growth emails | Currency | Notes |
|--------|---------------|---------------|----------|-------|
| `plans.ts` (canonical) | 25,000 | 100,000 | USD | **Source of truth** |
| `prompts_v2.py` (system prompt) | 25,000 | 100,000 | USD | ✅ Matches |
| `billing-dispute.md` playbook | **15,000** | **150,000** | USD | ❌ WRONG |
| `quota-rate-limits-billing.md` | **15,000** | 100,000 | USD | ❌ WRONG Starter |
| `stripe.md` tool contract | **10,000** | **25,000** | **EUR** | ❌ Different entirely |

**Impact**: The billing-dispute and quota playbooks have WRONG plan limits. Training examples sourced from those docs would teach incorrect facts. The Stripe contract shows EUR pricing with different plan names — likely an older or European-market configuration.

**Action required**: Fix `billing-dispute.md` and `quota-rate-limits-billing.md` to match `plans.ts`.

### 2E. Additional Pricing Details NOT in Training

Found in `billing-dispute.md`:
- **Dedicated IP add-on**: $49/mo (Growth plan optional)
- **Contact limits per plan**: Free 500, Starter 2,500, Pro 10,000, Growth 25,000, Scale 100,000, Enterprise Unlimited
- **Overage for contacts**: $5 per 1,000 extra contacts
- **SLA credit tiers**: 99.0-99.9% → 10%, 95-99% → 25%, 90-95% → 50%, <90% → 100%

Found in `private-cloud.md`:
- **Private cloud base**: from $2,500/mo
- **Per-million-emails**: $0.50
- **Additional IPs**: $50/mo each

---

## 3. Support Playbooks — Content & Gaps

### Coverage Heatmap (vs. 1,067 training examples)

| Playbook | Training Coverage | Gap Level |
|----------|-------------------|-----------|
| a-domain-dns-troubleshooting | ✅ Good (Sections F, K, Q) | Low |
| b-dkim-spf-dmarc-correctness | ✅ Good | Low |
| c-sender-identity-alignment | 🟡 Partial | Medium — Free mailbox From rejection, "via" display |
| d-api-auth-troubleshooting | 🟡 Partial | Medium — HMAC verification, idempotency, attachment limits |
| e-webhooks-events-troubleshooting | 🟡 Partial | Medium — Full 17 event types, retry schedule |
| f-bounces-complaints-suppressions | ✅ Good | Low |
| g-deliverability-inbox-placement | ✅ Good | Low |
| h-templates-rendering-content | 🟡 Partial | Medium — MJML, Handlebars helpers, dark mode |
| **ip-allowlist-security-controls** | 🔴 **Weak** | **HIGH — 14 scopes, RBAC matrix, IP allowlist recovery** |
| **ip-pools-warmup-infrastructure** | 🟡 Partial | **HIGH — Full 29-day warmup table, rDNS** |
| **link-tracking-branding** | 🟡 Partial | Medium — SSL provisioning, Cloudflare conflicts, bot detection |
| llm-chatbot-runtime | N/A (internal) | Don't train |
| **message-diagnostics-retention** | 🔴 **Weak** | **HIGH — Message lifecycle, "stuck in queue", SMTP transcript** |
| quota-rate-limits-billing | 🟡 Partial | Medium (also has pricing errors!) |
| **sdk-integration-runtime** | 🔴 **Weak** | **HIGH — ESM/CJS, TypeScript, Next.js/Express integration** |
| sending-suspended | 🟡 Partial | Medium |
| webhook-failures | 🟡 Partial | Medium |
| **cmp-compliance-privacy-retention** | 🟡 Partial | **HIGH — GDPR erasure API endpoint, CAN-SPAM details** |
| **account-lockout** | 🔴 **Weak** | **HIGH — Lockout causes, MFA recovery, SSO failures** |
| **api-errors** | 🔴 **Weak** | **HIGH — 40+ error codes with resolution** |
| **billing-dispute** | 🔴 **Weak** | **HIGH — SLA credits, dedicated IP pricing, dispute process** |
| bounce-investigation | 🟡 Partial | Medium |
| **data-export** | 🔴 **Weak** | **HIGH — GDPR export endpoints, data locations** |
| deliverability-triage | 🟡 Partial | Medium |
| domain-verification | ✅ Good | Low |
| **performance-degradation** | 🔴 **Weak** | Medium — "API is slow" responses |

### Key Content Summaries (from playbooks NOT well covered)

**ip-allowlist-security-controls.md** (1,120 lines):
- 14 API key scopes: `emails:send`, `emails:read`, `domains:manage`, `domains:read`, `webhooks:manage`, `webhooks:read`, `templates:manage`, `templates:read`, `suppressions:manage`, `suppressions:read`, `analytics:read`, `contacts:manage`, `contacts:read`, `admin`
- 5 RBAC roles with full permissions matrix: Owner, Admin, Developer, Analyst, Billing
- IP allowlisting is per-key (not per-account), supports IPv4/IPv6/CIDR
- Recovery: Dashboard uses session auth, NOT API key auth — always accessible
- Default lockout: 5 failed attempts → 30-minute lockout
- MFA: TOTP + SMS fallback, recovery codes

**message-diagnostics-retention.md** (1,075 lines):
- Message lifecycle: Accept → Queue → Process → Deliver → Track → Feedback
- Statuses: `accepted` → `queued` → `processing` → `delivered`/`bounced`/`deferred`/`failed`
- Retention by data type: message metadata 90d, body 7d, events 90d, webhook logs 30d, SMTP transcripts 7d, analytics forever, suppression list forever
- "Delivered" = remote MTA accepted (250 OK), NOT in inbox

**sdk-integration-runtime.md** (1,049 lines):
- Node.js SDK: `@apexmail/node` — send, sendBatch, domains, contacts, templates, suppressions, webhooks
- Python SDK: `apexmail` — sync + async clients
- ESM vs CJS resolution steps
- TypeScript: `module: "nodenext"`, `moduleResolution: "nodenext"`
- Headers polyfill for Node.js <18
- Webhook verification code examples (Node.js + Python)

**account-lockout.md** (298 lines):
- 5 failure reasons: `invalid_password`, `account_locked`, `mfa_failed`, `sso_error`, `session_invalidated`
- SSO failures: expired cert, ACS URL mismatch, attribute mapping, clock skew, stale metadata
- Identity verification required before any recovery (2 of 4 methods)

**api-errors.md** (483 lines):
- Full error codes: `invalid_api_key`, `expired_token`, `token_revoked`, `insufficient_scope`, `ip_not_allowed`, `invalid_email`, `sender_not_verified`, `missing_required_field`, `invalid_field_type`, `field_too_long`, `invalid_json`, `resource_not_found`, `template_not_found`, `list_not_found`, `duplicate_resource`, `recipient_suppressed`, `missing_template_variables`, `attachment_too_large`, `message_already_sent`, `campaign_invalid_status`, `no_recipients`, `rate_limit_exceeded`, `daily_limit_exceeded`, `insufficient_credits`, `subscription_required`, `internal_error`, `service_unavailable`

---

## 4. API Documentation — Content & Gaps

### Coverage Assessment

| Topic | Trained? | In Docs? | Gap |
|-------|----------|---------|-----|
| API key types (live/test) | ✅ Yes | ✅ | — |
| Bearer token auth | ✅ Yes | ✅ | — |
| **OAuth 2.0 / PKCE flow** | 🔴 No | ✅ auth.md | New examples needed |
| **JWT refresh/revocation** | 🔴 No | ✅ auth.md | New examples needed |
| **14 API scopes** | 🔴 No | ✅ playbook + auth.md | New examples needed |
| **Error codes (27+ trained vs 40+ available)** | 🔴 Weak | ✅ errors.md | ~20 error examples |
| **Rate limit headers (X-RateLimit-*)** | 🟡 Partial | ✅ rate-limits.md | Need header interpretation examples |
| **Webhook HMAC-SHA256 verification code** | 🔴 No | ✅ webhooks.md | Node.js + Python code samples |
| **Webhook event types (7 documented)** | 🟡 Partial | ✅ webhooks.md | Full payload examples |
| SDK initialization options | 🟡 Partial | ✅ sdk-reference.md | timeout, retries, baseURL |
| **SDK batch methods** | 🔴 No | ✅ sdk-reference.md | `sendBatch()` training |
| **Contact API endpoints** | 🔴 No | ✅ endpoints/contacts.md | CRUD + CSV import |
| **Analytics endpoints** | 🔴 No | ✅ endpoints/analytics.md | Dashboard data API |
| Campaign endpoints (full) | 🟡 Partial | ✅ endpoints/campaigns.md | list/update/delete |
| Template versioning/preview | 🟡 Partial | ✅ endpoints/templates.md | Preview, versions |

---

## 5. Enterprise Features — Content & Gaps

### ⚠️ THIS IS THE BIGGEST GAP. Enterprise customers pay $1,299/mo and the agent barely knows their features.

| Feature | Training Examples | Documented? | Gap Level |
|---------|-------------------|-------------|-----------|
| **SSO (SAML/OIDC)** | 1 mention | 239 lines | 🔴 CRITICAL — 10 examples needed |
| **SSO troubleshooting** | 0 | In account-lockout.md | 🔴 CRITICAL — 5 examples |
| **Sub-accounts** | 0 | 374 lines | 🔴 CRITICAL — 10 examples |
| **White-label** | 1 example | 360 lines | 🔴 HIGH — 8 examples |
| **Support tiers/SLA** | 0 | 454 lines | 🔴 HIGH — 5 examples |
| **Compliance (consent API)** | 0 | 507 lines | 🔴 HIGH — 8 examples |
| **Log streaming** | 0 | 498 lines | 🔴 HIGH — 8 examples |
| **Private cloud** | 0 | 381 lines | 🟡 Medium — 3 examples (→ escalate) |
| **QBR** | 0 | 493 lines | 🟡 Medium — 3 examples (→ escalate) |
| **Template approval workflows** | 0 | 441 lines | 🔴 HIGH — 8 examples |

### Key Content the Agent Should Know

**SSO** (`enterprise/sso.md`):
- Supported IdPs: Okta, Azure AD, OneLogin, Ping, Google Workspace, ADFS, Auth0, Keycloak
- SAML setup: ACS URL = `https://api.apexmail.ee/enterprise/v1/sso/saml/callback`, EntityID = `https://api.apexmail.ee/saml/{account_id}`
- OIDC: Redirect URI = `https://api.apexmail.ee/enterprise/v1/sso/oidc/callback`
- Auto-provisioning with `"autoProvision": true`
- Available on Scale ($399) and Enterprise ($1,299) only

**Sub-accounts** (`enterprise/sub-accounts.md`):
- Create via API: `POST /enterprise/v1/sub-accounts`
- Resource quotas per sub-account (emails, domains, API keys, users, storage, templates)
- Consolidated billing — single invoice with per-sub-account breakdown
- Scale plan: up to 10 sub-accounts; Enterprise: up to 100
- Each sub-account can have its own sending domains, API keys, users

**Log Streaming** (`enterprise/log-streaming.md`):
- 8 destinations: S3, BigQuery, Snowflake, Kafka, Kinesis, Elasticsearch, Datadog, Custom Webhook
- Configurable event filters, batch size, format (JSON)
- Enterprise plan only

**Template Approval** (`enterprise/template-approval.md`):
- Multi-stage (content → legal → final), role-based approvers
- Auto-approve timer (e.g., 72h), escalation to manager
- Checklist items per stage
- Scale and Enterprise plans

**Support Tiers** (`enterprise/support.md`):
- Standard (24h email, business hours)
- Premium (4h email+chat, extended hours, dedicated CSM)
- Enterprise (15min email+chat+phone, 24/7, dedicated CSM + TAM, Slack channel, QBRs)

---

## 6. Compliance & Security — Content & Gaps

| Topic | Trained? | Key Content | Gap |
|-------|----------|-------------|-----|
| **Legal entity** | 🔴 No | Bel Consulting OÜ, Registry 16192499, Tallinn, Estonia | Need 2+ examples |
| **Controller vs Processor** | 🟡 Partial | Customer = controller, ApexMail = processor | Need examples |
| **Sub-processor** | 🔴 No | Hetzner Online GmbH (EU) | Need examples |
| **GDPR erasure endpoint** | 🔴 No | `POST /v1/compliance/gdpr` with `type: "erasure"` | Need 3+ examples |
| **GDPR data export** | 🔴 No | `POST /v1/compliance/gdpr` with `type: "access"` | Need 2+ examples |
| **Data retention by type** | 🔴 No | Email body 30d, events 90d, billing 7yr, backups 30d | Need 3+ examples |
| **Encryption** | 🔴 No | AES-256-GCM at rest, TLS 1.3 in transit, per-org keys | Need 2+ examples |
| **Breach notification** | 🔴 No | 72 hours to Estonian DPA | Need 1 example |
| **DPA availability** | 🔴 No | Available for all customers, escalate to contact@apexmail.ee | Need 1 example |
| **AUP key rules** | 🟡 Partial | No phishing, malware, purchased lists, deceptive headers | Strengthen |
| **CAN-SPAM requirements** | 🔴 No | Physical address, unsubscribe mechanism, 10 business days | Need 2+ examples |
| **HIPAA BAA process** | 🟡 Partial | Enterprise plan required, escalate to CSM | Strengthen |
| **ARC/MTA-STS/TLSRPT/BIMI** | 🔴 Weak | Practical setup guides exist but no training | Need 5+ examples |
| **Consent management API** | 🔴 No | Full API in enterprise/compliance.md | Need examples (Enterprise) |
| **Unsubscribe timelines** | 🔴 No | CAN-SPAM 10d, GDPR immediately, Google/Yahoo 2d | Need 1 example |

---

## 7. User Guide — Content & Gaps

| Topic | Trained? | Key Content | Gap |
|-------|----------|-------------|-----|
| Account setup flow | 🟡 Partial | Step-by-step in getting-started.md | Low |
| Domain verification | ✅ Good | Well covered | — |
| **CSV import** | 🔴 No | Max 25MB / 100K rows, field mapping, conflict resolution (skip/update/overwrite) | Need 3+ examples |
| **Contact segments** | 🔴 No | Dynamic filter rules, composite conditions | Need 2+ examples |
| **Contact scoring** | 🔴 No | 0-100 scale, Hot/Warm/Cool/Cold tiers | Need 1 example |
| **Inbox placement testing** | 🔴 No | Seed list testing, benchmarks, ISP-specific results | Need 2+ examples |
| **Glossary terms** | 🟡 Partial | 30+ terms defined but VERP/DSN/FBL/ARF not trained | Need 5+ examples |
| **Troubleshooting: 409 Conflict** | 🔴 No | Concurrent update, idempotency keys | Need 1 example |
| **Troubleshooting: 413 Too Large** | 🔴 No | 25MB single / 50MB total attachments | Need 1 example |
| **Troubleshooting: 402 Payment** | 🔴 No | Insufficient credits, subscription required | Need 1 example |

---

## 8. Operations — Content & Gaps (Agent Knows SLOs Only)

| What Agent Should Know | Trained? | Source | Gap |
|------------------------|----------|--------|-----|
| **99.9% API availability SLO** | 🔴 No | slo-management.md | HIGH — need 2+ examples |
| **P99 < 500ms latency target** | 🔴 No | slo-management.md | Need 1 example |
| **98% email delivery in 5 minutes** | 🔴 No | slo-management.md | Need 1 example |
| **"Is ApexMail down?"** response | 🔴 No | — | Need 2+ examples |
| **"When will it be fixed?"** | 🔴 No | on-call.md + support.md | Need 1 example |
| **Backup reassurance** | 🔴 No | disaster-recovery.md | Need 1 example |
| **Status page link** | 🔴 No | — | Need 1 example |

---

## 9. Tool Contracts — Internal Only (Never Reveal)

The agent should gain INDIRECT knowledge from tool contracts:

| Indirect Knowledge | Trained? | Gap |
|--------------------|----------|-----|
| **"My payment failed"** → dunning flow (no Stripe mention) | 🔴 No | Need 2 examples |
| **"I cancelled but still charged"** → access until period end | 🔴 No | Need 1 example |
| **"I upgraded but nothing changed"** → provisioning delay | 🔴 No | Need 1 example |
| **Subscription states** (trial → active → past_due → canceled) | 🔴 No | Need 1 example |

---

## 10. Production Code — Action Types Gap

### `unified.ts` defines ~80 action types; system prompt lists ~35 tools

**Missing from system prompt (42 action types):**

#### Diagnostics / Message Tracing (6)
- `get_smtp_transcript` — view SMTP session
- `get_scheduled_send_status` — check scheduled messages
- `get_message_event_timeline` — full event timeline
- `trace_message` — end-to-end trace
- `validate_template` — template validation
- `get_content_scan_result` — content scan

#### DNS / Authentication (3)
- `force_dns_recheck` — force re-verification
- `check_bimi_status` — BIMI record check
- `check_rdns_ptr` — reverse DNS check

#### Deliverability / Reputation (3)
- `run_deliverability_audit` — full audit
- `get_geo_sending_report` — geographic report
- `get_complaint_rate` — current rate

#### Webhooks / Tracking (7)
- `get_webhook_config`, `get_webhook_delivery_log`, `resend_webhook_events`, `enable_webhook_endpoint`
- `get_tracking_domain_config`, `rotate_tracking_domain`, `check_cert_provisioning_status`

#### API Diagnostics (4)
- `get_rate_limit_status`, `get_api_error_log`, `get_api_health_detailed`, `enable_sdk_debug_mode`

#### Account / Quota (4)
- `get_quota_status`, `get_usage_breakdown`, `get_sending_status`, `get_invoice_reconciliation`

#### Security (9)
- `manage_ip_allowlist`, `get_user_permissions`, `resend_team_invite`, `get_audit_log`
- `set_emergency_throttle`, `get_api_access_log`, `unlock_account`, `freeze_account`, `export_audit_log`

#### Compliance / Privacy (7)
- `execute_gdpr_erasure`, `get_consent_record`, `set_retention_policy`, `request_dpa`
- `request_compliance_doc`, `set_legal_hold`, `get_compliance_risk_score`

#### Operations (8)
- `request_dedicated_ip`, `get_warmup_status`, `get_ip_assignment`, `get_throttle_status`
- `rollback_deployment`, `get_system_health`, `reconcile_analytics`, `get_worker_status`

#### LLM Self-Diagnostics (4 — keep internal)
- `get_llm_config`, `get_llm_session_log`, `get_intent_debug`, `get_rag_debug`

**Recommendation**: Add ~30 of these to the system prompt (exclude LLM self-diagnostics and some ops tools). Create 2-3 training examples per new tool.

---

## 11. Customer Profiles

### Current Coverage: 50+ profiles across 7 plan tiers

| Plan | Profiles | Industries |
|------|----------|-----------|
| Free | 4 | Shop, studio, blogger, pet groomer |
| Starter | 7 | Restaurant, nonprofit, tutoring, bakery, fitness |
| Pro | 6 | Agency, EdTech, realtor, gadget review, vineyard |
| Growth | 8+ | SaaS, CloudFlare DKIM, crypto, gaming, logistics, travel, gmail promo |
| Scale | 5+ | Healthcare, insurance, media, deliverability, key rotation |
| Enterprise | 6+ | Compliance/HIPAA, whitelabel, fintech, government, ecommerce, MFA lockout |
| PAYG | 6+ | API-first, seasonal, high-volume, low-volume |

### Missing Profile Scenarios

| Needed Profile | Context Key Suggestion | Scenario |
|----------------|----------------------|----------|
| **Enterprise + SSO misconfigured** | `enterprise_sso_broken` | SAML cert expired, users locked out |
| **Enterprise + sub-accounts** | `enterprise_subaccounts` | Agency managing 5+ client sub-accounts |
| **Enterprise + log streaming** | `enterprise_log_streaming` | BigQuery stream failing |
| **Enterprise + template approval** | `enterprise_template_stuck` | Template stuck in legal review |
| **Scale + A/B testing active** | `scale_ab_testing` | Running send-time optimization experiment |
| **Growth + account lockout** | `growth_locked_out` | Admin locked out after team member left |
| **Pro + SDK integration issue** | `pro_sdk_esm_issue` | ESM/CJS import error in Next.js |
| **Any + OAuth integration** | `growth_oauth_app` | Third-party app using OAuth PKCE |

---

## 12. Error Codes — Complete Reference

### From `packages/lib/src/error-codes.ts` (24 codes)

| Code | Category |
|------|----------|
| `AUTH_REQUIRED` | Auth |
| `INVALID_API_KEY` | Auth |
| `INVALID_TOKEN` | Auth |
| `TOKEN_EXPIRED` | Auth |
| `TOKEN_REVOKED` | Auth |
| `INSUFFICIENT_SCOPE` | Auth |
| `FORBIDDEN` | Auth |
| `BAD_REQUEST` | Validation |
| `VALIDATION_ERROR` | Validation |
| `INVALID_INPUT` | Validation |
| `INVALID_ID` | Validation |
| `INVALID_EMAIL` | Validation |
| `NOT_FOUND` | Resource |
| `CONFLICT` | Resource |
| `DUPLICATE_KEY` | Resource |
| `DOMAIN_EXISTS` | Resource |
| `VERIFICATION_EXPIRED` | Resource |
| `RATE_LIMITED` | Rate Limiting |
| `DAILY_LIMIT_REACHED` | Rate Limiting |
| `INTERNAL_ERROR` | Server |
| `SERVICE_UNAVAILABLE` | Server |
| `CSRF_ORIGIN_MISMATCH` | CSRF |
| `CSRF_MISSING_HEADER` | CSRF |
| `IDEMPOTENCY_CONFLICT` | Idempotency |

### From `docs/api/errors.md` (27+ additional codes)

`expired_token`, `ip_not_allowed`, `sender_not_verified`, `missing_required_field`, `invalid_field_type`, `field_too_long`, `invalid_json`, `resource_not_found`, `template_not_found`, `list_not_found`, `duplicate_resource`, `recipient_suppressed`, `missing_template_variables`, `attachment_too_large`, `message_already_sent`, `campaign_invalid_status`, `no_recipients`, `rate_limit_exceeded`, `daily_limit_exceeded`, `insufficient_credits`, `subscription_required`, `internal_error`, `service_unavailable`

### Training Coverage: Only `invalid_api_key` and `rate_limit_exceeded` are well-trained. ~35 codes are untrained.

---

## 13. Context Keys — Current vs. Needed

### Current Context Keys (56 total in `customer_profiles.py`)

```
enterprise_compliance, enterprise_dunning, enterprise_ecommerce,
enterprise_fintech, enterprise_government, enterprise_hipaa,
enterprise_mfa_lockout, enterprise_whitelabel,
free_brand_new, free_hitting_limits, free_hobby_blogger, free_spf_broken,
growth_cloudflare_dkim, growth_complaint_suspended, growth_crypto,
growth_dkim_fail, growth_gaming, growth_gmail_promo_tab, growth_ip_warmup,
growth_logistics, growth_rate_limited, growth_saas_healthy, growth_travel,
no_context,
payg_active, payg_api_401, payg_high_volume, payg_low_volume, payg_seasonal,
pro_agency_multi_domain, pro_dmarc_none, pro_edtech, pro_new_user,
pro_outlook_rendering, pro_realtor, pro_template_issue,
scale_deliverability, scale_greylist, scale_healthcare, scale_insurance,
scale_key_rotation, scale_media, scale_sso_issue, scale_subaccounts,
starter_bounce_spike, starter_dunning_soft, starter_gdpr_deletion,
starter_healthy, starter_nonprofit, starter_over_limit,
starter_restaurant, starter_webhook_dead
```

### Recommended NEW Context Keys (8)

| Key | Plan | Scenario |
|-----|------|----------|
| `enterprise_sso_broken` | Enterprise | SAML cert expired, all SSO users locked out |
| `enterprise_subaccounts_active` | Enterprise | Managing 8 client sub-accounts, one over quota |
| `enterprise_log_stream_failing` | Enterprise | BigQuery destination returning errors |
| `enterprise_template_approval` | Enterprise | Template stuck in legal review stage |
| `scale_ab_testing` | Scale | A/B test running, wants to analyze results |
| `growth_account_lockout` | Growth | Admin locked out after password change |
| `pro_sdk_integration` | Pro | Next.js integration failing with ESM error |
| `growth_oauth_app` | Growth | Third-party app using OAuth 2.0 PKCE |

---

## 14. Priority Gap Summary & Recommendations

### Phase 1: CRITICAL (Fix Immediately) — ~85 new examples

| Gap | Examples Needed | Priority |
|-----|-----------------|----------|
| Fix pricing discrepancies in playbooks | 0 (doc fix) | 🔴 CRITICAL |
| Enterprise SSO setup & troubleshooting | 10 | 🔴 CRITICAL |
| Enterprise sub-accounts | 10 | 🔴 CRITICAL |
| Enterprise template approval | 8 | 🔴 HIGH |
| Enterprise log streaming | 8 | 🔴 HIGH |
| Enterprise white-label | 8 | 🔴 HIGH |
| Enterprise support tiers/SLA | 5 | 🔴 HIGH |
| Enterprise compliance (consent API) | 8 | 🔴 HIGH |
| API error codes (top 20) | 20 | 🔴 HIGH |
| Account lockout / MFA recovery | 8 | 🔴 HIGH |
| **Subtotal** | **~85** | |

### Phase 2: HIGH (Next Sprint) — ~80 new examples

| Gap | Examples Needed | Priority |
|-----|-----------------|----------|
| SDK troubleshooting (ESM/CJS, TS, frameworks) | 15 | 🔴 HIGH |
| Update system prompt with ~30 new tools | 0 (prompt update) + 30 training | 🔴 HIGH |
| Webhook HMAC verification (code samples) | 5 | 🟡 MEDIUM |
| Rate limit header interpretation | 5 | 🟡 MEDIUM |
| Billing/payment failure scenarios | 5 | 🟡 MEDIUM |
| SLO/uptime questions | 5 | 🟡 MEDIUM |
| Compliance basics (GDPR export/erasure, encryption) | 10 | 🟡 MEDIUM |
| Message diagnostics & lifecycle | 10 | 🟡 MEDIUM |
| **Subtotal** | **~85** | |

### Phase 3: MEDIUM (Backlog) — ~60 new examples

| Gap | Examples Needed | Priority |
|-----|-----------------|----------|
| IP warmup schedule specifics | 8 | 🟡 MEDIUM |
| Link tracking & Cloudflare conflicts | 5 | 🟡 MEDIUM |
| Contact management (CSV, segments, scoring) | 8 | 🟡 MEDIUM |
| Inbox placement testing | 5 | 🟡 MEDIUM |
| CAN-SPAM/CASL/unsubscribe requirements | 5 | 🟡 MEDIUM |
| Advanced auth (ARC/MTA-STS/BIMI) | 5 | 🟡 MEDIUM |
| Glossary terms (VERP, DSN, FBL, ARF) | 8 | 🟢 LOW |
| Private cloud / QBR (escalation only) | 6 | 🟢 LOW |
| Template rendering (MJML, Handlebars, dark mode) | 5 | 🟡 MEDIUM |
| Data retention by type | 5 | 🟡 MEDIUM |
| **Subtotal** | **~60** | |

### TOTAL: ~230 new training examples recommended

---

## 15. Specific New Training Example Proposals

### 15A. Enterprise SSO (context: `enterprise_sso_broken`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "How do I set up SSO with Okta?" | SAML config steps: ACS URL, Entity ID, certificate upload. Scale/Enterprise only. |
| 2 | "Our SSO stopped working after IdP certificate rotation" | Check cert expiry via metadata URL, upload new cert |
| 3 | "SAML assertion errors when logging in" | Check attribute mapping (email/name), clock skew (<5min), ACS URL match |
| 4 | "Can I use Google Workspace for SSO?" | Yes, OIDC setup with redirect URI |
| 5 | "What is auto-provisioning with SSO?" | JIT provisioning, optional SCIM, defaultRole setting |
| 6 | "User can't log in — SSO loops endlessly" | Check SSO config, cert, ACS URL, attribute mapping |
| 7 | "How do I enforce SSO for all users?" | Set `ssoEnforced: true`, password login disabled |
| 8 | "How do I migrate from password auth to SSO?" | Configure SSO → test → enforce → notify users |
| 9 | "Which IdPs do you support?" | SAML: Okta/Azure AD/OneLogin/Ping/Google/ADFS. OIDC: Okta/Auth0/Azure/Google/Keycloak |
| 10 | "SSO is showing 'insufficient_scope' error" | Check SSO config scopes, API key permissions |

### 15B. Enterprise Sub-Accounts (context: `enterprise_subaccounts_active`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "How do I create a sub-account for a client?" | API: POST /enterprise/v1/sub-accounts with settings |
| 2 | "Can sub-accounts have their own domains?" | Yes — resource isolation, separate sending domains |
| 3 | "How does billing work across sub-accounts?" | Consolidated billing — single invoice, per-sub breakdown |
| 4 | "How do I set quotas for a sub-account?" | PUT /enterprise/v1/sub-accounts/{id}/quotas |
| 5 | "Sub-account is over its email quota" | Check quota status, increase quota or upgrade parent plan |
| 6 | "Can sub-account users access the parent account?" | No — strict isolation. Parent admins can access sub-accounts. |
| 7 | "How many sub-accounts can I create?" | Scale: 10, Enterprise: 100 |
| 8 | "How do I delete a sub-account?" | API + confirmation, data deleted after 30-day grace |
| 9 | "Can sub-accounts have different plans?" | Quotas are set per sub-account, inherit from parent or custom |
| 10 | "Sub-account API key not working" | Check parent account status, sub-account status, key scopes |

### 15C. API Error Codes (context: various profiles)

| # | Error | Context | Expected Response |
|---|-------|---------|-------------------|
| 1 | `sender_not_verified` | `pro_new_user` | Verify domain in Dashboard → Domains, add DNS records |
| 2 | `recipient_suppressed` | `starter_bounce_spike` | Check suppression list, remove if appropriate |
| 3 | `template_not_found` | `pro_template_issue` | Verify template_id exists, check for typos |
| 4 | `attachment_too_large` | `growth_saas_healthy` | Max 25MB single / 50MB total, use hosting service |
| 5 | `insufficient_scope` | `payg_api_401` | Check API key scopes, need `emails:send` |
| 6 | `ip_not_allowed` | `scale_key_rotation` | Add IP to key's allowlist, or use key without restriction |
| 7 | `missing_template_variables` | `pro_edtech` | Include all required vars: check template for {{}} |
| 8 | `campaign_invalid_status` | `growth_saas_healthy` | Can only start draft/scheduled campaigns |
| 9 | `daily_limit_exceeded` | `free_hitting_limits` | Wait until midnight UTC, or upgrade plan |
| 10 | `duplicate_resource` | `starter_healthy` | Contact already exists — use update instead |
| 11 | `subscription_required` | `free_hitting_limits` | Feature requires paid plan (e.g., A/B testing → Growth+) |
| 12 | `expired_token` | any | Refresh using refresh token endpoint |
| 13 | `rate_limit_exceeded` | `growth_rate_limited` | Implement backoff, check X-RateLimit-* headers |
| 14 | `insufficient_credits` | `payg_low_volume` | Top up credits in Dashboard → Billing |
| 15 | `internal_error` | any | Include requestId, contact support |

### 15D. SDK Troubleshooting (context: `pro_sdk_integration`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "Getting 'require() of ES Module not supported'" | CJS/ESM mismatch, use dynamic import or set type: module |
| 2 | "'Headers is not defined' error" | Node.js <18, upgrade or install undici polyfill |
| 3 | "TypeScript errors with SDK" | Set module: nodenext, moduleResolution: nodenext |
| 4 | "How do I send batch emails?" | `client.emails.sendBatch([...])` — max 100 per batch |
| 5 | "SDK timeout on large sends" | Configure timeout: `new ApexMail(key, { timeout: 30000 })` |
| 6 | "How do I verify webhook signatures in Node.js?" | HMAC-SHA256 with signing secret, verify X-ApexMail-Signature |
| 7 | "How do I verify webhooks in Python?" | `apexmail.webhooks.verify(payload, signature, secret)` |
| 8 | "Next.js App Router integration" | Use in Server Components/Route Handlers, not client components |
| 9 | "Express middleware pattern" | Show middleware setup for webhook endpoint |
| 10 | "SDK retry logic / error handling" | Built-in retries, configure maxRetries, handle specific error codes |

### 15E. Compliance & Legal (context: various)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "Is my data encrypted?" | AES-256-GCM at rest, TLS 1.3 in transit, per-org keys |
| 2 | "Where is my data stored?" | EU (Hetzner), specific regions for private cloud |
| 3 | "What's your legal entity?" | Bel Consulting OÜ, Registry Code 16192499, Tallinn, Estonia |
| 4 | "How do I delete a contact under GDPR?" | POST /v1/compliance/gdpr with type: erasure, 30-day grace |
| 5 | "How do I request a data export?" | POST /v1/compliance/gdpr with type: access, JSON/CSV |
| 6 | "Do you have a DPA?" | → Escalate to contact@apexmail.ee (legal request) |
| 7 | "How long do you keep my data?" | By type: body 30d, events 90d, analytics 2yr, billing 7yr |
| 8 | "How do I comply with CAN-SPAM?" | Physical address, unsubscribe link, 10 business days |
| 9 | "What does your AUP prohibit?" | Phishing, malware, purchased lists, deceptive headers |
| 10 | "I need a BAA for HIPAA compliance" | Enterprise plan required → CSM handles BAA |
| 11 | "Who is your sub-processor?" | Hetzner Online GmbH (EU infrastructure) |
| 12 | "How fast must unsubscribes be honored?" | CAN-SPAM 10d, GDPR immediate, Google/Yahoo 2d, ApexMail: immediate |

### 15F. SLO / Uptime / Service Health (context: various)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "What's your uptime SLA?" | 99.9% API availability; Scale/Enterprise get SLA credits |
| 2 | "Is ApexMail down?" | Acknowledge concern, suggest checking status, offer to check health |
| 3 | "How quickly will emails be delivered?" | 98% within 5 minutes SLO |
| 4 | "API seems slow — what's going on?" | Acknowledge, check API health tool, explain P99 < 500ms target |
| 5 | "What SLA credit do I get for downtime?" | Formula: 99-99.9% → 10%, 95-99% → 25%, 90-95% → 50%, <90% → 100% |

### 15G. Account Lockout & MFA (context: `growth_account_lockout`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "I'm locked out of my account" | 5 failed attempts = 30min lockout. Self-service: wait or reset pwd |
| 2 | "My MFA codes aren't working" | Check clock sync (TOTP drift), try recovery codes |
| 3 | "I lost my authenticator app" | Use recovery codes, contact support for identity verification |
| 4 | "Multiple team members locked out at once" | Likely SSO misconfiguration — check IdP settings |
| 5 | "How do I reset my password?" | Dashboard → Forgot Password, or contact support |

### 15H. Message Diagnostics (context: various)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "My email was accepted but never delivered" | Call get_message_status, check if queued/processing/deferred |
| 2 | "What does 'delivered' actually mean?" | Remote MTA returned 250 OK — doesn't guarantee inbox |
| 3 | "Email stuck in queue for 10 minutes" | Check queue health via tool, may be worker issue |
| 4 | "Show me what happened to message X" | Call get_message_events — full event timeline |
| 5 | "How long are SMTP transcripts kept?" | 7 days (not configurable) |

### 15I. Billing & Payment (context: various)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "My payment failed" | Check billing in Dashboard → Billing, update payment method |
| 2 | "I cancelled but was still charged" | Access continues until billing period end |
| 3 | "I upgraded but my limits haven't changed" | May take a few minutes to provision; check Dashboard |
| 4 | "How much does a dedicated IP cost?" | Included in Scale/Enterprise; add-on at $49/mo for Growth |
| 5 | "I want an SLA credit for last week's outage" | → Escalate to contact@apexmail.ee with incident details |

### 15J. Log Streaming (context: `enterprise_log_stream_failing`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "How do I stream events to BigQuery?" | Enterprise only. Config via API or Dashboard → Log Streaming |
| 2 | "My S3 log stream stopped working" | Check bucket permissions, credentials, verify endpoint |
| 3 | "What events can I stream?" | All email events: sent, delivered, opened, clicked, bounced, complained |
| 4 | "Can I stream to Kafka?" | Yes — Kafka, Kinesis, Datadog, Elasticsearch, custom webhook |
| 5 | "What format are streamed events in?" | JSON, configurable batch size and interval |

### 15K. Template Approval (context: `enterprise_template_stuck`)

| # | Question | Expected Behavior |
|---|----------|-------------------|
| 1 | "How do I set up template approval?" | Scale/Enterprise. API: POST /enterprise/v1/template-workflows |
| 2 | "Template stuck in approval for 3 days" | Check auto-approve timer, ping approver, check escalation |
| 3 | "Can I auto-approve after a timeout?" | Yes — `autoApproveAfter: 72` (hours) in stage config |
| 4 | "How do I bypass approval for urgent templates?" | Admin can force-approve, but requires audit log entry |

---

## Summary Statistics

| Category | Files | Total Lines | Training Examples Needed |
|----------|-------|-------------|------------------------|
| Support Playbooks | 26 | ~13,000+ | ~80 |
| API Documentation | 14 | ~4,000+ | ~40 |
| Enterprise Features | 9 | ~3,600+ | ~70 |
| Compliance & Security | 7 | ~2,000+ | ~25 |
| User Guide | 5 | ~1,900+ | ~15 |
| Operations (SLOs only) | 6 | ~2,200+ | ~10 |
| Production Code (tools gap) | 1 | 2,105 | ~30 (prompt update) |
| Billing/Payment | 2 | ~1,100+ | ~10 |
| **TOTAL** | **70+** | **~30,000+** | **~230 new examples** |

This would bring the dataset from **1,067 → ~1,300 examples**, improving coverage from approximately **75% to 95%** of documented product knowledge.
