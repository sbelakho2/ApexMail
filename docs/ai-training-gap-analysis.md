# ApexMail AI Agent — Training Data Gap Analysis

> **Generated**: Comprehensive audit of all repository content vs. existing training coverage.
> **Scope**: Every file the AI agent should learn from — playbooks, API docs, enterprise docs, compliance, security, operations, tool contracts, user guides, and production code.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Training Architecture Overview](#2-training-architecture-overview)
3. [CRITICAL: Pricing Discrepancies](#3-critical-pricing-discrepancies)
4. [Category 1: Support Playbooks (26 files)](#4-category-1-support-playbooks)
5. [Category 2: API Documentation (8+ files)](#5-category-2-api-documentation)
6. [Category 3: Enterprise Features (10 files)](#6-category-3-enterprise-features)
7. [Category 4: Compliance & Security (11 files)](#7-category-4-compliance--security)
8. [Category 5: User Guide (5 files)](#8-category-5-user-guide)
9. [Category 6: Operations (6+ files)](#9-category-6-operations)
10. [Category 7: Tool Contracts (8 files)](#10-category-7-tool-contracts)
11. [Category 8: Production Action Types Gap](#11-category-8-production-action-types-gap)
12. [Category 9: Customer Profile Coverage](#12-category-9-customer-profile-coverage)
13. [Category 10: Test Suite Coverage](#13-category-10-test-suite-coverage)
14. [Priority Recommendations](#14-priority-recommendations)
15. [Appendix: File Index](#15-appendix-file-index)

---

## 1. Executive Summary

### What exists
- **23 training sections** (A–Q plus remediation rounds R5–R8, R13, new_profiles) in `apps/ai/training/build_agent.py` (7,601 lines)
- **~1,067 training examples** across single-turn, tool-calling, multi-turn, clarification, safety, and knowledge categories
- **50+ customer profiles** in `apps/ai/training/customer_profiles.py` (1,541 lines) across all plan tiers
- **14 test categories** in `apps/ai/training/test_agent.py` (2,082 lines)
- **System prompt** with 35+ tools, pricing table, and behavior rules in `apps/ai/training/prompts_v2.py` (225 lines)

### What's covered well
- DNS/domain troubleshooting (playbooks A, B, C)
- Basic tool-calling format (get_domain_status, get_dns_records, get_usage_stats, etc.)
- Clarification behavior (when to ask vs. act)
- Safety/escalation boundaries
- PAYG pricing math
- Context-aware responses (reading customer data)
- Bounce and deliverability basics

### What's MISSING or critically weak
| Gap | Severity | Estimated training examples needed |
|-----|----------|-----------------------------------|
| **Pricing discrepancies across sources** | 🔴 CRITICAL | Fix first, then ~20 examples |
| Enterprise features (SSO, sub-accounts, log-streaming, private-cloud, QBR, template-approval) | 🔴 HIGH | ~60–80 examples |
| API error codes & resolution steps | 🔴 HIGH | ~40 examples |
| Webhook event types & payloads | 🟡 MEDIUM | ~25 examples |
| SDK troubleshooting (Node.js/Python) | 🟡 MEDIUM | ~30 examples |
| Operations knowledge (SLO, DR, monitoring) | 🟡 MEDIUM | ~20 examples |
| Compliance procedures (GDPR erasure API, data retention specifics) | 🟡 MEDIUM | ~25 examples |
| Message diagnostics & lifecycle | 🟡 MEDIUM | ~20 examples |
| IP warmup schedule specifics | 🟡 MEDIUM | ~15 examples |
| Link tracking & branding details | 🟡 MEDIUM | ~15 examples |
| Contact management (CSV import, limits, segments) | 🟢 LOW | ~10 examples |
| Glossary/terminology training | 🟢 LOW | ~10 examples |
| 42 production action types not in system prompt | 🟡 MEDIUM | System prompt update + ~40 examples |

**Total estimated gap: ~330–370 new training examples needed.**

---

## 2. Training Architecture Overview

### File locations
| File | Purpose | Lines |
|------|---------|-------|
| `apps/ai/training/prompts_v2.py` | System prompt, pricing, tools, behavior rules | 225 |
| `apps/ai/training/build_agent.py` | Training data builder (23 sections, all examples) | 7,601 |
| `apps/ai/training/test_agent.py` | Test suite (14 categories) | 2,082 |
| `apps/ai/training/customer_profiles.py` | 50+ simulated customer profiles | 1,541 |
| `apps/ai/src/assistant/unified.ts` | Production assistant (80+ action types) | 2,105 |
| `data/train_agent.jsonl` | Built training dataset | ~1,067 examples (2x-weighted = ~2,100 entries) |

### Training sections in build_agent.py
| Section | Name | Content |
|---------|------|---------|
| A | CONTEXT_AWARE | Single-turn using customer data |
| B | TOOL_CALLING | Tool call + result handling |
| C | CLARIFICATION | Asking before acting on ambiguity |
| D | MULTI_TURN | Multi-step diagnostic conversations |
| E | SAFETY | Refusals, escalation, off-topic |
| F | PLAYBOOK_COVERAGE | Playbook-sourced knowledge |
| G | PRICING_MATH | Compute exact pricing numbers |
| H | KNOWLEDGE_BASE | Core product knowledge |
| I | CONTEXT_AWARE_EXTRA | Additional context-aware examples |
| J | MULTI_TURN_EXTRA | Additional multi-turn diagnostics |
| K | PLAYBOOK_GAPS | Gap-fill for uncovered playbook topics |
| L | DATA_LOOKUP | "Show me my X" personalized queries |
| M | PAYG_EXAMPLES | Pay-as-you-go specific scenarios |
| N | RAG_VERIFICATION | When to verify context with tools |
| O | REMEDIATION_DRILLS | Targeted fixes for test failures |
| P | ROUND3_REMEDIATION | Round 3 targeted fixes |
| Q | COMPREHENSIVE | Full playbook + API + user guide coverage |
| — | REMEDIATION_R5 | Round 5 fixes (tool calling format, safety) |
| — | REMEDIATION_R6 | Round 6 fixes |
| — | REMEDIATION_R7 | Round 7 fixes |
| — | REMEDIATION_R8 | Round 8 fixes |
| — | NEW_PROFILE_TRAINING | New profile-specific training |
| — | REMEDIATION_R13 | Round 13 minimal fixes (1x weight) |

### Weighting
All sections get 2x weight **except** REMEDIATION_R13 (1x), REMEDIATION_R7 (1x — not in critical_sections list).

---

## 3. CRITICAL: Pricing Discrepancies

**This must be resolved before adding new training data.** Three sources show different numbers:

### Source comparison

| Attribute | System Prompt (`prompts_v2.py`) | Quota Playbook (`quota-rate-limits-billing.md`) | Stripe Tool Contract (`stripe.md`) | Billing Dispute Playbook (`billing-dispute.md`) |
|-----------|------|------|------|------|
| **Currency** | USD | USD | **EUR** | USD |
| **Starter price** | $29 | $29 | **€19** | $29 |
| **Starter emails** | 25,000 | **15,000** | **10,000** | **15,000** |
| **Pro price** | $59 | $59 | **€99 ("Professional")** | $59 |
| **Pro emails** | 50,000 | 50,000 | **50,000** | 50,000 |
| **Growth price** | $129 | $129 | **€49** | $129 |
| **Growth emails** | 100,000 | 100,000 | **25,000** | **100,000** |
| **Scale price** | $399 | $399 | **€199 ("Business")** | $399 |
| **Scale emails** | 500,000 | 500,000 | — | 500,000 |
| **Enterprise** | $1,299 | $1,299 | — | $1,299 |
| **Contacts limit** | Not mentioned | Listed per plan | Not mentioned | Not mentioned |
| **Daily limits** | Not mentioned | Listed per plan | Not mentioned | Not mentioned |

### Impact
- Training examples in sections G (PRICING_MATH) and M (PAYG) use system prompt numbers
- If system prompt is wrong, **every pricing-related training example teaches incorrect facts**
- The quota playbook appears more detailed (includes contacts limits, daily limits, burst rates) — may be more current
- The Stripe contract shows EUR pricing with different plan names — this may be the actual billing backend vs. the marketing/displayed pricing

### Required action
1. **Determine canonical source of truth** — is it `plans.ts` (referenced in prompts_v2.py), the database, or Stripe?
2. Reconcile all sources to a single pricing table
3. Update system prompt if needed
4. Review and fix all pricing math training examples

---

## 4. Category 1: Support Playbooks

### Coverage map

Files: `docs/support-playbooks/*.md` (26 files)

| Playbook | Issues | Training Coverage | Missing Topics |
|----------|--------|-------------------|----------------|
| **a-domain-dns-troubleshooting.md** (332 lines) | #1–18 | ✅ Good (Sections F, K, Q) | Squarespace CNAME limitations, wildcard DNS impact |
| **b-dkim-spf-dmarc-correctness.md** (285 lines) | #19–35 | ✅ Good (Sections F, K, Q) | Body hash failures on forwarded mail, selector rotation timing |
| **c-sender-identity-alignment.md** (193 lines) | #36–46 | 🟡 Partial | Free mailbox From (gmail.com rejection), plus-addressing, "via" display explanation, delegation without DNS |
| **d-api-auth-troubleshooting.md** (306 lines) | #47–60 | 🟡 Partial | Webhook signature HMAC-SHA256 computation, idempotency key dedup, max attachment 25MB/50MB total, max recipients 100/msg |
| **e-webhooks-events-troubleshooting.md** (358 lines) | #61–75 | 🟡 Partial | Full 17 event types table, TLS cert renewal, retry schedule (30s timeout, 8 retries over 24h), replay attacks |
| **f-bounces-complaints-suppressions.md** (350 lines) | #76–92 | ✅ Good | Detailed bounce categories (hard/soft/block/undetermined), retry schedule (5m→15m→30m→1h→4h), complaint rate threshold 0.1% math |
| **g-deliverability-inbox-placement.md** (501 lines) | #94–108 | ✅ Good | Gmail Promotions tab avoidance specifics, URL shortener rejection, tracking domain mismatch impact |
| **h-templates-rendering-content.md** (442 lines) | #109–120 | 🟡 Partial | MJML compilation, Handlebars helpers ({{#if}}, {{#each}}, {{formatDate}}), HTML injection prevention, dark mode rendering, image hosting requirements |
| **ip-allowlist-security-controls.md** (1,120 lines) | — | 🔴 Weak | 14 API key scopes listing, RBAC roles (owner/admin/developer/analyst/billing) with full permissions matrix, IP allowlisting per-key, MFA setup, audit log queries |
| **ip-pools-warmup-infrastructure.md** (719 lines) | — | 🟡 Partial | Full 29-day warmup schedule (Day 1: 50 → Day 29: 100K+), rDNS/PTR requirements, MTA-STS/DANE/TLS-RPT, inbound receiving roadmap |
| **link-tracking-branding.md** (856 lines) | — | 🟡 Partial | Click/open tracking architecture, SSL provisioning for custom tracking domains, bot detection logic, List-Unsubscribe RFC 8058, one-click unsubscribe |
| **llm-chatbot-runtime.md** (495 lines) | — | 🔴 Internal only | AI architecture reference — context window 8192, max output 4096, MiniLM-L6-v2 embeddings. **Agent should NOT learn this — internal doc** |
| **message-diagnostics-retention.md** (1,075 lines) | — | 🔴 Weak | Full message lifecycle (Accept→Queue→Process→Deliver→Track→Feedback), retention defaults per plan, message stuck in queue diagnosis, SMTP transcript analysis |
| **quota-rate-limits-billing.md** (572 lines) | — | 🟡 Partial (pricing discrepancy!) | What counts as a "send", daily sending limits, burst rate limits, overage handling, PAYG billing reconciliation |
| **sdk-integration-runtime.md** (1,049 lines) | — | 🔴 Weak | ESM vs CJS import issues, TypeScript type definitions, framework integration (Next.js App Router, Express middleware, Remix loaders), SDK retry/timeout config |
| **sending-suspended.md** (325 lines) | — | 🟡 Partial | Suspension reasons (complaint rate, content violation, DMCA), remediation steps, appeal process |
| **webhook-failures.md** (270 lines) | — | 🟡 Partial | Redis retry queue internals, endpoint reachability testing, failure vs. permanent disable |
| **cmp-compliance-privacy-retention.md** (516 lines) | — | 🟡 Partial | GDPR erasure API endpoints (`DELETE /v1/contacts/:id?gdpr=true`), 30-day grace period, what's retained vs deleted |
| **account-lockout.md** (298 lines) | — | 🔴 Weak | Lockout causes (failed logins, suspicious activity), self-service unlock, MFA recovery |
| **api-errors.md** (483 lines) | — | 🔴 Weak | Full error code reference with resolution steps (40+ error codes), HTTP status mapping, retry guidance per error type |
| **billing-dispute.md** (317 lines) | — | 🔴 Weak | Dispute handling process, overage calculation, credit/refund escalation path, dedicated IP add-on pricing ($49/mo) |
| **bounce-investigation.md** (270 lines) | — | 🟡 Partial | Deep bounce investigation workflow, SMTP response code interpretation, ISP-specific bounce patterns |
| **data-export.md** (349 lines) | — | 🔴 Weak | Export API endpoints, data formats (JSON, CSV), bulk export scheduling, GDPR data portability compliance |
| **deliverability-triage.md** (296 lines) | — | 🟡 Partial | Triage flowchart, ISP-specific troubleshooting, Google Postmaster Tools interpretation |
| **domain-verification.md** (316 lines) | — | ✅ Good | Overlaps well with playbook A training |
| **performance-degradation.md** (483 lines) | — | 🔴 Weak | Latency diagnosis, API response time thresholds, queue depth monitoring, worker health checks |

### Gaps to fill (estimated ~80 new training examples)

**High priority (customer-facing, frequently asked):**
1. API error codes — create training examples for the top 15 error codes with resolution steps
2. SDK integration issues — ESM/CJS, TypeScript types, framework-specific patterns
3. Message diagnostics — "my email is stuck", "show me the SMTP transcript", message lifecycle
4. IP warmup schedule — exact day-by-day volume table
5. Webhook event types — full reference of 17 event types with payload examples

**Medium priority:**
6. Account lockout — causes, self-service recovery, MFA
7. Template rendering — Handlebars helpers, MJML, dark mode, image requirements
8. Billing dispute scenarios — overage calculation, dedicated IP pricing
9. Performance degradation — latency troubleshooting, queue depth
10. Data export — API endpoints and formats

---

## 5. Category 2: API Documentation

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/api/authentication.md` | 397 | API keys, JWT, OAuth 2.0 (PKCE), scopes, token refresh/revocation |
| `docs/api/rate-limits.md` | ~200 | Rate limit headers, backoff, batch endpoints |
| `docs/api/errors.md` | 708 | Full error code reference (~40 codes) |
| `docs/api/webhooks.md` | 446 | Event payloads, signature verification |
| `docs/api/sdk-reference.md` | 480 | Node.js/Python SDK methods |
| `docs/api/endpoints/*.md` | 7 files | analytics, campaigns, contacts, domains, events, messages, templates |

### Training coverage assessment

| Topic | Covered? | Details |
|-------|----------|---------|
| API key types (live/test) | ✅ Yes | In system prompt + training |
| Bearer token auth | ✅ Yes | Basic auth covered |
| OAuth 2.0 / PKCE flow | 🔴 No | Not trained at all |
| JWT token refresh/revocation | 🔴 No | Not trained |
| API scopes (14 defined) | 🔴 No | Listed in playbook but not trained |
| Error code resolution | 🔴 Weak | Only `invalid_api_key`, `rate_limit_exceeded` trained; ~35 other codes untrained |
| Rate limit headers | 🟡 Partial | Mentioned but not detailed (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After) |
| Webhook signature verification | 🟡 Partial | Mentioned; full HMAC-SHA256 code not trained |
| SDK initialization | 🟡 Partial | Basic init covered; options (timeout, retries, baseURL) not |
| SDK batch methods | 🔴 No | `messages.sendBatch()` not trained |
| Contact endpoints | 🔴 No | CRUD + CSV import endpoints not trained |
| Analytics endpoints | 🔴 No | Not trained |
| Campaign endpoints | 🟡 Partial | Basic create/pause, but not list/update/delete |
| Template endpoints | 🟡 Partial | Basic CRUD, but not previewing or versioning |

### Specific gaps to fill (~40 examples)

1. **OAuth 2.0 flow** — "How do I set up OAuth for my app?" (PKCE flow, redirect URIs, scopes)
2. **Error code training** — Top 15 most common errors with exact resolution steps:
   - `sender_not_verified` → verify domain first
   - `template_not_found` → check template_id exists
   - `recipient_suppressed` → email on suppression list
   - `rate_limit_exceeded` → implement backoff, check headers
   - `payload_too_large` → attachment limit 25MB/50MB total
   - `invalid_webhook_url` → must be HTTPS, return 2xx
   - `domain_limit_exceeded` → upgrade plan
   - `ip_not_allowed` → check IP allowlist settings
   - `insufficient_scope` → API key missing required scope
3. **Rate limit header interpretation** — teach the agent to explain X-RateLimit-* headers
4. **Webhook signature verification** — code examples in Node.js and Python
5. **SDK troubleshooting** — timeout config, retry logic, error handling patterns
6. **Batch operations** — sendBatch, importContacts, bulk operations

---

## 6. Category 3: Enterprise Features

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/enterprise/sso.md` | 239 | SAML 2.0, OIDC, IdP setup (Okta, Azure AD), auto-provisioning |
| `docs/enterprise/sub-accounts.md` | 374 | Hierarchical accounts, API, resource quotas, consolidated billing |
| `docs/enterprise/whitelabel.md` | 360 | Custom domains, UI branding, CSS/JS, SSL provisioning |
| `docs/enterprise/support.md` | 454 | Support tiers (Standard 24h / Premium 4h / Enterprise 15min), ticket API |
| `docs/enterprise/compliance.md` | 507 | Consent management API, regulations (GDPR, CCPA, HIPAA, CASL, LGPD, PDPA, POPIA) |
| `docs/enterprise/log-streaming.md` | 498 | Real-time streaming to S3/BigQuery/Snowflake/Kafka/Kinesis/Elasticsearch/Datadog |
| `docs/enterprise/private-cloud.md` | 381 | Dedicated/private/on-prem deployment, regions (eu-fi, eu-de), from $2,500/mo |
| `docs/enterprise/qbr.md` | 493 | Quarterly Business Reviews, scheduling API |
| `docs/enterprise/template-approval.md` | 441 | Multi-stage approval workflows, role-based approvers |

### Training coverage assessment

| Feature | Covered? | What exists |
|---------|----------|-------------|
| SSO (SAML/OIDC) | 🟡 Partial | One mention in Section K (`build_agent.py` line 1098) — basic "SSO is available on Scale/Enterprise" + setup steps |
| SSO troubleshooting | 🔴 No | IdP config issues, SAML assertion errors, attribute mapping |
| Sub-accounts | 🔴 No | No training examples at all |
| White-label | 🟡 Minimal | One training example for branding leak fix (R8, line 6406) |
| White-label setup & troubleshooting | 🔴 No | SSL provisioning, custom CSS, tracking domain config |
| Support tiers | 🔴 No | SLA response times, priority levels, escalation paths not trained |
| Enterprise compliance features | 🟡 Partial | Basic "Enterprise has HIPAA/SOC2" mentioned, but not consent management API, regulation-specific flows |
| Log streaming | 🔴 No | No training examples |
| Private cloud | 🔴 No | No training examples |
| QBR | 🔴 No | No training examples (should escalate to CSM) |
| Template approval workflows | 🔴 No | No training examples |

### This is the BIGGEST gap in the training data.

Enterprise customers pay $1,299/mo and the agent can barely answer their feature-specific questions. Required examples (~60–80):

**SSO (10 examples):**
1. "How do I set up SSO with Okta?" — step-by-step SAML config
2. "SAML assertion is failing" — attribute mapping troubleshooting
3. "Can I use Google Workspace as my IdP?" — OIDC setup
4. "How does auto-provisioning work with SSO?" — SCIM/JIT provisioning
5. "User can't log in after SSO setup" — common misconfigs

**Sub-accounts (10 examples):**
6. "How do I create a sub-account for my client?" — API + dashboard
7. "Can sub-accounts have their own domains?" — resource isolation
8. "How does billing work with sub-accounts?" — consolidated billing
9. "Set resource quotas for a sub-account" — API params
10. "Sub-account user can't access parent features" — permissions model

**Log streaming (8 examples):**
11. "How do I stream events to BigQuery?" — setup config
12. "My S3 log stream stopped working" — troubleshooting
13. "What events are available for streaming?" — event type list
14. "Can I stream to Kafka?" — supported destinations

**Private cloud (5 examples):**
15. "What's the difference between shared and private cloud?" — comparison
16. "What regions are available?" — eu-fi, eu-de-south, eu-de-central
17. "How much does private cloud cost?" → Escalate to sales (from $2,500/mo base)

**QBR (3 examples):**
18. "How do I schedule a QBR?" → Escalate to CSM
19. "What's covered in a QBR?" — high-level overview

**Template approval (8 examples):**
20. "How do I set up template approval workflows?" — multi-stage config
21. "Template stuck in approval" — troubleshooting
22. "Can I auto-approve templates from certain users?" — timer config

**White-label (8 examples):**
23. "How do I set up white-labeling?" — domains, CSS, JS
24. "White-label SSL certificate not provisioning" — troubleshooting
25. "Customer seeing ApexMail branding" — CSS override diagnosis

**Support tiers (5 examples):**
26. "What response time can I expect on my ticket?" — tier lookup from plan
27. "How do I submit a ticket via API?" — ticket API

---

## 7. Category 4: Compliance & Security

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/compliance/gdpr-compliance.md` | 340 | Bel Consulting OÜ (Registry 16192499), controller vs processor, lawful bases, sub-processor: Hetzner |
| `docs/compliance/data-retention.md` | 183 | Full schedule: email content 30d, events 90d, analytics 2yr, billing 7yr, backups 30d |
| `docs/compliance/acceptable-use-policy.md` | 250 | Prohibited content (phishing, malware), consent requirements, volume limits |
| `docs/compliance/incident-response.md` | 329 | P1–P4 severity, response phases, GDPR breach notification 72h |
| `docs/security/data-protection.md` | 281 | AES-256-GCM, TLS 1.3/1.2, per-org encryption keys, tenant isolation |
| `docs/security/email-authentication.md` | 322 | ARC (RFC 8617), MTA-STS (RFC 8461), TLSRPT (RFC 8460), BIMI/VMC |

### Training coverage assessment

| Topic | Covered? | What exists |
|-------|----------|-------------|
| GDPR basics (controller/processor) | 🟡 Partial | One example in Section F about GDPR features |
| GDPR erasure API (`DELETE /v1/contacts/:id?gdpr=true`) | 🔴 No | Not trained with actual API endpoint |
| GDPR data export / portability | 🔴 No | Export endpoint not trained |
| Data retention schedule (by plan + data type) | 🔴 No | Plans list retention in system prompt (7d→730d) but no per-data-type schedule |
| AUP enforcement | 🟡 Partial | Suspension/sending-suspended trained briefly |
| Incident response severity levels | 🔴 No | P1–P4 classification not trained |
| GDPR breach notification (72h) | 🔴 No | Not trained |
| Encryption details (AES-256-GCM) | 🔴 No | Not trained (customers may ask "is my data encrypted?") |
| TLS version support | 🔴 No | TLS 1.3/1.2 not trained |
| ARC/MTA-STS/TLSRPT/BIMI | 🔴 Weak | Glossary terms exist but practical setup not trained |
| HIPAA BAA process | 🟡 Partial | "Enterprise has HIPAA" mentioned but BAA request flow not trained |
| SOC 2 certification | 🟡 Partial | Mentioned but not detailed |
| Legal entity info | 🔴 No | "Bel Consulting OÜ, Estonia" not explicitly trained as an answer |
| Sub-processor list | 🔴 No | Hetzner Online GmbH as sub-processor not trained |

### Gaps to fill (~25 examples)

1. "Is my data encrypted?" → AES-256-GCM at rest, TLS 1.3 in transit, per-org keys
2. "How long do you keep my data?" → Retention schedule by data type
3. "I need a GDPR data export for a contact" → API endpoint + escalation
4. "How do I delete a contact under GDPR?" → `DELETE /v1/contacts/:id?gdpr=true` + 30-day grace
5. "Where is my data stored?" → Hetzner (EU), specific regions
6. "Do you have a DPA?" → Escalate to contact@apexmail.ee (legal request)
7. "What's your legal entity?" → Bel Consulting OÜ, Registry Code 16192499, Tallinn
8. "How do I request a BAA for HIPAA?" → Enterprise plan required, escalate to CSM
9. "What happened during the incident?" → P1–P4 severity model, incident response process
10. "What does your AUP prohibit?" → Key prohibited practices
11. "How do I set up MTA-STS?" → MTA-STS record + policy file
12. "What is BIMI and do you support it?" → BIMI/VMC setup

---

## 8. Category 5: User Guide

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/user-guide/getting-started.md` | 366 | Account setup, domain verification, API key creation, first email |
| `docs/user-guide/contacts.md` | 434 | Contact lists, CSV import (max 25MB/100K rows), metadata, tags, segments |
| `docs/user-guide/inbox-placement-testing.md` | 353 | Seed list testing, benchmarks (transactional 95-99%, marketing 85-95%) |
| `docs/user-guide/glossary.md` | 276 | 30+ email terminology definitions |
| `docs/user-guide/troubleshooting.md` | 559 | Auth errors, rate limiting, spam, domain verification, webhooks, bounces |

### Training coverage

| Topic | Covered? | Notes |
|-------|----------|-------|
| Account setup flow | 🟡 Partial | Basic "create account" but not step-by-step |
| Domain verification walkthrough | ✅ Good | Well covered |
| First API key creation | 🟡 Partial | Mentioned but not hands-on |
| CSV import (limits, format, fields) | 🔴 No | Max 25MB / 100K rows, standard fields, conflict resolution not trained |
| Contact segments | 🔴 No | Segment creation and querying not trained |
| Contact tags | 🟡 Partial | Basic tagging mentioned |
| Inbox placement testing | 🔴 No | Seed list testing flow, benchmarks not trained |
| Glossary terms | 🟡 Partial | Some terms (SPF, DKIM) well trained; others (VERP, DSN, FBL, ARF) not |
| Troubleshooting: 409 Conflict | 🔴 No | Concurrent update resolution |
| Troubleshooting: 413 Payload Too Large | 🔴 No | Attachment limits resolution |
| Troubleshooting: billing issues | 🟡 Partial | Basic escalation trained |

### Gaps to fill (~10 examples)

1. "How do I import contacts from CSV?" → Format, limits (25MB/100K rows), required fields
2. "What's the max attachment size?" → 25MB single / 50MB total
3. "What is VERP?" / "What does FBL mean?" → Glossary training
4. "How do I test inbox placement?" → Seed list testing flow
5. "I'm getting a 409 error" → Concurrent update, idempotency keys
6. "How do I create a contact segment?" → Segment endpoints and logic

---

## 9. Category 6: Operations

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/operations/slo-management.md` | 313 | API 99.9%, P99 < 500ms, 98% delivery in 5min, 99.95% tracking |
| `docs/operations/monitoring.md` | 546 | Full Prometheus metrics catalog |
| `docs/operations/disaster-recovery.md` | 429 | Daily full + 6h incremental + WAL, PITR, RPO < 1min, RTO < 15min |
| `docs/operations/on-call.md` | 198 | Weekly rotation, P1–P4 response SLAs, PagerDuty |

### Training relevance
Operations docs are **internal** — the agent shouldn't reveal infrastructure details. **However**, the agent should know:

| What agent should know | Covered? |
|------------------------|----------|
| SLO commitments to customers (99.9% uptime, 98% delivery) | 🔴 No |
| "Is the service down right now?" → how to check/respond | 🔴 No |
| "When will the issue be resolved?" → response SLA commitments | 🔴 No |
| "What's your backup strategy?" → "We have redundant backups with point-in-time recovery" (vague, no specifics) | 🔴 No |
| "Is there a status page?" → link/info | 🔴 No |

### Gaps to fill (~20 examples)

1. "What's your uptime SLA?" → 99.9% API availability (Scale/Enterprise get credits)
2. "Is ApexMail down?" → Check status, acknowledge issue, provide ETA framework
3. "How quickly will my issue be fixed?" → P1–P4 response times by support tier
4. "Are my backups safe?" → Point-in-time recovery, RPO/RTO (no numbers — just reassurance)
5. "What's the delivery time SLA?" → 98% within 5 minutes
6. "Service seems slow" → Check API health, explain P99 targets

---

## 10. Category 7: Tool Contracts

### Source files
| File | Lines | Content |
|------|-------|---------|
| `docs/tool-contracts/ses.md` | 170 | SES as fallback ONLY, circuit breaker, 50 emails/sec, 100K/day |
| `docs/tool-contracts/stripe.md` | 227 | Products/pricing (EUR!), subscription lifecycle, webhooks |
| `docs/tool-contracts/hetzner.md` | 154 | CAX41 ARM servers, 5-server fleet, private network |
| `docs/tool-contracts/hono.md` | ? | Web framework contract |
| `docs/tool-contracts/postgresql.md` | ? | Database contract |
| `docs/tool-contracts/prometheus.md` | ? | Monitoring contract |
| `docs/tool-contracts/redis.md` | ? | Cache/queue contract |
| `docs/tool-contracts/zone-ee.md` | ? | Domain registrar contract |

### Training relevance
Tool contracts are **entirely internal** — the agent must NEVER reveal details. However:

| What agent should indirectly know | Covered? |
|-----------------------------------|----------|
| Billing flows (upgrade triggers Stripe subscription change) | 🔴 No |
| SES is NOT a primary sending path | 🔴 No (but agent shouldn't mention SES anyway) |
| Subscription lifecycle (trial → active → past_due → canceled) | 🔴 No |
| Payment failure handling ("dunning") | 🔴 No |

### Gaps to fill (~5 examples, carefully worded)

1. "My payment failed" → Agent should know dunning flow without revealing Stripe
2. "What happens when I cancel?" → Subscription lifecycle (access until period end)
3. "I upgraded but nothing changed" → Subscription provisioning delay

---

## 11. Category 8: Production Action Types Gap

### The problem
The production assistant (`unified.ts`) defines **~80 action types**, but the system prompt only lists **~35 tools**. This means the agent is being trained on a subset of its actual capabilities.

### Action types in unified.ts NOT in system prompt

**Diagnostics / message tracing (NOT trained):**
- `get_smtp_transcript` — view SMTP session for message
- `get_scheduled_send_status` — check scheduled messages
- `get_message_event_timeline` — full event timeline
- `trace_message` — end-to-end message trace
- `validate_template` — template validation
- `get_content_scan_result` — content scan results

**DNS / authentication diagnostics (NOT trained):**
- `force_dns_recheck` — force re-verification
- `check_bimi_status` — BIMI record check
- `check_rdns_ptr` — reverse DNS check

**Deliverability / reputation (NOT trained):**
- `run_deliverability_audit` — full audit
- `get_geo_sending_report` — geographic report
- `get_complaint_rate` — current complaint rate
- `get_suppression_scope` — suppression scope details

**Webhooks / events (NOT trained):**
- `get_webhook_config` — full config
- `get_webhook_delivery_log` — delivery history
- `resend_webhook_events` — replay events
- `enable_webhook_endpoint` — enable endpoint
- `get_tracking_domain_config` — tracking domain config
- `rotate_tracking_domain` — rotate tracking domain
- `check_cert_provisioning_status` — SSL cert status

**API diagnostics (NOT trained):**
- `get_rate_limit_status` — current rate limits
- `get_api_error_log` — API error history
- `get_api_health_detailed` — detailed health
- `enable_sdk_debug_mode` — SDK debug mode

**Account / quota (NOT trained):**
- `get_quota_status` — current quotas
- `get_usage_breakdown` — detailed usage
- `get_sending_status` — sending status
- `get_invoice_reconciliation` — invoice details

**Security (NOT trained):**
- `manage_ip_allowlist` — IP allowlist management
- `get_user_permissions` — user permission check
- `resend_team_invite` — resend invite
- `get_audit_log` — audit log access
- `set_emergency_throttle` — emergency throttle
- `get_api_access_log` — API access history
- `unlock_account` — unlock account
- `freeze_account` — freeze account
- `export_audit_log` — export audit data

**Compliance / privacy (NOT trained):**
- `execute_gdpr_erasure` — GDPR erasure
- `get_consent_record` — consent lookup
- `set_retention_policy` — retention policy
- `request_dpa` — DPA request
- `request_compliance_doc` — compliance docs
- `set_legal_hold` — legal hold
- `get_compliance_risk_score` — risk score

**Operations (NOT trained):**
- `request_dedicated_ip` — dedicated IP request
- `get_warmup_status` — IP warmup status
- `get_ip_assignment` — IP assignment
- `get_throttle_status` — throttle status
- `rollback_deployment` — deployment rollback
- `get_system_health` — system health
- `reconcile_analytics` — analytics reconciliation
- `get_worker_status` — worker status

**LLM self-diagnostics (NOT trained):**
- `get_llm_config` — LLM configuration
- `get_llm_session_log` — session log
- `get_intent_debug` — intent debug

### Recommendation
1. **Update `prompts_v2.py`** to include the ~42 missing action types as tools
2. Create training examples showing when to use each new tool
3. Some tools (LLM self-diagnostics, rollback_deployment, ops tools) should probably remain internal and not be exposed to the agent

---

## 12. Category 9: Customer Profile Coverage

### Current profiles in `customer_profiles.py`

| Plan | Count | Industries |
|------|-------|-----------|
| Free | 4 | Hobby blogger, student, nonprofit test, startup MVP |
| Starter | 6+ | Restaurant, photographer, real estate, local bakery, etc. |
| Pro | 6+ | EdTech, realtor, fitness, travel, etc. |
| Growth | 6+ | Logistics, crypto, travel agency, CloudFlare DKIM issue |
| Scale | 4+ | Insurance, deliverability focus |
| Enterprise | 4+ | Compliance/HIPAA, whitelabel, fintech |
| PAYG | 6+ | API-first, seasonal, high-volume |

### Gap assessment
Profiles are **well-covered** overall. Minor gaps:

1. **No gaming/entertainment industry** — common email use case
2. **No healthcare (non-enterprise)** — small clinics, health newsletters
3. **No government/public sector** — specific compliance needs
4. **No agency managing multiple clients** — sub-account use case
5. **No profile with active A/B test** — Growth+ feature
6. **No profile with log streaming configured** — Enterprise feature
7. **No profile with template approval workflow** — Enterprise feature

---

## 13. Category 10: Test Suite Coverage

### Current test categories in `test_agent.py`

| Category | Tests | What's tested |
|----------|-------|---------------|
| context_awareness | ~10 | Reference customer data from context |
| tool_calling | ~12 | Emit valid `tool_call` JSON blocks |
| clarification | ~10 | Ask before acting on ambiguity |
| pricing_math | ~8 | Compute exact pricing numbers |
| safety | ~8 | Refuse off-topic / malicious |
| knowledge | ~10 | Accurate product info |
| hallucination | ~8 | Don't invent features |
| escalation | ~6 | Escalate appropriately |
| multi_turn | ~6 | Multi-step conversations |
| playbook_coverage | ~10 | Playbook-sourced knowledge |
| data_lookup | ~8 | Personalized "show me X" |
| rag_verification | ~6 | Verify context with tools |
| personalized_variations | ~8 | Variations with different profiles |
| new_profile_scenarios | ~42 | New profile-specific tests |

### Missing test categories

1. **Enterprise features** — No tests for SSO, sub-accounts, whitelabel, log-streaming responses
2. **API error handling** — No tests for specific error code responses
3. **SDK troubleshooting** — No tests for SDK-specific questions
4. **Compliance questions** — No tests for GDPR, data retention, legal questions
5. **Operations/SLA** — No tests for uptime, response time, system health questions
6. **New tool usage** — No tests for the 42 action types not in system prompt

---

## 14. Priority Recommendations

### Phase 1: CRITICAL (do first)

#### 1.1 Resolve pricing discrepancies
- Determine canonical pricing source (plans.ts, Stripe, or docs)
- Update `prompts_v2.py` system prompt if needed
- Audit all training examples in sections G (PRICING_MATH) and M (PAYG)
- Update inconsistent playbooks

#### 1.2 Add enterprise feature training (~60 examples)
These customers pay the most and get the worst agent experience:
- SSO setup & troubleshooting (10 examples)
- Sub-accounts (10 examples)
- Log streaming (8 examples)
- White-label (8 examples)
- Template approval workflows (8 examples)
- Support tier awareness (5 examples)
- Private cloud (escalate to sales) (3 examples)
- QBR (escalate to CSM) (3 examples)

### Phase 2: HIGH (next sprint)

#### 2.1 API error code training (~30 examples)
- Top 15 error codes with resolution steps
- Rate limit header explanation
- Webhook signature verification (code samples)

#### 2.2 Update system prompt with missing tools (~42 new tools)
- Add production action types from `unified.ts` to `prompts_v2.py`
- Create training examples for new tools
- Categorize which are safe to expose vs. internal-only

#### 2.3 SDK troubleshooting training (~20 examples)
- ESM vs CJS import issues
- TypeScript type errors
- Framework integration (Next.js, Express)
- Error handling patterns

### Phase 3: MEDIUM (backlog)

#### 3.1 Message diagnostics (~15 examples)
- Message lifecycle explanation
- "Why is my email stuck in queue?"
- SMTP transcript interpretation

#### 3.2 Compliance & security knowledge (~15 examples)
- Data retention schedule by data type
- GDPR erasure API endpoint
- Encryption/TLS details
- Legal entity info

#### 3.3 Operations knowledge (~10 examples)
- SLO commitments
- "Is the service down?" responses
- Response time expectations

#### 3.4 Contact management (~10 examples)
- CSV import flow & limits
- Segments & tags
- Conflict resolution

### Phase 4: LOW (polish)

#### 4.1 Glossary/terminology (~10 examples)
- VERP, DSN, FBL, ARF definitions
- ARC, MTA-STS, BIMI practical setup

#### 4.2 Additional customer profiles (~5 profiles)
- Agency managing sub-accounts
- Profile with A/B testing active
- Profile with log streaming configured

#### 4.3 Additional test categories
- Enterprise feature tests
- API error handling tests
- Compliance question tests

---

## 15. Appendix: File Index

### Training system
| Path | Purpose |
|------|---------|
| `apps/ai/training/prompts_v2.py` | System prompt (225 lines) |
| `apps/ai/training/build_agent.py` | Training data builder (7,601 lines) |
| `apps/ai/training/test_agent.py` | Test suite (2,082 lines) |
| `apps/ai/training/customer_profiles.py` | Customer profiles (1,541 lines) |
| `data/train_agent.jsonl` | Built training dataset |

### Production code
| Path | Purpose |
|------|---------|
| `apps/ai/src/assistant/unified.ts` | Production assistant (2,105 lines, 80+ action types) |

### Support playbooks (26 files)
| Path | Lines | Key topics |
|------|-------|-----------|
| `docs/support-playbooks/a-domain-dns-troubleshooting.md` | 332 | Issues 1–18, DNS propagation, wrong domain |
| `docs/support-playbooks/b-dkim-spf-dmarc-correctness.md` | 285 | Issues 19–35, selector rotation, alignment |
| `docs/support-playbooks/c-sender-identity-alignment.md` | 193 | Issues 36–46, RFC 5322 From, Reply-To |
| `docs/support-playbooks/d-api-auth-troubleshooting.md` | 306 | Issues 47–60, keys, webhook signatures |
| `docs/support-playbooks/e-webhooks-events-troubleshooting.md` | 358 | Issues 61–75, 17 event types |
| `docs/support-playbooks/f-bounces-complaints-suppressions.md` | 350 | Issues 76–92, retry schedule |
| `docs/support-playbooks/g-deliverability-inbox-placement.md` | 501 | Issues 94–108, IP warmup |
| `docs/support-playbooks/h-templates-rendering-content.md` | 442 | Issues 109–120, Handlebars, MJML |
| `docs/support-playbooks/ip-allowlist-security-controls.md` | 1,120 | API scopes, RBAC, MFA |
| `docs/support-playbooks/ip-pools-warmup-infrastructure.md` | 719 | 29-day warmup schedule |
| `docs/support-playbooks/link-tracking-branding.md` | 856 | Click/open tracking, bot detection |
| `docs/support-playbooks/llm-chatbot-runtime.md` | 495 | Internal AI architecture |
| `docs/support-playbooks/message-diagnostics-retention.md` | 1,075 | Message lifecycle, retention |
| `docs/support-playbooks/quota-rate-limits-billing.md` | 572 | Plan quotas, daily limits |
| `docs/support-playbooks/sdk-integration-runtime.md` | 1,049 | Node.js/Python SDK |
| `docs/support-playbooks/sending-suspended.md` | 325 | Suspension reasons |
| `docs/support-playbooks/webhook-failures.md` | 270 | Webhook retry logic |
| `docs/support-playbooks/cmp-compliance-privacy-retention.md` | 516 | GDPR erasure API |
| `docs/support-playbooks/account-lockout.md` | 298 | Lockout causes, MFA |
| `docs/support-playbooks/api-errors.md` | 483 | 40+ error codes |
| `docs/support-playbooks/billing-dispute.md` | 317 | Disputes, overages |
| `docs/support-playbooks/bounce-investigation.md` | 270 | Deep bounce analysis |
| `docs/support-playbooks/data-export.md` | 349 | Export API |
| `docs/support-playbooks/deliverability-triage.md` | 296 | ISP-specific triage |
| `docs/support-playbooks/domain-verification.md` | 316 | Verification walkthrough |
| `docs/support-playbooks/performance-degradation.md` | 483 | Latency, queue depth |

### API documentation
| Path | Lines | Content |
|------|-------|---------|
| `docs/api/authentication.md` | 397 | API keys, JWT, OAuth 2.0 |
| `docs/api/rate-limits.md` | ~200 | Rate limit headers, backoff |
| `docs/api/errors.md` | 708 | 40+ error codes |
| `docs/api/webhooks.md` | 446 | Event payloads, signatures |
| `docs/api/sdk-reference.md` | 480 | Node.js/Python SDK |
| `docs/api/endpoints/*.md` | 7 files | Full REST API reference |

### Enterprise documentation
| Path | Lines | Content |
|------|-------|---------|
| `docs/enterprise/sso.md` | 239 | SAML 2.0, OIDC |
| `docs/enterprise/sub-accounts.md` | 374 | Hierarchical accounts |
| `docs/enterprise/whitelabel.md` | 360 | Custom branding |
| `docs/enterprise/support.md` | 454 | Support tiers |
| `docs/enterprise/compliance.md` | 507 | Consent management |
| `docs/enterprise/log-streaming.md` | 498 | Event streaming |
| `docs/enterprise/private-cloud.md` | 381 | Dedicated deployment |
| `docs/enterprise/qbr.md` | 493 | Quarterly reviews |
| `docs/enterprise/template-approval.md` | 441 | Approval workflows |

### Compliance & security
| Path | Lines | Content |
|------|-------|---------|
| `docs/compliance/gdpr-compliance.md` | 340 | GDPR framework |
| `docs/compliance/data-retention.md` | 183 | Retention schedule |
| `docs/compliance/acceptable-use-policy.md` | 250 | AUP |
| `docs/compliance/incident-response.md` | 329 | P1–P4, response phases |
| `docs/security/data-protection.md` | 281 | Encryption, isolation |
| `docs/security/email-authentication.md` | 322 | ARC, MTA-STS, BIMI |

### User guide
| Path | Lines | Content |
|------|-------|---------|
| `docs/user-guide/getting-started.md` | 366 | Account setup |
| `docs/user-guide/contacts.md` | 434 | Contact management |
| `docs/user-guide/inbox-placement-testing.md` | 353 | Seed list testing |
| `docs/user-guide/glossary.md` | 276 | Terminology |
| `docs/user-guide/troubleshooting.md` | 559 | Common issues |

### Operations (internal — agent should know SLOs only)
| Path | Lines | Content |
|------|-------|---------|
| `docs/operations/slo-management.md` | 313 | SLO targets |
| `docs/operations/monitoring.md` | 546 | Prometheus metrics |
| `docs/operations/disaster-recovery.md` | 429 | Backup/PITR |
| `docs/operations/on-call.md` | 198 | On-call rotation |

### Tool contracts (internal — agent should NEVER reveal)
| Path | Lines | Content |
|------|-------|---------|
| `docs/tool-contracts/ses.md` | 170 | SES fallback |
| `docs/tool-contracts/stripe.md` | 227 | Billing (EUR pricing!) |
| `docs/tool-contracts/hetzner.md` | 154 | Infrastructure |
| `docs/tool-contracts/hono.md` | ? | Web framework |
| `docs/tool-contracts/postgresql.md` | ? | Database |
| `docs/tool-contracts/prometheus.md` | ? | Monitoring |
| `docs/tool-contracts/redis.md` | ? | Cache |
| `docs/tool-contracts/zone-ee.md` | ? | Domain registrar |
