# Recovered Files Analysis — `/tmp/apexmail_scenarios/`

> Generated from deep read of all 13 recovered files (25,120 lines, ~1.7 MB total)

---

## CRITICAL FINDING: Two Conflicting Pricing Schemas

**Schema A** (used by `build_agent.py`, `expand_dataset.py`, `stress_test_extra.py`, `eval_500.py`):
| Plan | Price | Emails/mo | API Calls | Team | Domains |
|------|-------|-----------|-----------|------|---------|
| Free | $0 | 1,000 | 10,000 | 1 | 1 |
| Starter | $29 | 25,000 | 250,000 | 3 | 3 |
| Pro | $59 | 50,000 | 500,000 | 5 | 5 |
| Growth | $129 | 100,000 | 1,000,000 | 10 | — |
| Scale | $399 | 500,000 | 5,000,000 | 25 | Unlimited |
| Enterprise | $1,299 | 2,000,000 | 20,000,000 | Unlimited | Unlimited |

- API: `api.apexmail.ee/v1`, Auth: `Bearer am_live_xxx`
- Overage: $0.50/1,000 emails
- PAYG tiers: $0.001 (first 10K), $0.0008 (10K–100K), $0.0005 (100K–1M), $0.0003 (1M+)
- Annual billing: ~17% discount ($290/yr for Starter)

**Schema B** (used by `mega_pipeline.py`):
| Plan | Price | Emails/mo |
|------|-------|-----------|
| Starter | $25 | 10,000 |
| Growth | $65 | 50,000 |
| Business | $165 | 200,000 |
| Enterprise | Custom | Custom |

- API: `api.apexmail.com/v1`, Auth: `X-API-Key` header
- Overage: Starter $3/1K, Growth $2/1K, Business $1.50/1K
- Annual billing: 20% discount
- SDK: `apexmail` for Python (both schemas)

**Recommendation**: Schema A is canonical (matches `customer_profiles.py`, `build_agent.py`, and the primary system prompt). Schema B in `mega_pipeline.py` is outdated/alt-branch data — **do not merge** its pricing into training without resolution.

### Other Data Inconsistencies
| Datum | eval_500.py | eval.py | Notes |
|-------|------------|---------|-------|
| Open rate benchmark | 27% | 21.5% | industry-knowledge-base uses ~27% |
| Starter price | $29 | $25 | eval.py may use Schema B |
| Pro price | $59 | $65 + "150K emails" | eval.py Pro doesn't match either schema |
| API domain | .ee | — | eval.py uses the Python SDK `apexmail` |

---

## File-by-File Analysis

### 1. `adversarial-gym.test.ts` — 6,624 lines (470 KB)
**THE HIGHEST-VALUE FILE. Entirely novel.**

- **1,100 adversarial gym scenarios** (GYM-001 through GYM-1100) — multi-turn conversation tests
- **15 customer personas** with distinct styles (polite, angry, terse, confused, technical, verbose), backstories, plans (free→enterprise), roles (viewer→owner), account statuses (active/suspended/cancelled/trial/past_due)
- **10 quality dimensions**: personalization, accuracy, safety, helpfulness, action_correctness, tone, boundary, context_retention, escalation, robustness
- **~90+ unique categories** including:
  - **Security/Injection**: SQL injection, XSS, CRLF injection, JSON injection, homoglyph attack, template injection, escape sequence attack, path traversal, triple injection, whitespace attack, prompt injection, impersonation
  - **RBAC/Auth**: Viewer lockdown, role escalation, auth escalation, editor auth limits, unauth defense, unauth delete
  - **Account Status**: Cancelled cascade, suspended deep, past due account, past due destructive, cancelled exhaustive, cancelled knowledge
  - **Autonomous**: Campaign autonomous, billing autonomous, domain autonomous, contact autonomous, compliance autonomous, security autonomous, autonomous RBAC, autonomous injection, autonomous safe, autonomous escalation, autonomous edge, autonomous workflow, autonomous phrasing, autonomous knowledge deep
  - **Sentiment**: Sentiment detection, sentiment advanced, profanity handling
  - **Knowledge**: IP warming, subject lines, automation, bounce handling, ROI, CTR, list growth, complaint rate, mobile email, CTA, conversion rate, revenue per email, preheader, list hygiene, spam triggers, A/B testing, transactional email, welcome email, unsub knowledge
  - **Edge Cases**: Double negation, double barrel, long input, massive input, unicode, non-English, repetition handling, case insensitivity, terse messages, empty input, rapid context switch, typo tolerance
  - **Multi-Turn**: Multi-step workflow, stats then action, context switching, create-delete flow, billing chain, admin full workflow
  - **Proactive Triggers**: Proactive triggers (7 scenarios)
  - **Escalation**: Escalation requests (5 scenarios)

**Novel vs Current Pipeline**: This file contributes **~1,100 multi-turn adversarial scenarios** — none of which exist in the current 234 test cases or 247 stress tests. The autonomous agent testing, sentiment detection, and proactive trigger categories are completely new.

---

### 2. `build_agent.py` — 8,127 lines (614 KB)
**THE LARGEST FILE. Primary training data builder.**

- **~683 training examples** across 38 named sections (A through R14)
- Uses `prompts_v2.build_system_prompt()` with customer context templates
- **Format**: ChatML multi-turn with tool calls (`<|im_start|>system/user/assistant/tool`)
- **5 turn types**: single_turn, tool_turn, multi_tool_turn, clarification_turn, clarify_then_tool, full_conversation

**Sections**:
| Section | Lines | Description |
|---------|-------|-------------|
| A: Context-Aware Single-Turn | 101–284 | Model references customer data (12+ examples) |
| B: Tool-Calling with Results | 285–568 | Tool → result → answer (DNS, webhooks, campaigns) |
| C: Clarification Behavior | 569–732 | Ambiguous → clarify → resolve |
| D: Multi-Turn Diagnostics | 733–883 | 3-5 turn diagnostic conversations |
| E: Safety & Escalation | 884–1012 | Off-topic, dangerous commands, escalation |
| F: Playbook Coverage | 1013–1248 | 26 playbooks gap coverage |
| G: Pricing Math | 1249–1372 | Compute-heavy pricing calculations with PAYG |
| H: Knowledge Base | 1373–1746 | Core product knowledge |
| I: Additional Context-Aware | 1747–1815 | Extra context-aware examples |
| J: Additional Multi-Turn | 1816–1906 | Extra diagnostic conversations |
| K: Playbook Gaps | 1907–2289 | Missing playbook scenarios |
| L: Data Lookup | 2290–2466 | "Show me my X" personalized queries |
| M: PAYG-Specific | 2467–2522 | Pay-As-You-Go pricing scenarios |
| N: RAG Verification | 2523–2794 | When to verify context vs use cached |
| O: Remediation Drills | 2795–3590 | Targeted fixes for test failures |
| P: Round 3 Remediation | 3591–4594 | More targeted fixes |
| Q: Comprehensive Coverage | 4595–5745 | All 26 playbooks + 97 stress tests |
| R5: Round 5 Remediation | 5746–5988 | 45 targeted fixes for 82→90% |
| R6: Round 6 Remediation | 6884–7058 | 32 failures → 90%+ |
| R7: Round 7 Remediation | 7059–7304 | 34 remaining for 93%+ |
| R8: Remediation | 7305–7488 | Counter tool-eagerness regression |
| New Profiles | 7489–7518 | Diverse customer profiles training |
| R11: Round 11 | 7519–7967 | 34 failures from 88.5%→93% |
| R13: Minimal Fixes | 7968–8021 | 3 examples to avoid catastrophic forgetting |
| R14: Massive Expansion | — | Enterprise, SSO, Sub-Accounts, Log Streaming, Template Approval, SDK, API Errors, Account Lockout, Compliance, SLOs, Billing, Message Diagnostics, IP Warmup, Contacts, Data Retention |
| R14 Remediation | 7968–8127 | 8 targeted fixes for R13 failures |
| BUILD DATASET | 8058–8127 | Assembly + 2x weighting for critical sections |

**Novel content**:
- **Tool-calling format** with JSON tool calls and results (missing from current pipeline?)
- **Clarification behavior** training (ambiguous→clarify→resolve→tool)
- **RAG verification** — when to re-check vs trust cached context
- **14 API key scopes** (emails:send, emails:read, domains:manage, domains:read, webhooks:manage/read, templates:manage/read, suppressions:manage/read, analytics:read, contacts:manage/read, admin)
- **5 RBAC roles** (Owner, Admin, Developer, Analyst, Billing)
- **ARC (RFC 8617)** for DMARC-forwarded emails
- **MTA-STS (RFC 8461)** enforcement
- **TLSRPT (RFC 8460)** reporting
- **White-label** configuration details
- **3 support tiers** (Standard/Premium/Enterprise with response times 24h/4h/15min)
- **Sub-processor**: Hetzner Online GmbH, EU
- **SCCs** for cross-border data transfers
- **DPA** compliance via `support@apexmail.ee`

---

### 3. `customer_profiles.py` — 1,888 lines (106 KB)
**60 detailed customer profiles. Entirely novel.**

**Profile distribution by plan**:
| Plan | Count | Key Scenarios |
|------|-------|---------------|
| Free | 4 | hitting_limits, brand_new, hobby_blogger, spf_broken |
| Starter | 6 | healthy, webhook_dead, over_limit, restaurant, nonprofit, bounce_spike |
| Pro | 6 | new_user, agency_multi_domain, edtech, realtor, dmarc_none, template_issue |
| Growth | 13 | dkim_fail, saas_healthy, ip_warmup, gaming, logistics, complaint_suspended, travel, crypto, cloudflare_dkim, account_lockout, oauth_app, + more |
| Scale | 9 | deliverability, insurance, sso_issue, media, healthcare, subaccounts, greylist, ab_testing, + more |
| Enterprise | 12 | compliance, ecommerce, fintech, sso_broken, subaccounts_active, log_stream_failing, template_approval, + more |
| PAYG | 5 | (not fully read) |
| Unknown | 1 | (edge case) |

**Each profile contains**: account_id, plan_name, plan_price, emails_sent, email_limit, api_calls, api_call_limit, team_count, team_limit, created_at, domain_count, domain_details (with SPF/DKIM/DMARC status), recent_events, open_issues, billing_cycle_date, team_members, api_keys, webhooks_summary, template_count, templates_summary, contact_count

**19 industries covered**: SaaS, E-commerce, EdTech, FinTech, Healthcare, Legal, Real Estate, Non-profit, Agency, Logistics, Media, Gaming, Travel, Food/Restaurant, Crypto/Web3, HR/Recruitment, Insurance, IoT/Hardware, Government

**22+ problem types**: DKIM failures, SPF issues, bounce spikes, complaint spikes, webhook failures, IP blocklisting, quota exhaustion, deliverability drops, account suspension, pending verification, API auth issues, template rendering, greylist delays, warmup struggles, dunning/billing, GDPR requests, SSO misconfiguration, subaccount management, MFA lockout, Cloudflare DKIM flattening, OAuth token expiry, purchased list AUP violation

**Novel**: These profiles provide the exact context templates that `build_agent.py` references via `ctx_key`. They contain realistic, internally-consistent numbers (sent/limit/bounce rates/complaint rates) — critical for context-aware training.

---

### 4. `industry-knowledge-base.ts` — 2,231 lines (117 KB)
**Domain knowledge base. Entirely novel as a structured asset.**

**8 sections**:

1. **GLOSSARY** (~45 entries): Open Rate, CTR, CTOR, Conversion Rate, Bounce Rate, Unsubscribe Rate, Complaint Rate, RPE, List Growth Rate, Sender Reputation, SPF, DKIM, DMARC, BIMI, IP Warming, Feedback Loop, Spam Trap, Apple MPP, Inbox Placement Rate, CAN-SPAM, GDPR, CCPA, Double Opt-in, List-Unsubscribe Header, A/B Testing, Segmentation, Personalization, Lead Magnet, Email Cadence, Re-engagement Campaign, Sunset Policy, Drip Campaign, Trigger Email, Welcome Email, Abandoned Cart Email, List Hygiene, Email Verification, Preference Center, Call-to-Action, Preheader, Dynamic Content, Plain Text Email, SMTP, MTA, MX Record, Tracking Pixel, Transactional Email, Email Heatmap, Cohort Analysis, Email Attribution
   - Each entry: term, aliases, definition, category, relatedTerms

2. **INDUSTRY BENCHMARKS** (15 industries): Technology (18.34% OR), Education (37.66%), Financial Services (27.76%), Healthcare (34.87%), Retail (31.83%), Real Estate (32.79%), Travel & Tourism (39.15%), Nonprofit (39.13%), Legal (32.84%), Manufacturing (26.54%), Consulting (27.48%), Food & Dining (36.50%), Entertainment (39.13%), SaaS (22.15%), Ecommerce (29.81%)

3. **EMAIL TYPE BENCHMARKS** (14 types): Welcome (63.91% OR, 14.34% CTR), Newsletter (27.90%), Promotional (21.33%), Transactional (80.00%), Abandoned Cart (45.00%), Browse Abandonment (37.00%), Win-back (35.00%), Post-Purchase (52.00%), Birthday (47.00%), Autoresponder (35.91%), RSS/Digest (44.54%), Cold Outreach (44.00%), Product Update (45.00%), Survey (30.00%)

4. **SUBJECT LINE BEST PRACTICES** (10 rules with evidence/impact/priority)

5. **DELIVERABILITY CHECKLIST** (14 rules by severity: must-have, should-have, nice-to-have)

6. **CONVERSATION PATTERNS** (10+ intent→response templates): improve_open_rate, improve_deliverability, create_campaign, write_subject_line, reduce_unsubscribes, understand_metrics, automation_help, compliance_help, email_roi, debug_email_authentication
   - Each: intent, keywords, sampleQuestions, contextualResponse, suggestedFollowUps, relatedGlossaryTerms

7. **APEXMAIL SYSTEM CAPABILITIES** (8 features): Campaign Management, Contact & List Management, Analytics & Reporting, Content Generation, Automation & Workflows, Deliverability Tools, Send Time Optimization, Compliance Management
   - Each: commands, apiEndpoints

8. **QUALITY SCORING** — Calibrated engagement multipliers: subjectLine (personalization: 1.06, question: 1.15, emoji: 1.032, number: 1.12, under50: 1.08, under33: 1.12), body (personalization: 1.06, CTA: 1.40, socialProof: 1.15, under200Words: 1.15, readability60+: 1.10, images: 1.40, headers: 1.27)

**Helper functions**: `lookupGlossaryTerm()` (fuzzy + NL wrapper stripping), `matchConversationPattern()`, `getIndustryBenchmark()`, `getEmailTypeBenchmark()`

**Novel**: Every data point is sourced from real 2023-2025 industry reports. The structured glossary, benchmarks, and pattern library don't exist in the current pipeline.

---

### 5. `eval-100.test.ts` — 1,022 lines
**100 evaluation tests across 10 categories + unit tests.**

| Category | Count | Novel? |
|----------|-------|--------|
| A: Campaign commands | 15 | Synonym handling (pause=stop, remove=delete, upload=import), action block parsing with params |
| B: Contact/list | 12 | `add_contact`, `remove_contact`, `import_contacts`, `create_list` actions |
| C: Billing | 10 | `get_billing_status`, `get_billing_history`, `upgrade_plan`, `process_refund`, `cancel_subscription` |
| D: Domain/API | 10 | `verify_domain`, `check_deliverability`, `get_sender_reputation`, `create_api_key` |
| E: Knowledge Q&A | 20 | Bounce rate, DKIM, SPF, DMARC, deliverability, CAN-SPAM, GDPR, automation, unsubscribes, subject lines, metrics, A/B testing, IP warming, ROI, list hygiene, Apple MPP |
| F: Content requests | 8 | Subject line writing, email copy, CTA suggestions, preheader, design tips, send time |
| G: Edge cases | 10 | Empty string, single char, random symbols, long message, SQL/XSS injection, emoji, misspelling, mixed intent, numeric only |
| H: Context & multi-step | 5 | Confirmation flow (confirm/cancel), invalid confirmation ID, session context, multi-message |
| I: Security & safety | 5 | API key request, prompt injection, internal endpoints, mass delete, off-topic |
| J: Greetings & chitchat | 5 | Hello, Hi, Thanks, Bye, OK |

Plus **10 intent detection unit tests** and **4 action parsing unit tests**.

**Novel**: The `detectIntent()` + `parseActions()` unit tests provide test coverage for the core intent engine. The synonym/action correctness tests (G07 emoji preservation, F02 clarification for ambiguous input) are new patterns.

---

### 6. `customer-support.test.ts` — 904 lines
**87 tests across 10 categories (K–T) with RBAC/auth focus.**

| Category | Count | Focus |
|----------|-------|-------|
| K: Customer greetings | 12 | Personalized greetings using name, plan, quota, status |
| L: Plan & quota awareness | 10 | Quota warnings, plan-specific feature knowledge |
| M: RBAC | 12 | Viewer/editor/admin/owner action permissions |
| N: Authentication & elevated auth | 8 | Basic vs elevated auth, delete requires elevated |
| O: Account status enforcement | 8 | Suspended/cancelled/trial/past-due behavior |
| P: Input sanitization | 10 | SQL injection, XSS, HTML strip, prompt injection, unicode, empty/long input |
| Q: PII redaction | 6 | Credit card, SSN, hex tokens, Bearer tokens, normal text preservation |
| R: Rate limiting | 3 | Normal usage, burst, 31-message rate limit |
| S: Context-aware multi-turn | 8 | Session history, context updates, campaign-specific suggestions, confirmation flow |
| T: Security utility unit tests | 10 | `checkActionSecurity()`, `sanitizeInput()`, `redactPII()` |

**8 customer profiles**: FREE_VIEWER (Alice), PRO_EDITOR (Bob), ENTERPRISE_ADMIN (Carol), OWNER_ELEVATED (Dave), SUSPENDED_USER (Eve), CANCELLED_USER (Frank), PAST_DUE_USER (Grace), QUOTA_MAXED_USER (Hank)

**Novel**: RBAC enforcement tests, PII redaction (CC/SSN/Bearer/hex), rate limiting tests, `checkActionSecurity()` function testing — all completely new to the pipeline. The customer profile-driven testing pattern is unique.

---

### 7. `stress_test_r34.py` — 662 lines
**171 tests across 26 categories (A–Z).**

Key novel content:
- **Internal architecture refusal** (10 tests): Must NOT reveal Qwen, llama.cpp, GGUF, LoRA, PostgreSQL, Redis, BullMQ, Hetzner, Docker, Kubernetes, Grafana, Prometheus, vLLM, RAG, MiniLM, embeddings, temperature settings, circuit breaker
- **Provider migration** (12): SendGrid, Resend, Amazon SES, Postmark, Mailgun gotchas
- **SDK multi-language** (10): Go 1.21+, Ruby 2.7+, PHP 8.1+ (apexmail/apexmail-php), Java JDK 17 (ee.apexmail)
- **Technical facts**: DKIM CNAME → bounce.apexmail.ee, _spf.apexmail.ee, 25MB attachment limit, 7-day message body retention, 30-day webhook replay, 72h deferred retry, 72h scheduled limit, $30/mo dedicated IP, $0.40/1K overage, 72h team invite expiry, 1h password reset expiry, 5 failed logins → 15-min lockout, 102KB Gmail clipping
- **Compliance retention** (8): CCPA deletion, GDPR erasure, log streaming retention
- **Billing/SLA** (6): 99.99% uptime SLO, 15-min P1 response for Enterprise

---

### 8. `stress_test_extra.py` — 222 lines
**~80 extra tests across 12 categories.**

Novel content:
- **Business scenario tests**: 50-person startup, e-commerce seasonal spikes, 20-domain agency, HIPAA requirements
- **Growth email vs API confusion**: Tests that confuse email quota with API call limits
- **Multi-step pricing math**: "If I send 75K on Starter, what's the overage cost?"
- **PAYG tier calculations**: Specific volume calculations with tier boundaries

---

### 9. `expand_dataset.py` — 735 lines
**Dataset expansion generator producing 2000+ examples across 9 categories.**

Novel generation functions:
- **15 hallucination traps**: SMS, mobile app, social media, phone support, CRM, IDE, push notifications, hardware, fax, AI image generator, crypto payments, video hosting, landing pages, project management, web hosting
- **12 off-topic deflections**: weather, poetry, capital of France, jokes, hacking, stocks, web scraping, jailbreak, quantum computing, elections, pizza ordering, meaning of life
- **5 competitor comparisons**: vs SendGrid, Mailchimp, Amazon SES, Postmark, Resend
- **10 tricky/ambiguous queries**: "free plan", empty message, "???", "hello", "thanks", "ok", "test", "I want to cancel", "URGENT HELP NEEDED!!!", "asdfghjkl"
- **7 multi-turn conversations**: domain setup, deliverability troubleshooting, API integration, pricing/upgrade, template creation, analytics deep-dive, webhook debugging, enterprise features
- **8 action blocks**: send_email, delete_bounced, add_contact, upgrade_plan, create_api_key, cancel_subscription, pause_campaign, unsuppress_contact
- **4 compliance topics**: GDPR, CAN-SPAM, encryption, CASL
- **Paraphrase augmentation**: 15 template patterns for diversity

---

### 10. `mega_pipeline.py` — 949 lines
**Full training pipeline (expand→train→test→fix→export→package).**

Novel pipeline components:
- **17 generator functions**: pricing, API, deliverability, hallucination resistance, safety boundaries, troubleshooting, templates, action blocks, webhooks, enterprise, compliance, greetings, analytics, consistency pairs, multi-turn, edge cases, doc-mined Q&A
- **Consistency pairs**: Cross-validates same facts asked differently
- **Doc mining**: Auto-extracts Q&A from `docs/` markdown files
- **6-phase pipeline**: Data expansion → Training (Qwen3) → Stress test → Targeted fixes → GGUF export → Package artifacts
- **Multi-round training**: Round 3 (3 epochs, lr=1.5e-4) → Round 4 if fixes needed (2 epochs, lr=8e-5)
- **Auto-remediation**: Parses stress test failures and generates corrective training examples by category

⚠️ **Uses Schema B pricing** — not canonical. If integrating, strip pricing data and use only structural/pipeline logic.

---

### 11. `eval_500.py` — 390 lines
**500-question evaluation framework.**

- Loads questions from `docs/500-fixes-checklist.md`
- **5-point scoring rubric**: relevance, no hallucination, helpfulness, safety, factual accuracy
- **Grade levels**: A (excellent) → F (failing)
- **Pass threshold**: A+B rate ≥ 70%
- **Hallucination blocklist**: sendgrid.com, mailchimp.com, mailgun.com, aws.amazon.com/ses, postmark, sparkpost, api.apexmail.com, apexmail.io, apexmail.org
- **Known facts**: api_url=api.apexmail.ee/v1, company=Bel Consulting, country=Estonia, city=Tallinn, founded=2022, open_rate_benchmark=27%, ROI=$36
- **Base model**: TinyLlama-1.1B

---

### 12. `eval.py` — 434 lines
**Golden-set evaluation with ~17 inline test cases.**

- **Categories**: pricing, api, deliverability, features, actions, safety, anti-hallucination
- **Pass threshold**: ≥95% A-grade
- **Base model**: Qwen3-Next-80B-A3B-Instruct
- **Key test patterns**: must_contain / must_not_contain keyword lists per test case
- ⚠️ Uses some Schema B pricing values — validate before using

---

### 13. `run_all_tests.py` — 532 lines
**Unified test runner for 360 tests (189 + 171).**

- Merges `test_agent.py` (189) + `stress_test_r34.py` (171) = 360 total tests
- **Mock tool results**: get_dns_records, search_events, get_suppression_status, list_webhooks, get_usage_stats, get_deliverability_report, check_blocklist
- **Multi-turn test support** with tool call extraction
- Imports from `prompts_v2.build_system_prompt()`
- Infrastructure code — no novel test scenarios itself

---

### 14. `training-index.ts` — 406 lines
**ML training orchestrator (NOT customer support data).**

Three pipelines:
1. Email Writing Model (92% quality threshold)
2. Subject Line Optimizer (90%)
3. Lead Scoring/Webscraping (88%)

Infrastructure code only — no training data content.

---

## Summary: What's Novel & Additive

### Test Scenarios
| Source | Count | Status |
|--------|-------|--------|
| Current pipeline | 234 tests / 29 categories | Baseline |
| adversarial-gym.test.ts | **1,100 scenarios / ~90 categories** | **NEW — highest priority** |
| eval-100.test.ts | 100 tests / 10 categories + 14 unit tests | **NEW** |
| customer-support.test.ts | 87 tests / 10 categories (K–T) | **NEW** |
| stress_test_r34.py | 171 tests / 26 categories | **NEW** |
| stress_test_extra.py | ~80 tests / 12 categories | **NEW** |
| **Total new test scenarios** | **~1,538** | |

### Training Data
| Source | Count | Status |
|--------|-------|--------|
| Current pipeline | 1,145 examples | Baseline |
| build_agent.py | ~683 examples (×2 for critical = ~1,200 effective) | **NEW — context-aware, tool-calling** |
| expand_dataset.py | 2,000+ generated examples | **NEW — hallucination/safety/compliance** |
| mega_pipeline.py | 200+ generated + doc-mined | **NEW (strip Schema B pricing)** |
| customer_profiles.py | 60 structured profiles | **NEW — context templates for training** |
| industry-knowledge-base.ts | ~45 glossary + 15 benchmarks + 14 email type benchmarks + 10 patterns | **NEW — domain knowledge seed** |

### Completely New Capabilities (not in current pipeline)
1. **Autonomous agent testing** (adversarial-gym: ~80 autonomous scenarios)
2. **Sentiment detection** (14 sentiment scenarios)
3. **Proactive triggers** (7 proactive message scenarios)
4. **RBAC enforcement testing** (customer-support: 12 RBAC + 10 security utility tests)
5. **PII redaction** (6 tests: CC, SSN, hex tokens, Bearer tokens)
6. **Rate limiting** (3 tests with burst behavior)
7. **Tool-calling training format** (build_agent: ChatML with `<|im_start|>tool`)
8. **Clarification behavior** (build_agent: ambiguous→clarify→resolve)
9. **RAG verification** (build_agent: when to re-check vs trust context)
10. **Customer profiles as context** (60 profiles with realistic industry/plan/issue data)
11. **Structured industry knowledge** (45 glossary terms, 15 industry benchmarks, 14 email type benchmarks)
12. **Internal architecture refusal** (stress_test_r34: 10 tests blocking model/infra leaks)
13. **Provider migration guides** (12 competitor-specific migration scenarios)
14. **Multi-language SDK testing** (Go, Ruby, PHP, Java, Python, Node)
15. **Enterprise features** (SSO, sub-accounts, log streaming, template approval, white-label, DPA compliance)

### Key Technical Facts Extracted (for system prompt / knowledge base)

**Support email**: `support@apexmail.ee`
**Company**: Bel Consulting OÜ, Tallinn, Estonia, founded 2022
**API key scopes**: 14 scopes (emails:send/read, domains:manage/read, webhooks:manage/read, templates:manage/read, suppressions:manage/read, analytics:read, contacts:manage/read, admin)
**RBAC roles**: Owner, Admin, Developer, Analyst, Billing
**Support tiers**: Standard (24h, email, business hours), Premium (4h, email+chat, extended), Enterprise (15min, email+chat+phone, 24/7)
**SLO**: 99.99% uptime
**Sub-processor**: Hetzner Online GmbH (EU)
**Data retention**: 7-day message body (Starter), 30-day event, 90-day analytics
**Security**: 5 failed logins → 15-min lockout, 72h invite expiry, 1h password reset, 102KB Gmail clipping
**Dedicated IP**: $30/mo add-on, available on Growth+
**Attachment limit**: 25MB, base64 encoded
**GGUF export**: For llama.cpp CPU inference deployment
**Webhook replay**: 30-day window
**Deferred retry**: 72 hours
**Scheduled limit**: 72 hours ahead
