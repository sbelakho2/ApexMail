# Sales Autopilot vs SalesCloser — Scoped Gap Analysis and Build Plan (v2)

**Date:** 2026-10-05 · **Revision:** v2 — scope narrowed by owner directive: of everything SalesCloser has, **only four capabilities are adopted** — **screen-share demos, automated objection handling, chat, instant response** — each to be built on the repository's existing chatbot/mailbot infrastructure. Everything else SalesCloser offers is explicitly excluded (§0.2). **Deliverable: analysis only — no code changes accompany this document.**

**Method.** Three research passes: (1) a full read of every `sales-autopilot` module plus its control-plane surfaces at HEAD (`95986139`); (2) a live-fetch pass over SalesCloser's site, Wayback pricing, investor filings, and the review corpus; (3) a rigorous read of the four capabilities' intended substrate — the ai-service chat stack, the mailbot (`email_agent`), the inbound reply pipeline, the AI-draft approval surface, and every objection/knowledge artifact in the workspace — with file:line evidence. Sources tagged **[F]** fetched, **[S]** snippet, **[U]** vendor-only.

---

## 0. Executive summary

SalesCloser (salescloser.ai) is a live-conversation AI sales agent — voice/video calls, screen-share product demos, adaptive walkthroughs, real-time objection handling, website chat, instant lead response — sold demo-gated with non-cancellable annual terms, and carrying a review record dominated by billing/cancellation complaints and robotic-conversation 1-stars (§2). Sales Autopilot at HEAD is a governance-heavy outbound email engine — nine-gate decision brain, legal-policy engine, evidence grounding, exactly-once durability, Thompson-sampling experiments, sender-reputation isolation — with no live-conversation channel of any kind (§1).

**This revision adopts exactly four capabilities from SalesCloser — screen-share demos, objection handling, chat, instant response — and plans them on top of what the repository already runs**, after a rigorous audit of that substrate (§3). The audit's most important results:

- **Chat is the strongest asset.** A hardened, grounded chat pipeline already runs end-to-end: api-server proxy (`/v1/ai/chat`) → ai-service `ChatService` (retrieval with tri-state, evidence-grounded prompt, `ResponseVerifier` policy + claim-support checks, corrective retry, escalation, per-tenant/user rate limits, per-turn audit). It has **no UI consumer anywhere**, and its canonical facts are **stale against the deployed billing catalog** (chat says Pro €65/Free 30k; billing says Pro €89/Free 3k+30k) — a contradiction that must be fixed before chat is exposed to prospects (§3.3, §4.1).
- **Objection handling exists only in fragments today**: "strong objection = complaint/unsubscribe → account stop" (`account_coordination.rs`), a claim-validated `MessageStrategy` composer, the 11-disposition reply classifier with its 0.7 gate, and a verified sales knowledge base — but **no objection taxonomy, no objection library, no objection sub-classification, and no generation path** (§3.2). The AI classifier the pipeline expects (`/reply/classify`) is implemented by no service.
- **Instant response has the rails but no engine**: the MTA commits inbound mail and the worker polls every 5 s, `email_queue.priority` (0–100) is a ready priority lane — but the reply handler cannot see production inbound rows (`from_email` is never populated by the MTA writer), no code generates a first response, the mailbot (`email_agent`) is unwired library code with a draft-and-approve chain waiting for a runtime owner, and new-lead form submissions trigger nothing (§3.4).
- **Screen-share demos have no substrate for the literal feature** (zero WebRTC/browser-control/session-mirroring code or dependencies — verified workspace-wide); what exists is the raw material for a **scripted, server-driven demo**: the SSR console, the live API explorer sandbox (real router execution, real grader, real pricing calculator), the feature registry, and a chat engine that can render rich HTML but has no view/embed protocol (§3.1).

### 0.1 The four adopted capabilities, one line each

1. **Chat** — expose the already-built grounded chat to the console and the marketing surface; refresh its knowledge source; add server-side sessions.
2. **Automated objection handling** — one objection taxonomy + approved-response library, generated through the grounded chat/mailbot pipeline, gated by the existing claims/legal/approval machinery, measured by experiments.
3. **Instant response** — first-response drafts (and policy-gated sends) on inbound email, contact-form leads, and chat, riding the reply pipeline + a new priority lane + the mailbot's approval chain.
4. **Screen-share demos** — a shareable, scripted walkthrough of the real UI plus live sandbox executions (send, grader, calculator), narrated through the same chat engine and knowledge sources.

### 0.2 Explicitly excluded (the owner's directive, itemized)

SalesCloser capabilities that are **not adopted**, and why each is out of scope:

| Excluded | Reason |
|---|---|
| Voice/phone calls, telephony, dialers, Twilio/Telnyx-style PSTN | No telephony exists; the four adopted capabilities deliberately exclude the live-audio subsystem |
| Camera-on video presence, embedded video avatars, voice selection/cloning | Same subsystem |
| Zoom/browser call joining, "computer use" driving the product | Requires new browser-control/streaming infrastructure; the adopted demo path (§3.1) achieves prospect-value without it |
| 32-language live conversation | Rides the excluded audio subsystem; chat/docs remain English-first |
| Meeting bots, call recording, transcripts, talk-ratio call analytics | Rides the excluded audio subsystem |
| Meeting minutes/summaries as a product surface | Rides recorded calls; the platform's meeting records stay what they are |
| Automated meeting reminders (24h/2h/15min) | Not among the four adopted capabilities |
| White-label/reseller, agency program, influencer program | Commercial programs, not adopted |
| 200+-integration marketplace, Zapier, CRM connectors (HubSpot/Salesforce/Pipedrive/…), Slack/ClickUp/Airtable/Gmail connectors | External CRM sync is not among the four; the internal CRM remains the system of record |
| Lead-capture forms as a new product surface | Excluded as a surface; the existing contact forms are used only as an instant-response *trigger* (§3.4) |
| ICP enforcement at first touch, human handoff routing dashboards | Not adopted as surfaces; the reply pipeline's existing routing/locking semantics carry over |
| Free calculators, ROI calculators, script generators, training audits | Marketing gadgets, not adopted |
| Mobile app | Not adopted |
| Demo Flow Editor / Agent Studio / 60-word builder as authoring products | The demo is a scripted server-driven walkthrough (§3.1), not a no-code authoring platform |
| SOC 2 / GDPR program claims as a competitive feature | The platform's compliance posture stands on its own existing artifacts; nothing new is committed here |

**Kept from the SalesCloser analysis beyond the four:** the complaint-derived commercial-practice commitments (§4.3) remain in force as *constraints on how the four capabilities are sold and run* — they cost nothing and they are where SalesCloser bleeds.

---

## 1. Sales Autopilot as it exists right now

### 1.1 What it is

A single-tenant (platform-owner "system" tenant only), service-process outbound email engine behind one shared internal token, hard-restricted to `SALES_ALLOWED_TENANTS=system` at boot; owner-only external boundary enforced by a dedicated middleware (human CP session + system tenant + live `users.role == 'owner'`; machine credentials refused). It owns the brain (decision, policy, scoring, sequencing, experiments, CRM) and delegates every effect to the platform (send admission → worker → transport; tracking; warmup; outbound-mta).

### 1.2 Capability inventory (condensed; anchors in Appendix A)

**Outreach execution** — multi-step sequences with 10 step kinds (email, wait, enrich, research, condition, branch, manual_task, meeting_invite, nurture, stop); deterministic delay jitter; send windows, recipient-timezone timing, allowed weekdays per step; versioned sequences immutable once active; logical send identity giving exactly-once sends across retries/crashes; personalization placeholders (HTML-escaped); CAN-SPAM footer with an explicit truthful reason for contact; RFC 8058 one-click unsubscribe (opaque random tokens, hashes stored, 365-day expiry) + browser confirmation; legacy HMAC links read-only. Atomic reservations: per-account weekly touch budget (`max(15, active_contacts×5)` rolling 7 days), per-sender daily limits, both released on refusal. Suppression across sales + platform stores; `valid|risky` verification only. Durable lease queue: per-claim fencing, `FOR UPDATE SKIP LOCKED`, exponential backoff, dead-letter + operator replay.

**Autonomy and governance (the differentiating core)** — five modes, fail-closed (disabled → shadow → assisted → approval_required → autonomous_guarded; no unrestricted mode; unknown persisted values fail to disabled). One `decide()` gate with nine ordered hard gates (kill switch → autonomy → suppression both stores → verification → legal policy → human-reply lock → sender health → account weekly budget → contact-point flag); every decision — including denials and shadow decisions — persists an explainable packet (rationale, evidence ids, policy id, sender, variant, model/scoring version, block reasons). Approvals never bypass: revalidation at review and again immediately before enqueue. Kill switch halts new outbound (inbound reply handling continues); pause = shadow; resume = lowest sending mode. Account-coordination rules: stop-account after strong objection, negative-reply cooldown, persona ordering, multi-threading gate, concurrent-contact cap, referral exceptions. Legal engine: versioned counsel-approved policies keyed (jurisdiction × channel × contact type), EU/EEA mapping, natural-vs-legal-person discrimination failing closed on unknown, consent-evidence state machine, audit row per attempt; seeded defaults require approval for every send. Grounding: strategy built from account/contact/evidence/signals; factual claims must cite evidence or be omitted; verified knowledge base validates claims; fake-personalization bans; AI outage writes zero fabricated evidence.

**Discovery/enrichment/scoring** — 22-field enrichment waterfall with per-field provenance, TTLs, cost-aware routing, auto-scoring on lead creation; discovery jobs (provider API + first-party source) with jurisdiction allowlists, leased cursor-resumable batches, dedupe, cost accounting; 11-dimension explainable score with signed reason codes and EV economics; account change signals with decay.

**Replies/meetings/learning/sender ops** — 11-disposition reply classification with a 0.7 confidence gate (nothing irreversible below it), OOO rescheduling, complaint/unsubscribe/bounce auto-suppress, enrollment locking; calendar availability (working hours, buffers, notice, caps, IANA/DST-correct, Google + Microsoft availability, round-robin, double-booking prevention via GiST exclusion, reschedule/cancel mirrored); experiments (Thompson sampling, 13-step reward ladder with opens/clicks never positive, 10-dimension contextual buckets, exploration budgets, promotion gated on win probability + budget, Brier/log-loss calibration gating, replay + champion/challenger); sender pools (sales-only isolation by DB CHECK, health scoring, quarantine/pause/throttle breakers, 30-day warmup maturity); attribution from discovery source to paid MRR.

**Platform capabilities sales rides on** — DKIM signing; shared-pool or dedicated-IP transport; warmup admission; tracking (opens/clicks/unsubscribes); bounce/complaint processing; quota/entitlements; dedicated outbound MTA with DSNs and an idempotent acceptance ledger.

### 1.3 The owner's UI/UX today

Zero-JS SSR, owner-only. `/sales` page top→bottom: hero KPIs (Revenue 30d, Meetings 30d, Decisions 24h, Blocked 24h); revenue-by-outcome; autonomy state + kill-switch banner (**read-only**); live decision stream (account, action, contact, confidence, variant, sender, legal allowed/blocked, EV, rationale, all block reasons); recent decisions; exceptions (**read-only**, disabled Replay button); action-queue health; enrollments counts; **two working forms** — "Run enrichment" (comma-separated domains → `/enrich`) and "Enroll contacts" (**raw UUID inputs** for sequence, autonomy policy, 1–100 contact ids); compliance note; costs panel ("not yet instrumented"). `/discovery` is read-only. Everything else the console cannot mutate exists only as JSON admin APIs (mode/pause/resume/kill-switch, review, replay, leads, campaign pause/resume/cancel, discovery job create, settings). Every mutation audit-logged.

### 1.4 Product-level gaps in the code (relevant to the four adopted capabilities marked ◆)

1. **No sequence authoring anywhere** (DB-only); same for experiment arms (unknown key dead-letters the step).
2. No sender-identity management surface (DB/env-driven).
3. Autonomy controls API-only; console renders them read-only.
4. **◆ Discovery is disconnected** — the SSR "discovery run" form actually calls `/enrich`; `promote_candidate` has no route; nothing calls `POST /discovery/jobs/:id/run` in production.
5. No console for inbox, calendar, replies, campaigns, conversions (engine-internal only).
6. **◆ External-provider booking unreachable** — only the legacy internal-provider route is wired; the Google/Microsoft-aware `CalendarService::book` has no HTTP caller; `BOOK_MEETING` has no producer.
7. **◆ Configured AI is non-functional** — the sales client targets `/v1/sales/*` paths no service implements; production runs deterministic templates. (This is the same class of gap as the reply classifier's `/reply/classify` and the mailbot's runtime — §3.)
8. `sales_settings` is writable but read by nothing.
9. **◆ Analytics minimal** — 4 KPIs + counts; no funnel, trend, per-sequence/step/rep, deliverability, A/B results, attribution or calibration views (all exist as library functions with no route); costs not instrumented. Fixed 25-row sections; no pagination/filter/sort in the console.
10. Only `SEND_STEP` is ever enqueued; 8 of 9 action types have no producer.
11. **◆ No chat, voice, SMS, LinkedIn, or inbound lead surface of any kind** (workspace-verified).

---

## 2. SalesCloser, detail by detail (fact base; adopted items marked ★)

### 2.1 Product and company

Live-conversation AI sales agent: joins calls with camera and screen share, runs product demos ★(screen-share concept), branches walkthroughs, handles objections ★, qualifies, books, writes back to CRM. Four agent types (Demo, Discovery, Onboarding, Support). Formerly Wishpond; now TSXV-listed standalone (SCAI; ~$1.7M ARR run-rate reported Nov 2025, 150+ customers May 2025). Targets SaaS/tech, financial services, real estate, education; healthcare/e-commerce "coming soon". [F: vendor site, PR Newswire, StockTitan]

### 2.2 Features (vendor claims; ★ = adopted in this plan)

**Live conversation** [F]: voice+video calls over phone/Zoom/browser; camera-on presence; ★screen-share demos with "computer use"; adaptive branching ★(the scripting idea, not the runtime); ★real-time objection handling with an objection library; embedded website video avatar; ★website chat; function calling mid-call; voice selection/persona; 32 languages (launch said 10); no voice cloning (ElevenLabs credited instead).

**Workflow** [F]: qualification questions; lead scoring; ICP enforcement; meeting booking + reminders; ★instant lead response ("eleven seconds"); follow-up/nurture; human handoff; CRM write-back; minutes/transcripts; call recording (financial vertical).

**Channels** [F]: **no cold email** (explicitly "not email sequences"); **no LinkedIn** (explicit positioning); no native dialer.

**Integrations** [F]: marketplace lists ten (Slack, Pipedrive, HubSpot, ClickUp, ActiveCampaign, Salesforce, OpenAI, Gmail, Calendly, Airtable); marketing claims "200+".

**Analytics** [F/S]: call analytics, lead reporting, capture forms, minutes, summaries; **no A/B testing anywhere**; dashboards never concretely described.

**Compliance** [F]: SOC 2 Type I; Type II in progress; GDPR "working toward"; TCPA/DNC/CASL/10DLC/AI-disclosure duties pushed to the customer in the terms; transcripts used to train unless opted out; HIPAA unavailable.

**Commercial** [F]: white-label program (no published pricing); **no public docs** (docs./help. subdomains don't resolve); API/webhooks unevidenced.

### 2.3 UX and pricing [F live + Wayback]

Demo-gated: no self-serve signup, no public prices ("Let's Talk Pricing"). Historical tiers: Starter **$1,000/mo** (2 agents, 1,500 min), Scale **$2,000/mo** (5 agents, 3,600 min). Terms: annual prepaid **non-refundable**; **60-day non-renewal notice**; monthly cancel by email at 30 days; early termination → balance immediately due. Claimed setup: knowledge upload → pick a voice → map integrations; "60-word" builder; concierge build. Five contradictory time-to-live claims ("seconds"/"under 30 minutes"/"hours"/"days"/"<6 days").

### 2.4 Complaints (deduplicated; sources)

1. **Billing/auto-renewal/cancellation — dominant.** "Large amount deducted after a so-called free trial"; "No clear button or option to cancel"; "Auto-renewal caught me off guard"; "Impossible to contact" [F: Trustpilot via compiled mirrors; direct 403]. Slashdot 1★ ×2: "emailed to end the contract but money was still being taken"; "keeps charging their credit card… Nothing works" [F]. Contract terms corroborate the mechanics.
2. **Conversation quality.** G2 1★: "sounded like someone using Google Translate… confused and unnatural"; "felt like we were their first customer" [S/F]. SoftwareFinder 1★: two months of daily calls, "awkward, confused and unnatural", never implemented [F]. "Responses take too long" [F]; no latency data published [F].
3. **Implementation/reliability.** "Ineffective technology and poor customer service" [S]; "billing transparency and technology reliability" concerns; "unclear CRM compatibility" [F]; "6 months and £1200 later still not able to produce anything close to what was required" [F].
4. **Support.** "Impossible to contact"; review sentiment on response time "heavily divided" [F/S].
5. **Transparency/validation.** No public pricing/docs/API docs/self-serve cancellation [F]; G2 has 3 reviews (two incentivized, the organic one 1★) [F]; SoftwareFinder 2.7/5 [F]; Trustpilot 3.2–3.7 across snapshots [S/F]; case studies duplicated and tagged "ai generated" [F]; comparison pages templated [F].
6. **Reddit: essentially no organic footprint** [S; direct Reddit blocked — Appendix C]. A signal for a product marketed to sales teams.

### 2.5 Praise [F/S]

Immediate response lifts engagement [S]; "setup is ridiculously simple" [S]; a "$10K close handled flawlessly" testimonial [F]; concierge onboarding praised [F]; multilingual + professional objection handling "a major advantage" (3★; misses personal touch) [F]; meeting minutes "especially impressive" (4★; too many alerts) [F].

### 2.6 Positioning-vs-reality contradictions [F]

200+ integrations vs 10 listed; 32 languages vs 10 at launch; five time-to-live claims; "not chatbots" vs its own chatbot marketing history; "doesn't replace reps" vs "fraction of a loaded SDR"; testimonial quotes vs ~3.2–3.7 aggregates dominated by billing 1★s; AI-generated case studies; templated comparison pages.

---

## 3. The adopted four — rigorous build plan on existing infrastructure

Each subsection: **what exists** (with anchors), **what is missing**, **the plan**, **the blockers**. Full anchors in Appendix D.

### 3.1 ★ Screen-share demos

**What exists.** Zero WebRTC/browser-control/session-mirroring code or dependencies anywhere (workspace-verified; Playwright exists only as a dev-time KiwiCaptcha test harness). The buildable substrate:
- The **SSR console and marketing UI** — 99 page builders in `ui-foundation/leptos_views.rs`, rendered through `axum_router::render_route*`; the api-server can render any page in-process (the explorer already proves real-router execution via `tower::ServiceExt::oneshot`).
- The **live API explorer sandbox** (`api-server/src/routes/explorer.rs`) — public zero-JS pages that execute REAL actions against a lazily provisioned sandbox tenant: send a real email (to @example.com policy), run the domain grader (`email-grader` crate), compute plan pricing from `billing_service` — all rate-limited, all sandboxed.
- The **feature registry** (`compliance/src/feature_registry.rs`, GA/Beta/Planned) and the verified sales knowledge base — a factual script source.
- The **chat engine** can render rich HTML (sanitized `a/img/table/headings` allowlist) but exposes no structured view/embed protocol.
- **Visual fixtures** (goldens, parity snapshots, charts/primitives) for pre-rendered frames.

**What is missing.** Any demo/tour runtime; any live browser-driving service; a structured "view" protocol in chat responses; a demo guide script data model; (for a literal agent-driven remote screen share) the whole browser-control/streaming subsystem.

**The plan.** Deliver "screen-share demo" as a **scripted, server-driven guided demo session** — the salesperson shares a link; the prospect watches real product behavior, not slides:
1. A demo session model (scripted steps; the script drawn from the feature registry + sales KB so no step can state an unverified fact).
2. Step kinds that execute REAL actions through existing machinery: render a seeded console page (demo tenant), run `/explorer/exec` (real send to the sandbox), run the grader, run the pricing calculator, show a campaign/report page from demo data.
3. Narration through the existing grounded chat engine (per-step prose generated and verified by `ChatService`/`ResponseVerifier`, so demo copy cannot drift from product facts).
4. Chat rendering gains a minimal **view/embed contract** (e.g. `citations`-style structured step descriptors) so the demo client (SSR pages, zero-JS) can walk steps and show live results.
5. Replay/recording: the server-side session (step + results) is stored so a prospect can be sent a re-playable demo URL — the "screen share" outcome without any streaming infra.

**Blockers.** The knowledge-fact drift (§4.1) — the demo script would inherit wrong prices from the chat side; and no chat UI exists to narrate from (shared with §3.3).

### 3.2 ★ Automated objection handling

**What exists (rigorously, this is the complete list).**
- The **reply pipeline's disposition machinery**: 11-disposition classification (deterministic first, then an AI layer, then a policy table) with a **0.7 confidence gate** below which nothing irreversible is executed; `not_interested` is the one refusal category — and it deliberately does **not** auto-suppress (`reply_handler/{classifier,policy,types}.rs`).
- **Account coordination**: `STRONG_OBJECTION_DISPOSITIONS = ["complaint","unsubscribe"]` → the whole account stops unconditionally (`account_coordination.rs`).
- **Claim-safe composition**: `personalization::MessageStrategy` (observed_fact, problem_hypothesis, value_prop, proof_point, offer, cta, tone, language) with banned fake-personalization patterns and evidence-id requirements; the **verified sales KB** (`sales-autopilot/src/knowledge.rs`: plans, features incl. planned/roadmap, rate limits, security/compliance, SLA, case studies) with `validate_claim` numeric grounding and `Verified + in-date + allowed_in_external_copy` as the only externally-sayable class; the sequence worker's **claims gate** that drops unproven claims and falls back to operator templates.
- **Experiment arms** for message angles with the reward ladder (angles are free-text today; no objection mapping).
- The **mailbot** (`ai-service/src/email_agent.rs`) — draft-only reply generation with loop guards, caps, sanitization, and the transactional approval surface (`admin/ai_drafts.rs`) — currently unwired, and its verifier call is **policy-only** (no grounding facts passed).

**What is missing.** An objection taxonomy (price/timing/competitor/authority/trust/need — no table, enum, or migration row exists); an objection **library** of approved, evidence-carrying responses (the KB could host them — none exist); an objection **classifier** (no sub-labels under `not_interested`/`question`; the AI layer is disabled and its endpoint unimplemented); a **generation path** for rebuttals (no code generates a reply anywhere in the pipeline; `ActionType::AutoReply` has no producer); delivery/approval wiring for outbound rebuttals beyond the unwired mailbot; objection-level analytics/experiments.

**The plan.** One objection brain, assembled from the existing pieces:
1. **Taxonomy + library first**: define objection classes and persist approved responses as `SalesKnowledgeFact` entries (with evidence ids, validity windows, externally-sayable flags) — reusing the exact claim-validation that already gates all outbound copy. Price-class entries must cite the canonical billing catalog once the knowledge source is unified (§4.1).
2. **Classify**: extend the reply classification with objection sub-labels (and enable the AI layer by implementing `/reply/classify` on ai-service — it is the same LLM client, prompt-versioning, and 0.7-gate policy the pipeline already expects; the deterministic layer gains price/timing/competitor keyword families as the fallback).
3. **Generate**: route objection responses through the grounded pipeline — the mailbot upgraded to pass canonical facts + `verify_grounded` (today it is policy-only), or the chat `ChatService` for synchronous channels. Every generated rebuttal passes `validate_claim` + the claims gate before it can leave the building.
4. **Deliver**: email rebuttals ride the draft-only + `ai_drafts` transactional approval chain (human approval by default; a future per-class autonomy policy can auto-send only classes whose library entries are `Verified` and whose legal policy allows it — the legal engine already exists and would gate this, not a new bypass).
5. **Learn**: objection classes become experiment dimensions — arm selection among approved responses, reward ladder as-is (replies → meetings → revenue; opens/clicks never positive). This is where the product beats SalesCloser's "objection library" marketing claim: theirs is static content; this one is measured and gated.
6. **Safety rails already in force**: strong-objection account stop stays unconditional; below-threshold classifications still do nothing irreversible.

**Blockers.** The knowledge-source unification (a price-objection rebuttal built on the stale chat KB would state wrong prices and the verifier would reject the real ones); the AI classifier endpoint; the mailbot runtime.

### 3.3 ★ Chat

**What exists.** A complete, hardened chat pipeline:
- **Service**: `ai-service/src/chat.rs` — sanitize input (Critical threats rejected) → retrieval with tri-state (`Available/Empty/Unavailable`; citation markers rejected under Unavailable) → fail-closed without a model runtime → grounded byte-stable prompt (shared prefix + passages + account context + sanitized history) → generate (≤1024 tokens) → `ResponseVerifier` (pricing, safety/injection, URL allowlist, quality, PII, DNS-claim, SLA/competitor checks + **atomic-claim support**: numbers/entities must appear in canonical facts, account context, tool output, or the cited chunk — a citation marker alone proves nothing) → one corrective retry → escalation; output sanitized before response and audit; per-turn audit rows with 90-day pruning; EU AI Act disclosure constant.
- **Transport**: `ai-service/routes.rs` `/chat` requires the tenant header (401/400/403 semantics), per-tenant governor; `api-server/src/routes/ai_chat.rs` `/v1/ai/chat` proxy with `ai:read` scope, 4,000-char input cap, account context assembled from tenant-scoped queries, 20/min per-user Redis limiter, 45 s timeout.
- **Knowledge**: `ai-service/src/knowledge.rs` canonical facts + `verifier.rs` price/limit tables (asserted equal in tests); retrieval corpus = the repo `docs/` tree indexed into `ai_docs_chunks` with content-hash versioning.
- **Reusable extras**: history sanitation (role-marker forgery dropped), prompt-prefix caching design, `ai_chat_messages` audit table.

**What is missing.** Any UI consumer at all (console or marketing widget — tests are the only callers); a server-side conversation store (histories are client-supplied; only audit rows persist); streaming/SSE (request/response only; the "streaming" client chunks a completed response); a knowledge-base refresh (the price drift, §4.1); unified rate budgeting across channels (per-process governor).

**The plan.**
1. **Console assistant page** — a zero-JS SSR chat surface posting to the existing `/v1/ai/chat` (plain form + PRG rendering of the answer with its sanitized HTML and citations), inside the authenticated console; marketing-facing widget deferred (the console first, because it is owner/customer-tenant scoped already).
2. **Server-side sessions** — a `ai_chat_sessions` table (tenant, user, turns, retention aligned with the existing 90-day prune) so history survives devices and the audit is the source of truth, replacing client-supplied history while keeping the existing cap semantics.
3. **Knowledge unification (§4.1)** before any prospect sees an answer.
4. **Structured answers** — extend `ChatResponse` with a minimal view/embed descriptor (reused by the demo runtime, §3.1) without changing the sanitization contract.

**Blockers.** None technical beyond the knowledge refresh; the service is production-grade today.

### 3.4 ★ Instant response

**What exists (the rails).**
- **Inbound email**: the MTA accepts and commits `inbound_messages` (raw_message) and best-effort notifies Redis (`mta:webhook_queue` — **no consumer exists**); the worker's reply handler polls every **5 s**, claims `processed_at IS NULL` rows **where `from_email IS NOT NULL`** with `FOR UPDATE SKIP LOCKED`, classifies (deterministic → AI → policy), applies transactional locks/suppressions/reschedules, and hands off analytics. Stale-claim reclaim at 10 min. The AI classifier layer expects `POST /reply/classify` — **implemented by no service**; the worker never enables it (production is deterministic-only).
- **Queue priority**: `email_queue.priority` (0–100, indexed) with the worker claiming `priority DESC`; **every producer uses 5** (campaigns, sales dispatch, system sender). No first-response lane exists.
- **Draft-and-approve**: the mailbot's chain (claim → guards → caps → sanitize → LLM → policy-only verify → sanitize → draft write with `pending_approval=true`) plus `admin/ai_drafts.rs` (single transaction: claim draft → enqueue through the verified system sender → hash-chained actor-attributed audit → commit; concurrency-tested; rollback on any failure). The mailbot is **unwired** (no binary starts it) and its drafts are ungrounded (no canonical facts block).
- **Triggers**: contact forms (`/v1/contact/*`) write account/contact/lead transactionally and **do nothing else**; chat exists but has no CRM write-back; everything else is the email path above.

**What is missing.** A first-response generator (no auto-reply exists; `ActionType::AutoReply` unreachable); the ingestion fix (the MTA never populates `from_email`/`to_email`/`subject`/`body_*`, so the reply handler's claim **cannot see production inbound rows** — migration 114 relaxed NOT NULL for exactly this reason); the mailbot's runtime; a priority value/policy beyond 5; lead-capture → generation triggers; a first-response latency metric/SLO.

**The plan.**
1. **Unblock ingestion**: either populate the mirror columns at MTA-accept time (parse raw MIME once) or change the claim to parse `raw_message` (the mailbot's approach). The former keeps one parse location; the latter requires no MTA change. Pick the former for the reply pipeline, and delete the unconsumed Redis notification or wire it as the trigger.
2. **Wire the mailbot** with grounding: pass canonical facts + `verify_grounded` (job one), keep draft-only + `ai_drafts` approval as the default autonomy, and record its drafts against the reply pipeline's classification so objection-handling (§3.2) and first-response share one brain.
3. **Priority lane**: add a priority parameter to `queue_system_email_in_transaction`; first responses enqueue at a high priority (e.g. 100) — the worker's existing `priority DESC` claim needs no schema change. Latency budget published: 5 s poll + generation + approval/queue + send.
4. **Triggers**: contact-form submissions and new-lead creations emit a first-response job (draft on the mailbot chain; chat answers synchronously already); a chat→CRM write-back creates the lead so the three channels converge on one record.
5. **Policy-gated auto-send** (optional, later): a per-category autonomy policy (the sales legal engine + the 0.7 gate + the claims gate as the gates) can auto-send only classes whose content is fully Verified and legally allowed; everything else stays human-approved. This is the design that makes "instant" safe — no auto-send bypasses the existing machinery.

**Blockers.** The ingestion fix is a hard prerequisite (without it the pipeline is blind); the knowledge refresh (any first response citing prices); the mailbot runtime; and the acknowledgment that end-to-end "instant" is bounded by the 5 s poll plus approval unless policy-gated auto-send is adopted.

---

## 4. Better than SalesCloser, re-scoped

### 4.1 Fix-before-ship: the two contradictions the audit found

1. **Knowledge-fact drift (critical).** ai-service `knowledge.rs`/`verifier.rs` state Free 30k / Starter €25 / Pro €65 / Growth €150 / Scale €350 / Enterprise €3,000, while the deployed billing catalog (`billing-service/src/plans.rs`) and `docs/pricing.md` state Free 3k (+30k launch) / Developer €29 / Pro €89 / Growth €229 / Business €699 / Enterprise Cloud €1,750. The chat verifier would reject the real prices and bless the stale ones; the demo script and every objection rebuttal inherit this. **One canonical fact source (billing) feeding chat, the sales KB, the demo script and the verifier tables, with a drift test** — the platform already has the pattern (the sales KB and verifier tables each carry equality assertions; they just assert against the wrong source).
2. **The reply pipeline's input gap.** A repo-faithful deployment writes `inbound_messages` rows the reply handler cannot claim. Until fixed, "instant response" and objection classification on inbound email observe nothing.

### 4.2 Why the four capabilities, so scoped, beat SalesCloser's versions

| Capability | SalesCloser | This plan |
|---|---|---|
| Screen-share demos | Live agent joins your call with camera + screen share; "computer use" drives the product; five contradictory time-to-live claims; reviews cite robotic delivery | Scripted server-driven demo executing REAL sandbox actions (live send, grader, calculator) with narration generated and **verified** against product facts — no voice-quality risk, replayable, link-shareable, no meeting logistics |
| Objection handling | A static "objection library" behind a live audio agent whose calls reviewers describe as "Google Translate", "confused and unnatural" | Taxonomy + evidence-carrying library + grounded generation + claims/legal gates + approval chain; objection classes become **measured experiment dimensions** (their library is unmeasured content) |
| Chat | Website chat/video avatar as part of a demo-gated bundle | A hardened grounded chat with claim-support verification, escalation, per-tenant rate limits and per-turn audit — already built; shipping a console UI is the delta |
| Instant response | "Eleven seconds" claim, no measured methodology | First-response drafts on the existing 5 s reply rail with a dedicated priority lane, grounded by the canonical knowledge source, human-approved by default, policy-gated auto-send as the explicit later opt-in — with the **latency measured and published**, not claimed |

### 4.3 Commercial-practice commitments (kept from the complaint analysis)

These cost nothing and are where SalesCloser bleeds: public pricing with real numbers and a self-serve path (their #1 friction); one-click cancellation, no 60-day notice, no non-refundable annual lock-in; no auto-renewal surprises; measured-and-published latency/quality instead of five contradictory claims; verifiable evidence instead of "ai generated" case studies; a named support channel with a response-time target. The platform's existing attribution/audit machinery makes the "verifiable evidence" commitment a byproduct of features already shipped.

### 4.4 Build order

**Tier 0 — unblock (prerequisites; nothing ships before these).** Canonical knowledge unification + drift test; inbound ingestion fix (mirror columns or claim-level parse); mailbot grounding upgrade + runtime; implement `/reply/classify` and the `/v1/sales/*` client contract on ai-service (one LLM, one prompt registry, one governor).
**Tier 1 — chat (smallest delta to a shippable capability).** Console assistant page (SSR) on the existing proxy; server-side sessions; structured answer descriptors.
**Tier 2 — instant response.** Priority lane; contact-form/new-lead triggers; first-response drafts through the mailbot chain; latency metric/SLO; chat→CRM write-back.
**Tier 3 — objection handling.** Taxonomy + library as KB facts; sub-label classification on the enabled AI layer; grounded generation; approval-chain delivery; experiments on objection classes.
**Tier 4 — screen-share demos.** Demo session model + script from the registry/KB; live sandbox step kinds; chat-narrated steps; replayable session URLs.

---

## Appendix A — Sales Autopilot evidence anchors

Decision gate `sales-autopilot/src/decision_engine.rs:41-55,232-515`; modes `:250-274`; approvals `control.rs:567-753`, `sequence_worker.rs:2317-2405`; budgets `decision_engine.rs:1277-1485`; sender pool `sender_pool.rs:46-125`; legal `legal_policy.rs:1-120,313-560`; experiments `experiments.rs:1-120,535-620,1806-1950`; scoring `scoring.rs:1-96`; calendar `calendar/availability.rs:24-302`, `calendar/internal.rs:170-260`; dispatcher/unsubscribe `dispatcher.rs:178-459,1477-1756`; console page `ui-foundation/src/leptos_views.rs:2094-2517`; CP forms `api-server/src/routes/web.rs:7973-8159`; owner gate `api-server/src/middleware/sales_owner.rs:1-125`.

## Appendix B — SalesCloser sources

Vendor: salescloser.ai ( /, /pricing/, /demo/, /industry/, /alternatives/*, /build-sales-agents/, /qualifying-platform/, /ai-sdr-software/, /our-purpose/, /app/, /terms-of-use/, /privacy-policy/, /case-studies/, sitemap) [F]. Wayback pricing 2024-03 [F]. PR Newswire 302461260; StockTitan LOI/Q1-2026; investors.salescloser.ai [F]. Reviews: Trustpilot (3.2–3.7; direct 403 — snippets + compiled mirrors) [S/F]; G2 (3 reviews; snippets) [S]; SoftwareFinder full [F]; Slashdot full [F]; SalesRobot/Outly/Prospeo/Skywork/Salesforge [F/S]; Product Hunt [F]. Reddit/aggregators direct: blocked (Appendix C).

## Appendix C — Access log (summary)

**Worked:** all vendor pages listed; Wayback; StockTitan; PR Newswire; Product Hunt; SoftwareFinder; Slashdot; prospeo.io; salesrobot.co; useoutly.com; skywork.ai. **Blocked:** Reddit (all entry points), Trustpilot/G2/Capterra/TrustRadius direct, DuckDuckGo html/lite, Bing, most independent search engines; docs./help.salescloser.ai (DNS). Complaint quotes are aggregated from fetched mirrors and snippets with the strongest available tag; no claim rests on a snippet where a fetched page existed to corroborate it.

## Appendix D — Substrate anchors for the four capabilities

**Chat:** `ai-service/src/chat.rs:76-127,269-585` (contract, pipeline, audit); `verifier.rs:44-229,278-324,1005-1189` (policy + claim support); `retrieval.rs:37-50,107-330` (tri-state, corpus, versioning); `knowledge.rs:27-174` (canonical facts — stale, §4.1); `routes.rs:582-646,741-777` (tenant header, endpoint domains); `api-server/src/routes/ai_chat.rs:20-47,73-175,215-301` (proxy, caps, Redis limiter); **no UI consumer** (grep verified).
**Mailbot:** `ai-service/src/email_agent.rs:13-16` (unwired), `:74-84,141-188` (draft-only, claim/retry/quarantine), `:193-250,529-559` (config, approval-required start), `:921-937` (policy-only verify); `api-server/src/routes/admin/ai_drafts.rs:55-275` (transactional approve/reject + audit).
**Reply pipeline:** `worker-processors/src/reply_handler/{classifier,policy,processor}.rs` (0.7 gate `policy.rs:29-38`; claim `processor.rs:64-98`; transactional lock `:479-713`); `ai.rs:17-49,201-204,278-346` (`/reply/classify` contract — unimplemented); worker wiring `bin/worker.rs:175-177,580-587` (llm disabled); ingestion gap: `mta/src/servers/inbound.rs:1801-1827` vs claim requirement (migration 114 note).
**Objection machinery:** `account_coordination.rs:53,212-222,459-481` (strong objection); `personalization.rs:95-104,262-299,336-668` (strategy, bans, validation); `knowledge.rs:127-144,298-489,516-593` (facts, validate_claim, external-copy rule); `sequence_worker.rs:870-965,1249-1302` (claims gate); `reply_handler/types.rs:96-108` (11 dispositions; `not_interested` non-suppressing).
**Instant response rails:** `email_queue.priority` (migration 001:46; index 001:53; claim `email/processor.rs:510-535`); all producers at 5 (`system_sender.rs:167-176`); poll cadence `bin/worker.rs:184-198`; contact forms `contact.rs:25-27,328-592` (write only); demo substrate `explorer.rs:34-41,74-300,958-960`, `ui-foundation/src/explorer.rs:129-433`, `compliance/src/feature_registry.rs:124`.
