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


---

# PART II — FULL IMPLEMENTATION PLAN

## 5. Completing what exists but does not run, then the four capabilities

Three capabilities are *half-built*: the chat engine runs with no UI, the mailbot is unwired code, the instant-response rail is blind to its own input. The plan's first act is completing them, then extending to the adopted four.

### 5.1 Completion matrix (what exists → what completes it)

| Existing but incomplete | Today | Completion work |
|---|---|---|
| Chatbot engine (`ai-service` ChatService/verifier/retrieval, `/v1/ai/chat` proxy) | No UI consumer; client-supplied history; stale canonical facts | §5.2 — console chat surface + server-side sessions + knowledge unification |
| Mailbot (`ai-service/src/email_agent.rs` + `admin/ai_drafts.rs`) | Draft-only code, no runtime owner, policy-only verifier, ungrounded prompt | §5.3 — runtime loop, grounded verification, drafts review UI, classification link |
| Instant reply pipeline (`worker-processors/src/reply_handler`) | Polls rows the MTA never populates; deterministic-only; no first-response generation | §5.4 — ingestion fix, AI classifier route, first-response requests, priority lane, triggers |

### 5.2 Chat — files to change and what to do

| File | Change | Tests |
|---|---|---|
| `services/mail-server/crates/billing-service/src/plans.rs` (catalog) + new shared source | Extract the plan catalog (names, prices, limits) into a single canonical source consumed by billing, ai-service knowledge/verifier tables, sales KB, and `docs/pricing.md` generation | drift test (new) |
| `crates/ai-service/src/knowledge.rs`, `verifier.rs` | Replace hardcoded PLANS/limit tables with the canonical source (build-time include or generated const); keep the existing equality assertions, now against the canonical source | update existing equality tests; new drift regression |
| `crates/ai-service/src/routes.rs` | (unchanged for chat) + new `/reply/classify` (§5.4) | header/tenant tests extend |
| `crates/api-server/src/routes/ai_chat.rs` | Add `ai_chat_sessions`-backed endpoints: create/list session, post turn, read window; keep the 4,000-char cap, Redis limiter, account-context assembly | session lifecycle, tenant scoping, hostile history |
| new migration `233_ai_chat_sessions.sql` | `ai_chat_sessions(id, tenant_id, user_id, created_at, updated_at)` + `ai_chat_session_turns(session_id, role, content, created_at)`; retention aligned with `AI_CHAT_RETENTION_DAYS` | migration applies on canonical chain |
| `crates/api-server/src/routes/web.rs` + `crates/ui-foundation/src/leptos_views.rs` (`web_assistant_page*`), `axum_router.rs` (route arm), `routing.rs` + `docs/development/ui-baseline-manifest.json` | New **console assistant page** `/assistant`: SSR conversation (history from session), input form → PRG, answer rendered with its sanitized HTML and citations as `<details>`; escalation and model-disabled states rendered explicitly; nav entry under Account | console flow test; goldens regenerated; a11y/contrast/link gates |
| `crates/ui-foundation/src/view_data.rs` + `api-server/src/routes/web/data.rs` | `AssistantPageData` loader (session + last N turns) with the unavailable contract on DB failure | loader fault tests |

### 5.3 Mailbot — files to change and what to do

| File | Change | Tests |
|---|---|---|
| `crates/ai-service/src/email_agent.rs` | Runtime loop owned by a unit: spawn from `ai-service` main behind `AI_EMAIL_AGENT_ENABLED` (the process already owns the DB pool, LLM client, governor); upgrade `assess_draft` to `verify_grounded` with the canonical facts block + sales KB facts; attach the reply pipeline's classification (join by message id) to each draft for objection labels | loop lifecycle (start/stop), grounded rejection cases, join correctness |
| `crates/ai-service/src/inference.rs` / `governor.rs` | No change; the mailbot reuses them (one LLM client instance, one governor budget) | — |
| `crates/api-server/src/routes/web.rs` + views/routing/manifest (as §5.2) | **AI drafts review page** `/reviews/ai-drafts` (and a `/sales` exceptions link): pending drafts table, draft + evidence + classification, approve/reject via the existing `/v1/admin/ai/drafts` mutations wrapped in SSR forms (CSRF, PRG, audit) | approve/reject flows through the browser; exactly-one-winner concurrency through the UI path |
| `docker-compose.yml` / `docker-compose.prod.yml` / `.env.production.example` | `AI_EMAIL_AGENT_ENABLED=true` in the managed baseline (draft-only; approval required); document `AI_REPLY_FROM`, poll cadence | compose posture gate (new env becomes an explicit security-adjacent decision in the posture checker's control list if it can send) |
| `deploy/DEPLOYMENT.md` | Mailbot runtime section | — |

### 5.4 Instant response — files to change and what to do

| File | Change | Tests |
|---|---|---|
| `crates/mta/src/servers/inbound.rs` | At accept time, parse the raw message once (mail_parser, the mailbot's pattern) and populate the existing mirror columns (`from_email`, `to_email`, `subject`, `body_text`, `body_html`, `headers`, `received_at`) in the same insert; replace the unconsumed Redis notification with either a real consumer or remove it | inbound tests extended: columns populated for real messages; DSN rows keep their shape |
| `crates/ai-service/src/reply_classify.rs` (new) + `routes.rs` | Implement `POST /reply/classify` (service-token domain): prompt `reply-classifier-v1`, the 11-disposition taxonomy + objection sub-labels (§5.5), JSON contract exactly as `reply_handler/ai.rs` expects; errors keep the no-guess fallback | contract tests against the exact client shape; outage fallback |
| `crates/worker-processors/src/bin/worker.rs`, `common/config.rs` | Enable the AI classifier layer: `WORKER_REPLY_CLASSIFIER_AI_ENABLED` + base URL env (deterministic layer stays first; 0.7 gate unchanged) | classification integration with the real route |
| new migration `234_first_response_requests.sql` | `first_response_requests(id, kind contact_form|inbound_email|chat_lead, subject_ref, payload jsonb, state, created_at, due_at, lease)` | migration applies |
| `crates/ai-service/src/email_agent.rs` | Claim first-response requests alongside inbound rows; produce a first-response draft (grounded, same chain, `pending_approval=true`) | draft for each trigger kind |
| `crates/api-server/src/routes/contact.rs` | After the transactional lead write, enqueue a `first_response_requests` row (kind=contact_form) in the same transaction | trigger row committed with the lead |
| `crates/api-server/src/routes/ai_chat.rs` | Chat→CRM: when a tenant-scoped, verifier-gated answer identifies a contact intent, create the lead via the existing contact machinery (deterministic extraction only; no free-form writes) | lead created once; no writes on ordinary questions |
| `crates/api-server/src/routes/system_sender.rs` + `crates/sales-autopilot/src/dispatcher.rs` | `queue_system_email_in_transaction` gains a `priority` parameter; first-response sends use 100, everything else keeps 5; sales dispatch keeps 5 | worker claim order test (priority lane beats backlog); existing producers unchanged |
| `crates/worker-processors/src/email/processor.rs` (metrics) | `first_response_latency_seconds` histogram (accept→enqueue) on first responses | metric emitted |
| `deploy/alerting-rules.yml` | `FirstResponseSloBurn` alert on the histogram (p95 target published in docs) | rule lint (topology gate) |
| first-response SLO page | `docs/operations/first-response-slo.md`: methodology, target, measurement | — |

### 5.5 Objection handling — files to change and what to do

| File | Change | Tests |
|---|---|---|
| new crate `crates/sales-knowledge` (workspace member) | Extract `SalesKnowledgeFact` + `validate_claim` + the claim verdict ladder from `sales-autopilot/src/knowledge.rs` so **both** sales-autopilot and ai-service (mailbot/classifier) share one claim validator; sales-autopilot re-exports (no behavior change) | extraction regression: every existing claim test passes against the shared crate |
| `sales-autopilot/src/knowledge.rs` + new migration `235_objection_library.sql` | Objection taxonomy (price, timing, competitor, authority, trust, need) + approved-response library seeded as knowledge facts: each entry carries evidence ids, validity window, `allowed_in_external_copy`, and the objection class; owner/counsel approval recorded the way legal policies are | library gate: no external-copy-eligible entry without evidence |
| `crates/ai-service/src/reply_classify.rs` + `worker-processors/src/reply_handler/types.rs` | Objection sub-labels under `not_interested`/`question` (extend the canonical disposition enum with `objection_class: Option<ObjectionClass>`); deterministic keyword families as the fallback layer | taxonomy tests; fallback classification; 0.7 gate unchanged; `not_interested` behaviors preserved |
| `crates/ai-service/src/email_agent.rs` (+ ChatService for chat) | Objection response generation: strategy selection (reuse `MessageStrategy` shape) → grounded draft with the library entry's evidence → `verify_grounded` + shared `validate_claim` | claim-bypass corpus (forbidden prices/roadmap/SLA must not leave) |
| `crates/api-server/src/routes/admin/ai_drafts.rs` | No change (the same approval chain carries objection replies); drafts list gains the classification/objection fields | echo fields pinned |
| `crates/sales-autopilot/src/experiments.rs` + a new internal route `POST /experiments/:key/arms` (owner-token) | Arms authoring for objection classes; objection class joins the contextual bucket dimensions; reward ladder unchanged (replies → meetings → revenue; opens/clicks excluded) | arm creation validation; bucketing determinism; reward idempotency |
| `crates/sales-autopilot/src/personalization.rs` | `compose_objection_response` path reusing banned-phrase and evidence rules | banned-phrase coverage |

### 5.6 Screen-share demos — files to change and what to do

| File | Change | Tests |
|---|---|---|
| new migration `236_demo_sessions.sql` | `demo_sessions(id, token_hash, script_key, state, created_by, expires_at)` + `demo_session_steps(session_id, idx, kind, input jsonb, result jsonb, ran_at)` | migration applies |
| `crates/api-server/src/routes/admin/demos.rs` (new, owner-gated like sales) | Presenter API: create session from a script, advance steps, read results; tokens returned once and stored hashed | token hashing; owner gate; expiry |
| `crates/api-server/src/routes/web.rs` + views/routing/manifest | **Presenter page** (CP: `/demos` — create, step through, live results) and **viewer page** (public-with-token `/demo/:token`: SSR step list, live-executed results, replay of a completed session) | SSR goldens; a11y/contrast/links; token tamper/expiry refused |
| Demo runtime module `crates/api-server/src/routes/demos/runtime.rs` (new) | Step kinds executing REAL machinery in-process: `render_page` (axum_router render for a seeded demo tenant), `explorer_exec` (reuse the explorer sandbox lane), `grader`, `calculator`, `chat_narrate` (ChatService call; narration verified) | per-kind execution against the sandbox; rate limits inherited; hostile script input refused |
| Demo script + fixtures | `docs/demos/demo-script.md` (script drawn from the feature registry + KB facts; no unverified claims) + a seeded `demo` tenant fixture (cargo-managed fixture, not production data) | script lint: every claim cites a registry/KB fact |
| Chat `ChatResponse` extension (ai-service `chat.rs`) | Minimal structured step descriptor so the viewer can render narration + live results without a view protocol invention | serialization pinned |

## 6. Training plan (knowledge, model, operators, corpus)

1. **Knowledge/CAG (context-augmented generation)**: unify the canonical fact source (§5.2); re-run the docs corpus index (`POST /admin/reindex` on ai-service) after every content change; every new surface's content (objection library, demo script) lives as KB facts / docs under the indexed tree so retrieval, chat, drafts, and demos read the same truth. Prompt prefix stays byte-stable (CAG efficiency: shared prefix + cached prompt).
2. **Model evaluation corpus and runs**: build `docs/eval/` corpora — chat Q&A goldens (question → must-contain / must-not-contain), reply-classification cases (message → disposition + objection class), objection-rebuttal cases (objection → required evidence + forbidden claims) — and run them through the existing `POST /evaluate` (AI_ADMIN_TOKEN) on each model/prompt change; record results as release evidence. Prompt registry versions: `reply-classifier-v1` (existing), add `objection-response-v1`, `assistant-v2` after knowledge unification.
3. **Retrieval quality**: keep hybrid lexical + trigram (no new deps); measure retrieval hit-rate on the eval corpus; `ai-embeddings` stays unwired unless hit-rate targets demand it (explicit decision point, not silent).
4. **Operator training**: runbooks — drafts review queue (SLA, what to check), demo presenter guide (script + live sandbox etiquette), objection library maintenance (author → evidence → counsel approval), first-response SLO monitoring; all as `docs/operations/*` and referenced from the console pages' help text.
5. **Sales team training**: objection taxonomy and library usage, when automation escalates to human, latency expectations per channel.

## 7. UI/UX specification — globally compliant, beautiful, interactive, smooth

**Foundations (non-negotiable, already gated):** the Apex design system (tokens in `ui-foundation/assets/globals.css`; brand, spacing, motion, radius; light/dark via `prefers-color-scheme`); zero-JS SSR (CSP `script-src 'none'` except the existing nonce'd KiwiCaptcha island precedent); WCAG 2.2 AA enforced by the existing required gates (contrast pixel gate, a11y static checker: lang/alt/labels/one-h1/viewport/autocomplete/button-type, layout-spill, 44px targets, focus-visible, reduced-motion, no color-only status, skip links).

**Global compliance:**
- **GDPR**: chat sessions store minimal data (message + answer + citations; account context is read at request time, not persisted); 90-day retention prune already exists — extend to session rows; no PII in prompts beyond the sanitized account context; data-residency note in the assistant page footer.
- **EU AI Act**: the existing disclosure constant is rendered on every assistant/draft/demo narration surface; drafts and demo narrations are visibly marked as AI-generated with the review path named.
- **Accessibility beyond the gates**: conversation tables get row headers; citation `<details>` are keyboard-operable; the demo viewer's step list is an ordered list with `aria-current`; latency/status indicators pair color with text.
- **i18n readiness**: all new strings enter the strings catalog (`tools/extract_ui_strings.py`); `lang="en"` pinned; no concatenated sentences.

**Interactivity and smoothness within the architecture:**
- Phase 1 (ships with §5.2): pure SSR — chat turns post → PRG → the response renders server-side; the conversation window scrolls to the newest turn via an `#latest` anchor; a CSS-only "pending" shimmer uses the existing motion tokens on the submit control; slow answers (>600 ms guidance) show the existing busy affordances. The live-refresh pattern (allowlisted `<meta http-equiv="refresh">`, already used for live-metrics pages) renders the drafts queue and first-response KPIs updating without JS.
- Phase 2 (optional, precedent-gated): a nonce'd CSP JavaScript island — exactly like the KiwiCaptcha widget exception — for the assistant's streaming scroll and the demo viewer's step auto-advance, only if usability testing shows the SSR loop insufficient; it must pass the no-inline-handler and CSP gates and add zero external dependencies.
- **Graphic quality**: charts from `ui-foundation/src/charts.rs` (latency percentiles on the SLO panel; decision-stream sparklines already exist) rendered as SSR SVG; the demo viewer uses the same chart primitives for live results; all new pages follow the Spiral-Lock visual language and enter the golden set.

**Per-surface specification:**

| Surface | Layout | States | Gates |
|---|---|---|---|
| `/assistant` (console) | nav column + conversation column (turns as definition-style blocks), input form with char counter, citations `<details>` under each answer, disclosure footer | empty (prompt starters), pending, model-disabled (explicit), escalated-to-human, rate-limited (friendly 429), unavailable (DB/AI down, honest copy) | goldens, a11y, contrast, link, form-hygiene, flash-copy canon |
| `/reviews/ai-drafts` | table (age, sender, classification + objection class, excerpt), expandable draft with evidence list, approve/reject buttons through the signed-confirm pattern | empty, pending-only, approve-refused (revalidation), audit-linked success | as above + confirm-signature tests |
| `/sales` additions | first-response KPI tile (p50/p95 vs target), drafts-pending tile linking to reviews | unavailable contract on query failure | goldens regen |
| `/demos` (CP presenter) | script steps list with live result panes; "next step" form; session token copy chip (reveal-once pattern) | pre-create, running, expired, tampered token | goldens; token tests |
| `/demo/:token` (viewer) | ordered step list, each step's live result (page render, send receipt, grade meters, price table), replay banner when completed | invalid/expired token page; completed session replay | public-page contract; marketing-shell consistent |

## 8. Extremely adversarial test plan

**Cross-cutting (every new feature):**
1. **Truthfulness corpora**: for each generative surface (chat answer, objection rebuttal, first-response draft, demo narration), a corpus of prompts engineered to extract unverified claims (fake prices, roadmap items, SLAs, invented features, "ignore your instructions" injections, role-marker forgeries, homoglyph/unicode tricks). Pass = the verifier rejects or escalates; fail = any unverified claim rendered. Runs under `cargo nextest` in the new suites and as an eval-corpus battery.
2. **Knowledge-drift test**: the canonical fact source vs billing vs docs vs chat/verifier tables — equality asserted; the new CI gate re-checks on every build.
3. **Tenant isolation**: chat sessions, drafts, first-response requests, demo sessions — cross-tenant probes at both API and SSR layers; machine-credential probes on owner surfaces.
4. **Race and kill windows**: mailbot claim races (two workers, one draft), first-response double-send under retry (idempotency key), draft approval exactly-one-winner (exists — extend through the new UI path), demo step execution being replayed after crash (idempotent step ids), priority-lane starvation (backlog test), session-consume races.
5. **Fault injection**: LLM down (draft declines, chat escalates — never a crash, never a fabricated answer), Redis down (rate limits fail closed where security-relevant; chat limiter), DB down (every new loader renders unavailable, never zero/absent-confusable), MTA parse failure (message still accepted; no skip), reindex failure (old index served; version pinned).
6. **Injection and rendering**: XSS corpus against answer HTML (sanitizer allowlist), citation spoofing (fake `[n]` with no chunk), markdown/HTML smuggling in drafts, CSV/link integrity for any new table exports.
7. **Rate/abuse**: per-user/per-tenant chat limits, first-response burst cap, demo viewer token brute-force, contact-form spam routing.
8. **SLO tests**: first-response latency histogram asserted under a seeded burst (bounded, deterministic in CI with the fault proxy as the clock source where possible).
9. **Existing gates carried over**: a11y, contrast, layout, links, goldens, form hygiene, flash-copy, terminology, capability-claims (registry entries added for chatbot/mailbot/objection/demo/first-response with their stages), release-mode soft-skip.

**Per capability:** chat (session retention expiry, history forgery, unicode/empty/4k+ input bounds, disconnected AI service 5xx mapping), mailbot (loop guards: self-mail, auto-submitted, per-sender cap, quarantine; grounded rejection of stale prices), instant response (ingestion columns for real MIME shapes incl. multipart/DSN; trigger transactional commit; priority ordering; latency), objection (taxonomy boundary cases, sub-label precision corpus, library evidence gate, claims gate on generated text), demos (script with an unverified claim refused at load; step execution against sandbox constraints; replay determinism).

## 9. CI plan

- **validate stage**: `check_knowledge_consistency.py` (new; facts vs billing vs verifier tables) wired as a required `ci_check`; capability-claims registry gains the five new capability entries (stages raised as each lands); repo-map regenerated; posture gate picks up any new env (mailbot enable) as explicit; objection-library evidence lint (extends the existing claims gate).
- **test stage**: all new suites ride the existing nextest lane (junit + coverage ratchet raised by the same PRs); release mode (`APEXMAIL_RELEASE_TEST_MODE=1`) is already enforced, so no new suite can soft-skip.
- **ui stage** (already required): goldens for every new page; a11y/contrast/link/terminology/flash-copy cover the new surfaces' copy; strings catalog regenerated.
- **security stage**: unchanged gates; semgrep/toolchain already fail-closed.
- **New perf smoke**: `first-response latency` test asserting the p95 bound on a seeded burst; starts advisory for two runs, then required (the platform's standard flips).
- **Meta-tests**: the new checker gets its `--self-test` (mutated knowledge fixtures must fail); the SLO test gets an intentionally-slow fixture proving it fails.
- **Release evidence**: Woodpecker posts the sha-bound status (already wired); the release manifest carries the eval-corpus results as an artifact.
- **Woodpecker**: no new services needed; the mailbot runtime is in-process.

## 10. Dogfooding plan (run the four capabilities on ApexMail itself)

Follow the campaign's DF pattern (parallel DF agents, scratch reports, fix-and-verify loops):

- **DF-1 Assistant**: operators ask the platform's real questions (pricing, deliverability, compliance, API) against the console assistant for a week; every answer is scored against the eval corpus + human review; gaps become KB/docs edits + reindex; defects fixed in the same loop. Exit: ≥95% answers fully grounded, zero stale-price answers.
- **DF-2 Objection handling**: take real inbound replies (contact form + support) — classify, generate rebuttal drafts, human-review every draft, record accept/edit/reject with reasons; accepted edits seed the library; measure precision of the objection classifier and the draft acceptance rate. Exit: classifier precision published; ≥80% drafts accepted-or-lightly-edited before any auto-send policy is considered.
- **DF-3 Instant response**: wire the contact form and inbound sales inbox end-to-end; measure p50/p95 first-response latency over ≥100 real inquiries; fault-inject LLM/DB/Redis outages during the window and record degradation behavior; fix everything found. Exit: SLO met or the target re-derived from data, with the measurement page updated.
- **DF-4 Demos**: run prospect-style demos (internal + friendly external) through the presenter/viewer flow; collect friction notes per step; iterate the script and the sandbox fixtures; verify every narration claim against the registry. Exit: a demo runs end-to-end in ≤15 minutes with zero unverified claims and zero manual fixes.
- **DF-5 Gates on our own surfaces**: run the full gate battery (a11y/contrast/layout/links/goldens/copy) over the new pages in release mode; the dogfood reports land in `docs/dogfood/` with defect lists and resolutions.

## 11. Deliverables

1. **Code** (per capability, one PR each with migrations 233–236, tests, and gate updates): chat sessions + console assistant; mailbot runtime + grounded verification + drafts UI; ingestion fix + first-response requests + priority lane + triggers + SLO metric/alert; objection taxonomy/library + classifier sub-labels + generation + arm authoring; demo sessions + runtime + presenter/viewer pages + fixtures.
2. **Canonical knowledge source** + the drift gate; regenerated docs/pricing consistency.
3. **Corpora**: `docs/eval/` (chat Q&A, classification, rebuttal), objection library content pack, demo script pack.
4. **UI artifacts**: new pages with goldens, strings catalog, a11y evidence; the phase-2 JS-island decision recorded.
5. **CI**: new gates wired and meta-tested; ratchet raised; release evidence including eval results.
6. **Docs**: operator runbooks, first-response SLO methodology, demo presenter guide, objection library maintenance guide, deployment updates for the mailbot env.
7. **Dogfood reports** (`docs/dogfood/df-1..df-5`) with defect lists and resolutions.
8. **Acceptance criteria** (all must hold before any of this is called shipped):

| # | Criterion |
|---|---|
| 1 | Zero stale-fact answers: knowledge drift gate green; eval corpus passes on every prompt/model change |
| 2 | Every generative surface verifier-gated; adversarial corpora green in CI |
| 3 | Chat usable from the console (SSR), sessions persistent, GDPR retention enforced |
| 4 | Mailbot runs in production draft-only; every draft grounded and human-approved; review UI live |
| 5 | First response: measured p50/p95 published; SLO met or re-derived with data; fault behavior recorded |
| 6 | Objection classifier precision published; drafts accepted before any auto-send is enabled; auto-send only via policy-gated, legally-allowed, fully-verified classes |
| 7 | Demo runs end-to-end with live sandbox actions and zero unverified narration claims; replayable sessions |
| 8 | All new surfaces pass the required UI gates and enter the goldens/strings catalogs |
| 9 | Release-mode CI green with all new gates required; no soft skips; ratchet raised |
| 10 | Dogfood reports closed with zero open defects above P2 |
