# Dogfood LIVE — the AI chatbot (multi-user, concurrent, RBAC-gated, tenant-isolated)

Brief: `docs/audit/dogfood-2026-10-06/brief-live-chatbot.md` (including both
appendices). Owner paths touched: `crates/api-server/src/routes/ai_chat.rs`,
`crates/ui-foundation/src/{view_data,leptos_views,fixture_states}.rs`, the
assistant handlers in `crates/api-server/src/routes/web.rs`
(`form_assistant_message`) and `web/data.rs` (`load_assistant`) — the last two
under the coordinator's explicit scoped grant; the drafts handlers were not
touched. Test tooling added: `tools/dogfood-chatbot-live.py`,
`tools/mock-llm/mock_llm.py`.

Environment: compose stack at `127.0.0.1:8080` (app host
`app.apexmail.ee`), Postgres `127.0.0.1:5432/apexmail`, Redis
`127.0.0.1:16379`, Mailpit `127.0.0.1:8025`. The api-server image was rebuilt
from this tree by the coordinator; the ai-service model runtime is the
`mock-llm` OpenAI-compatible mock (its chat behaviour is verified by
`probe_model` before every content stage — a mock that cannot answer
canonical facts makes content probes meaningless).

Status legend: PASS / FAIL / NOT-VERIFIED (could not prove).

## 1. Enumeration — the assistant's answerable space

Sources read: `crates/ai-service/src/knowledge.rs` +
`crates/platform-catalog/src/lib.rs` (the canonical facts the prompt carries),
`docs/pricing.md` (the published pricing surface the gate treats as
canonical), `crates/ai-service/src/chat.rs` (grounding, escalation ladder,
history sanitization, refusal classes), `crates/ai-service/src/verifier.rs`
(violation classes), `crates/ai-service/src/assistant.rs` (deterministic
helpers), the ai_chat route table, and the published docs tree
(`docs/api/**`, `docs/sending/**`, `docs/user-guide/**`,
`docs/getting-started/**`, `docs/domains/**`, `docs/sla.md`).

| Surface | Answerable rows |
|---|---|
| Plan catalogue | 7 plans × price / email limit / API limit / team / retention; annual billing; PAYG (usage, no monthly price) |
| Rates | overage per 1,000 per plan; +100% allowance and hard-stop on Free; PAYG email tiers (4); PAYG API (100K free, then €0.10/1K) |
| Compliance | GDPR/EU-EEA + DPA; HIPAA (not offered); SOC 2 (not offered); encryption; data locations/subprocessors |
| Security | TLS/AES-256; hashed keys (keyed HMAC); MFA/TOTP; KiwiCaptcha PoW; per-tenant limits; audit logs; backups; EU hosting |
| Deliverability | domain verification; per-domain DNS records via the workspace / `POST /v1/domains/dns-records`; DKIM/SPF/DMARC; inbound authentication |
| SDK/API | 5 SDK languages; unpublished-to-registries status; REST + SMTP available today |
| Feature gates | REST/SMTP (all), webhooks/templates/advanced analytics/export (Starter+), tracking domain/send-time optimisation (Pro+), A/B testing/audit logs/custom retention (Growth+), SSO/inbound/approval workflow/subaccounts (Business+), white-label/private cloud/BYOIP (Enterprise) |
| Dedicated IPs | add-on prices (€49 first / €69 each additional), plan inclusions |
| Billing lifecycle | Stripe-verified subscription start; overage invoicing; plan-change request path |
| SLA | contract terms only — the verifier forbids inventing uptime percentages |
| Console session surface | `POST /v1/ai/chat`, `GET /v1/ai/chat/history`, `POST|GET /v1/ai/chat/sessions`, `POST|GET /v1/ai/chat/sessions/:id/turns`; scope `ai:read`; per-tenant `ai_chat` flag; per-user 20/min bucket; contact-intent lead capture (the only write) |
| `assistant.rs` | NOT part of the chat's answerable space: it is a deterministic helper library (subject lines/sentiment/summarize) with no route, so it contributes no chat-answerable rows. Its behaviour is covered by its own unit tests. |

## 2. Budgets (B2, numeric, defined before the run)

| Budget | Value | Why |
|---|---|---|
| Chat turns in the mass-concurrency proof | N=16 concurrent (6 per tenant × 3 tenants), sustained ≥60s | brief B2 |
| Server errors | 0 | B2 |
| Cross-tenant contamination | 0 turns whose content/owner is not the caller's | B2 |
| p95 end-to-end turn latency | ≤ 2,000 ms (deterministic mock runtime; a real model would set its own) | B2 "documented performance budget" |
| Worst single turn | ≤ 10,000 ms | B2 hard ceiling |
| Per-tenant rate limiting | tenant A 429s while tenant B keeps 200 | B2 |
| DB truth | 0 rows where a turn's tenant differs from its session's tenant | isolation |
| Console document budget | ≤ 200 kB HTML for the assistant page | sane payload |

## 3. Findings fixed (P1) — with regression tests proven to fail before

### F1 (P1) — the console entry point bypassed every chat gate (flag, rate limit, scope)
`web.rs::form_assistant_message` called `ai_chat::session_turn_inner`
directly. The capability flag and the per-user rate limit lived in
`post_session_turn` (the JSON wrapper), so a workspace with `ai_chat`
disabled could still chat from `/assistant`, the documented per-user throttle
never applied to console messages, and a role without `ai:read` (a member)
was served by the console while the same identity got 403 on
`POST /v1/ai/chat`. `docs/user-guide/assistant.md` promises the opposite
("the page reports that the capability is not enabled"; "Per-user and
per-tenant rate limits apply").

Fix: the flag and the rate limit are enforced INSIDE `session_turn_inner`
(both entry points share it; the JSON route no longer double-counts), the
console handler checks `ai:read` and the flag before creating a session, and
the disabled refusal maps to its NAMED flash instead of "temporarily
unavailable".

Tests (fail before, pass after):
`crates/api-server/src/routes/ai_chat.rs::session_tests::session_turn_inner_refuses_a_disabled_capability_without_writing`,
`session_turn_inner_applies_the_per_user_rate_limit`,
`crates/api-server/src/routes/web.rs::tests::db_backed::assistant_message_refuses_a_disabled_capability`,
`assistant_message_refuses_a_role_without_ai_read`.

Fail-before / pass-after evidence (same four tests, gates reverted, then
restored):

```
# gates removed (pre-fix behaviour):
Summary [1.481s] 4 tests run: 0 passed, 4 failed, 2018 skipped
  FAIL assistant_message_refuses_a_disabled_capability
  FAIL assistant_message_refuses_a_role_without_ai_read
  FAIL session_turn_inner_refuses_a_disabled_capability_without_writing
  FAIL session_turn_inner_applies_the_per_user_rate_limit
      panicked at ai_chat.rs: "the 21st console turn in a minute must be refused"

# gates restored (the fix):
Summary [1.208s] 4 tests run: 4 passed, 2018 skipped
```

The full ai_chat/assistant regression set (16 tests, including the pre-existing
PRG, scope, cap, prune and lead-capture tests) passes with the fix:
`16 tests run: 16 passed`.

### F2 (P1) — the disabled tenant's console page rendered a working-looking form
`load_assistant` never consulted the flag, so a switched-off workspace got a
normal conversation page whose every submission was refused — contradicting
the documented availability contract and the brief's matrix item 6.

Fix: `AssistantPageData.capability_disabled` (ui-foundation) is set from the
flag service in `load_assistant` (a flag-lookup FAILURE is the existing
`unavailable` state, never a silent empty page), and `web_assistant_page`
renders the named refusal with NO message form.

Test: `ui-foundation/src/leptos_views.rs::tests::assistant_disabled_state_names_the_capability_and_hides_the_form`.

### Static notes (not defects)
- `ai_chat_session_turns` has `ON DELETE CASCADE` from sessions, so the
  retention prune removes conversation content as documented.
- `require_scopes` refusal on the JSON routes is `missing required scope:
  ai:read` (machine-readable); the console flash uses human copy instead.

## 4. Live matrix

(filled from the live run; see `tools/dogfood-chatbot-live.py` and the JSON
transcript `/tmp/dogfood-chatbot/transcript.jsonl`)

## 5. Content corpus (owner mandate, appendix)

`docs/eval/**` is owned by the corpus-sweep agent; their corpora are the
machine-checked artifact (147 chat cases + the technical corpus, gate green).
The live replay is `tools/run-eval-live.py --sections chat`; the
category→case table is `python3 tools/check_eval_corpora.py --coverage`.

## 6. Disclosure suite (B3)

(filled from the live run)

## 7. Observations outside the owned paths (named severity + owner)

### O1 (P3) — the CP demo presenter is the third `ask_assistant` call site
`routes/demos/mod.rs::chat_narrate` calls `ai_chat::ask_assistant` directly:
the capability flag, the rate limit and the scope gate do not apply, and the
tenant comes from the demo step's `tenant_id` input (default `system`). It is
an internal presenter surface aimed at platform operators (who can already
read every tenant's facts), so it is not a customer bypass — but it is the one
remaining caller that bypasses the capability flag, and a workspace with
`ai_chat` disabled can still be narrated in a demo. Owner: demos agent.

### O2 (P2, docs honesty) — chat→CRM lead capture is not disclosed
When a message contains a contact-intent phrase and a grounded answer
succeeds, `session_turn_inner` writes the lead (email + the message body) into
the platform CRM (`store_lead_with_kind`, kind `chat_lead`; the existing test
pins `tenant_id = 'system'`). `docs/user-guide/assistant.md` §Privacy says only
that the question/history/account facts go to the model runtime and that "the
assistant cannot change anything in your workspace" — it does not say the
message and address are captured into the sales pipeline. The behaviour itself
is the documented plan §5.4 design; the user guide should disclose it. Owner:
docs/corpus agent.

### O3 (P2, not mine) — `ai_draft_review_queue_approve_and_reject_flow_through_the_page` is red
Full-suite evidence: `cargo nextest run -p api-server` →
`1928 passed, 1 failed`; the failure reproduces in isolation:

```
cargo nextest run -p api-server -E 'test(ai_draft_review_queue_approve_and_reject_flow_through_the_page)'
  panicked at crates/api-server/src/routes/web.rs:10685: approval consumed the draft
```

Cause (verified in code): `admin::ai_drafts::approve_draft_core` gained the
F4 send-admission marketing-consent gate; the test's draft has no consent row,
so the approval is refused BY DESIGN (claim rolled back, draft stays pending)
and the test's assertion predates the gate. Not caused by this brief's
changes (the failing router never mounts any changed function); owner:
mailbot agent (test needs a consent fixture or an assertion on the refusal).
