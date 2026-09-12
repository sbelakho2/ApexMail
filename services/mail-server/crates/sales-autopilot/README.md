# sales-autopilot

Sales automation — the canonical outbound sales engine: discovery, scoring,
decisioning, durable actions, and outreach delivery.

## Overview

The `sales-autopilot` crate powers ApexMail's sales automation. It scores
accounts and contacts from evidence and signals, decides the next best action
through a single decision gate, queues durable actions, and dispatches sequence
mail into the platform's own delivery pipeline. It integrates with external CRM
systems to keep pipeline data synchronized.

The control plane reads and steers this service through the authenticated
`/control/*` surface; it does not run a second sales loop of its own.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it
as a dependency:

```toml
sales-autopilot = { path = "../sales-autopilot" }
```

## Development

```sh
cargo test -p sales-autopilot
cargo clippy -p sales-autopilot
```

---

# The single send path

## One external effect path

Every external sales message is produced by the durable action worker. The
legacy campaign surface no longer dispatches mail:

- `CampaignManager::start_campaign` (src/campaigns.rs:297) adapts every legacy
  campaign recipient into canonical contacts/contact points and enrolls them
  through `enrollments::start_outreach`. `sales_campaigns` /
  `sales_campaign_recipients` are a read-compatibility ledger for the control
  plane, not a send engine.
- Enrollments enqueue `send_step` rows in the durable `sales_actions` queue.
- `sales_autopilot::actions::run`, spawned in `src/bin/server.rs:251`, claims
  those actions and runs `sequence_worker::SequenceStepHandler`, which passes
  the Decision Packet, legal gate, sender-health gate and action fence.
- `src/scheduler.rs` is a documentation stub. The old campaign dispatch loop
  (`tick`/`run` calling `ProductionCampaignDispatcher::dispatch_batch`) was
  deleted because it bypassed those gates (src/scheduler.rs:1-25;
  src/bin/server.rs:179-183).
- The single-touch `enqueue_recipient` / `dispatch_batch` methods still exist in
  `dispatcher.rs` and are exercised by tests, but no production path calls
  them; the live paths derive keys through
  `send_idempotency_key` (src/dispatcher.rs:870).

A `POST /inbox/:id/reply` manual reply is a separate, non-bulk path (see below);
it does not go through the action queue.

## Enqueue into `email_queue` exactly like the REST send path

`ProductionCampaignDispatcher::enqueue_sequenced` (src/dispatcher.rs:1401) is
the canonical sequence enqueue. It mirrors
`crates/api-server/src/routes/messages.rs` — the REST enqueue path — for every
platform guarantee:

| REST send (`messages.rs`) | Sequenced dispatch (`dispatcher.rs`) |
|---|---|
| `resolve_sender_domain_id` — verified + DKIM-ready domain row lock (`FOR SHARE`), SES/SMTP transport gate | same SQL, same predicate |
| platform `suppressions` check | the SAME canonical admission check **plus** crate-local `sales_unsubscribes`, re-checked inside the enqueue transaction |
| `reserve_email_quota` / `rollback_email_quota` via the shared `SendAdmissionService` | the SAME service, same `EmailsSent` counter, same validated category (see the admission note below) |
| `insert_message_and_queue` — one `messages` row + one `email_queue` row per recipient, `ON CONFLICT (tenant_id, idempotency_key) DO NOTHING` | the same two inserts; the canonical sequence path uses the logical step-execution identity (see below) |
| `Idempotency-Key` request header (per API call) | deterministic per logical send identity — a crash/restart can never double-send |

### Envelope sender is the resolved sales identity

`enqueue_sequenced` takes an explicit `&SenderIdentity` and uses
`sender.from_email` as the envelope sender (src/dispatcher.rs:1374-1414).
`SALES_CAMPAIGN_FROM_EMAIL` is only the legacy/manual-reply default and the
display-name fallback; the sender is resolved by
`sender_pool::resolve_sales_sender`, which refuses any non-sales pool
(reputation isolation: sales traffic never selects a transactional pool;
src/sender_pool.rs:139-204).

### Send identity is a logical sequence step execution

The canonical multi-touch send path keys a message on **one step execution of
one enrollment**:

```text
sa:{enrollment_id}:{sequence_version_id}:{step_id}:{attempt_kind}:{variant}
```

Built by [`send_idempotency_key(SendIdentity::StepExecution)`](src/dispatcher.rs)
via [`sales_step_idempotency_key`](src/sequences.rs:341-354). This is what
makes a second, legitimate email to the same person a *different* message
rather than a suppressed duplicate: `(enrollment, version, step, attempt kind,
variant)` is unique per logical send, including follow-ups, meeting invites and
nurture touches of the same sequence.

The legacy single-touch key `sacmp:{campaign_id}:{recipient_email}` remains in
`send_idempotency_key` for the callerless single-touch methods; the production
campaign surface no longer uses it.

### Unified send admission

Every sales send (sequenced, legacy campaign, and manual reply) calls the ONE
shared `billing_service::send_admission::SendAdmissionService` — the same gate
the REST and SMTP submission paths use. `ProductionCampaignDispatcher::new`
takes the shared `SendAdmissionBackend` (production:
`PostgresAdmissionBackend`), so sales cannot drift from the platform on:

* **quota/entitlement** — the same `EmailsSent` plan counter through
  `record_with_quota_check`, reserved under the send's deterministic logical
  identity (`sa-send:{step_execution_id}` for sequence mail,
  `sacmp:{campaign}:{recipient}` for campaign mail,
  `sareply:{inbox_message_id}` for replies), so a retry cannot double-reserve;
* **suppression** — the canonical tenant suppression lookup, applied before
  the enqueue transaction;
* **category** — validated by the shared helper and written EXPLICITLY into
  `messages.message_category` / `email_queue.message_category`: sequence and
  campaign mail are `marketing` (non-exempt), a 1:1 reply is `transactional`;
* **settlement** — committed only after the enqueue transaction commits,
  rolled back on every refusal/error.

A quota refusal is a retryable deferral (`SalesError::QuotaExhausted`); a
suppression refusal is a non-retryable skip (`EnqueueOutcome::Suppressed`,
mapped to the terminal `cancelled` step state) — retrying a suppression is the
loop the release gates forbid.

Once the rows are in `email_queue`, the platform worker delivers them with ALL
platform guarantees: DKIM signing (SMTP) or SES BYODKIM, retries with
backoff, bounce/complaint processing (hard bounces and opt-out replies are
written to `suppressions` by the worker), tracking-pixel injection and link
rewriting (`worker-processors/src/email/tracking.rs`), spam filtering on
inbound replies. Sequence mail is therefore indistinguishable from — and
governed identically to — ordinary platform mail.

The queue rows carry typed provenance — `sales_decision_id`,
`sales_sender_identity_id`, `sales_step_execution_id`, `sales_enrollment_id` —
on both `messages` and `email_queue` (migration 202; inserts at
src/dispatcher.rs:962-992), and `email_queue.campaign_id` is NULL for sequence
mail.

## Dispatch pipeline — canonical sequence path

For each claimed `send_step` action, `SequenceStepHandler` runs
(src/sequence_worker.rs:1814):

1. **Gates before planning** — kill switch / autonomy `permits_execution`, the
   enrollment human-reply lock, and the enrollment state
   (src/sequence_worker.rs:1854-1899).
2. **Planning** — load account/contact facts, refresh evidence when the
   next-best-action asks for information, recompute and persist the score
   (`scoring::score`), choose the NBA, compose and validate the copy, select the
   experiment arm (src/sequence_worker.rs:1901-2022).
3. **Actual sender resolution** — `sender_pool::resolve_sales_sender` resolves
   the identity from the step's declared sales pool; its id is recorded on the
   step execution and the decision (src/sequence_worker.rs:2046-2093).
4. **Decision Packet** — `decision_engine::decide` evaluates the kill switch,
   autonomy, suppression, address verification, legal policy, human reply,
   sender health and frequency budget, and persists one `sales_decisions` row
   (src/sequence_worker.rs:2120-2252). `Enforcement::Denied` and `Shadowed`
   skip without retrying; `AwaitApproval` parks the action.
5. **Fenced enqueue** — `enqueue_sequenced` verifies the action lease fence
   inside the transaction before any insert, re-checks suppression, resolves
   the sender domain under `FOR SHARE`, and inserts `messages` + `email_queue`
   with the step-execution idempotency key (src/dispatcher.rs:1462-1634). A
   stale lease returns `LeaseLost` and enqueues nothing.
6. **Advance** — the step execution is marked `sent`, the enrollment advances
   and the next step's action is enqueued with its own key
   (src/sequence_worker.rs:2410-2432).

Any failure rolls the transaction back and releases the quota reservation; a
duplicate key means "this logical step was already enqueued" — a replay is a
no-op.

## Unsubscribe (CAN-SPAM / RFC 8058)

Every rendered message gets an HTML + text footer with a one-click link.

- New sends use **opaque v2 tokens** (32 random bytes, URL-safe base64). Only
  the SHA-256 hash is stored, in `sales_unsubscribe_tokens`; the URL carries no
  recipient or tenant data (src/dispatcher.rs:202-246, `create_unsubscribe_token`).
  `resolve_unsubscribe_token` decodes → SHA-256 → looks up the hash with
  `expires_at > now()` (src/dispatcher.rs:280-308).
- **v1 legacy tokens** (`v1.{tenant_hex}.{email_hex}.{expiry}.{sig}`) are
  verified **read-only** for one expiry cycle (365 days) so links in
  already-delivered mail keep working; no new v1 token may be minted
  (src/dispatcher.rs:178-189; fallback in src/routes.rs:1335-1383).
- `GET /u/:token` — validates, marks the recipient suppressed in
  `sales_unsubscribes` AND the platform `suppressions` table (so the REST send
  path excludes them too), then redirects to a branded page.
- `POST /u/:token` with body `List-Unsubscribe=One-Click` — same suppression,
  `200 {"success":true}` for mail-client auto-unsubscribers.
- Invalid signature / expired token ⇒ `400`. Double-unsubscribe is idempotent
  (`ON CONFLICT DO NOTHING` in both tables).
- These two routes are public (like `/health`); authenticity comes from the
  token, not from the shared service token.

## Inbox replies (`POST /inbox/:id/reply`)

The sender identity IS resolvable whenever the production dispatcher is
configured, so the endpoint composes and delivers:

- **Configured** (`SALES_CAMPAIGN_FROM_EMAIL` + `SALES_UNSUBSCRIBE_SECRET`,
  sender domain verified/DKIM-ready for the tenant): composes
  `Re: {original subject}` (no double-prefix, 255-char cap) and an
  HTML-escaped body (`compose_reply_subject` / `compose_reply_html` in
  src/dispatcher.rs), then enqueues `messages` + `email_queue` with quota
  reservation and the same sender-domain `FOR SHARE` gate as the REST send
  path. Idempotency key `sareply:{inbox_message_id}` — one enqueued reply
  per message; a double-click returns `202 {duplicate:true}` and never
  double-sends. The `replied` flag on `sales_inbox_messages` commits
  ATOMICALLY with the enqueue (a failed reply leaves the message visibly
  unanswered for retry).
- **Unconfigured**: honest `501` BEFORE mutating anything ("no sender
  identity is configured …").

Suppression decision (documented in `enqueue_reply`): a reply is 1:1
transactional correspondence, not bulk mail. Exactly like api-server's REST
send path, only the **platform `suppressions` table** (hard bounces,
complaints, platform-level unsubscribes) blocks it. A campaign opt-out in
`sales_unsubscribes` deliberately does NOT block a personal reply — a lead
who opted out of marketing may still receive a direct answer to their own
inbound question. Replies carry no `List-Unsubscribe` headers (those are for
bulk mail, RFC 8058).

## Bounce & complaint handling

The worker writes hard bounces and unsubscribe-reply classifications into the
platform `suppressions` table (`worker-processors/src/email/processor.rs`,
`reply_handler/processor.rs`). The dispatcher **polls**: suppression is
re-checked inside the enqueue transaction (and the due-recipient queries
re-check it per batch on the legacy surface), so a bounce that lands between
ticks is honoured before the next send. That is the documented minimal-viable
mechanism; a push subscription (LISTEN/NOTIFY on `suppressions`) is a future
enhancement, noted in the code.

## Scheduling

`bin/server.rs` runs two background jobs (both with graceful shutdown):

- **Durable action worker** (`actions::run`, src/bin/server.rs:251) — claims
  `sales_actions` rows with `FOR UPDATE SKIP LOCKED` and executes them through
  the sequence step handler. Bounded concurrency (8 actions per process),
  intervals paced by `SALES_DISPATCH_INTERVAL_SECS` (default 30). Without a
  configured production dispatcher the worker is not started at all, so queued
  actions are left untouched rather than claimed and dead-lettered.
- **Outcome projector** (`outcome_projector::run`, src/bin/server.rs:275) —
  folds `sales_sender_events` into `sales_sender_health` and
  `sales_outcomes` into experiment posteriors. Runs unconditionally.

There is no campaign dispatch loop and no synchronous first batch on
`start_campaign`; starting a campaign materializes enrollments, and the action
worker does the sending.

## Start flow & dry-run

- Starting a campaign no longer requires a dispatcher: it materializes
  canonical enrollments and returns the per-recipient enrollment outcome
  (`already_enrolled` / rejected reasons) alongside the campaign
  (src/routes.rs:1239-1276). Delivery then waits on the durable action worker;
  if no dispatcher is configured the worker is not started and that is stated
  loudly at startup and on the readiness surface (src/bin/server.rs:265-272).
- `POST /campaigns/:id/dry-run` renders templates, resolves the sender
  domain, and evaluates suppression/frequency-cap filters WITHOUT enqueueing
  or stamping a ledger — an operator safety net and the test seam.

## Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `SALES_CAMPAIGN_FROM_EMAIL` | — (unset or unverifiable ⇒ no dispatcher) | legacy/manual-reply envelope From and display-name fallback; domain must be verified + DKIM-ready for the tenant |
| `SALES_CAMPAIGN_FROM_NAME` | `ApexMail` | display-name fallback recorded in message metadata |
| `SALES_UNSUBSCRIBE_SECRET` | — (unset ⇒ no dispatcher) | HMAC key for v1 unsubscribe tokens (≥ 32 chars); v2 tokens are secret-independent |
| `SALES_PUBLIC_BASE_URL` | `http://localhost:3010` | base URL used to build unsubscribe links |
| `SALES_UNSUBSCRIBE_REDIRECT_URL` | built-in branded page | redirect target after GET unsubscribe |
| `SALES_DISPATCH_INTERVAL_SECS` | 30 | action-worker / projector tick cadence |
| `SALES_DISPATCH_BATCH_SIZE` | 100 | legacy single-touch batch size (no production caller) |
| `SALES_DISPATCH_CONCURRENCY` | 4 | legacy single-touch concurrency (no production caller) |

## Operator integration (control plane)

The ApexMail control plane owns **no** sales brain: every read is a view over
the canonical tables and every write is an operator intent. It reaches this
service at **`SALES_AUTOPILOT_BASE_URL`** — the compose stacks set
`http://sales-autopilot:3010` (service-name host; a bind address such as
`0.0.0.0` is not routable from inside the api-server container). The
api-server default is a loopback address for local runs.

CP requests forward the internal service token (`x-api-key`) plus
`x-tenant-id`. The `/control/*` surface (authenticated) is:

| Route | Purpose |
|---|---|
| `GET /control/overview` | autonomy state, pipeline and exceptions |
| `GET /control/decisions` | what was decided and why |
| `GET /control/exceptions` | work that needs a human |
| `GET /control/actions` | action queue state |
| `POST /control/mode` | set the autonomy mode |
| `POST /control/pause` / `POST /control/resume` | pause (→ Shadow) / resume (→ ApprovalRequired) |
| `POST /control/kill-switch` | stop new outbound work immediately |
| `POST /control/decisions/:id/review` | approve/reject a decision |
| `POST /control/actions/:id/replay` | replay an action (idempotent; refused for `awaiting_approval`) |

### Autonomy modes

The mode lives in `sales_autonomy_state.mode`; a tenant with no row fails
closed to `disabled`. The mode is read on every decision (never cached), so a
mode change or the kill switch stops new outbound work immediately. Inbound
reply processing is deliberately unaffected — the data needed to recover must
keep flowing.

| Mode | Think | Generate copy | Execute |
|---|---|---|---|
| `disabled` | no | no | no |
| `shadow` | yes | yes | no — records what it *would* have done |
| `assisted` | yes | yes | only what an operator approves |
| `approval_required` | yes | yes | approved decisions only |
| `autonomous_guarded` | yes | yes | automatically when every policy/confidence gate passes |

There is intentionally no unrestricted fully-autonomous mode. Unknown
persisted mode values fail closed to `disabled`.

### Approval does not bypass the hard gates

An approval-gated decision parks its action in the `awaiting_approval` queue
state (`ActionOutcome::AwaitApproval`, src/actions.rs:194-212); nothing is
complete and nothing is claimable until an operator review releases it.
`sales_decisions.review_status` is the authoritative approval signal, and
`decision_engine::revalidate_execution` (src/decision_engine.rs:737) re-runs
every hard gate immediately before the external effect — at approval time in
`control::apply_review` and again in the worker before the enqueue. An
approval recorded minutes ago does not defeat an unsubscribe, a human reply, a
legal-policy change or a newly quarantined sender.

### Truthful footer

Every rendered outreach message gets a policy-resolved footer
(`render_for_recipient_with_footer`, src/dispatcher.rs:647; the worker passes
`FooterReason::BusinessContact`, src/sequence_worker.rs:2083-2093). The
default footer (src/dispatcher.rs:613-630) describes a business contact
identified by research; it never claims a signup that did not happen.
Manufacturing consent in a footer is both untrue and illegal.

## Schema (owned by the canonical migration chain)

Schema ownership is deterministic: **every** sales table is created by the
canonical migration chain (`services/mail-server/migrations`, applied by the
deploy-gate `migrator` binary). `routes::initialize_schema` is a
**verification**, not a bootstrap: it checks the required tables/columns and
refuses to start (`SalesError::SchemaIncompatible`) when anything is missing
or stale (including retired tables from the old control-plane sales system
still being present). There is no `CREATE TABLE IF NOT EXISTS` and no
`ALTER TABLE` at runtime — the effective schema can never depend on service
start order (routes.rs:123-125; schema::REQUIRED_TABLES in src/schema.rs).

The old runtime-managed columns now live in migration 200
(`sales_campaign_recipients.message_id`, `sales_campaigns.last_error`, the
`sales_campaign_recipients` send ledger and the canonical
sequence/enrollment/step-execution tables). Platform tables (`messages`,
`email_queue`, `suppressions`, `templates`, `domains`) are used as-is.

Operators: run the migrator before starting this service; a drift error at
startup means the database is not the schema this build expects, not a bug in
the service.

## Test strategy

- Unit tests (no DB): token signing/verification/tamper/expiry, HTML escaping
  of personalization values (`<script>` lead names), footer/header rendering,
  idempotency key derivation (step-execution identity), config validation,
  action-state transitions (`awaiting_approval` is never replayable).
- Integration tests (real Postgres via `SALES_TEST_DATABASE_URL`, soft-skip
  only when the variable is unset): the platform schema is applied through the
  REAL production migrator (`migrator::test_support::shared_canonical_db`,
  audit F01) — the same canonical chain a deploy installs, not a hand-written
  or archived schema. `routes::initialize_schema` then verifies the chain
  produced the sales schema. Covers: suppression exclusion (platform + local),
  frequency cap, crash-restart idempotency (no double-send), quota-exhausted
  handling, batch-failure retry semantics, unsubscribe happy/invalid/double
  paths, List-Unsubscribe header presence, inbox-reply path
  (compose+escape+enqueue, double-reply idempotency, suppressed correspondent,
  campaign-optout-does-not-block-reply, cross-tenant 404, sender-domain gate,
  501 when unconfigured), and the release gates (Decision Packet coverage,
  approval revalidation, action fence).
