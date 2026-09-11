# sales-autopilot

Sales automation — lead scoring, outreach campaigns, CRM integration.

## Overview

The `sales-autopilot` crate powers ApexMail's sales automation features. It
scores inbound leads based on engagement signals, orchestrates multi-step
outreach campaigns, and integrates with external CRM systems to keep pipeline
data synchronized and actionable for sales teams.

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

# Campaign dispatch architecture

## Problem

`start_campaign` used to flip a status flag (and, after SA-5, call a
dispatcher that was never wired in production). Operators got
`503 dispatcher not configured` and campaigns never sent anything. This crate
now ships a **real, production dispatcher** that sends through the platform's
OWN delivery pipeline.

## Chosen design: enqueue into `email_queue` exactly like the REST send path

`ProductionCampaignDispatcher` (src/dispatcher.rs) mirrors
`crates/api-server/src/routes/messages.rs` — the canonical enqueue path —
statement for statement:

| REST send (`messages.rs`) | Campaign dispatch (`dispatcher.rs`) |
|---|---|
| `resolve_sender_domain_id` — verified + DKIM-ready domain row lock (`FOR SHARE`), SES/SMTP transport gate | same SQL, same predicate |
| `suppressed_recipients` — platform `suppressions` table | platform `suppressions` **and** crate-local `sales_unsubscribes`, checked per batch before any send |
| `reserve_email_quota` / `rollback_email_quota` via `billing_service::usage::record_with_quota_check` | the same contract, behind the `QuotaGateway` trait (see the billing note below) |
| `insert_message_and_queue` — one `messages` row + one `email_queue` row per recipient, `ON CONFLICT (tenant_id, idempotency_key) DO NOTHING` | the same two inserts; the canonical sequence path uses the logical step-execution identity (see below) |
| `Idempotency-Key` request header (per API call) | deterministic per logged send identity — a crash/restart can never double-send |

### Send identity is a logical sequence step execution

The canonical multi-touch send path (`ProductionCampaignDispatcher::enqueue_sequenced`)
keys a message on **one step execution of one enrollment**:

```text
sa:{enrollment_id}:{sequence_version_id}:{step_index}:{attempt_kind}:{variant}
```

Built by [`send_idempotency_key(SendIdentity::StepExecution)`](src/dispatcher.rs) via
[`sales_step_idempotency_key`](src/sequences.rs). This is what makes a second,
legitimate email to the same person a *different* message rather than a
suppressed duplicate: `(enrollment, version, step, attempt kind, variant)` is
unique per logical send, including follow-ups, meeting invites and nurture
touches of the same sequence.

The legacy single-touch campaign path (`enqueue_recipient`) still keys on
`sacmp:{campaign_id}:{recipient_email}` — correct only for a campaign that
sends exactly one email per recipient. New multi-touch work must use
`SendIdentity::StepExecution`.

### Billing quota integration

`BillingQuotaGateway` (src/dispatcher.rs) calls the platform's real
`billing_service::usage::record_with_quota_check` / `rollback_usage_record`
directly — same Redis counters, dedup keys and `metering_events`
persistence as the REST send path. There is no local quota mirror.

Once the rows are in `email_queue`, the platform worker delivers them with ALL
platform guarantees: DKIM signing (SMTP) or SES BYODKIM, retries with
backoff, bounce/complaint processing (hard bounces and opt-out replies are
written to `suppressions` by the worker), tracking-pixel injection and link
rewriting (`worker-processors/src/email/tracking.rs`), spam filtering on
inbound replies. Campaign mail is therefore indistinguishable from — and
governed identically to — ordinary platform mail.

### Rejected alternative: direct SMTP client to the MTA

Rejected because it duplicates the platform's signing/retry/bounce/tracking
stack inside this crate: a second DKIM implementation to keep in sync, a
private retry queue without the worker's visibility leases, no bounce
suppression feedback, and no billing quota enforcement. It would also bypass
`email_queue`, so ops dashboards would not see campaign volume. The enqueue
design reuses every guarantee for free.

## Dispatch pipeline — single-touch campaign path (per recipient, one DB transaction)

For each due recipient of an active campaign (batch of at most
`SALES_DISPATCH_BATCH_SIZE`, default 100 per tick):

1. **Quota reservation** — `billing_service::usage::record_with_quota_check`
   (Redis check-and-increment + `metering_events` row). Quota exhausted ⇒ the
   campaign is **paused with an error state** (`sales_campaigns.last_error`),
   never partially-silent.
2. **Send-ledger claim** — `UPDATE sales_campaign_recipients SET sent_at =
   NOW(), message_id = $msg WHERE … AND sent_at IS NULL RETURNING email`.
   Zero rows ⇒ a concurrent dispatcher already claimed it ⇒ skip (and release
   the reservation).
3. **`messages` insert** with the campaign idempotency key
   (`sacmp:{campaign}:{email}` on this legacy single-touch path),
   `ON CONFLICT DO NOTHING`. Zero rows ⇒ idempotent duplicate (replay or a
   ledger stamped by an older code path) ⇒ skip the queue insert.

The **canonical sequence path** (`enqueue_sequenced`) differs deliberately: the
caller (the durable action worker) has already claimed the logical
`sales_step_executions` row, which *is* the send ledger; suppression is
re-checked inside the transaction; the message carries the step-execution key
above and `email_queue.campaign_id` is NULL (sequence mail is attributed to a
step execution, not a campaign). A duplicate key means "this logical step was
already enqueued" — a replay is a no-op.
4. **`email_queue` insert** — single-recipient row, `status='pending'`,
   `priority=5`, plus custom headers:
   - `List-Unsubscribe: <https://…/u/{token}>` (angle-bracket form, RFC 2369)
   - `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058)
5. **`sales_campaigns.sent = sent + 1`** — same transaction.
6. Commit. Any failure rolls the transaction back and releases the quota
   reservation; the recipient stays unclaimed and is retried on the next tick.

Steps 2–5 are atomic: a crash at ANY point either leaves the recipient fully
dispatched (ledger + queue row) or not at all. The idempotency key is the
second line of defence for deployments where the ledger was stamped by an
older code path.

## Unsubscribe (CAN-SPAM / RFC 8058)

Every rendered message gets an HTML + text footer with a one-click link.
Tokens are HMAC-SHA256 signed (`SALES_UNSUBSCRIBE_SECRET`, ≥ 32 chars) over
`v1.{tenant_hex}.{email_hex}.{expiry_unix}` and carry no plaintext PII.

- `GET /u/:token` — validates, marks the recipient suppressed in
  `sales_unsubscribes` AND the platform `suppressions` table (so the REST send
  path excludes them too), then redirects to a branded page.
- `POST /u/:token` with body `List-Unsubscribe=One-Click` — same suppression,
  `200 {"success":true}` for mail-client auto-unsubscribers.
- Invalid signature / expired token ⇒ `400`. Double-unsubscribe is idempotent
  (`ON CONFLICT DO NOTHING` in both tables).
- These two routes are public (like `/health`); authenticity comes from the
  HMAC, not from the shared service token.

## Inbox replies (`POST /inbox/:id/reply`)

Previously 501 ("no outbound email path"). Now that the crate owns the
enqueue pipeline, the sender identity IS resolvable whenever the production
dispatcher is configured, so the endpoint composes and delivers:

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
`reply_handler/processor.rs`). The dispatcher **polls**: the due-recipient
query re-checks `suppressions` (and `sales_unsubscribes`) immediately before
every batch, so a bounce that lands between ticks is honoured before the next
send. That is the documented minimal-viable mechanism; a push subscription
(LISTEN/NOTIFY on `suppressions`) is a future enhancement, noted in the code.

## Scheduling

`bin/server.rs` runs a background job (spawned task with graceful shutdown):

- every `SALES_DISPATCH_INTERVAL_SECS` (default 30) ± 20% jitter,
- selects active campaigns,
- dispatches at most `SALES_DISPATCH_BATCH_SIZE` recipients per campaign per
  tick (bounded blast radius),
- concurrency-bounded across campaigns (`SALES_DISPATCH_CONCURRENCY`,
  default 4, semaphore),
- completes a campaign (active → completed) when no due recipients remain,
- reconciles `opened`/`clicked` stats from `messages.open_count/click_count`
  (maintained by the tracking service) for every campaign it touched.

`start_campaign` still performs the FIRST batch synchronously through the
injected dispatcher (trait contract honoured), so a start either visibly
sends or visibly fails; the loop then continues the campaign.

## Start flow & dry-run

- No production dispatcher (missing `SALES_CAMPAIGN_FROM_EMAIL` /
  `SALES_UNSUBSCRIBE_SECRET` or an unverified sender domain) ⇒ `503`, exactly
  as before — "genuinely unconfigured" deployments stay loud.
- `POST /campaigns/:id/dry-run` renders templates, resolves the sender
  domain, and evaluates suppression/frequency-cap filters WITHOUT enqueueing
  or stamping the ledger — an operator safety net and the test seam.

## Configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `SALES_CAMPAIGN_FROM_EMAIL` | — (unset ⇒ 503) | envelope From for campaign mail; domain must be verified + DKIM-ready for the tenant |
| `SALES_CAMPAIGN_FROM_NAME` | `ApexMail` | display name recorded in message metadata |
| `SALES_UNSUBSCRIBE_SECRET` | — (unset ⇒ 503) | HMAC key for unsubscribe tokens (≥ 32 chars) |
| `SALES_PUBLIC_BASE_URL` | `http://localhost:3010` | base URL used to build unsubscribe links |
| `SALES_UNSUBSCRIBE_REDIRECT_URL` | built-in branded page | redirect target after GET unsubscribe |
| `SALES_DISPATCH_INTERVAL_SECS` | 30 | tick cadence (jittered ±20%) |
| `SALES_DISPATCH_BATCH_SIZE` | 100 | max recipients per campaign per tick |
| `SALES_DISPATCH_CONCURRENCY` | 4 | concurrent campaigns per tick |

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
| `POST /control/actions/:id/replay` | replay an action (idempotent) |

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

### Truthful footer

Every rendered outreach message gets the policy-resolved footer
(`render_for_recipient_with_footer`, src/dispatcher.rs). The footer's reason
line must never claim a signup that did not happen: cold/prospected contacts
are described as business contacts identified by research, not as
subscribers. Manufacturing consent in a footer is both untrue and illegal.

## Schema (owned by the canonical migration chain)

Schema ownership is deterministic: **every** sales table is created by the
canonical migration chain (`services/mail-server/migrations`, applied by the
deploy-gate `migrator` binary). `routes::initialize_schema` is now a
**verification**, not a bootstrap: it checks the required tables/columns and
refuses to start (`SalesError::SchemaIncompatible`) when anything is missing
or stale (including retired tables from the old control-plane sales system
still being present). There is no `CREATE TABLE IF NOT EXISTS` and no
`ALTER TABLE` at runtime — the effective schema can never depend on service
start order.

The required/retired manifest is
[`schema::REQUIRED_TABLES`](src/schema.rs); the old runtime-managed columns
now live in migration 200 (`sales_campaign_recipients.message_id`,
`sales_campaigns.last_error`, the `sales_campaign_recipients` send ledger and
the canonical sequence/enrollment/step-execution tables). Platform tables
(`messages`, `email_queue`, `suppressions`, `templates`, `domains`) are used
as-is.

Operators: run the migrator before starting this service; a drift error at
startup means the database is not the schema this build expects, not a bug in
the service.

## Test strategy

- Unit tests (no DB): token signing/verification/tamper/expiry, HTML escaping
  of personalization values (`<script>` lead names), footer/header rendering,
  idempotency key derivation (step-execution identity), config validation.
- Integration tests (real Postgres via `SALES_TEST_DATABASE_URL`, soft-skip
  only when the variable is unset): the platform schema is applied through the
  REAL production migrator (`migrator::test_support::shared_canonical_db`,
  audit F01) — the same canonical chain a deploy installs, not a hand-written
  or archived schema. `routes::initialize_schema` then verifies the chain
  produced the sales schema. Covers: suppression exclusion (platform + local),
  frequency cap, crash-restart idempotency (no double-send), quota-exhausted
  pause with error state, batch-failure retry semantics, unsubscribe
  happy/invalid/double paths, List-Unsubscribe header presence, stats
  increment, and the inbox-reply path (compose+escape+enqueue, double-reply
  idempotency, suppressed correspondent,
  campaign-optout-does-not-block-reply, cross-tenant 404, sender-domain gate,
  501 when unconfigured).
