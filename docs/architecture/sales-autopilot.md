# Sales Autopilot

> **Implementation Note (2026-09):** `sales-autopilot` runs as a separate Axum service for ApexMail's internal sales workflow. It is not part of the customer-facing `/v1` API surface. This document describes the architecture AFTER the sales-autopilot audits; where an older revision of this file described in-memory stores and boot-time DDL, those descriptions are superseded below.

## Overview

The `sales-autopilot` crate is the outreach engine behind ApexMail's own sales: account/contact intake, evidence-grounded enrichment and discovery, sequence orchestration, the central decision engine, durable action execution, reply intelligence, experiments, sender health, and the automations executor.

The server binary lives at `services/mail-server/crates/sales-autopilot/src/bin/server.rs` and listens on port `3010` by default (`SALES_PORT` / `SALES_AUTOPILOT_PORT`).

## Runtime Model

- Separate process from the main API server; internal-only, protected by `INTERNAL_SERVICE_TOKEN` (`x-api-key` or `Authorization: Bearer …`) on every route except `/health` and the public unsubscribe path `/u/:token`.
- Requires `DATABASE_URL` at startup. Schema is **migration-owned**: the canonical chain in `services/mail-server/migrations/` (embedded at compile time by the `migrator` crate) is the only writer of schema. There is no runtime DDL in this crate.
- Startup VERIFIES the schema instead of creating it: `schema.rs` holds a required-table list and a required-view list, and a missing or wrong-shaped object refuses startup naming the object. The schema contract is also asserted by `crates/functional-tests/tests/schema_contract_tests.rs`.
- A `256 KB` body limit and a `30-second` request timeout apply; `/health` reports degraded/503 when PostgreSQL is unreachable.

## The canonical model: accounts and contacts, not leads

The core objects are `sales_accounts` (one company) and `sales_contacts` (one human), with `sales_contact_points` for each channel address (email/phone/social), carrying verification provenance and suppression. Evidence, enrichment facts, provider stats, signals, scores, sequences, enrollments, step executions, decisions, actions, sender identities/health, reply classifications, meetings, opportunities, outcomes, experiments and discovery jobs hang off that model.

`sales_leads` is **a derived, read-only VIEW** over `sales_contacts` + `sales_accounts` (migration 223). It exists so the control-plane lead UI and the lead-oriented API keep their shape — it is not a store. It exposes `id` (the contact's stable `legacy_lead_id` mapping), company/contact display fields, a derived `status`, and the lead-only projection columns (`score`, `source`, `notes`, `tags`, `deal_value`, `snoozed_until`, `last_reply_at`, `priority`). Writes target the canonical tables; a regression test in this crate scans the production source and fails if a write against the view is reintroduced.

Identity is deliberately not an email address: an address is a verified contact point, so a person can change address without becoming a new person, and suppression attaches to the address rather than to the human.

## Core Components

### Decision engine

`decision_engine::decide` is the mandatory gateway for every external sales action. It evaluates the legal policy, the sender pool and sender health, the kill switch, the frequency budget, the economic gate and the account-level coordination budget, then persists a `sales_decisions` row carrying an enforcement verdict (`execute` / `denied` / `shadowed` / `await_approval`), the selected sender identity and a review status. An approved decision is consumed later only through `revalidate_execution`, so a stale approval cannot outlive a policy or sender-health change. Refusals are recorded decisions, not silent skips.

### Sequence execution

A sequence version's steps execute as `sales_step_executions`. The idempotency identity is a logical step execution — `sa:{enrollment}:{version}:{step}:{attempt_kind}:{variant}` — with `sa-send:{step_execution_id}` as the logical send unit, so retrying a step cannot produce a second message.

`actions.rs` is a durable leased queue: claims use `FOR UPDATE SKIP LOCKED` with a per-claim `lease_token`, every write is fenced by that token (`verify_fence_in_tx`), expired leases are requeued, and the worker heartbeat makes a crashed process's work recoverable. The worker runs under a bounded semaphore, so a burst cannot open unbounded concurrent sends.

### Delivery path

Outbound sales mail goes through the shared `SendAdmissionService` (in `billing-service`) before the message insert, with an explicit server-owned `message_category`: `marketing` for outreach (commercial mail gets no opt-out exemption), `transactional` only for a 1:1 reply answering a message the recipient sent us. The message and `email_queue` rows carry typed sales provenance (`sales_decision_id`, `sales_sender_identity_id`, `sales_step_execution_id`, `sales_enrollment_id`), and the footer is generated truthfully — it never claims a subscription the recipient never made.

Dedicated-IP routes are handled by the route-aware transport in `worker-processors`: a route that cannot report the actual source IP is refused BEFORE `DATA`, and warmup capacity is consumed only when the acceptance reports the requested IP.

### Reply intelligence

Inbound replies are classified into a canonical taxonomy and mapped to sequence consequences (pause, stop, meeting intent, negative, out-of-office). The reply handler writes canonical state only; it no longer maintains legacy lead columns.

### Experiments

Thompson sampling over `sales_experiments` / `sales_experiment_arms` selects variants for real sends; outcomes are recorded through an idempotent outcome ledger and rewards are projected back onto the arms by the outcome projector loop.

### Automations executor

`automations.rs` executes the automation rules stored by the customer-facing API. Trigger events are produced canonically (migration 224's triggers on `contacts` and `inbound_messages`), claimed with leases, and evaluated against the stored `trigger_config` / `conditions`; supported actions are `send_email` (through `SendAdmissionService`, category `marketing`), `add_tag` / `remove_tag`, list add/remove, and `webhook` (enqueued for the existing webhook worker — no in-process HTTP, no SSRF surface). Runs and per-action outcomes are persisted (`automation_runs`, `automation_run_actions`), so "why did nothing happen?" is answerable from the database. Unsupported trigger/action kinds are recorded as unsupported rather than silently ignored: `delay` has no durable per-action timer, and schedule/webhook triggers have no stored contract or inbound producer.

### CRM, enrichment, discovery, calendar, inbox

- `crm.rs` is the in-memory store for tests and self-contained local flows; `crm_pg.rs` is the PostgreSQL implementation over the canonical tables.
- Enrichment is an evidence waterfall: providers are tried in cost order, every fact carries its provenance, and `sales_provider_stats` accumulates per-provider yield and cost. Results land as `sales_enrichment_facts` / `sales_evidence`, never as unsourced account fields.
- Discovery runs as leased, fenced jobs (`sales_discovery_jobs`): a crashed run is reclaimed and a duplicate run cannot double-write candidates.
- The calendar models working hours in the entity's time zone with UTC storage (`sales_calendar_events`), 30-minute slots, and overlap rejection.
- Inbox triage persists to `sales_inbox_messages`.

### Scraper utilities

`WebScraper` provides deterministic prospecting helpers (email extraction, company-info derivation, URL validation, conservative `robots.txt` evaluation). These are text-processing helpers; the crate embeds no browser and no autonomous crawler.

## HTTP Surface

| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | `GET` | Liveness/readiness |
| `/leads`, `/leads/{id}` | `GET`, `POST` | Lead-shaped read/create over the canonical model |
| `/companies`, `/enrich` | `GET`, `POST` | Enriched companies and the enrichment waterfall |
| `/campaigns`, `/campaigns/:id/{recipients,start,pause,dry-run}` | `GET`, `POST` | Campaign orchestration and dry-run profiling |
| `/calendar` | `GET` | List events / availability |
| `/calendar/events`, `/calendar/events/:id` | `POST`, `DELETE` | Create / cancel an event |
| `/calendar/slots` | `GET` | Available slots |
| `/inbox`, `/inbox/:id/reply` | `GET`, `POST` | Reply triage and handling |
| `/discovery/jobs`, `/discovery/jobs/:id`, `/discovery/jobs/:id/run` | `GET`, `POST` | Leased discovery jobs |
| `/control/{overview,decisions,actions,actions/:id/replay,exceptions,mode,pause,resume,kill-switch}` | `GET`, `POST` | The autonomous control surface: mode, kill switch, decision/action inspection, exception queue, replay |
| `/u/:token` | `GET`, `POST` | Public unsubscribe (token-scoped; no PII in the token) |

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `SALES_PORT` / `SALES_AUTOPILOT_PORT` | `3010` | HTTP listen port |
| `DATABASE_URL` | none (required) | Postgres connection string |
| `REDIS_URL` | none | Rate limiting / caches |
| `INTERNAL_SERVICE_TOKEN` | empty | Internal route authentication |
| `ENRICHMENT_API_URL`, `ENRICHMENT_API_KEY` (or the `SALES_ENRICHMENT_*` template names) | — | Enrichment provider |
| `CALENDAR_SYNC_INTERVAL` | `300` | Calendar sync interval (seconds) |
| `MAX_CAMPAIGNS` | `50` | Maximum active campaigns |
| `SALES_DISPATCH_BATCH_SIZE`, `SALES_DISPATCH_CONCURRENCY`, `SALES_DISPATCH_INTERVAL_SECS` | — | Sequence dispatcher pacing |
| `SALES_CAMPAIGN_FROM_EMAIL`, `SALES_CAMPAIGN_FROM_NAME` | — | Campaign sender identity defaults |
| `SALES_PUBLIC_BASE_URL`, `SALES_UNSUBSCRIBE_REDIRECT_URL` | — | Public URLs used in footers and unsubscribe links |
| `SALES_ALLOWED_TENANTS` | — | Tenant allowlist (unset = all) |
| `AUTOMATION_TICK_SECS` | `30` | Automation executor tick period |
| `LEAD_SCORE_{ENGAGEMENT,COMPANY_SIZE,RECENCY}_WEIGHT` | compile-time defaults | Legacy lead-score weights (canonical scoring is the explainable `OpportunityScore`) |
| `EMAIL_TRANSPORT_TYPE` | — | Transport selection for local runs |

An unparseable configured value is an error (`SalesConfig::from_env`); the service does not silently fall back to a default for a value an operator set.

## Persistence Boundaries

Every sales object is persisted in PostgreSQL through the canonical chain. There is no in-memory-only state in the shipped binary and no runtime DDL anywhere: `enriched_companies`, `sales_calendar_events`, `sales_inbox_messages`, `sales_conversions` and `sales_campaign_recipients` — which older revisions of this document listed as boot-time creations — are canonical tables (migration 200).

In-memory state exists only in tests and in `crm.rs` for self-contained local flows.

## Honest limitations

- Dedicated-IP *provisioning* (ordering, PTR, reputation ramp) is a control-plane/compliance concern; this service selects and reports, it does not provision.
- Schedule- and webhook-triggered automations, and the `delay` action, are reported as unsupported rather than half-implemented (see above).
- The automations executor and the action worker run inside this service's process, so automation and sequence execution require `sales-autopilot` to be running.

## Relevant Source Files

- `src/bin/server.rs` — the service and its loops (action worker, outcome projector, automation executor)
- `src/decision_engine.rs`, `src/legal_policy.rs` — the decision gateway and jurisdiction policy
- `src/actions.rs`, `src/sequence_worker.rs`, `src/dispatcher.rs` — durable execution and the delivery path
- `src/crm_pg.rs`, `src/schema.rs` — canonical persistence and the startup schema contract
- `src/automations.rs` — the automations executor
- `src/control.rs`, `src/control_read.rs`, `src/routes.rs` — the control surface and HTTP routing
- `src/experiments.rs`, `src/outcome_projector.rs` — experiment arms and reward projection
- `src/enrichment.rs`, `src/discovery.rs`, `src/calendar.rs`, `src/inbox.rs` — the supporting workflows
