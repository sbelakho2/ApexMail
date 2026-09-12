# Outbound Delivery Transport

> Last updated: 2026-09-11

This document describes the **live** outbound delivery path: who decides the
route, where the warmup cap is enforced, what the transport contract actually
guarantees, and which link in the chain is still unimplemented. Every claim
below is taken from the current source; gaps are stated as gaps.

**Scope:** outbound only. The inbound, submission and bounce MTA servers are
covered by [MTA Configuration](mta-configuration.md) and
[Hybrid Email Infrastructure](hybrid-email-infrastructure.md).

## End-to-end sequence

```text
canonical account/contact
  → score / evidence / next-best-action   sequence_worker::load_planner_facts + scoring::score
  → actual sales SenderIdentity           sender_pool::resolve_sales_sender
  → legal + autonomy + sender-health      decision_engine::decide → sales_decisions
  → durable fenced sales_action           sales_actions + lease_token + ActionFence
  → dispatcher with explicit sender       ProductionCampaignDispatcher::enqueue_sequenced
  → email_queue with typed provenance     sales_decision_id / sales_sender_identity_id /
                                          sales_step_execution_id / sales_enrollment_id
  → worker resolves the delivery route    DeliveryRoute (worker-processors)
  → per-source-IP warmup admission        check_warmup_limit (Redis, canonical schedule)
  → transport                             EmailTransport::send(email, route) → DeliveryReceipt
  → route verification                    verify_delivery_route / settle_delivery_route
  → events / sales_outcomes / sales_sender_events
  → experiment + sender-health projectors outcome_projector
```

## 1. One sales send path

There is exactly **one** path that produces an external sales effect: the
durable action worker.

- `CampaignManager::start_campaign` no longer dispatches mail itself. It
  materializes recipients into canonical contacts/contact points and a
  compatibility sequence (keyed by `sales_sequences.legacy_campaign_id`), then
  enrolls them through `enrollments::start_outreach`
  (`services/mail-server/crates/sales-autopilot/src/campaigns.rs:297`).
- Enrollments enqueue `send_step` rows into the durable `sales_actions` queue;
  the action worker (`sales_autopilot::actions::run`, spawned in
  `src/bin/server.rs:251`) claims them with `FOR UPDATE SKIP LOCKED` and runs
  `sequence_worker::SequenceStepHandler`.
- `src/scheduler.rs` is now a documentation stub: the old campaign dispatch
  loop was deleted because it bypassed the Decision Packet, legal gate,
  sender-health gate and action fence
  (`services/mail-server/crates/sales-autopilot/src/scheduler.rs:1-25`;
  `src/bin/server.rs:179-183`).
- The dispatcher's canonical method is
  `ProductionCampaignDispatcher::enqueue_sequenced`, which uses the **resolved**
  sales `SenderIdentity` as the envelope sender, not the deployment-wide
  `SALES_CAMPAIGN_FROM_EMAIL`
  (`services/mail-server/crates/sales-autopilot/src/dispatcher.rs:1374-1414`).
- The send idempotency unit is a **logical step execution**, not a
  `(campaign, recipient)` pair:
  `sa:{enrollment_id}:{sequence_version_id}:{step_id}:{attempt_kind}:{variant}`
  (`src/sequences.rs:341-354`, applied by
  `dispatcher::send_idempotency_key`, `src/dispatcher.rs:839-895`). The legacy
  `sacmp:{campaign}:{recipient}` key remains only for the single-touch campaign
  surface.
- The queued rows carry typed provenance columns — `sales_decision_id`,
  `sales_sender_identity_id`, `sales_step_execution_id`, `sales_enrollment_id`
  — on both `messages` and `email_queue` (migration 202; inserts at
  `src/dispatcher.rs:962-992`).

### Autonomy modes

The mode lives in `sales_autonomy_state.mode` and is read on every decision;
a tenant with no row fails closed to `disabled`
(`services/mail-server/crates/sales-autopilot/src/types.rs:29-35`,
`src/autonomy.rs:22-47`). Unknown persisted values also fail closed.

| Mode | Brain / copy | Execution |
|------|--------------|-----------|
| `disabled` | no | no |
| `shadow` | yes — records what it would have done | no |
| `assisted` | yes | only operator-approved decisions |
| `approval_required` | yes | approved decisions only |
| `autonomous_guarded` | yes | automatically when every policy/confidence gate passes (`decide` returns `Execute`) |

`shadow` deliberately runs the whole brain and blocks only execution
(`src/types.rs:61-67`). There is intentionally no unrestricted
`autonomous_full` mode (`src/types.rs:25-26`).

Approval does not bypass the hard gates. An awaiting decision parks the action
in the `awaiting_approval` state
(`src/actions.rs:194-197`, `src/actions.rs:212`); `sales_decisions.review_status`
is the authoritative approval signal (`src/decision_engine.rs:108-118`), and
`decision_engine::revalidate_execution` re-runs every hard gate immediately
before the external effect, so an unsubscribe, a human reply, a legal-policy
change or a newly quarantined sender still stops an approved send
(`src/decision_engine.rs:1-13`, `src/decision_engine.rs:737`; consumed by the
worker at `src/sequence_worker.rs:2166-2226`).

## 2. Warmup admission (per source IP)

A dedicated IP is selected by the worker from `dedicated_ips` rows with
`status = 'warming'`; the least-warmed IP is the binding identity for the
tenant (`GET_DOMAIN_SQL` and `select_binding_warmup_ip`, both in
`services/mail-server/crates/worker-processors/src/email/processor.rs:312-418`).

- **One admission function:** `EmailProcessor::check_warmup_limit`
  (`processor.rs:2337`), called from the dispatch path before the transport
  (`processor.rs:1990-1999`).
- **Canonical schedule:** `mail_common::warmup::limit_for_day` (60 days, 50/day
  ramping to unlimited) with the warmup day derived from
  `dedicated_ips.warmup_started_at` (`mail-common/src/warmup.rs:3-23`;
  `processor.rs:2357-2362`). Day 60+ is unlimited and needs no counter.
- **One Redis key:**
  `apexmail:warmup:ip:{ip_address}:{utc_day}` (48 h TTL), written by the
  check-and-increment Lua script `WARMUP_RESERVE_LUA` through
  `reserve_warmup_send` (`processor.rs:789-854`; key builder
  `processor.rs:791-793`, reservation at `processor.rs:2364-2367`). The
  historical key `apexmail:outbound:warmup:{identity}:{day}` is **not** the
  live key — it does not appear in the send path.
- **No overflow:** a full cap defers the row through the normal requeue path
  (`WarmupAdmission::QuotaExhausted`); the row's attempt is preserved
  (`processor.rs:2369-2378`). Redis being unavailable also fails closed and
  defers (`processor.rs:2379-2387`). There is no automatic overflow to SES
  shared sending.
- **ISP-specific cap: does not exist.** There is no ISP/provider cap in the
  send path, and none can be computed there: no per-recipient provider is
  resolvable at admission time (the SMTP relay performs MX resolution and does
  not report it; SES does not report it either). The inert ISP rule was
  deleted. The `isp_warmup_templates` / `isp_warmup_schedules` tables and the
  admin warmup routes are **advisory catalog data only** — they are not read
  by any send path (`services/mail-server/crates/api-server/src/routes/admin/warmup.rs:1-27`;
  `services/mail-server/crates/apexmail-db/src/repos/warmup.rs:1-50`).

## 3. Transport contract

There is **one** `EmailTransport` abstraction:

```rust
async fn send(
    &self,
    email: &PreparedEmail,
    route: &DeliveryRoute,
) -> ProcessorResult<DeliveryReceipt>;
```

(`services/mail-server/crates/worker-processors/src/email/transport.rs:32-49`).
The route is derived per send from the warmup-IP identity the admission gate
used (`delivery_route`, `processor.rs:938-960`): a selected warming IP yields
`DeliveryRoute::Dedicated { dedicated_ip_id, source_ip }`; no warming IP yields
`DeliveryRoute::SesShared`
(`email/types.rs:230-273`).

`email/transport_router.rs` is **route resolution only** — a pure mapping from
a resolved route to `TransportKind` (`transport_kind_for`). The second
`EmailTransport` trait, its `bind_ip` config, its `send_raw_email` path and the
DB-backed `TransportRouter` cache that the running processor never called were
deleted (`services/mail-server/crates/worker-processors/src/email/transport_router.rs:17-59`).

### Dedicated route wire contract

For a dedicated route the SMTP transport injects internal routing metadata
into the existing authenticated relay submission:

```text
X-ApexMail-Route: v1 dedicated <dedicated_ip_id> <source_ip>
```

- Constant: `APEXMAIL_ROUTE_HEADER = "X-ApexMail-Route"`
  (`email/transport.rs:110-118`); the namespace is reserved and a
  caller-supplied header of the same name is dropped before the transport
  writes its own (`transport.rs:519-565`).
- Absent header means shared-pool/SES routing, no binding.
- The receiving relay is expected to report the actually-bound source IP back
  in the end-of-DATA reply as `X-ApexMail-Source-IP: <ip>`
  (`APEXMAIL_SOURCE_IP_REPLY_HEADER`, `transport.rs:120-125`).

### Known gap: the MTA side is not implemented in this repository

The receiving component is the outbound relay MTA behind `SMTP_HOST`. It is
**not implemented here** — `crates/mta` contains only the inbound, submission,
bounce and feedback-loop servers, and no recipient-facing outbound connector
exists in this tree. The source-IP binding is a documented contract with a
`TODO(mta-owner)` (`transport.rs:93-108`). Until the relay honours and reports
it, `SmtpTransport` reports `actual_source_ip: None`
(`transport.rs:738-756`), and the processor refuses to count the send as
dedicated. **The dedicated-IP route is therefore not verified end to end in
production today.**

## 4. Route verification and receipts

`DeliveryReceipt` (`email/types.rs:275-310`) carries:

| Field | Meaning |
|-------|---------|
| `transport` / `transport_message_id` | which transport carried the message; SES `MessageId`, `None` on the SMTP relay path |
| `actual_source_ip` | recipient-facing source IP actually used; `None` = not reported. The ONLY evidence a dedicated route really happened |
| `recipient_provider` / `provider_source` | mailbox provider when the delivery path actually resolved it, plus its provenance (`mx_resolved`, `provider_callback`, `inferred`) |

Enforcement is deliberately asymmetric (`verify_delivery_route`,
`processor.rs:976-990`):

- `Dedicated` requires `actual_source_ip == source_ip`. A different IP is a
  mismatch; a missing report is **unverified** — both are hard errors, never
  assumed success.
- `SesShared` has no IP to confirm, so no requirement applies.

On failure, `settle_delivery_route` releases the warmup reservation (deletes
the per-send marker and decrements the counter) so capacity is never counted
for a send that did not demonstrably use the IP
(`processor.rs:2398-2430`; release script `processor.rs:861-891`).

The shared SES transport refuses a `Dedicated` route up front rather than
silently sending from the shared pool (`transport.rs:141-147`,
`transport.rs:996-1005`).

## 5. Feedback loops

The worker records each delivery fact into the canonical sales feedback
ledgers — `sales_sender_events` (one row per fact) and `sales_outcomes` (the
outcome ladder) — with a single insert function per table
(`services/mail-server/crates/worker-processors/src/email/processor.rs:3736-3760`,
inserts at `processor.rs:3962-4070`). Recipient-provider provenance is carried
onto the `events` rows where known (migration
`202_sales_feedback_delivery_binding.sql`).

`sales_autopilot::outcome_projector::run` (spawned in `src/bin/server.rs:275-300`)
is the one consumer that folds those ledgers forward:

1. `sales_sender_events` → `sales_sender_health` via
   `sender_health::record_event`;
2. `sales_outcomes.reward_processed_at` → `experiments::record_reward`, keyed
   by `sales-outcome:{sales_outcomes.id}`
   (`services/mail-server/crates/sales-autopilot/src/outcome_projector.rs:1-22`).

Note that `DeliveryReceipt.actual_source_ip` is verification evidence only: it
is not persisted to the events tables.

## 6. What is intentionally not active

- No per-tenant `TransportRouter` cache, no 30-second refresh loop, no
  `transport_routing_cache` read in the delivery worker.
- No automatic SES overflow when a dedicated IP's warmup cap is reached.
- No ISP/provider-specific warmup cap (see section 2).
- No warmup progress cron: `DedicatedIpProvider::tick_warmup()` and
  `SesProvider::sync_warmup_progress()` exist, but no runtime component in this
  tree calls them. Graduation/progress only advances if an operator invokes it
  (`services/mail-server/crates/api-server/src/ip_provider.rs:504-515`).

## Related Documents

- [MTA Configuration](mta-configuration.md) — inbound only
- [Hybrid Email Infrastructure](hybrid-email-infrastructure.md)
- [Warmup Schedule](../operations/warmup-schedule.md)
- [Sales Autopilot Architecture](sales-autopilot.md)
- [Configuration Reference](../deployment/configuration.md)
