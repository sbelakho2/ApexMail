# Progress — sales, money and compliance slice

Slice: sales-autopilot, sales-knowledge, platform-catalog, billing-service, accounting-core,
compliance, ai-service, email-grader, sdk-php/python/java/ruby.
Working tree: main, dirty (expected). Reviewer: subagent, read-only.

## Batch 1 — canonical money sources
- [x] services/mail-server/crates/platform-catalog/src/lib.rs
- [x] services/mail-server/crates/sales-knowledge/src/lib.rs
- [x] services/mail-server/crates/billing-service/src/lib.rs
- [x] services/mail-server/crates/billing-service/src/types.rs
- [x] services/mail-server/crates/billing-service/src/config.rs
- [x] services/mail-server/crates/billing-service/src/plans.rs

## Canonical money reference (from platform-catalog, for cross-checks)
- free: 0c, 3000 emails, 30000 api, 7d, 1 seat, no overage; launch allowance 30000 emails/30d
- starter "Developer": 2900c/29000c, 50000 emails, 500k api, 30d, 5, overage 80 mc
- pro: 8900/89000, 150k, 2M, 60d, 10, 60 mc
- growth: 22900/229000, 500k, 5M, 90d, 25, 35 mc
- scale "Business": 69900/699000, 2M, 20M, 365d, 50, 35 mc
- enterprise: 175000/1750000, 5M, api -1, 730d, seats -1, 35 mc
- payg: 0, unlimited, 30d, 5; PAYG tiers 100/80/50/30 millicents per email at 10k/100k/1M/inf
- rate-limit tiers: free 10 rps, standard 100, high 500, unlimited 5000
- [x] services/mail-server/crates/billing-service/src/overage.rs
- [x] services/mail-server/crates/billing-service/src/accounting_postings.rs
- [x] services/mail-server/crates/billing-service/src/send_admission.rs
- [x] services/mail-server/crates/billing-service/src/subscriptions.rs
- [x] services/mail-server/crates/billing-service/src/usage.rs (finding P1: ledger not released on rollback)
- [x] services/mail-server/crates/billing-service/src/usage_ingest.rs
- [x] services/mail-server/crates/billing-service/src/metering_monitor.rs
- [x] services/mail-server/crates/billing-service/src/invoices.rs (part 1/2)
- [x] services/mail-server/crates/billing-service/src/credit_notes.rs
- [x] services/mail-server/crates/billing-service/src/stripe_webhooks.rs (targeted: settlement/tax/import/period snapshot; 2 findings reviewed)
- [x] services/mail-server/crates/billing-service/src/maintenance.rs (targeted: SLA credits, auto-pay, wallet sweeps, payment recovery; finding P2 dead reservation machinery)
- [x] services/mail-server/crates/accounting-core/src/posting.rs (clean)
- [x] services/mail-server/crates/accounting-core/src/adapters.rs (clean)
- [x] services/mail-server/crates/accounting-core/src/bank_ingest.rs (clean)
- [x] services/mail-server/crates/accounting-core/src/sweeps.rs (clean)
- [x] services/mail-server/crates/accounting-core/src/periods.rs (clean)
- [x] services/mail-server/crates/billing-service/src/vat_recognition.rs (finding P2: cash-special sweep unscheduled)
- [x] services/mail-server/crates/billing-service/src/accounting_export.rs (clean)

## Coverage notes (honest accounting)
Fully or substantially read: platform-catalog; sales-knowledge; billing-service {lib, types, config, plans, overage,
usage, usage_ingest, metering_monitor, invoices (money core), credit_notes, accounting_postings, send_admission,
subscriptions, vat_recognition, accounting_export, money_invariants}; accounting-core {posting, adapters,
bank_ingest, sweeps, periods}; compliance {consent_enforcement, suppressions (pure half), gdpr_automation (request
processing/erasure core)}; ai-service {knowledge, verifier (core), pipeline (run/fallback)}; sales-autopilot
{autonomy, sequence_worker execution gate, personalization claim gate, dispatcher admission greps}; SDK endpoint
surfaces (php/python/java/ruby greps + PHP/Python email resources).
Targeted/hit-scan only (high-signal greps, not full reads): billing-service {stripe_webhooks, maintenance, routes,
vat_kmd, vat_emta, simulation, bin/server, coverage_adversarial}; compliance {audit_logger, dsr_outbox_flush,
dsr_rate_limit, retention_sweep, routes, governance, entitlements, claims_registry, feature_registry, trust_portal,
spending_controls, abuse_gating, signing}; ai-service {chat, email_agent, routes, tools, defense, inference,
retrieval, config, analytics}; sales-autopilot {decision_engine, dispatcher, control, legal_policy, campaigns,
enrollments, sender_pool, sender_health, actions, routes, experiments}; email-grader {scoring, grader, routes,
config}; remaining SDK resource files.
NOT reviewed file-by-file: the bulk of compliance tests + ~60 compliance modules, ai-service adversarial/training
files, most sales-autopilot src/test files, email-grader crypto/network_checks/dns_provider, and the billing
coverage_adversarial test suite. This review ran out of budget before the whole 235-file slice could be read; the
five findings above are proved from the files read.
- [x] services/mail-server/crates/compliance/src/ledger_sweep.rs (clean; sweep is hosted by compliance bin/server.rs:385)
- [x] services/mail-server/crates/compliance/src/consent_enforcement.rs (finding P1: zero callers)
- [x] services/mail-server/crates/sales-autopilot/src/autonomy.rs (clean; kill switch enforced in decision_engine + sequence_worker execution gate)
- [x] SDK endpoint-surface check (php/python/java/ruby): every distinctive path found is mounted in api-server routes (webhooks rotate-secret, templates rollback/render, events timeseries, messages batch/cancel, suppressions bulk/check, analytics deliverability)
Findings written this session: 6 (1xP1 usage-ledger rollback, 1xP2 flat overage rate, 1xP2 dead wallet reservations, 1xP2 unscheduled cash-special VAT sweep, 1xP1 dead consent enforcer, 1xP1 unprotected suppression deletion).
