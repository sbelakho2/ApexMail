//! Legacy campaign dispatch scheduler — REMOVED.
//!
//! This module used to run the second send engine: a background loop that
//! listed active `sales_campaigns` rows and pushed their `due_recipients`
//! straight through [`crate::dispatcher::ProductionCampaignDispatcher`] into
//! the outbound queue. That path bypassed the Decision Packet, the legal
//! gate, the sender-health gate and the action fence, so it has been deleted.
//!
//! There is exactly ONE send path now:
//!
//! 1. `CampaignManager::start_campaign` (see [`crate::campaigns`]) adapts the
//!    legacy campaign into canonical contacts, contact points and a
//!    compatibility sequence keyed by `sales_sequences.legacy_campaign_id`,
//!    then enrolls those contacts through
//!    [`crate::enrollments::start_outreach`];
//! 2. enrollments enqueue `send_step` rows in the durable `sales_actions`
//!    queue;
//! 3. the durable action worker (`sales_autopilot::actions::run` with
//!    [`crate::sequence_worker::SequenceStepHandler`]) claims and executes
//!    them, and every execution passes the Decision Packet, legal,
//!    sender-health and fence gates.
//!
//! Do not re-introduce a `tick`/`run` loop that calls
//! `ProductionCampaignDispatcher::dispatch_batch` (or any other direct
//! enqueue) here. `sales_campaign_recipients` remains only as a
//! read-compatibility ledger for the CP.
