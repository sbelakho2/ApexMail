#![deny(unsafe_code)]
//! Sales autopilot — the canonical outbound sales engine.
//!
//! One brain, one source of truth. The control plane reads and steers this
//! service through the authenticated `/control/*` surface; it does not run a
//! second sales loop of its own.
//!
//! The pipeline, in order:
//!
//! ```text
//! canonical account/contact
//!   → evidence + score + next-best-action (sales_evidence, sales_signals)
//!   → sales SenderIdentity (sender_pool; sales pools only)
//!   → Decision Packet (autonomy + legal + sender health → sales_decisions)
//!   → durable fenced action (sales_actions, lease token, SKIP LOCKED)
//!   → dispatcher with the resolved sender (enqueue_sequenced → messages)
//!   → email_queue with typed decision/sender/step provenance
//!   → worker: delivery route + per-source-IP warmup admission
//!   → events / sales_outcomes / sales_sender_events
//!   → experiment + sender-health projectors (outcome_projector)
//! ```
//!
//! Delivery itself (route resolution, transport, MTA source-IP binding) lives
//! in `worker-processors`; its dedicated-route MTA side is not implemented in
//! this repository.

pub mod account_coordination;
pub mod actions;
pub mod attribution;
// Automation execution engine: the missing consumer of `automations.actions`
// (audit implementation-order item 3). Sends only through the shared
// `billing_service::send_admission::SendAdmissionService` gate.
pub mod automations;
pub mod autonomy;
pub mod calendar;
pub mod calibration;
pub mod campaigns;
pub mod config;
pub mod control;
pub mod control_read;
pub mod crm;
pub mod crm_pg;
pub mod decision_engine;
pub mod discovery;
pub mod dispatcher;
pub mod enrichment;
pub mod enrollments;
pub mod experiments;
pub mod inbox;
pub mod intelligence;
pub mod knowledge;
pub mod legal_policy;
pub mod outcome_projector;
pub mod personalization;
pub mod research;
pub mod routes;
pub mod scheduler;
pub mod schema;
pub mod scoring;
pub mod sender_health;
pub mod sender_pool;
pub mod sequence_worker;
pub mod sequences;
pub mod signals;
pub mod simulation;
#[cfg(test)]
mod test_db;
pub mod types;
