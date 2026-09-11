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
//! discovery (provider-backed)
//!   → enrichment (waterfall, provenance preserved in sales_enrichment_facts)
//!   → evidence + signals (sales_evidence, sales_signals)
//!   → scoring (explainable feature vector, reason codes)
//!   → decision engine (hard gates → Decision Packet)
//!   → durable actions (sales_actions, leased, SKIP LOCKED)
//!   → sequences (sales_sequence_* + sales_enrollments + sales_step_executions)
//!   → dispatcher (messages + email_queue)
//!   → outcomes (sales_outcomes) → attribution → experiments/calibration
//! ```

pub mod account_coordination;
pub mod actions;
pub mod attribution;
pub mod autonomy;
pub mod calendar;
pub mod calibration;
pub mod campaigns;
pub mod config;
pub mod control;
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
