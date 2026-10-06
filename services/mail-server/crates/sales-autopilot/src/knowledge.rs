//! Verified sales knowledge base — re-exported from the shared crate.
//!
//! The implementation moved to `crates/sales-knowledge` (plan §5.5) so the
//! ai-service mailbot/classifier validate claims against the SAME code as the
//! sales engine. This module keeps the historical path
//! (`sales_autopilot::knowledge::*`) working unchanged: every item is a
//! re-export, and behavior is byte-identical.
//!
//! Sources, freshness rules and the claim ladder are documented on the shared
//! crate. `SalesKnowledgeBase::canonical()` derives the plan facts from
//! `platform-catalog`.

pub use sales_knowledge::*;
