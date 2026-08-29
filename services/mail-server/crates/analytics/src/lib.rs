#![deny(unsafe_code)]
pub mod bot_detection;
pub mod campaign_autopilot;
pub mod churn_prediction;
pub mod clickhouse_engine;
pub mod compaction;
pub mod config;
pub mod email_hash;
pub mod engagement_trust;
pub mod inbox_placement;
pub mod ip_mask;
pub mod query_engine;
pub mod reconciliation;
pub mod reply_tracking;
pub mod send_time_optimizer;
pub mod subject_line_analyzer;
pub mod types;

pub use clickhouse_engine::ClickHouseEngine;
pub use query_engine::{QueryEngine, QueryError};
