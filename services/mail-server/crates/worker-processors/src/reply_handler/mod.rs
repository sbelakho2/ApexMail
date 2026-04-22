//! Reply handler — Inbound email classification.
//!
//! This module handles classification of inbound emails://! - Aho-Corasick pattern matching for common reply types
//! - ReplyClassification enum (AutoReply, Bounce, Complaint, Forward, etc.)
//! - SuggestedAction generation
//! - Optional LLM fallback for ambiguous cases

mod classifier;
mod processor;
mod types;

pub use classifier::classify;
pub use processor::ReplyHandler;
pub use types::{
    ActionType, ClassificationResult, ExtractedData, InboundMessage, ProcessedReply,
    ReplyClassification, Sentiment, SuggestedAction, Urgency,
};
