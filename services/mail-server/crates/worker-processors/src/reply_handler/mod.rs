//! Reply handler — Inbound email classification.
//!
//! This module handles classification of inbound emails:
//! - Aho-Corasick pattern matching for common reply types
//! - ReplyClassification enum (AutoReply, Bounce, Complaint, Forward, etc.)
//! - SuggestedAction generation
//! - Optional LLM fallback for ambiguous cases

// TODO: Implement processor
