//! Reusable multi-pattern matching engine built on Aho-Corasick.
//!
//! Provides O(n) pattern matching with zero backtracking, suitable for
//! bot detection, spam scoring, phishing URL detection, and content policy rules.

pub mod bot_patterns;
pub mod matcher;
pub mod rules;
pub mod spam_patterns;

pub use matcher::{MatchResult, PatternMatcher};
pub use rules::{Rule, RuleCategory, RuleSet, Severity};
