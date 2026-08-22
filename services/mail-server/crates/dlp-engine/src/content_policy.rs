//! Content policy scanning — confidentiality markers, classification labels
//!
//! Detects organizational sensitivity markers in outbound email content://! - "CONFIDENTIAL", "INTERNAL ONLY", "DO NOT DISTRIBUTE"
//! - Custom keyword lists configured by policy
//! - Classification banners

use aho_corasick::AhoCorasick;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Content policy match
#[derive(Debug, Clone)]
pub struct PolicyMatch {
    /// Matched keyword/phrase
    pub keyword: String,
    /// Risk score
    pub risk: f64,
    /// Byte offset
    pub offset: usize,
}

/// Global count of automaton build failures. A failing build disables the
/// content-policy channel and MUST be observable, not silent.
static BUILD_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Number of times the content-policy automaton failed to build.
pub fn content_policy_build_failures() -> u64 {
    BUILD_FAILURES.load(Ordering::Relaxed)
}

/// (internal) count a build failure.
pub(crate) fn record_build_failure() {
    BUILD_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Cache of compiled automatons keyed by a hash of the keyword list, so the
/// automaton is not rebuilt on every scanned message.
fn automaton_cache() -> &'static Mutex<HashMap<u64, Arc<AhoCorasick>>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Arc<AhoCorasick>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn keywords_hash(keywords: &[String]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    keywords.len().hash(&mut hasher);
    for k in keywords {
        k.hash(&mut hasher);
    }
    hasher.finish()
}

/// Lock the automaton cache, recovering the data from a poisoned lock:
/// the cache is a pure optimization, so a panic elsewhere in the process
/// must not take content scanning down with it.
fn lock_automaton_cache() -> std::sync::MutexGuard<'static, HashMap<u64, Arc<AhoCorasick>>> {
    automaton_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Compile (or fetch from cache) the automaton for a keyword list.
/// Returns `Err` with a human-readable reason when the automaton cannot be
/// built — callers must treat this as "channel unavailable", never as
/// "no matches".
fn automaton_for(keywords: &[String]) -> Result<Arc<AhoCorasick>, String> {
    let key = keywords_hash(keywords);
    if let Some(cached) = lock_automaton_cache().get(&key) {
        return Ok(Arc::clone(cached));
    }

    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(keywords)
        .map_err(|e| format!("aho-corasick build failed for keyword list: {e}"))?;
    let ac = Arc::new(ac);
    // Bound the cache:keep at most 32 configurations.
    let mut cache = lock_automaton_cache();
    if cache.len() >= 32 {
        cache.clear();
    }
    cache.insert(key, Arc::clone(&ac));
    Ok(ac)
}

/// Scan content against confidentiality keywords.
/// Fails loudly with `Err` when the matcher cannot be compiled (the caller
/// is expected to log and count the outage — never to treat it as "clean").
pub fn scan_content_policy(text: &str, keywords: &[String]) -> Result<Vec<PolicyMatch>, String> {
    if keywords.is_empty() {
        return Ok(Vec::new());
    }

    let ac = automaton_for(keywords)?;

    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for mat in ac.find_iter(text) {
        let idx = mat.pattern().as_usize();
        if idx < keywords.len() && seen.insert(idx) {
            // Assign risk based on keyword severity
            let keyword = &keywords[idx];
            let risk = classify_keyword_risk(keyword);
            matches.push(PolicyMatch {
                keyword: keyword.clone(),
                risk,
                offset: mat.start(),
            });
        }
    }

    Ok(matches)
}

/// Classify risk based on keyword
fn classify_keyword_risk(keyword: &str) -> f64 {
    let lower = keyword.to_lowercase();
    if lower.contains("top secret") || lower.contains("classified") {
        8.0
    } else if lower.contains("confidential")
        || lower.contains("restricted")
        || lower.contains("privileged")
    {
        6.0
    } else if lower.contains("internal")
        || lower.contains("proprietary")
        || lower.contains("trade secret")
    {
        4.0
    } else if lower.contains("do not distribute") || lower.contains("attorney") {
        5.0
    } else {
        3.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidential_detection() {
        let keywords = vec!["confidential".into(), "internal only".into()];
        let text = "This document is CONFIDENTIAL and for Internal Only distribution.";
        let matches = scan_content_policy(text, &keywords).expect("build ok");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_matches() {
        let keywords = vec!["confidential".into(), "top secret".into()];
        let text = "Hey team, the meeting is moved to 3pm tomorrow.";
        let matches = scan_content_policy(text, &keywords).expect("build ok");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_risk_classification() {
        assert!(classify_keyword_risk("top secret") > classify_keyword_risk("internal only"));
        assert!(classify_keyword_risk("confidential") > classify_keyword_risk("internal only"));
    }

    #[test]
    fn test_empty_keywords() {
        let matches = scan_content_policy("some text", &[]).expect("build ok");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let keywords = vec!["secret".into()];
        let text = "This is secret and that is also secret and everything is secret.";
        let matches = scan_content_policy(text, &keywords).expect("build ok");
        assert_eq!(matches.len(), 1, "Should deduplicate same keyword");
    }

    #[test]
    fn test_automaton_is_cached_by_config() {
        let keywords = vec!["cache-probe".to_string()];
        automaton_for(&keywords).expect("build ok");
        automaton_for(&keywords).expect("cached build ok");
        // Same hash → same Arc contents (cache hit path exercised twice).
        let a = automaton_for(&keywords).expect("again");
        let b = automaton_for(&keywords).expect("and again");
        assert!(Arc::ptr_eq(&a, &b), "identical config must hit the cache");
    }
}
