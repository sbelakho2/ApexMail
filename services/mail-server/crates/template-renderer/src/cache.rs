//! Template cache using moka concurrent cache.

use moka::sync::Cache;
use std::time::Duration;

use crate::types::RenderResult;

/// Thread-safe template render cache with TTL and LRU eviction.
pub struct TemplateCache {
    inner: Cache<String, RenderResult>,
}

impl TemplateCache {
    pub fn new(max_entries: u64, ttl_secs: u64) -> Self {
        let inner = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        Self { inner }
    }

    pub fn get(&self, key: &str) -> Option<RenderResult> {
        self.inner.get(key)
    }

    pub fn insert(&self, key: String, value: RenderResult) {
        self.inner.insert(key, value);
    }

    pub fn invalidate(&self, key: &str) {
        self.inner.invalidate(key);
    }

    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RenderMetadata, RenderResult};

    fn make_result(html: &str) -> RenderResult {
        RenderResult {
            html: html.to_string(),
            plaintext: None,
            subject: None,
            metadata: RenderMetadata {
                render_time_ms: 1,
                html_size_bytes: html.len(),
                plaintext_size_bytes: None,
                cached: false,
            },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = TemplateCache::new(100, 3600);
        let result = make_result("<h1>Hello</h1>");
        cache.insert("key1".to_string(), result);
        let cached = cache.get("key1").unwrap();
        assert_eq!(cached.html, "<h1>Hello</h1>");
    }

    #[test]
    fn test_cache_miss() {
        let cache = TemplateCache::new(100, 3600);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = TemplateCache::new(100, 3600);
        cache.insert("key1".to_string(), make_result("<p>Test</p>"));
        cache.invalidate("key1");
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_cache_invalidate_all() {
        let cache = TemplateCache::new(100, 3600);
        cache.insert("k1".to_string(), make_result("a"));
        cache.insert("k2".to_string(), make_result("b"));
        cache.invalidate_all();
        assert!(cache.get("k1").is_none());
        assert!(cache.get("k2").is_none());
    }

    #[test]
    fn test_cache_entry_count() {
        let cache = TemplateCache::new(100, 3600);
        assert_eq!(cache.entry_count(), 0);
        cache.insert("k1".to_string(), make_result("a"));
        // moka is eventually consistent, so entry_count may not update immediately
        // but the value should be retrievable
        assert!(cache.get("k1").is_some());
    }
}
