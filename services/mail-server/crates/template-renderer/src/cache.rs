//! Template cache using moka concurrent cache.

use moka::sync::Cache;
use std::time::Duration;

use crate::types::{RenderOptions, RenderResult};

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

    /// Force moka's pending maintenance (evictions, TTL expiry) so
    /// `entry_count` is accurate — used by the bound test; production reads
    /// go through `get`, which maintains itself on access.
    pub fn run_pending_tasks(&self) {
        self.inner.run_pending_tasks();
    }
}

// ─── HTTP render cache key (P1 #11) ────────────────────────────

/// Version of the HTTP (`/render`) cache-key contract. It stands in for the
/// transpiler + sandbox + plaintext-sanitizer semantics: ANY change that can
/// alter rendered output for the same inputs MUST bump this constant, which
/// rotates every key (stale renders can never outlive a deploy that changes
/// rendering behavior).
pub const SOURCE_RENDER_CACHE_KEY_VERSION: u8 = 1;

/// Versioned inputs of the HTTP render cache key. Serialized to JSON and
/// SHA-256-hashed — the SAME versioned-structure pattern as the stored
/// template path's `stored_render_cache_key` in `renderer.rs`.
#[derive(serde::Serialize)]
struct SourceRenderCacheKeyInputs<'a> {
    key_version: u8,
    /// The inline template source (the HTTP contract has no template id —
    /// the content itself is the identity, so "never source-id alone" is
    /// trivially satisfied: the full source is hashed).
    source: &'a str,
    /// Canonicalized props JSON (object keys sorted recursively), so two
    /// requests with the same props in different key order share one entry
    /// and different props never do.
    props_canonical: String,
    subject: Option<&'a str>,
    minify: bool,
    generate_plaintext: bool,
    missing_field_fallback: Option<&'a str>,
}

/// Canonical JSON text: object keys sorted recursively. `serde_json`'s
/// default map is already sorted, but the feature set is workspace-global —
/// serializing explicitly keeps the key stable regardless of feature flags.
fn canonical_json(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for item in items {
                if out.len() > 1 {
                    out.push(',');
                }
                let _ = write!(out, "{}", canonical_json(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for key in keys {
                if out.len() > 1 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{}:{}",
                    serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()),
                    canonical_json(&map[key])
                );
            }
            out.push('}');
            out
        }
    }
}

/// SHA-256 cache key for an HTTP `/render` request, covering EVERYTHING that
/// affects the output: the template source, the props (canonical form), and
/// every output-affecting `RenderOptions` field (`subject`, `minify`,
/// `generate_plaintext`, `missing_field_fallback`) plus
/// [`SOURCE_RENDER_CACHE_KEY_VERSION`]. Adding a new output-affecting option
/// means adding it to [`SourceRenderCacheKeyInputs`] and bumping the version.
pub fn source_render_cache_key(source: &str, options: &RenderOptions) -> String {
    use sha2::{Digest, Sha256};
    let inputs = SourceRenderCacheKeyInputs {
        key_version: SOURCE_RENDER_CACHE_KEY_VERSION,
        source,
        props_canonical: canonical_json(&options.props),
        subject: options.subject.as_deref(),
        minify: options.minify,
        generate_plaintext: options.generate_plaintext,
        missing_field_fallback: options.missing_field_fallback.as_deref(),
    };
    // A serialization failure can only come from a non-serializable value;
    // the fallback marker still distinguishes the request from every other
    // one (and never collides two DIFFERENT inputs).
    let serialized = serde_json::to_string(&inputs).unwrap_or_else(|error| {
        format!(
            "{{\"key_version\":{SOURCE_RENDER_CACHE_KEY_VERSION},\"serialization_error\":\"{error}\"}}"
        )
    });
    let hash = Sha256::digest(serialized.as_bytes());
    format!("source-render:{hash:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RenderMetadata, RenderOptions, RenderResult};
    use serde_json::json;

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

    fn base_options() -> RenderOptions {
        RenderOptions {
            props: json!({}),
            generate_plaintext: true,
            minify: false,
            subject: None,
            missing_field_fallback: None,
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

    // ── P1 #11: HTTP render cache key + bound ────────────────────────

    #[test]
    fn source_render_key_is_stable_for_identical_inputs() {
        let opts = base_options();
        let a = source_render_cache_key("<p>{{ name }}</p>", &opts);
        let b = source_render_cache_key("<p>{{ name }}</p>", &opts);
        assert_eq!(a, b, "identical (source, options) must share one key");
        assert!(a.starts_with("source-render:"), "{a}");
    }

    #[test]
    fn source_render_key_rotates_with_source_and_props() {
        let opts = base_options();
        let base = source_render_cache_key("<p>{{ name }}</p>", &opts);
        assert_ne!(
            base,
            source_render_cache_key("<p>{{ other }}</p>", &opts),
            "different source must rotate the key"
        );
        let mut props = base_options();
        props.props = json!({ "name": "A" });
        assert_ne!(
            base,
            source_render_cache_key("<p>{{ name }}</p>", &props),
            "different props must rotate the key"
        );
    }

    /// Props key ORDER must not fragment the cache: canonical-JSON props make
    /// `{"a":1,"b":2}` and `{"b":2,"a":1}` one entry.
    #[test]
    fn source_render_key_canonicalizes_props_key_order() {
        let mut a = base_options();
        a.props = json!({ "a": 1, "b": 2 });
        let mut b = base_options();
        b.props = json!({ "b": 2, "a": 1 });
        assert_eq!(
            source_render_cache_key("<p>x</p>", &a),
            source_render_cache_key("<p>x</p>", &b),
            "props key order must not change the key"
        );
    }

    /// EVERY output-affecting option participates: changing any single one
    /// (or the key-version constant standing in for renderer/sanitizer
    /// semantics) must produce a different key.
    #[test]
    fn source_render_key_covers_every_option_and_version() {
        let source = "<p>{{ name }}</p>";
        let base = source_render_cache_key(source, &base_options());

        let mut variant = base_options();
        variant.minify = true;
        assert_ne!(base, source_render_cache_key(source, &variant), "minify");

        let mut variant = base_options();
        variant.generate_plaintext = false;
        assert_ne!(
            base,
            source_render_cache_key(source, &variant),
            "generate_plaintext"
        );

        let mut variant = base_options();
        variant.subject = Some("Hi {{ name }}".into());
        assert_ne!(base, source_render_cache_key(source, &variant), "subject");

        let mut variant = base_options();
        variant.missing_field_fallback = Some("—".into());
        assert_ne!(
            base,
            source_render_cache_key(source, &variant),
            "missing_field_fallback"
        );

        // The version input: same inputs hashed under a different contract
        // version must rotate (this is what a semantics bump relies on).
        let inputs = |version: u8| SourceRenderCacheKeyInputs {
            key_version: version,
            source,
            props_canonical: "{}".to_string(),
            subject: None,
            minify: false,
            generate_plaintext: true,
            missing_field_fallback: None,
        };
        use sha2::{Digest, Sha256};
        let hash = |version: u8| format!("{:x}", Sha256::digest(serde_json::to_string(&inputs(version)).unwrap().as_bytes()));
        assert_ne!(hash(1), hash(2), "key version must rotate the key");
    }

    /// The cache is bounded: inserting more distinct entries than
    /// `max_entries` evicts (LRU) instead of growing without limit.
    #[test]
    fn cache_is_bounded_at_max_entries() {
        let max_entries = 8;
        let cache = TemplateCache::new(max_entries, 3600);
        for i in 0..(max_entries * 4) {
            cache.insert(format!("k{i}"), make_result("x"));
        }
        cache.run_pending_tasks();
        assert!(
            cache.entry_count() <= max_entries,
            "entry_count {} exceeded the bound {max_entries}",
            cache.entry_count()
        );
    }
}
