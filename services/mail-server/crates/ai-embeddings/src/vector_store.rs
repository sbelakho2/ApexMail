//! In-memory vector store with LRU eviction and NDJSON persistence with HMAC integrity.
//!
//! # Concurrency model (O-9.4)
//! Uses `DashMap` (sharded fine-grained locking) instead of a single `RwLock<HashMap>`,
//! eliminating lock contention under high read concurrency. Each search iteration
//! acquires per-shard locks rather than a global lock.
//!
//! # Persistence integrity (O-9.2)
//! NDJSON export/import includes an HMAC-SHA256 signature computed over the data.
//! On import, the HMAC is verified before deserialization to detect tampering.

use std::cmp::max;
use std::collections::BinaryHeap;
use std::io::{BufRead, Write};
use std::time::Instant;

use chrono::Utc;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};
use uuid::Uuid;

use crate::embeddings::cosine_similarity;
use crate::types::{EmbeddingError, EmbeddingVector, SearchResult, StoreStats};

type HmacSha256 = Hmac<Sha256>;

/// The HMAC header line prefix written at the end of NDJSON exports.
const HMAC_HEADER_PREFIX: &str = "# hmac-sha256:";

/// Thread-safe in-memory vector store with DashMap (sharded locking).
pub struct VectorStore {
    /// Sharded concurrent map: keyed by UUID.
    inner: DashMap<Uuid, EmbeddingVector>,
    dimension: usize,
    max_vectors: usize,
    eviction_threshold: usize,
    /// Optional HMAC key for NDJSON integrity (hex-encoded 32 bytes).
    hmac_key: Vec<u8>,
}

fn metadata_tenant_id(metadata: &serde_json::Value) -> Option<&str> {
    metadata
        .get("tenant_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
}

/// True when the vector's L2 norm is meaningfully greater than zero.
/// Zero-norm vectors cannot be normalized and are rejected at write/search.
fn has_nonzero_norm(vector: &[f32]) -> bool {
    let norm: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    norm > f32::EPSILON && norm.is_finite()
}

impl VectorStore {
    pub fn new(
        dimension: usize,
        max_vectors: usize,
        eviction_threshold: usize,
        hmac_key: Vec<u8>,
    ) -> Self {
        Self {
            inner: DashMap::new(),
            dimension,
            max_vectors,
            eviction_threshold,
            hmac_key,
        }
    }

    /// Add a vector to the store, evicting LRU entries if needed.
    ///
    /// The vector is L2-normalized on write so cosine similarity in
    /// [`VectorStore::search`] operates on unit vectors even when a caller
    /// supplies an unnormalized one.
    pub fn add(
        &self,
        text: String,
        vector: Vec<f32>,
        metadata: serde_json::Value,
    ) -> Result<Uuid, EmbeddingError> {
        if metadata_tenant_id(&metadata).is_none() {
            return Err(EmbeddingError::MissingTenantScope);
        }

        if vector.len() != self.dimension {
            return Err(EmbeddingError::DimensionMismatch {
                got: vector.len(),
                expected: self.dimension,
            });
        }

        if !has_nonzero_norm(&vector) {
            return Err(EmbeddingError::ZeroNormVector);
        }
        let vector = crate::embeddings::l2_normalize(vector);

        // Evict if at threshold (check approximate size via len(), which is O(1) for DashMap)
        if self.inner.len() >= self.eviction_threshold {
            self.evict_lru();
        }

        if self.inner.len() >= self.max_vectors {
            return Err(EmbeddingError::StoreFull {
                count: self.inner.len(),
                max: self.max_vectors,
            });
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        self.inner.insert(
            id,
            EmbeddingVector {
                id,
                text,
                vector,
                metadata,
                created_at: now,
                last_accessed: now,
            },
        );

        Ok(id)
    }

    /// Add multiple vectors in batch.
    pub fn add_batch(
        &self,
        items: Vec<(String, Vec<f32>, serde_json::Value)>,
    ) -> Result<Vec<Uuid>, EmbeddingError> {
        let mut ids = Vec::with_capacity(items.len());
        for (text, vector, metadata) in items {
            ids.push(self.add(text, vector, metadata)?);
        }
        Ok(ids)
    }

    /// Get a vector by ID (updates last_accessed for LRU).
    pub fn get(&self, id: Uuid) -> Option<EmbeddingVector> {
        let mut entry = self.inner.get_mut(&id)?;
        entry.last_accessed = Utc::now();
        Some(entry.clone())
    }

    /// Remove a vector by ID.
    pub fn remove(&self, id: Uuid) -> bool {
        self.inner.remove(&id).is_some()
    }

    /// Search for the top-K most similar vectors using a min-heap.
    /// Uses DashMap's iterator which acquires per-shard locks.
    ///
    /// The query vector is L2-normalized on entry (zero-norm queries are
    /// rejected) so cosine similarity stays within [-1, 1] even when the
    /// caller submits a raw, unnormalized embedding.
    pub fn search(&self, query_vector: &[f32], top_k: usize, tenant_id: &str) -> Vec<SearchResult> {
        if query_vector.len() != self.dimension || tenant_id.trim().is_empty() {
            return vec![];
        }
        if !has_nonzero_norm(query_vector) {
            return vec![];
        }
        let normalized_query = crate::embeddings::l2_normalize(query_vector.to_vec());

        let start = Instant::now();
        let mut heap: BinaryHeap<MinScoreEntry> = BinaryHeap::new();

        for entry in self.inner.iter() {
            if metadata_tenant_id(&entry.metadata) != Some(tenant_id) {
                continue;
            }

            let score = cosine_similarity(&normalized_query, &entry.vector);

            if heap.len() < top_k {
                heap.push(MinScoreEntry {
                    score,
                    id: entry.id,
                    text: entry.text.clone(),
                    metadata: entry.metadata.clone(),
                });
            } else if let Some(min) = heap.peek() {
                if score > min.score {
                    heap.pop();
                    heap.push(MinScoreEntry {
                        score,
                        id: entry.id,
                        text: entry.text.clone(),
                        metadata: entry.metadata.clone(),
                    });
                }
            }
        }

        let elapsed = start.elapsed();
        let total_entries = self.inner.len();
        // Record metrics using the dedicated record/gauge methods
        metrics::histogram!("vector_store.search_duration_secs").record(elapsed.as_secs_f64());
        metrics::gauge!("vector_store.search_scanned").set(total_entries as f64);

        // Convert heap to sorted results (highest score first)
        let results: Vec<SearchResult> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|e| SearchResult {
                id: e.id,
                text: e.text,
                score: e.score,
                metadata: e.metadata,
            })
            .collect();

        results
    }

    /// Get store statistics.
    pub fn stats(&self) -> StoreStats {
        let total_vectors = self.inner.len();

        let now = Utc::now();
        let oldest = self
            .inner
            .iter()
            .map(|v| v.last_accessed)
            .min()
            .unwrap_or(now);
        let newest = self
            .inner
            .iter()
            .map(|v| v.last_accessed)
            .max()
            .unwrap_or(now);

        // Estimate memory: per vector = dimension * 4 bytes (f32) + overhead
        let vec_mem = total_vectors * (self.dimension * 4 + 256);

        StoreStats {
            total_vectors,
            dimension: self.dimension,
            memory_bytes: vec_mem,
            oldest_access: Some(oldest),
            newest_access: Some(newest),
        }
    }

    /// Export store to NDJSON writer with HMAC-SHA256 signature line.
    ///
    /// Format: one JSON object per line, followed by:
    /// `# hmac-sha256:<hex_signature>`
    pub fn export_ndjson<W: Write>(&self, writer: &mut W) -> Result<usize, EmbeddingError> {
        let mut count = 0;
        let mut data_bytes: Vec<u8> = Vec::new();

        // Write all vectors and collect raw bytes for HMAC computation
        for v in self.inner.iter() {
            let line = serde_json::to_string(&*v)?;
            writeln!(writer, "{}", line)?;
            writeln!(data_bytes, "{}", line)?;
            count += 1;
        }

        // Compute and append HMAC-SHA256 signature
        if !self.hmac_key.is_empty() {
            let sig = compute_hmac(&self.hmac_key, &data_bytes)?;
            writeln!(writer, "{}{}", HMAC_HEADER_PREFIX, sig)?;
            info!(count, "NDJSON export with HMAC integrity signature");
        } else if count > 0 {
            warn!(
                "NDJSON export without HMAC — integrity not protected (set PERSISTENCE_HMAC_KEY)"
            );
        }

        Ok(count)
    }

    /// Import vectors from NDJSON reader with HMAC verification.
    ///
    /// Expects an optional trailing `# hmac-sha256:<hex>` line. If the HMAC key
    /// is configured, the signature is verified before any deserialization.
    pub fn import_ndjson<R: BufRead>(&self, reader: R) -> Result<usize, EmbeddingError> {
        let mut hmac_verifier = if !self.hmac_key.is_empty() {
            // If HMAC key is set, accumulate data bytes for verification
            Some(
                HmacSha256::new_from_slice(&self.hmac_key)
                    .map_err(|_| EmbeddingError::MissingHmacKey)?,
            )
        } else {
            None
        };

        let mut lines: Vec<String> = Vec::new();
        let mut maybe_signature: Option<String> = None;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            if line.starts_with(HMAC_HEADER_PREFIX) {
                // This is the HMAC signature line — store it
                let sig = line
                    .strip_prefix(HMAC_HEADER_PREFIX)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                maybe_signature = Some(sig);
                // Don't add this line to the data for verification
                continue;
            }

            if let Some(ref mut verifier) = hmac_verifier {
                use std::io::Write;
                writeln!(verifier, "{}", line).map_err(|_| EmbeddingError::IntegrityCheckFailed)?;
            }
            lines.push(line);
        }

        // Verify HMAC if key is configured
        if let Some(verifier) = hmac_verifier {
            let expected_sig = maybe_signature.ok_or(EmbeddingError::IntegrityCheckFailed)?;
            let computed_sig = hex::encode(verifier.finalize().into_bytes());
            if !constant_time_eq(&computed_sig, &expected_sig) {
                // No signature material in the log — the hex digests are
                // integrity secrets-adjacent output and belong nowhere.
                warn!(
                    "NDJSON HMAC verification FAILED — data may be tampered or corrupted. \
                     Refusing to load."
                );
                return Err(EmbeddingError::IntegrityCheckFailed);
            }
            info!("NDJSON HMAC integrity check passed");
        } else if !lines.is_empty() && maybe_signature.is_some() {
            // HMAC key not set but signature exists — warn the user
            warn!(
                "NDJSON file has HMAC signature but no key is configured — loading anyway. \
                 Set PERSISTENCE_HMAC_KEY to verify integrity."
            );
        }

        // Parse and import all vectors. Imported rows go through the same
        // validation and normalization as `add()`: tenant-scoped metadata is
        // required and vectors are L2-normalized (zero-norm rows rejected).
        let mut parsed = Vec::new();
        for line in &lines {
            let mut v: EmbeddingVector = serde_json::from_str(line)?;
            if v.vector.len() != self.dimension {
                return Err(EmbeddingError::DimensionMismatch {
                    got: v.vector.len(),
                    expected: self.dimension,
                });
            }
            if metadata_tenant_id(&v.metadata).is_none() {
                return Err(EmbeddingError::MissingTenantScope);
            }
            if !has_nonzero_norm(&v.vector) {
                return Err(EmbeddingError::ZeroNormVector);
            }
            v.vector = crate::embeddings::l2_normalize(v.vector);
            parsed.push(v);
        }

        // Admit through the same capacity machinery as `add()`: LRU
        // eviction at the threshold, a hard stop at `max_vectors`. The old
        // raw `insert()` loop bypassed both caps, so restoring a snapshot
        // could exceed the memory budget the live path enforces. Once the
        // cap is reached the remaining rows are dropped (warn + truncated
        // count) rather than failing the whole restore.
        let mut imported = 0usize;
        for v in parsed {
            if self.inner.len() >= self.eviction_threshold {
                self.evict_lru();
            }
            if self.inner.len() >= self.max_vectors {
                warn!(
                    imported,
                    cap = self.max_vectors,
                    "NDJSON import hit max_vectors — remaining rows dropped"
                );
                break;
            }
            self.inner.insert(v.id, v);
            imported += 1;
        }

        Ok(imported)
    }

    /// Evict the oldest (least recently accessed) entries.
    fn evict_lru(&self) {
        let target = max(1, self.eviction_threshold / 10); // Remove 10%, at least 1
        let target = target.min(self.inner.len());

        // Collect all entries with their last_accessed times
        let mut entries: Vec<(Uuid, chrono::DateTime<Utc>)> =
            self.inner.iter().map(|v| (v.id, v.last_accessed)).collect();

        // Sort by access time (oldest first)
        entries.sort_by_key(|(_, ts)| *ts);

        for (id, _) in entries.iter().take(target) {
            self.inner.remove(id);
        }
    }

    /// Return a reference to the HMAC key (for testing).
    #[cfg(test)]
    pub fn hmac_key(&self) -> &[u8] {
        &self.hmac_key
    }

    /// Return the current number of entries in the store.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Compute HMAC-SHA256 hex digest over data.
fn compute_hmac(key: &[u8], data: &[u8]) -> Result<String, EmbeddingError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| EmbeddingError::MissingHmacKey)?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// RS-064: Constant-time comparison that does NOT leak length through timing.
/// Always iterates over both strings fully regardless of length difference.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let len_matches = a.len() == b.len();
    let mut result = 0u8;
    for (ca, cb) in a.bytes().zip(b.bytes().chain(std::iter::repeat(0))) {
        result |= ca ^ cb;
    }
    for cb in b.bytes().skip(a.len()) {
        result |= cb;
    }
    len_matches && result == 0
}

/// Min-heap entry for top-K search (inverted comparison).
struct MinScoreEntry {
    score: f64,
    id: Uuid,
    text: String,
    metadata: serde_json::Value,
}

impl PartialEq for MinScoreEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for MinScoreEntry {}

impl PartialOrd for MinScoreEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinScoreEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering for min-heap behavior
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embeddings::l2_normalize;

    fn make_store() -> VectorStore {
        VectorStore::new(3, 1000, 900, Vec::new())
    }

    fn make_store_with_hmac(key: &str) -> VectorStore {
        VectorStore::new(3, 1000, 900, key.as_bytes().to_vec())
    }

    fn tenant_metadata(tenant_id: &str) -> serde_json::Value {
        serde_json::json!({"tenant_id": tenant_id})
    }

    #[test]
    fn test_add_and_get() {
        let store = make_store();
        let id = store
            .add(
                "hello".into(),
                vec![1.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        let v = store.get(id).unwrap();
        assert_eq!(v.text, "hello");
        assert_eq!(v.vector, vec![1.0, 0.0, 0.0]);
    }

    #[test]
    fn test_add_dimension_mismatch() {
        let store = make_store();
        let err = store
            .add("bad".into(), vec![1.0, 2.0], tenant_metadata("tenant-a"))
            .unwrap_err();
        assert!(matches!(err, EmbeddingError::DimensionMismatch { .. }));
    }

    #[test]
    fn test_add_requires_tenant_scope() {
        let store = make_store();
        let err = store
            .add("bad".into(), vec![1.0, 0.0, 0.0], serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, EmbeddingError::MissingTenantScope));
    }

    #[test]
    fn test_remove() {
        let store = make_store();
        let id = store
            .add(
                "rm".into(),
                vec![1.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        assert!(store.remove(id));
        assert!(store.get(id).is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let store = make_store();
        assert!(!store.remove(Uuid::new_v4()));
    }

    #[test]
    fn test_search_top_k() {
        let store = make_store();
        store
            .add(
                "a".into(),
                l2_normalize(vec![1.0, 0.0, 0.0]),
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "b".into(),
                l2_normalize(vec![0.9, 0.1, 0.0]),
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "c".into(),
                l2_normalize(vec![0.0, 1.0, 0.0]),
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "d".into(),
                l2_normalize(vec![0.0, 0.0, 1.0]),
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = store.search(&query, 2, "tenant-a");

        assert_eq!(results.len(), 2);
        // Most similar should be "a" (identical direction)
        assert_eq!(results[0].text, "a");
        assert!(results[0].score > 0.9);
    }

    #[test]
    fn test_search_filters_by_tenant() {
        let store = make_store();
        store
            .add(
                "tenant-a-match".into(),
                l2_normalize(vec![1.0, 0.0, 0.0]),
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "tenant-b-match".into(),
                l2_normalize(vec![1.0, 0.0, 0.0]),
                tenant_metadata("tenant-b"),
            )
            .unwrap();

        let query = l2_normalize(vec![1.0, 0.0, 0.0]);
        let results = store.search(&query, 5, "tenant-a");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "tenant-a-match");
        assert_eq!(results[0].metadata["tenant_id"], "tenant-a");
    }

    #[test]
    fn test_search_empty_store() {
        let store = make_store();
        let results = store.search(&[1.0, 0.0, 0.0], 5, "tenant-a");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_wrong_dimension() {
        let store = make_store();
        store
            .add("a".into(), vec![1.0, 0.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        let results = store.search(&[1.0, 0.0], 5, "tenant-a"); // wrong dimension
        assert!(results.is_empty());
    }

    #[test]
    fn test_stats() {
        let store = make_store();
        store
            .add("a".into(), vec![1.0, 0.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("b".into(), vec![0.0, 1.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        let stats = store.stats();
        assert_eq!(stats.total_vectors, 2);
        assert_eq!(stats.dimension, 3);
        assert!(stats.memory_bytes > 0);
    }

    #[test]
    fn test_export_import_ndjson_without_hmac() {
        let store = make_store();
        store
            .add(
                "hello".into(),
                vec![1.0, 0.0, 0.0],
                serde_json::json!({"k":"v", "tenant_id":"tenant-a"}),
            )
            .unwrap();
        store
            .add(
                "world".into(),
                vec![0.0, 1.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        let mut buf = Vec::new();
        let exported = store.export_ndjson(&mut buf).unwrap();
        assert_eq!(exported, 2);

        let store2 = make_store();
        let imported = store2
            .import_ndjson(std::io::BufReader::new(buf.as_slice()))
            .unwrap();
        assert_eq!(imported, 2);
        assert_eq!(store2.stats().total_vectors, 2);
    }

    #[test]
    fn test_export_import_ndjson_with_hmac() {
        let key = "my-32-byte-test-secret-key!!";
        let store = make_store_with_hmac(key);
        store
            .add(
                "hello".into(),
                vec![1.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "world".into(),
                vec![0.0, 1.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        let mut buf = Vec::new();
        let exported = store.export_ndjson(&mut buf).unwrap();
        assert_eq!(exported, 2);

        // Verify the HMAC line was written
        let output = String::from_utf8(buf.clone()).unwrap();
        assert!(output.contains(HMAC_HEADER_PREFIX));

        // Import into a new store with the same key
        let store2 = make_store_with_hmac(key);
        let imported = store2
            .import_ndjson(std::io::BufReader::new(buf.as_slice()))
            .unwrap();
        assert_eq!(imported, 2);
        assert_eq!(store2.stats().total_vectors, 2);
    }

    #[test]
    fn test_import_with_hmac_key_mismatch_fails() {
        let key = "my-32-byte-test-secret-key!!";
        let store = make_store_with_hmac(key);
        store
            .add(
                "data".into(),
                vec![1.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        let mut buf = Vec::new();
        store.export_ndjson(&mut buf).unwrap();

        // Try importing with a different key
        let store2 = make_store_with_hmac("different-key-here-32-bytes!!");
        let result = store2.import_ndjson(std::io::BufReader::new(buf.as_slice()));
        assert!(result.is_err());
        assert!(matches!(result, Err(EmbeddingError::IntegrityCheckFailed)));
    }

    #[test]
    fn test_import_tampered_data_fails() {
        let key = "my-32-byte-test-secret-key!!";
        let store = make_store_with_hmac(key);
        store
            .add(
                "data".into(),
                vec![1.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        let mut buf = Vec::new();
        store.export_ndjson(&mut buf).unwrap();

        // Tamper with the data
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            buf[pos + 1] = b'X'; // modify first byte after newline
        }

        let store2 = make_store_with_hmac(key);
        let result = store2.import_ndjson(std::io::BufReader::new(buf.as_slice()));
        assert!(result.is_err());
        assert!(matches!(result, Err(EmbeddingError::IntegrityCheckFailed)));
    }

    #[test]
    fn test_batch_add() {
        let store = make_store();
        let items = vec![
            ("a".into(), vec![1.0, 0.0, 0.0], tenant_metadata("tenant-a")),
            ("b".into(), vec![0.0, 1.0, 0.0], tenant_metadata("tenant-a")),
            ("c".into(), vec![0.0, 0.0, 1.0], tenant_metadata("tenant-a")),
        ];
        let ids = store.add_batch(items).unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(store.stats().total_vectors, 3);
    }

    #[test]
    fn test_store_full() {
        let store = VectorStore::new(2, 2, 3, Vec::new()); // max 2 vectors, eviction at 3
        store
            .add("a".into(), vec![1.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("b".into(), vec![0.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap();
        let err = store
            .add("c".into(), vec![1.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap_err();
        assert!(matches!(err, EmbeddingError::StoreFull { .. }));
    }

    #[test]
    fn test_lru_eviction() {
        let store = VectorStore::new(2, 100, 3, Vec::new());
        store
            .add("a".into(), vec![1.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("b".into(), vec![0.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("c".into(), vec![1.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap();
        let stats = store.stats();
        assert!(stats.total_vectors <= 100);
    }

    #[test]
    fn test_dashmap_concurrent_access() {
        use std::thread;
        let store = std::sync::Arc::new(VectorStore::new(3, 10000, 8000, Vec::new()));
        let mut handles = Vec::new();

        // Spawn 4 threads that each add 100 vectors
        for t in 0..4 {
            let store = store.clone();
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let text = format!("thread-{t}-vec-{i}");
                    let tenant = format!("tenant-{}", t % 2);
                    let _ = store.add(
                        text,
                        l2_normalize(vec![1.0, 0.0, 0.0]),
                        serde_json::json!({"tenant_id": tenant}),
                    );
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(store.stats().total_vectors, 400);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn add_normalizes_stored_vectors() {
        let store = make_store();
        let id = store
            .add(
                "big".into(),
                vec![3.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        let stored = store.get(id).unwrap();
        let norm: f32 = stored.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-5,
            "stored vectors must be unit norm"
        );
    }

    #[test]
    fn add_rejects_zero_norm_vectors() {
        let store = make_store();
        let err = store
            .add(
                "zero".into(),
                vec![0.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap_err();
        assert!(matches!(err, EmbeddingError::ZeroNormVector));
    }

    #[test]
    fn unnormalized_query_scores_stay_within_unit_range() {
        let store = make_store();
        store
            .add("a".into(), vec![9.0, 0.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add(
                "b".into(),
                vec![0.0, 25.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();
        store
            .add(
                "opposite".into(),
                vec![-40.0, 0.0, 0.0],
                tenant_metadata("tenant-a"),
            )
            .unwrap();

        // Deliberately unnormalized query with a large magnitude.
        let results = store.search(&[500.0, 0.0, 0.0], 3, "tenant-a");
        assert!(!results.is_empty());
        for r in &results {
            assert!(
                (-1.0..=1.0).contains(&r.score),
                "cosine score {} outside [-1, 1] — query was not normalized",
                r.score
            );
        }
        // Zero-norm queries are rejected outright.
        assert!(store.search(&[0.0, 0.0, 0.0], 3, "tenant-a").is_empty());
    }

    #[test]
    fn import_ndjson_validates_tenant_scope_and_normalizes() {
        let store = make_store();
        // Hand-crafted NDJSON with an unnormalized vector and a tenant scope.
        let id = Uuid::new_v4();
        let line = serde_json::json!({
            "id": id,
            "text": "imported",
            "vector": [5.0, 0.0, 0.0],
            "metadata": {"tenant_id": "tenant-a"},
            "created_at": Utc::now(),
            "last_accessed": Utc::now(),
        });
        let mut buf = Vec::new();
        writeln!(buf, "{}", line).unwrap();
        let imported = store
            .import_ndjson(std::io::BufReader::new(buf.as_slice()))
            .unwrap();
        assert_eq!(imported, 1);
        let stored = store.get(id).unwrap();
        let norm: f32 = stored.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-5,
            "imported vector must be normalized"
        );

        // Rows without tenant scope must be refused.
        let bad = serde_json::json!({
            "id": Uuid::new_v4(),
            "text": "orphan",
            "vector": [1.0, 0.0, 0.0],
            "metadata": {},
            "created_at": Utc::now(),
            "last_accessed": Utc::now(),
        });
        let mut buf2 = Vec::new();
        writeln!(buf2, "{}", bad).unwrap();
        let result = store.import_ndjson(std::io::BufReader::new(buf2.as_slice()));
        assert!(matches!(result, Err(EmbeddingError::MissingTenantScope)));
    }
}
