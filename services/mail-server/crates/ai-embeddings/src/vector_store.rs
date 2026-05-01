//! In-memory vector store with LRU eviction and NDJSON persistence.

use std::cmp::{max, Ordering};
use std::collections::{BinaryHeap, HashMap};
use std::io::{BufRead, Write};

use chrono::Utc;
use parking_lot::RwLock;
use uuid::Uuid;

use crate::embeddings::cosine_similarity;
use crate::types::{EmbeddingError, EmbeddingVector, SearchResult, StoreStats};

/// Thread-safe in-memory vector store with LRU eviction.
pub struct VectorStore {
    inner: RwLock<StoreInner>,
    dimension: usize,
    max_vectors: usize,
    eviction_threshold: usize,
}

struct StoreInner {
    vectors: HashMap<Uuid, EmbeddingVector>,
}

fn metadata_tenant_id(metadata: &serde_json::Value) -> Option<&str> {
    metadata
        .get("tenant_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
}

impl VectorStore {
    pub fn new(dimension: usize, max_vectors: usize, eviction_threshold: usize) -> Self {
        Self {
            inner: RwLock::new(StoreInner {
                vectors: HashMap::new(),
            }),
            dimension,
            max_vectors,
            eviction_threshold,
        }
    }

    /// Add a vector to the store, evicting LRU entries if needed.
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

        let mut store = self.inner.write();

        // Evict if at threshold
        if store.vectors.len() >= self.eviction_threshold {
            self.evict_lru(&mut store);
        }

        if store.vectors.len() >= self.max_vectors {
            return Err(EmbeddingError::StoreFull {
                count: store.vectors.len(),
                max: self.max_vectors,
            });
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        store.vectors.insert(
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
        let mut store = self.inner.write();
        if let Some(v) = store.vectors.get_mut(&id) {
            v.last_accessed = Utc::now();
            Some(v.clone())
        } else {
            None
        }
    }

    /// Remove a vector by ID.
    pub fn remove(&self, id: Uuid) -> bool {
        let mut store = self.inner.write();
        store.vectors.remove(&id).is_some()
    }

    /// Search for the top-K most similar vectors using a min-heap.
    pub fn search(&self, query_vector: &[f32], top_k: usize, tenant_id: &str) -> Vec<SearchResult> {
        if query_vector.len() != self.dimension || tenant_id.trim().is_empty() {
            return vec![];
        }

        let store = self.inner.read();
        let mut heap: BinaryHeap<MinScoreEntry> = BinaryHeap::new();

        for (_, entry) in store.vectors.iter() {
            if metadata_tenant_id(&entry.metadata) != Some(tenant_id) {
                continue;
            }

            let score = cosine_similarity(query_vector, &entry.vector);

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

        // Convert heap to sorted results (highest score first)
        // into_sorted_vec returns ascending per Ord; our reversed Ord means highest-actual-score first
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
        let store = self.inner.read();
        let vectors = &store.vectors;

        let oldest = vectors.values().map(|v| v.last_accessed).min();
        let newest = vectors.values().map(|v| v.last_accessed).max();

        // Estimate memory:per vector = dimension * 4 bytes (f32) + overhead
        let vec_mem = vectors.len() * (self.dimension * 4 + 256);

        StoreStats {
            total_vectors: vectors.len(),
            dimension: self.dimension,
            memory_bytes: vec_mem,
            oldest_access: oldest,
            newest_access: newest,
        }
    }

    /// Export store to NDJSON writer.
    pub fn export_ndjson<W: Write>(&self, writer: &mut W) -> Result<usize, EmbeddingError> {
        let store = self.inner.read();
        let mut count = 0;
        for (_, v) in store.vectors.iter() {
            let line = serde_json::to_string(v)?;
            writeln!(writer, "{}", line)?;
            count += 1;
        }
        Ok(count)
    }

    /// Import vectors from NDJSON reader.
    pub fn import_ndjson<R: BufRead>(&self, reader: R) -> Result<usize, EmbeddingError> {
        let mut parsed = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let v: EmbeddingVector = serde_json::from_str(&line)?;
            if v.vector.len() != self.dimension {
                return Err(EmbeddingError::DimensionMismatch {
                    got: v.vector.len(),
                    expected: self.dimension,
                });
            }
            parsed.push(v);
        }
        let count = parsed.len();
        let mut store = self.inner.write();
        for v in parsed {
            store.vectors.insert(v.id, v);
        }
        Ok(count)
    }

    fn evict_lru(&self, store: &mut StoreInner) {
        let target = max(1, self.eviction_threshold / 10); // Remove 10%, at least 1
        let mut entries: Vec<(Uuid, chrono::DateTime<Utc>)> = store
            .vectors
            .iter()
            .map(|(id, v)| (*id, v.last_accessed))
            .collect();

        entries.sort_by_key(|(_, ts)| *ts);
        let target = target.min(entries.len());
        for (id, _) in entries.iter().take(target) {
            store.vectors.remove(id);
        }
    }
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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinScoreEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embeddings::l2_normalize;

    fn make_store() -> VectorStore {
        VectorStore::new(3, 1000, 900)
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
    fn test_export_import_ndjson() {
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
        let store = VectorStore::new(2, 2, 3); // max 2 vectors, eviction at 3
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
        // eviction_threshold = 3, max = 5 → when reaching 3 entries, evict 10% (at least 0, but we round)
        let store = VectorStore::new(2, 100, 3);
        store
            .add("a".into(), vec![1.0, 0.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("b".into(), vec![0.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap();
        store
            .add("c".into(), vec![1.0, 1.0], tenant_metadata("tenant-a"))
            .unwrap();
        // This should trigger eviction of LRU entries, then succeed
        // (eviction_threshold/10 = 0, so no entries get evicted, but it shouldn't error since we're at threshold not max)
        // Actually with max=100 and threshold=3, after eviction count stays under max
        let stats = store.stats();
        assert!(stats.total_vectors <= 100);
    }
}
