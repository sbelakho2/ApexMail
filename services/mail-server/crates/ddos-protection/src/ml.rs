//! Machine Learning anomaly detection using Isolation Forest
//!
//! Provides real-time anomaly scoring for traffic patterns to detect
//! zero-day attacks and behavioral anomalies.

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::collections::VecDeque;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Deserialize, Serialize};

/// Feature vector for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Request rate (requests per second)
    pub request_rate: f64,
    /// Bytes rate (bytes per second)
    pub bytes_rate: f64,
    /// Connection age (seconds)
    pub connection_age: f64,
    /// Request size variance
    pub size_variance: f64,
    /// Inter-arrival time mean
    pub iat_mean: f64,
    /// Inter-arrival time variance
    pub iat_variance: f64,
    /// Endpoint diversity (unique endpoints / total requests)
    pub endpoint_diversity: f64,
    /// Error rate
    pub error_rate: f64,
    /// Geographic distance from normal
    pub geo_distance: f64,
    /// Time-of-day factor (0-1, distance from normal patterns)
    pub time_factor: f64,
}

impl FeatureVector {
    /// Create a new feature vector
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Convert to slice for tree operations
    pub fn as_slice(&self) -> [f64; 10] {
        [
            self.request_rate,
            self.bytes_rate,
            self.connection_age,
            self.size_variance,
            self.iat_mean,
            self.iat_variance,
            self.endpoint_diversity,
            self.error_rate,
            self.geo_distance,
            self.time_factor,
        ]
    }
    
    /// Create from slice
    pub fn from_slice(data: &[f64; 10]) -> Self {
        Self {
            request_rate: data[0],
            bytes_rate: data[1],
            connection_age: data[2],
            size_variance: data[3],
            iat_mean: data[4],
            iat_variance: data[5],
            endpoint_diversity: data[6],
            error_rate: data[7],
            geo_distance: data[8],
            time_factor: data[9],
        }
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self {
            request_rate: 0.0,
            bytes_rate: 0.0,
            connection_age: 0.0,
            size_variance: 0.0,
            iat_mean: 0.0,
            iat_variance: 0.0,
            endpoint_diversity: 0.0,
            error_rate: 0.0,
            geo_distance: 0.0,
            time_factor: 0.0,
        }
    }
}

/// A node in an Isolation Tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationNode {
    /// Internal node with split
    Internal {
        /// Feature index to split on
        feature_idx: usize,
        /// Split value
        split_value: f64,
        /// Left child (< split_value)
        left: Box<IsolationNode>,
        /// Right child (>= split_value)
        right: Box<IsolationNode>,
    },
    /// Leaf node
    Leaf {
        /// Size of the subsample that reached this leaf
        size: usize,
    },
}

impl IsolationNode {
    /// Calculate the path length for a sample
    pub fn path_length(&self, sample: &[f64], current_depth: usize) -> f64 {
        match self {
            IsolationNode::Internal { feature_idx, split_value, left, right } => {
                if sample[*feature_idx] < *split_value {
                    left.path_length(sample, current_depth + 1)
                } else {
                    right.path_length(sample, current_depth + 1)
                }
            }
            IsolationNode::Leaf { size } => {
                // Add expected path length for remaining samples
                current_depth as f64 + c_factor(*size)
            }
        }
    }
}

/// Isolation Tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationTree {
    /// Root node
    root: IsolationNode,
    /// Maximum depth of the tree
    max_depth: usize,
    /// Number of features
    num_features: usize,
}

impl IsolationTree {
    /// Build an isolation tree from samples
    pub fn build(samples: &[[f64; 10]], max_depth: usize, rng: &mut StdRng) -> Self {
        let num_features = 10;
        let root = Self::build_node(samples, 0, max_depth, num_features, rng);
        
        Self {
            root,
            max_depth,
            num_features,
        }
    }
    
    fn build_node(
        samples: &[[f64; 10]],
        depth: usize,
        max_depth: usize,
        num_features: usize,
        rng: &mut StdRng,
    ) -> IsolationNode {
        // Stop conditions
        if depth >= max_depth || samples.len() <= 1 {
            return IsolationNode::Leaf { size: samples.len() };
        }
        
        // Random feature selection
        let feature_idx = rng.gen_range(0..num_features);
        
        // Get min/max for this feature
        let mut min_val = f64::MAX;
        let mut max_val = f64::MIN;
        for sample in samples {
            if sample[feature_idx] < min_val {
                min_val = sample[feature_idx];
            }
            if sample[feature_idx] > max_val {
                max_val = sample[feature_idx];
            }
        }
        
        // If all values are the same, make a leaf
        if (max_val - min_val).abs() < f64::EPSILON {
            return IsolationNode::Leaf { size: samples.len() };
        }
        
        // Random split value
        let split_value = rng.gen_range(min_val..max_val);
        
        // Partition samples
        let (left_samples, right_samples): (Vec<_>, Vec<_>) = samples
            .iter()
            .cloned()
            .partition(|s| s[feature_idx] < split_value);
        
        // If partition is degenerate, make a leaf
        if left_samples.is_empty() || right_samples.is_empty() {
            return IsolationNode::Leaf { size: samples.len() };
        }
        
        // Recursively build children
        let left = Self::build_node(&left_samples, depth + 1, max_depth, num_features, rng);
        let right = Self::build_node(&right_samples, depth + 1, max_depth, num_features, rng);
        
        IsolationNode::Internal {
            feature_idx,
            split_value,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    
    /// Calculate path length for a sample
    pub fn path_length(&self, sample: &[f64; 10]) -> f64 {
        self.root.path_length(sample, 0)
    }
}

/// Isolation Forest for anomaly detection
pub struct IsolationForest {
    /// Collection of trees
    trees: Vec<IsolationTree>,
    /// Number of samples used for training
    sample_size: usize,
    /// Configuration
    config: IsolationForestConfig,
    /// Training data buffer (for online learning) — VecDeque for O(1) pop_front
    training_buffer: RwLock<VecDeque<[f64; 10]>>,
    /// Number of samples in the buffer at the time of last training.
    /// Used by needs_retraining() to detect when enough NEW data has
    /// accumulated since the last training (not just since startup).
    samples_at_last_training: AtomicUsize,
}

/// Configuration for Isolation Forest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForestConfig {
    /// Number of trees in the forest
    pub num_trees: usize,
    /// Sample size for each tree
    pub sample_size: usize,
    /// Maximum tree depth
    pub max_depth: usize,
    /// Anomaly threshold (0-1, higher = more anomalous)
    pub anomaly_threshold: f64,
    /// Online learning buffer size
    pub online_buffer_size: usize,
    /// Retrain threshold (fraction of buffer to fill before retraining)
    pub retrain_threshold: f64,
}

impl Default for IsolationForestConfig {
    fn default() -> Self {
        Self {
            num_trees: 100,
            sample_size: 256,
            max_depth: 8, // ceil(log2(256))
            anomaly_threshold: 0.7,
            online_buffer_size: 10000,
            retrain_threshold: 0.5,
        }
    }
}

impl IsolationForest {
    /// Create a new, untrained Isolation Forest
    pub fn new(config: IsolationForestConfig) -> Self {
        Self {
            trees: Vec::new(),
            sample_size: config.sample_size,
            config,
            training_buffer: RwLock::new(VecDeque::new()),
            samples_at_last_training: AtomicUsize::new(0),
        }
    }
    
    /// Train the forest on a dataset
    pub fn train(&mut self, data: &[[f64; 10]], seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        
        let sample_size = self.config.sample_size.min(data.len());
        self.sample_size = sample_size;
        
        self.trees.clear();
        
        for _ in 0..self.config.num_trees {
            // Sample data for this tree
            let sample_indices: Vec<usize> = (0..sample_size)
                .map(|_| rng.gen_range(0..data.len()))
                .collect();
            
            let samples: Vec<[f64; 10]> = sample_indices
                .iter()
                .map(|&i| data[i])
                .collect();
            
            let tree = IsolationTree::build(&samples, self.config.max_depth, &mut rng);
            self.trees.push(tree);
        }
    }
    
    /// Calculate anomaly score for a sample (0-1, higher = more anomalous)
    pub fn anomaly_score(&self, features: &FeatureVector) -> f64 {
        if self.trees.is_empty() {
            return 0.5; // Untrained, return neutral
        }
        
        let sample = features.as_slice();
        
        // Calculate average path length
        let avg_path_length: f64 = self.trees.iter()
            .map(|tree| tree.path_length(&sample))
            .sum::<f64>() / self.trees.len() as f64;
        
        // Normalize to [0, 1] using the expected path length formula
        let c = c_factor(self.sample_size);
        
        // Guard against division by zero when sample_size <= 1
        // (c_factor returns 0.0 for n <= 1)
        if c <= 0.0 {
            return 0.5; // Return neutral if model was trained with insufficient data
        }
        
        // Anomaly score: 2^(-path_length / c)
        // Short paths (anomalies) -> score close to 1
        // Long paths (normal) -> score close to 0
        let score = 2.0_f64.powf(-avg_path_length / c);
        
        score
    }
    
    /// Check if a sample is anomalous
    pub fn is_anomalous(&self, features: &FeatureVector) -> bool {
        self.anomaly_score(features) > self.config.anomaly_threshold
    }
    
    /// Add sample to training buffer for online learning.
    /// Uses VecDeque for O(1) eviction of oldest entries instead of
    /// Vec::remove(0) which was O(n).
    /// 
    /// Under high load (100K+ RPS), this method uses try_write() to avoid
    /// blocking on lock contention. Dropped samples are acceptable for
    /// online learning as long as the buffer eventually fills.
    pub fn observe(&self, features: &FeatureVector) {
        let sample = features.as_slice();
        
        // Use try_write to avoid blocking under high contention.
        // If the lock is held (e.g., during retrain), skip this observation.
        // Online learning is robust to occasional dropped samples.
        let mut buffer = match self.training_buffer.try_write() {
            Some(guard) => guard,
            None => return, // Lock held elsewhere, skip this sample
        };
        
        buffer.push_back(sample);
        
        // Evict oldest if over capacity (O(1) with VecDeque)
        if buffer.len() > self.config.online_buffer_size {
            buffer.pop_front();
        }
    }
    
    /// Check if retraining is needed.
    /// Returns true when enough NEW samples have been added since the last
    /// training (or since startup if never trained). Previously this checked
    /// `self.trees.is_empty()` which meant it never triggered after the
    /// first training, breaking the online learning loop.
    pub fn needs_retraining(&self) -> bool {
        let buffer = self.training_buffer.read();
        let last = self.samples_at_last_training.load(Ordering::Relaxed);
        let new_samples = buffer.len().saturating_sub(last);
        let threshold_size = (self.config.online_buffer_size as f64 * self.config.retrain_threshold) as usize;
        
        new_samples >= threshold_size
    }
    
    /// Retrain on buffered data
    pub fn retrain(&mut self, seed: u64) {
        let buffer = self.training_buffer.read();
        if buffer.len() < 10 {
            return; // Not enough data
        }
        
        let data: Vec<[f64; 10]> = buffer.iter().cloned().collect();
        let current_len = buffer.len();
        drop(buffer); // Release lock before training
        
        self.train(&data, seed);
        self.samples_at_last_training.store(current_len, Ordering::Relaxed);
    }
    
    /// Get model statistics
    pub fn stats(&self) -> IsolationForestStats {
        let buffer_size = self.training_buffer.read().len();
        
        IsolationForestStats {
            num_trees: self.trees.len(),
            sample_size: self.sample_size,
            training_buffer_size: buffer_size,
            is_trained: !self.trees.is_empty(),
        }
    }

    /// Serialize the trained model (trees + config) to a JSON byte vector
    /// for persistence across restarts.
    ///
    /// Call this after `train()` or `retrain()` and write the bytes to a file
    /// or object store. On next startup, use [`Self::restore_snapshot`] to
    /// warm-start the model instead of waiting for the online buffer to fill.
    ///
    /// Returns `None` if no trees have been trained yet.
    pub fn snapshot(&self) -> Option<Vec<u8>> {
        if self.trees.is_empty() {
            return None;
        }
        let snap = ModelSnapshot {
            trees: self.trees.clone(),
            sample_size: self.sample_size,
            config: self.config.clone(),
        };
        serde_json::to_vec(&snap).ok()
    }

    /// Restore a model from a previously saved snapshot.
    ///
    /// This replaces the current trees and configuration, allowing the model
    /// to start scoring immediately without waiting for online learning data.
    /// The training buffer is NOT restored — new observations will accumulate
    /// and eventually trigger a `retrain()` that incorporates fresh data.
    pub fn restore_snapshot(snapshot_bytes: &[u8]) -> Option<Self> {
        let snap: ModelSnapshot = serde_json::from_slice(snapshot_bytes).ok()?;
        Some(Self {
            trees: snap.trees,
            sample_size: snap.sample_size,
            config: snap.config.clone(),
            training_buffer: RwLock::new(VecDeque::new()),
            samples_at_last_training: AtomicUsize::new(0),
        })
    }
}

/// Serializable snapshot of a trained Isolation Forest model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSnapshot {
    /// Trained trees
    pub trees: Vec<IsolationTree>,
    /// Sample size used for training
    pub sample_size: usize,
    /// Configuration at time of snapshot
    pub config: IsolationForestConfig,
}

/// Model statistics
#[derive(Debug, Clone)]
pub struct IsolationForestStats {
    /// Number of trees
    pub num_trees: usize,
    /// Sample size per tree
    pub sample_size: usize,
    /// Current training buffer size
    pub training_buffer_size: usize,
    /// Whether model is trained
    pub is_trained: bool,
}

/// Expected path length adjustment factor
/// c(n) = 2H(n-1) - 2(n-1)/n where H is the harmonic number
fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    
    let n_f = n as f64;
    
    // H(n-1) approximation using Euler-Mascheroni constant
    let h_n_minus_1 = (n_f - 1.0).ln() + 0.5772156649;
    
    2.0 * h_n_minus_1 - (2.0 * (n_f - 1.0) / n_f)
}

/// Ensemble model combining multiple detection methods
pub struct AnomalyEnsemble {
    /// Isolation Forest
    isolation_forest: IsolationForest,
    /// Statistical thresholds
    stat_thresholds: StatisticalThresholds,
    /// Ensemble weights
    weights: EnsembleWeights,
}

/// Statistical threshold configuration
#[derive(Debug, Clone)]
pub struct StatisticalThresholds {
    /// Max requests per second before suspicious
    pub max_rps: f64,
    /// Max bytes per second
    pub max_bps: f64,
    /// Min inter-arrival time (ms)
    pub min_iat_ms: f64,
    /// Max error rate
    pub max_error_rate: f64,
    /// Min endpoint diversity
    pub min_endpoint_diversity: f64,
}

impl Default for StatisticalThresholds {
    fn default() -> Self {
        Self {
            max_rps: 100.0,
            max_bps: 10_000_000.0, // 10 MB/s
            min_iat_ms: 10.0,
            max_error_rate: 0.5,
            min_endpoint_diversity: 0.1,
        }
    }
}

/// Ensemble component weights
#[derive(Debug, Clone)]
pub struct EnsembleWeights {
    /// Weight for Isolation Forest score
    pub isolation_forest: f64,
    /// Weight for statistical anomaly
    pub statistical: f64,
}

impl Default for EnsembleWeights {
    fn default() -> Self {
        Self {
            isolation_forest: 0.7,
            statistical: 0.3,
        }
    }
}

impl AnomalyEnsemble {
    /// Create new ensemble
    pub fn new(
        if_config: IsolationForestConfig,
        thresholds: StatisticalThresholds,
        weights: EnsembleWeights,
    ) -> Self {
        Self {
            isolation_forest: IsolationForest::new(if_config),
            stat_thresholds: thresholds,
            weights,
        }
    }
    
    /// Calculate statistical anomaly score
    fn statistical_score(&self, features: &FeatureVector) -> f64 {
        let mut score = 0.0;
        let mut count = 0;
        
        // Check each threshold
        if features.request_rate > self.stat_thresholds.max_rps {
            score += (features.request_rate / self.stat_thresholds.max_rps).min(1.0);
            count += 1;
        }
        
        if features.bytes_rate > self.stat_thresholds.max_bps {
            score += (features.bytes_rate / self.stat_thresholds.max_bps).min(1.0);
            count += 1;
        }
        
        if features.iat_mean < self.stat_thresholds.min_iat_ms && features.iat_mean > 0.0 {
            score += (self.stat_thresholds.min_iat_ms / features.iat_mean).min(1.0);
            count += 1;
        }
        
        if features.error_rate > self.stat_thresholds.max_error_rate {
            score += 1.0;
            count += 1;
        }
        
        if features.endpoint_diversity < self.stat_thresholds.min_endpoint_diversity 
            && features.endpoint_diversity > 0.0 {
            score += 1.0;
            count += 1;
        }
        
        if count > 0 {
            (score / count as f64).min(1.0)
        } else {
            0.0
        }
    }
    
    /// Calculate combined anomaly score
    pub fn anomaly_score(&self, features: &FeatureVector) -> f64 {
        let if_score = self.isolation_forest.anomaly_score(features);
        let stat_score = self.statistical_score(features);
        
        // Weighted combination
        let combined = self.weights.isolation_forest * if_score 
            + self.weights.statistical * stat_score;
        
        combined.min(1.0)
    }
    
    /// Train the ensemble
    pub fn train(&mut self, data: &[[f64; 10]], seed: u64) {
        self.isolation_forest.train(data, seed);
    }
    
    /// Observe for online learning
    pub fn observe(&self, features: &FeatureVector) {
        self.isolation_forest.observe(features);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn generate_normal_samples(count: usize, rng: &mut StdRng) -> Vec<[f64; 10]> {
        (0..count)
            .map(|_| {
                [
                    rng.gen_range(1.0..10.0),   // request_rate
                    rng.gen_range(1000.0..50000.0), // bytes_rate
                    rng.gen_range(1.0..300.0),  // connection_age
                    rng.gen_range(100.0..1000.0), // size_variance
                    rng.gen_range(50.0..500.0), // iat_mean
                    rng.gen_range(10.0..100.0), // iat_variance
                    rng.gen_range(0.3..0.9),    // endpoint_diversity
                    rng.gen_range(0.0..0.05),   // error_rate
                    rng.gen_range(0.0..100.0),  // geo_distance
                    rng.gen_range(0.0..0.5),    // time_factor
                ]
            })
            .collect()
    }
    
    #[test]
    fn test_isolation_forest_training() {
        let mut rng = StdRng::seed_from_u64(42);
        let data = generate_normal_samples(500, &mut rng);
        
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        
        forest.train(&data, 42);
        
        assert!(!forest.trees.is_empty());
    }
    
    #[test]
    fn test_anomaly_detection() {
        let mut rng = StdRng::seed_from_u64(42);
        let data = generate_normal_samples(500, &mut rng);
        
        let config = IsolationForestConfig::default();
        let mut forest = IsolationForest::new(config);
        forest.train(&data, 42);
        
        // Normal sample should have low anomaly score
        let normal = FeatureVector {
            request_rate: 5.0,
            bytes_rate: 20000.0,
            connection_age: 100.0,
            size_variance: 500.0,
            iat_mean: 200.0,
            iat_variance: 50.0,
            endpoint_diversity: 0.6,
            error_rate: 0.02,
            geo_distance: 50.0,
            time_factor: 0.2,
        };
        
        let normal_score = forest.anomaly_score(&normal);
        
        // Anomalous sample should have high anomaly score
        let anomalous = FeatureVector {
            request_rate: 1000.0,     // Very high
            bytes_rate: 10000000.0,   // Very high
            connection_age: 0.5,       // Very short
            size_variance: 0.1,        // Suspiciously uniform
            iat_mean: 0.5,            // Very fast
            iat_variance: 0.01,        // Very uniform
            endpoint_diversity: 0.01,  // Single endpoint
            error_rate: 0.8,          // High errors
            geo_distance: 10000.0,    // Unusual location
            time_factor: 1.0,         // Unusual time
        };
        
        let anomalous_score = forest.anomaly_score(&anomalous);
        
        // Anomalous should have higher score than normal
        assert!(anomalous_score > normal_score, 
            "anomalous: {}, normal: {}", anomalous_score, normal_score);
    }
    
    #[test]
    fn test_c_factor() {
        // Known values
        assert!(c_factor(1) == 0.0);
        assert!(c_factor(2) > 0.0);
        assert!(c_factor(256) > c_factor(2));
    }
    
    #[test]
    fn test_ensemble() {
        let mut rng = StdRng::seed_from_u64(42);
        let data = generate_normal_samples(500, &mut rng);
        
        let mut ensemble = AnomalyEnsemble::new(
            IsolationForestConfig::default(),
            StatisticalThresholds::default(),
            EnsembleWeights::default(),
        );
        
        ensemble.train(&data, 42);
        
        let normal = FeatureVector::default();
        let score = ensemble.anomaly_score(&normal);
        
        assert!(score >= 0.0 && score <= 1.0);
    }
}
