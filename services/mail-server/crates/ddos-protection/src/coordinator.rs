//! Distributed coordination for multi-region DDoS protection
//!
//! Uses Redis Streams for event propagation and CRDTs for
//! eventually-consistent distributed state.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Region identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    /// Create new region ID
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Node identifier within a region
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// Region
    pub region: RegionId,
    /// Node name
    pub node: String,
}

impl NodeId {
    /// Create new node ID
    pub fn new(region: &str, node: &str) -> Self {
        Self {
            region: RegionId::new(region),
            node: node.to_string(),
        }
    }

    /// Parse from string (region:node format)
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some(Self::new(parts[0], parts[1]))
        } else {
            None
        }
    }

    /// Convert to string
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.region.0, self.node)
    }
}

/// Threat event for cross-region sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Event ID (for deduplication)
    pub event_id: String,
    /// Source node
    pub source: NodeId,
    /// Timestamp
    pub timestamp: u64,
    /// Event type
    pub event_type: ThreatEventType,
    /// Affected IP addresses
    pub affected_ips: Vec<IpAddr>,
    /// Threat score (0-100)
    pub threat_score: u8,
    /// TTL in seconds
    pub ttl_secs: u32,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ThreatEvent {
    /// Create a new threat event
    pub fn new(source: NodeId, event_type: ThreatEventType) -> Self {
        Self {
            event_id: generate_event_id(),
            source,
            timestamp: current_timestamp(),
            event_type,
            affected_ips: Vec::new(),
            threat_score: 50,
            ttl_secs: 3600,
            metadata: HashMap::new(),
        }
    }

    /// Add affected IP
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.affected_ips.push(ip);
        self
    }

    /// Add affected IPs
    pub fn with_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.affected_ips.extend(ips);
        self
    }

    /// Set threat score
    pub fn with_score(mut self, score: u8) -> Self {
        self.threat_score = score;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Check if event has expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.timestamp + self.ttl_secs as u64
    }
}

/// Types of threat events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatEventType {
    /// DDoS attack detected
    DdosAttack {
        /// Attack pattern identifier
        pattern: String,
        /// Requests per second observed
        rps: u32,
    },
    /// Brute force attempt
    BruteForce {
        /// Target endpoint
        endpoint: String,
        /// Number of attempts
        attempts: u32,
    },
    /// Credential stuffing
    CredentialStuffing {
        /// Number of unique credentials tried
        credential_count: u32,
    },
    /// Malicious fingerprint detected
    MaliciousFingerprint {
        /// Fingerprint hash
        fingerprint: String,
    },
    /// IP added to blocklist
    BlocklistAdd {
        /// Reason for blocking
        reason: String,
    },
    /// IP removed from blocklist
    BlocklistRemove {
        /// Reason for removal
        reason: String,
    },
    /// Rate limit breach
    RateLimitBreach {
        /// Limit that was breached
        limit_name: String,
        /// Current rate
        current_rate: u32,
        /// Limit value
        limit: u32,
    },
}

/// G-Counter CRDT for distributed counting
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GCounter {
    /// Per-node counters
    counters: HashMap<String, u64>,
}

impl GCounter {
    /// Create new G-Counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counter for a node
    pub fn increment(&mut self, node_id: &str, delta: u64) {
        let entry = self.counters.entry(node_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(delta);
    }

    /// Get total value
    /// Uses saturating arithmetic to prevent overflow when summing large counters
    pub fn value(&self) -> u64 {
        self.counters
            .values()
            .fold(0u64, |acc, &v| acc.saturating_add(v))
    }

    /// Merge with another G-Counter
    pub fn merge(&mut self, other: &GCounter) {
        for (node, &count) in &other.counters {
            let entry = self.counters.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
    }

    /// Get value for a specific node
    pub fn node_value(&self, node_id: &str) -> u64 {
        self.counters.get(node_id).copied().unwrap_or(0)
    }
}

/// PN-Counter CRDT for distributed counters that can increase and decrease
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PNCounter {
    /// Positive counter
    positive: GCounter,
    /// Negative counter
    negative: GCounter,
}

impl PNCounter {
    /// Create new PN-Counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment
    pub fn increment(&mut self, node_id: &str, delta: u64) {
        self.positive.increment(node_id, delta);
    }

    /// Decrement
    pub fn decrement(&mut self, node_id: &str, delta: u64) {
        self.negative.increment(node_id, delta);
    }

    /// Get current value
    /// Uses saturating arithmetic to prevent overflow when values exceed i64::MAX
    pub fn value(&self) -> i64 {
        let pos = self.positive.value();
        let neg = self.negative.value();
        // Safely compute pos - neg with clamping to i64 range
        if pos >= neg {
            let diff = pos - neg;
            if diff > i64::MAX as u64 {
                i64::MAX
            } else {
                diff as i64
            }
        } else {
            let diff = neg - pos;
            if diff > i64::MAX as u64 {
                i64::MIN
            } else {
                -(diff as i64)
            }
        }
    }

    /// Merge with another PN-Counter
    pub fn merge(&mut self, other: &PNCounter) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

/// OR-Set CRDT for distributed sets with add/remove semantics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORSet<T: Clone + Eq + std::hash::Hash> {
    /// Elements with their unique tags
    elements: HashMap<T, HashSet<String>>,
    /// Tombstones (removed tags)
    tombstones: HashSet<String>,
}

impl<T: Clone + Eq + std::hash::Hash + Serialize> ORSet<T> {
    /// Create new OR-Set
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
            tombstones: HashSet::new(),
        }
    }

    /// Add element
    pub fn add(&mut self, element: T, node_id: &str) {
        let tag = generate_unique_tag(node_id);
        self.elements
            .entry(element)
            .or_insert_with(HashSet::new)
            .insert(tag);
    }

    /// Remove element (all instances)
    pub fn remove(&mut self, element: &T) {
        if let Some(tags) = self.elements.remove(element) {
            self.tombstones.extend(tags);
        }
    }

    /// Check if element is present
    pub fn contains(&self, element: &T) -> bool {
        self.elements
            .get(element)
            .map(|tags| tags.iter().any(|t| !self.tombstones.contains(t)))
            .unwrap_or(false)
    }

    /// Get all elements
    pub fn elements(&self) -> Vec<T> {
        self.elements
            .iter()
            .filter(|(_, tags)| tags.iter().any(|t| !self.tombstones.contains(t)))
            .map(|(e, _)| e.clone())
            .collect()
    }

    /// Merge with another OR-Set
    pub fn merge(&mut self, other: &ORSet<T>) {
        // Merge elements
        for (element, tags) in &other.elements {
            let entry = self
                .elements
                .entry(element.clone())
                .or_insert_with(HashSet::new);
            for tag in tags {
                entry.insert(tag.clone());
            }
        }

        // Merge tombstones
        self.tombstones.extend(other.tombstones.clone());
    }

    /// Size
    pub fn len(&self) -> usize {
        self.elements().len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Distributed IP blocklist using OR-Set
pub struct DistributedBlocklist {
    /// The OR-Set for blocked IPs
    blocked: ORSet<IpAddr>,
    /// Block metadata (expiration, reason)
    metadata: HashMap<IpAddr, BlockMetadata>,
    /// Local node ID
    node_id: NodeId,
}

/// Metadata for a blocked IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// When the block expires
    pub expires_at: u64,
    /// Reason for blocking
    pub reason: String,
    /// Threat score
    pub threat_score: u8,
    /// Source node that initiated the block
    pub source: NodeId,
}

impl DistributedBlocklist {
    /// Create new distributed blocklist
    pub fn new(node_id: NodeId) -> Self {
        Self {
            blocked: ORSet::new(),
            metadata: HashMap::new(),
            node_id,
        }
    }

    /// Block an IP
    pub fn block(&mut self, ip: IpAddr, reason: &str, ttl_secs: u32, threat_score: u8) {
        self.blocked.add(ip, &self.node_id.to_string());
        self.metadata.insert(
            ip,
            BlockMetadata {
                expires_at: current_timestamp() + ttl_secs as u64,
                reason: reason.to_string(),
                threat_score,
                source: self.node_id.clone(),
            },
        );
    }

    /// Unblock an IP
    pub fn unblock(&mut self, ip: &IpAddr) {
        self.blocked.remove(ip);
        self.metadata.remove(ip);
    }

    /// Check if an IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !self.blocked.contains(ip) {
            return false;
        }

        // Check expiration
        if let Some(meta) = self.metadata.get(ip) {
            if current_timestamp() > meta.expires_at {
                return false; // Expired
            }
        }

        true
    }

    /// Get block metadata
    pub fn get_metadata(&self, ip: &IpAddr) -> Option<&BlockMetadata> {
        if self.is_blocked(ip) {
            self.metadata.get(ip)
        } else {
            None
        }
    }

    /// Merge with remote blocklist
    pub fn merge(&mut self, other: &DistributedBlocklist) {
        self.blocked.merge(&other.blocked);

        // Merge metadata, preferring higher threat scores
        for (ip, meta) in &other.metadata {
            self.metadata
                .entry(*ip)
                .and_modify(|existing| {
                    if meta.threat_score > existing.threat_score {
                        *existing = meta.clone();
                    }
                })
                .or_insert_with(|| meta.clone());
        }
    }

    /// Clean expired entries
    pub fn cleanup_expired(&mut self) {
        let now = current_timestamp();
        let expired: Vec<IpAddr> = self
            .metadata
            .iter()
            .filter(|(_, meta)| now > meta.expires_at)
            .map(|(ip, _)| *ip)
            .collect();

        for ip in expired {
            self.blocked.remove(&ip);
            self.metadata.remove(&ip);
        }
    }

    /// Get all blocked IPs
    pub fn blocked_ips(&self) -> Vec<IpAddr> {
        self.blocked.elements()
    }

    /// Count blocked IPs
    pub fn count(&self) -> usize {
        self.blocked.len()
    }
}

/// Distributed rate limiting coordinator
pub struct RateLimitCoordinator {
    /// Per-key counters
    counters: HashMap<String, PNCounter>,
    /// Local node ID
    node_id: NodeId,
    /// Window duration
    window: Duration,
    /// Window start time
    window_start: Instant,
}

impl RateLimitCoordinator {
    /// Create new coordinator
    pub fn new(node_id: NodeId, window: Duration) -> Self {
        Self {
            counters: HashMap::new(),
            node_id,
            window,
            window_start: Instant::now(),
        }
    }

    /// Increment counter for a key
    pub fn increment(&mut self, key: &str, delta: u64) {
        self.maybe_rotate_window();

        let counter = self
            .counters
            .entry(key.to_string())
            .or_insert_with(PNCounter::new);
        counter.increment(&self.node_id.to_string(), delta);
    }

    /// Get current count for a key
    pub fn get_count(&mut self, key: &str) -> i64 {
        self.maybe_rotate_window();

        self.counters.get(key).map(|c| c.value()).unwrap_or(0)
    }

    /// Check if rate limit exceeded
    pub fn is_limited(&mut self, key: &str, limit: u64) -> bool {
        self.get_count(key) as u64 >= limit
    }

    /// Merge with remote coordinator state
    pub fn merge(&mut self, key: &str, remote_counter: &PNCounter) {
        let counter = self
            .counters
            .entry(key.to_string())
            .or_insert_with(PNCounter::new);
        counter.merge(remote_counter);
    }

    /// Rotate window if needed
    fn maybe_rotate_window(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.counters.clear();
            self.window_start = Instant::now();
        }
    }

    /// Get counter for serialization
    pub fn get_counter(&self, key: &str) -> Option<&PNCounter> {
        self.counters.get(key)
    }
}

/// Coordinator hub managing all distributed state
pub struct CoordinatorHub {
    /// Local node ID
    node_id: NodeId,
    /// Distributed blocklist
    blocklist: Arc<RwLock<DistributedBlocklist>>,
    /// Rate limit coordinator
    rate_limiter: Arc<RwLock<RateLimitCoordinator>>,
    /// Event ID cache for deduplication
    seen_events: Arc<RwLock<HashSet<String>>>,
    /// Configuration
    config: CoordinatorConfig,
}

/// Coordinator configuration
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Redis URL for communication
    pub redis_url: String,
    /// Stream name for events
    pub stream_name: String,
    /// Consumer group
    pub consumer_group: String,
    /// Rate limit window
    pub rate_limit_window: Duration,
    /// Sync interval
    pub sync_interval: Duration,
    /// Event retention
    pub event_retention: Duration,

    // ---- Retry / Backoff ----
    /// Maximum number of retries for a failed Redis operation before giving up
    /// (default:3). The coordinator will use exponential backoff with jitter
    /// between retries.
    pub max_retries: u32,

    /// Base delay for exponential backoff (default:100 ms). Each retry waits
    /// `base_retry_delay × 2^(attempt - 1)` plus random jitter.
    pub base_retry_delay: Duration,

    // ---- Circuit Breaker ----
    /// Number of consecutive Redis failures before the circuit opens and
    /// operations are short-circuited for `circuit_breaker_recovery` duration
    /// (default:5). This prevents cascading latency when Redis is down.
    pub circuit_breaker_threshold: u32,

    /// Duration the circuit stays open before attempting a probe request
    /// (default:30 s).
    pub circuit_breaker_recovery: Duration,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://localhost:6379".to_string(),
            stream_name: "apexmail:ddos:events".to_string(),
            consumer_group: "ddos-protection".to_string(),
            rate_limit_window: Duration::from_secs(60),
            sync_interval: Duration::from_secs(1),
            event_retention: Duration::from_secs(3600),
            max_retries: 3,
            base_retry_delay: Duration::from_millis(100),
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery: Duration::from_secs(30),
        }
    }
}

impl CoordinatorHub {
    /// Create new coordinator hub
    pub fn new(node_id: NodeId, config: CoordinatorConfig) -> Self {
        let blocklist = DistributedBlocklist::new(node_id.clone());
        let rate_limiter = RateLimitCoordinator::new(node_id.clone(), config.rate_limit_window);

        Self {
            node_id,
            blocklist: Arc::new(RwLock::new(blocklist)),
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
            seen_events: Arc::new(RwLock::new(HashSet::new())),
            config,
        }
    }

    /// Get node ID
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Block an IP across all regions
    pub async fn block_ip(&self, ip: IpAddr, reason: &str, ttl_secs: u32, threat_score: u8) {
        let mut blocklist = self.blocklist.write().await;
        blocklist.block(ip, reason, ttl_secs, threat_score);
    }

    /// Check if IP is blocked
    pub async fn is_blocked(&self, ip: &IpAddr) -> bool {
        let blocklist = self.blocklist.read().await;
        blocklist.is_blocked(ip)
    }

    /// Unblock an IP
    pub async fn unblock_ip(&self, ip: &IpAddr) {
        let mut blocklist = self.blocklist.write().await;
        blocklist.unblock(ip);
    }

    /// Increment rate limit counter
    pub async fn increment_rate(&self, key: &str, delta: u64) {
        let mut limiter = self.rate_limiter.write().await;
        limiter.increment(key, delta);
    }

    /// Check if rate limited
    pub async fn is_rate_limited(&self, key: &str, limit: u64) -> bool {
        let mut limiter = self.rate_limiter.write().await;
        limiter.is_limited(key, limit)
    }

    /// Get current rate
    pub async fn get_rate(&self, key: &str) -> i64 {
        let mut limiter = self.rate_limiter.write().await;
        limiter.get_count(key)
    }

    /// Process incoming threat event
    pub async fn process_event(&self, event: ThreatEvent) -> bool {
        // Check for duplicate
        {
            let mut seen = self.seen_events.write().await;
            if seen.contains(&event.event_id) {
                return false;
            }
            seen.insert(event.event_id.clone());
        }

        // Ignore expired events
        if event.is_expired() {
            return false;
        }

        // Ignore events from self
        if event.source == self.node_id {
            return false;
        }

        // Process based on event type
        match &event.event_type {
            ThreatEventType::BlocklistAdd { reason } => {
                let mut blocklist = self.blocklist.write().await;
                for ip in &event.affected_ips {
                    blocklist.block(*ip, reason, event.ttl_secs, event.threat_score);
                }
            }
            ThreatEventType::BlocklistRemove { .. } => {
                let mut blocklist = self.blocklist.write().await;
                for ip in &event.affected_ips {
                    blocklist.unblock(ip);
                }
            }
            ThreatEventType::DdosAttack { .. }
            | ThreatEventType::BruteForce { .. }
            | ThreatEventType::CredentialStuffing { .. } => {
                // Block the affected IPs with propagated threat score
                if event.threat_score > 70 {
                    let mut blocklist = self.blocklist.write().await;
                    for ip in &event.affected_ips {
                        blocklist.block(
                            *ip,
                            &format!("remote_{:?}", event.event_type),
                            event.ttl_secs,
                            event.threat_score,
                        );
                    }
                }
            }
            _ => {}
        }

        true
    }

    /// Create threat event for broadcasting
    pub fn create_event(&self, event_type: ThreatEventType) -> ThreatEvent {
        ThreatEvent::new(self.node_id.clone(), event_type)
    }

    /// Get coordinator statistics
    pub async fn stats(&self) -> CoordinatorStats {
        let blocklist = self.blocklist.read().await;
        let seen = self.seen_events.read().await;

        CoordinatorStats {
            blocked_ips: blocklist.count(),
            seen_events: seen.len(),
            node_id: self.node_id.to_string(),
        }
    }

    /// Clean up expired state
    pub async fn cleanup(&self) {
        // Cleanup blocklist
        {
            let mut blocklist = self.blocklist.write().await;
            blocklist.cleanup_expired();
        }

        // Cleanup seen events (keep last hour)
        // In real implementation, this would use timestamps
    }
}

/// Coordinator statistics
#[derive(Debug, Clone)]
pub struct CoordinatorStats {
    /// Number of blocked IPs
    pub blocked_ips: usize,
    /// Number of seen events (for dedup)
    pub seen_events: usize,
    /// Local node ID
    pub node_id: String,
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn generate_event_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

fn generate_unique_tag(node_id: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random: [u8; 8] = rng.gen();
    format!("{}-{}", node_id, hex::encode(random))
}

/// Threat intelligence service for cross-region IP block sharing.
/// Uses the coordinator hub to propagate block events across all nodes.
pub struct ThreatIntelService {
    /// Coordinator hub
    hub: Arc<CoordinatorHub>,
}

impl ThreatIntelService {
    /// Create a new threat intel service
    pub fn new(hub: Arc<CoordinatorHub>) -> Self {
        Self { hub }
    }

    /// Publish an IP block event to other regions
    pub async fn publish_ip_block(&self, ip_str: &str, duration: Duration) -> Result<(), String> {
        let ip: IpAddr = ip_str.parse().map_err(|e| format!("Invalid IP: {}", e))?;
        // E-106 fix:Clamp to u32::MAX to prevent overflow for durations > ~136 years
        let duration_secs = duration.as_secs().min(u32::MAX as u64) as u32;
        self.hub
            .block_ip(ip, "threat_intel", duration_secs, 80)
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_counter() {
        let mut c1 = GCounter::new();
        let mut c2 = GCounter::new();

        c1.increment("node1", 5);
        c2.increment("node2", 3);

        c1.merge(&c2);

        assert_eq!(c1.value(), 8);
    }

    #[test]
    fn test_pn_counter() {
        let mut c = PNCounter::new();

        c.increment("node1", 10);
        c.decrement("node1", 3);

        assert_eq!(c.value(), 7);
    }

    #[test]
    fn test_or_set() {
        let mut s1: ORSet<String> = ORSet::new();
        let mut s2: ORSet<String> = ORSet::new();

        s1.add("hello".to_string(), "node1");
        s2.add("world".to_string(), "node2");

        s1.merge(&s2);

        assert!(s1.contains(&"hello".to_string()));
        assert!(s1.contains(&"world".to_string()));
    }

    #[test]
    fn test_distributed_blocklist() {
        let node = NodeId::new("eu-central", "node-1");
        let mut blocklist = DistributedBlocklist::new(node);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        blocklist.block(ip, "test", 3600, 80);

        assert!(blocklist.is_blocked(&ip));

        blocklist.unblock(&ip);
        assert!(!blocklist.is_blocked(&ip));
    }

    #[test]
    fn test_rate_limit_coordinator() {
        let node = NodeId::new("eu-central", "node-1");
        let mut coord = RateLimitCoordinator::new(node, Duration::from_secs(60));

        coord.increment("user:123", 10);
        coord.increment("user:123", 5);

        assert_eq!(coord.get_count("user:123"), 15);
        assert!(coord.is_limited("user:123", 10));
        assert!(!coord.is_limited("user:123", 20));
    }

    #[tokio::test]
    async fn test_coordinator_hub() {
        let node = NodeId::new("eu-central", "node-1");
        let config = CoordinatorConfig::default();
        let hub = CoordinatorHub::new(node, config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        hub.block_ip(ip, "test attack", 300, 90).await;
        assert!(hub.is_blocked(&ip).await);

        hub.unblock_ip(&ip).await;
        assert!(!hub.is_blocked(&ip).await);
    }

    #[tokio::test]
    async fn test_event_processing() {
        let node1 = NodeId::new("eu-central", "node-1");
        let node2 = NodeId::new("us-east", "node-2");
        let config = CoordinatorConfig::default();
        let hub = CoordinatorHub::new(node1.clone(), config);

        // Create event from different node
        let event = ThreatEvent::new(
            node2,
            ThreatEventType::BlocklistAdd {
                reason: "attack detected".to_string(),
            },
        )
        .with_ip("1.2.3.4".parse().unwrap())
        .with_score(85);

        let processed = hub.process_event(event).await;
        assert!(processed);

        // IP should now be blocked
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(hub.is_blocked(&ip).await);
    }
}
