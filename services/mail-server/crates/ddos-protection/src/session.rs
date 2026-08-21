//! Session tracking for behavioral analysis

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::RequestContext;

/// Session tracker for behavioral analysis
pub struct SessionTracker {
    /// Active sessions
    sessions: Arc<DashMap<SessionKey, Arc<RwLock<Session>>>>,
    /// Session window duration
    window: Duration,
    /// Maximum sessions to track
    max_sessions: usize,
}

/// Session identification key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Client IP
    pub ip: IpAddr,
    /// Optional:API key ID for authenticated sessions
    pub api_key_id: Option<String>,
}

/// Session state
#[derive(Debug, Clone)]
pub struct Session {
    /// Session key
    pub key: SessionKey,
    /// When session started
    pub started_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Total requests in session
    pub request_count: u64,
    /// Error count (4xx/5xx responses)
    pub error_count: u64,
    /// Recent endpoint hashes (windowed, bounded memory)
    pub recent_endpoints: VecDeque<u64>,
    /// Request sequence (endpoint hashes)
    pub request_sequence: VecDeque<u64>,
    /// Inter-arrival times (milliseconds)
    pub inter_arrival_times: VecDeque<u64>,
    /// Request durations (milliseconds)
    pub request_durations: VecDeque<u64>,
}

impl Session {
    /// Create a new session
    fn new(key: SessionKey) -> Self {
        let now = Instant::now();
        Self {
            key,
            started_at: now,
            last_activity: now,
            request_count: 0,
            error_count: 0,
            recent_endpoints: VecDeque::with_capacity(100),
            request_sequence: VecDeque::with_capacity(100),
            inter_arrival_times: VecDeque::with_capacity(100),
            request_durations: VecDeque::with_capacity(100),
        }
    }

    /// Record a request
    fn record_request(&mut self, endpoint_hash: u64, is_error: bool) {
        let now = Instant::now();

        // Only record inter-arrival time after the first request.
        // The first call has no valid prior request to measure from —
        // using the session creation time would pollute the IAT analysis
        // with a meaningless near-zero value.
        if self.request_count > 0 {
            let inter_arrival = now.duration_since(self.last_activity).as_millis() as u64;
            if self.inter_arrival_times.len() >= 100 {
                self.inter_arrival_times.pop_front();
            }
            self.inter_arrival_times.push_back(inter_arrival);
        }

        // Request sequence
        if self.request_sequence.len() >= 100 {
            self.request_sequence.pop_front();
        }
        self.request_sequence.push_back(endpoint_hash);

        // Update counters
        self.request_count += 1;
        if is_error {
            self.error_count += 1;
        }

        // Windowed endpoint tracking (bounded memory)
        if self.recent_endpoints.len() >= 100 {
            self.recent_endpoints.pop_front();
        }
        self.recent_endpoints.push_back(endpoint_hash);

        self.last_activity = now;
    }

    /// Record request duration
    pub fn record_duration(&mut self, duration_ms: u64) {
        if self.request_durations.len() >= 100 {
            self.request_durations.pop_front();
        }
        self.request_durations.push_back(duration_ms);
    }

    /// Session age
    pub fn age(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Requests per minute
    pub fn requests_per_minute(&self) -> f64 {
        let age_secs = self.age().as_secs_f64();
        if age_secs < 1.0 {
            return self.request_count as f64 * 60.0;
        }
        (self.request_count as f64 / age_secs) * 60.0
    }

    /// Error rate
    pub fn error_rate(&self) -> f64 {
        if self.request_count == 0 {
            return 0.0;
        }
        self.error_count as f64 / self.request_count as f64
    }

    /// Endpoint diversity (unique endpoints / total in window)
    pub fn endpoint_diversity(&self) -> f64 {
        if self.recent_endpoints.is_empty() {
            return 1.0;
        }
        let unique: HashSet<&u64> = self.recent_endpoints.iter().collect();
        unique.len() as f64 / self.recent_endpoints.len() as f64
    }

    /// Coefficient of variation for inter-arrival times
    pub fn inter_arrival_cov(&self) -> f64 {
        if self.inter_arrival_times.len() < 10 {
            return 1.0;
        }

        let times: Vec<f64> = self.inter_arrival_times.iter().map(|&t| t as f64).collect();
        let mean = times.iter().sum::<f64>() / times.len() as f64;

        if mean <= 0.0 {
            return 0.0;
        }

        let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / times.len() as f64;
        let std_dev = variance.sqrt();

        std_dev / mean
    }

    /// Average request duration
    pub fn avg_duration(&self) -> f64 {
        if self.request_durations.is_empty() {
            return 0.0;
        }
        self.request_durations.iter().sum::<u64>() as f64 / self.request_durations.len() as f64
    }
}

impl SessionTracker {
    /// Create a new session tracker
    pub fn new(window: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::with_capacity(max_sessions / 4)),
            window,
            max_sessions,
        }
    }

    /// Track a request and return session info
    pub fn track(&self, ctx: &RequestContext) -> SessionInfo {
        let key = SessionKey {
            ip: ctx.ip,
            api_key_id: ctx.api_key_id.clone(),
        };

        // Capacity guard BEFORE inserting a new key: previously inserts were
        // unchecked between cleanup ticks, so a spoofed-IP flood could grow
        // the table (4 × 100-entry deques per (IP, key)) without bound.
        if !self.sessions.contains_key(&key) {
            self.enforce_capacity();
        }

        let endpoint_hash = hash_endpoint(&ctx.path);

        let session = self
            .sessions
            .entry(key.clone())
            .or_insert_with(|| Arc::new(RwLock::new(Session::new(key.clone()))))
            .clone();

        let mut session_guard = session.write();
        session_guard.record_request(endpoint_hash, false); // Error recorded separately

        SessionInfo {
            key: key.clone(),
            request_count: session_guard.request_count,
            requests_per_minute: session_guard.requests_per_minute(),
            error_rate: session_guard.error_rate(),
            endpoint_diversity: session_guard.endpoint_diversity(),
            inter_arrival_cov: session_guard.inter_arrival_cov(),
            age_secs: session_guard.age().as_secs(),
        }
    }

    /// Record an error for a session
    pub fn record_error(&self, ctx: &RequestContext) {
        let key = SessionKey {
            ip: ctx.ip,
            api_key_id: ctx.api_key_id.clone(),
        };

        if let Some(session) = self.sessions.get(&key).map(|entry| entry.clone()) {
            session.write().error_count += 1;
        }
    }

    /// Record request duration
    pub fn record_duration(&self, ctx: &RequestContext, duration_ms: u64) {
        let key = SessionKey {
            ip: ctx.ip,
            api_key_id: ctx.api_key_id.clone(),
        };

        if let Some(session) = self.sessions.get(&key).map(|entry| entry.clone()) {
            session.write().record_duration(duration_ms);
        }
    }

    /// Get session info if exists
    pub fn get_session(&self, ip: &IpAddr, api_key_id: Option<&str>) -> Option<SessionInfo> {
        let key = SessionKey {
            ip: *ip,
            api_key_id: api_key_id.map(String::from),
        };

        self.sessions.get(&key).map(|s| {
            let session = s.clone();
            let session = session.read();
            SessionInfo {
                key: key.clone(),
                request_count: session.request_count,
                requests_per_minute: session.requests_per_minute(),
                error_rate: session.error_rate(),
                endpoint_diversity: session.endpoint_diversity(),
                inter_arrival_cov: session.inter_arrival_cov(),
                age_secs: session.age().as_secs(),
            }
        })
    }

    /// Get number of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Cleanup expired sessions
    pub fn cleanup(&self, _now: Instant) {
        // Remove idle sessions
        self.sessions.retain(|_, session| {
            let s = session.read();
            s.idle_time() < self.window
        });

        // Enforce the hard capacity cap after idle removal.
        self.enforce_capacity();
    }

    /// Enforce the session-table capacity cap (fix G).
    ///
    /// Evicts a 10% batch of the least-recently-active sessions down to the
    /// target size. Eviction no longer requires sessions to be idle for 60s
    /// — an active flood at capacity previously removed nothing and let the
    /// table grow without bound between cleanup ticks.
    fn enforce_capacity(&self) {
        if self.max_sessions == 0 || self.sessions.len() < self.max_sessions {
            return;
        }
        let target = (self.max_sessions * 9 / 10).max(1);
        // Collect (key, last_activity) and evict the oldest activity first.
        let mut candidates: Vec<(SessionKey, Instant)> = self
            .sessions
            .iter()
            .map(|entry| {
                let session = entry.value().read();
                (entry.key().clone(), session.last_activity)
            })
            .collect();
        candidates.sort_by_key(|(_, last_activity)| *last_activity);
        let excess = self.sessions.len().saturating_sub(target);
        for (key, _) in candidates.into_iter().take(excess) {
            self.sessions.remove(&key);
        }
    }
}

/// Summary info about a session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session key
    pub key: SessionKey,
    /// Total requests
    pub request_count: u64,
    /// Requests per minute
    pub requests_per_minute: f64,
    /// Error rate (0-1)
    pub error_rate: f64,
    /// Endpoint diversity (0-1)
    pub endpoint_diversity: f64,
    /// Inter-arrival time coefficient of variation
    pub inter_arrival_cov: f64,
    /// Session age in seconds
    pub age_secs: u64,
}

/// Hash an endpoint for compact storage
fn hash_endpoint(path: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tracking() {
        let tracker = SessionTracker::new(Duration::from_secs(300), 1000);

        let ctx = RequestContext {
            ip: "192.168.1.1".parse().expect("hardcoded test IP"),
            path: "/v1/health".to_string(),
            method: "GET".to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        };

        let info = tracker.track(&ctx);
        assert_eq!(info.request_count, 1);

        let info = tracker.track(&ctx);
        assert_eq!(info.request_count, 2);
    }

    #[test]
    fn test_session_metrics() {
        let mut session = Session::new(SessionKey {
            ip: "192.168.1.1".parse().expect("hardcoded test IP"),
            api_key_id: None,
        });

        // Add some requests
        for i in 0..10 {
            session.record_request(i, false);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(session.request_count, 10);
        let unique: std::collections::HashSet<&u64> = session.recent_endpoints.iter().collect();
        assert_eq!(unique.len(), 10);
        assert!(session.inter_arrival_times.len() >= 9);
    }

    #[test]
    fn test_session_table_bounded_under_spoofed_ip_flood() {
        // Fix G: inserting 2× cap distinct (IP, key) entries must never
        // grow the table beyond the cap.
        let cap = 100;
        let tracker = SessionTracker::new(Duration::from_secs(300), cap);

        for i in 0..(cap * 2) {
            let ctx = RequestContext {
                ip: format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
                    .parse()
                    .expect("valid IPv4"),
                path: "/flood".to_string(),
                method: "GET".to_string(),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
            };
            tracker.track(&ctx);
            // Hard invariant at every step
            assert!(
                tracker.active_count() <= cap,
                "session table exceeded cap at iteration {i}: {}",
                tracker.active_count()
            );
        }
        assert!(tracker.active_count() <= cap);
    }

    #[test]
    fn test_session_cleanup_enforces_cap_for_active_sessions() {
        // Cleanup over capacity previously only removed sessions idle >60s;
        // fully-active floods removed nothing. It must now enforce the cap.
        let cap = 50;
        let tracker = SessionTracker::new(Duration::from_secs(300), cap);
        for i in 0..(cap * 3) {
            let ctx = RequestContext {
                ip: format!("192.0.2.{}", i & 0xFF).parse().expect("valid IPv4"),
                path: format!("/active/{i}"),
                method: "GET".to_string(),
                tls_fingerprint: None,
                h2_fingerprint: None,
                user_agent: None,
                body_size: 0,
                tenant_id: None,
                api_key_id: None,
            };
            tracker.track(&ctx);
        }
        tracker.cleanup(Instant::now());
        assert!(
            tracker.active_count() <= cap,
            "cleanup must enforce cap, got {}",
            tracker.active_count()
        );
    }
}
