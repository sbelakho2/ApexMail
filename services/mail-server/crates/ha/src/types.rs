//! HA domain types:enums, structs and helpers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Health ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl HealthStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "healthy" => Self::Healthy,
            "degraded" => Self::Degraded,
            "unhealthy" => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub latency_ms: Option<f64>,
    pub message: Option<String>,
    pub last_check: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub overall: HealthStatus,
    pub node_id: String,
    pub region: String,
    pub components: Vec<ComponentHealth>,
    pub uptime_secs: f64,
    pub checked_at: DateTime<Utc>,
}

// ── Failover ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverState {
    Normal,
    Detecting,
    FailingOver,
    FailedOver,
    FailingBack,
    SplitBrain,
}

impl std::fmt::Display for FailoverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Detecting => write!(f, "detecting"),
            Self::FailingOver => write!(f, "failing_over"),
            Self::FailedOver => write!(f, "failed_over"),
            Self::FailingBack => write!(f, "failing_back"),
            Self::SplitBrain => write!(f, "split_brain"),
        }
    }
}

impl FailoverState {
    pub fn parse(s: &str) -> Self {
        match s {
            "normal" => Self::Normal,
            "detecting" => Self::Detecting,
            "failing_over" => Self::FailingOver,
            "failed_over" => Self::FailedOver,
            "failing_back" => Self::FailingBack,
            "split_brain" => Self::SplitBrain,
            _ => Self::Normal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverType {
    Automatic,
    Manual,
    Scheduled,
}

impl std::fmt::Display for FailoverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Automatic => write!(f, "automatic"),
            Self::Manual => write!(f, "manual"),
            Self::Scheduled => write!(f, "scheduled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub id: Uuid,
    pub from_node: String,
    pub to_node: String,
    pub failover_type: String,
    pub state: String,
    pub reason: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub data_loss: bool,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfigInfo {
    pub enabled: bool,
    pub mode: String,
    pub threshold: u32,
    pub failback_enabled: bool,
    pub current_state: String,
    pub primary_node: String,
    pub replica_nodes: Vec<String>,
}

// ── Backup ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupType {
    Full,
    Incremental,
    Wal,
    Snapshot,
}

impl std::fmt::Display for BackupType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Incremental => write!(f, "incremental"),
            Self::Wal => write!(f, "wal"),
            Self::Snapshot => write!(f, "snapshot"),
        }
    }
}

impl BackupType {
    pub fn parse(s: &str) -> Self {
        match s {
            "full" => Self::Full,
            "incremental" => Self::Incremental,
            "wal" => Self::Wal,
            "snapshot" => Self::Snapshot,
            _ => Self::Full,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl std::fmt::Display for BackupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Expired => write!(f, "expired"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl BackupStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub id: Uuid,
    pub backup_type: String,
    pub status: String,
    pub size_bytes: i64,
    pub tables_included: Option<Vec<String>>,
    pub location: Option<String>,
    pub checksum: Option<String>,
    pub encrypted: bool,
    pub compressed: bool,
    pub compression_ratio: Option<f64>,
    pub wal_start_lsn: Option<String>,
    pub wal_end_lsn: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub parent_backup_id: Option<Uuid>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub full_cron: String,
    pub incremental_cron: String,
    pub wal_interval_secs: u64,
    pub retention_days: u32,
    pub next_full: Option<DateTime<Utc>>,
    pub next_incremental: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreOptions {
    pub backup_id: Uuid,
    pub target_time: Option<DateTime<Utc>>,
    pub validate_only: bool,
    pub parallel_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub success: bool,
    pub backup_id: Uuid,
    pub restored_tables: Vec<String>,
    pub duration_ms: i64,
    pub verification: Option<VerificationResult>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub tables_verified: u32,
    pub rows_verified: u64,
    pub checksum_match: bool,
    pub index_health: bool,
    pub constraint_valid: bool,
    pub sequence_valid: bool,
}

// ── Replication ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    Async,
    Sync,
    Quorum,
}

impl std::fmt::Display for ReplicationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Async => write!(f, "async"),
            Self::Sync => write!(f, "sync"),
            Self::Quorum => write!(f, "quorum"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaState {
    Streaming,
    CatchUp,
    Startup,
    Backup,
    Stopped,
    Unknown,
}

impl std::fmt::Display for ReplicaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Streaming => write!(f, "streaming"),
            Self::CatchUp => write!(f, "catchup"),
            Self::Startup => write!(f, "startup"),
            Self::Backup => write!(f, "backup"),
            Self::Stopped => write!(f, "stopped"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl ReplicaState {
    pub fn parse(s: &str) -> Self {
        match s {
            "streaming" => Self::Streaming,
            "catchup" => Self::CatchUp,
            "startup" => Self::Startup,
            "backup" => Self::Backup,
            "stopped" => Self::Stopped,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaInfo {
    pub pid: i32,
    pub application_name: String,
    pub client_addr: Option<String>,
    pub state: String,
    pub sent_lsn: Option<String>,
    pub write_lsn: Option<String>,
    pub flush_lsn: Option<String>,
    pub replay_lsn: Option<String>,
    pub sync_state: String,
    pub lag_bytes: Option<i64>,
    pub lag_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSlot {
    pub slot_name: String,
    pub plugin: Option<String>,
    pub slot_type: String,
    pub active: bool,
    pub restart_lsn: Option<String>,
    pub confirmed_flush_lsn: Option<String>,
    pub wal_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStats {
    pub mode: String,
    pub primary_node: String,
    pub replicas: Vec<ReplicaInfo>,
    pub slots: Vec<ReplicationSlot>,
    pub total_lag_bytes: i64,
    pub max_lag_ms: f64,
    pub avg_lag_ms: f64,
    pub is_healthy: bool,
}

// ── Multi-Region ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionStatus {
    Active,
    Standby,
    Draining,
    Inactive,
    Fenced,
}

impl std::fmt::Display for RegionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Standby => write!(f, "standby"),
            Self::Draining => write!(f, "draining"),
            Self::Inactive => write!(f, "inactive"),
            Self::Fenced => write!(f, "fenced"),
        }
    }
}

impl RegionStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "standby" => Self::Standby,
            "draining" => Self::Draining,
            "inactive" => Self::Inactive,
            "fenced" => Self::Fenced,
            _ => Self::Inactive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionRole {
    Primary,
    Secondary,
    Witness,
    ReadOnly,
}

impl std::fmt::Display for RegionRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary => write!(f, "primary"),
            Self::Secondary => write!(f, "secondary"),
            Self::Witness => write!(f, "witness"),
            Self::ReadOnly => write!(f, "read_only"),
        }
    }
}

impl RegionRole {
    pub fn parse(s: &str) -> Self {
        match s {
            "primary" => Self::Primary,
            "secondary" => Self::Secondary,
            "witness" => Self::Witness,
            "read_only" => Self::ReadOnly,
            _ => Self::Secondary,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FencingStatus {
    Normal,
    Fencing,
    Fenced,
    Released,
}

impl std::fmt::Display for FencingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Fencing => write!(f, "fencing"),
            Self::Fenced => write!(f, "fenced"),
            Self::Released => write!(f, "released"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub id: Uuid,
    pub name: String,
    pub endpoint: String,
    pub status: String,
    pub role: String,
    pub is_primary: bool,
    pub health_score: f64,
    pub latency_ms: Option<f64>,
    pub replication_lag_ms: Option<f64>,
    pub weight: i32,
    pub last_health_check: Option<DateTime<Utc>>,
    pub availability_zone: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDistribution {
    pub region: String,
    pub weight: f64,
    pub requests_per_second: f64,
    pub error_rate: f64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRoutingRule {
    pub id: Uuid,
    pub name: String,
    pub source_region: String,
    pub target_region: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Option<serde_json::Value>,
}

// ── Circuit Breaker ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half_open"),
        }
    }
}

impl CircuitState {
    pub fn parse(s: &str) -> Self {
        match s {
            "closed" => Self::Closed,
            "open" => Self::Open,
            "half_open" => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub name: String,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_ms: u64,
    pub half_open_max_calls: u32,
    pub enabled: bool,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            name: "default".into(),
            failure_threshold: 5,
            success_threshold: 2,
            timeout_ms: 30000,
            half_open_max_calls: 3,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStats {
    pub name: String,
    pub state: String,
    pub failure_count: u64,
    pub success_count: u64,
    pub total_calls: u64,
    pub last_failure: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub state_changed_at: DateTime<Utc>,
    pub error_rate: f64,
}

// ── Chaos Engineering ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentType {
    LatencyInjection,
    ErrorInjection,
    ResourceExhaustion,
    NetworkPartition,
    ProcessKill,
    DiskFull,
    ClockSkew,
    DnsFailure,
}

impl std::fmt::Display for ExperimentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LatencyInjection => write!(f, "latency_injection"),
            Self::ErrorInjection => write!(f, "error_injection"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::NetworkPartition => write!(f, "network_partition"),
            Self::ProcessKill => write!(f, "process_kill"),
            Self::DiskFull => write!(f, "disk_full"),
            Self::ClockSkew => write!(f, "clock_skew"),
            Self::DnsFailure => write!(f, "dns_failure"),
        }
    }
}

impl ExperimentType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "latency_injection" | "latency" => Some(Self::LatencyInjection),
            "error_injection" | "error" => Some(Self::ErrorInjection),
            "resource_exhaustion" | "resource" => Some(Self::ResourceExhaustion),
            "network_partition" | "network" => Some(Self::NetworkPartition),
            "process_kill" | "kill" => Some(Self::ProcessKill),
            "disk_full" | "disk" => Some(Self::DiskFull),
            "clock_skew" | "clock" => Some(Self::ClockSkew),
            "dns_failure" | "dns" => Some(Self::DnsFailure),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Aborted,
}

impl std::fmt::Display for ExperimentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

impl ExperimentStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "aborted" => Self::Aborted,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentTarget {
    pub service: String,
    pub instances: Vec<String>,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentParameters {
    pub duration_ms: u64,
    pub intensity: f64,
    pub error_codes: Option<Vec<u16>>,
    pub latency_ms: Option<u64>,
    pub resource_type: Option<String>,
    pub resource_limit: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheck {
    pub name: String,
    pub check_type: String,
    pub threshold: f64,
    pub operator: String,
    pub abort_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
    pub experiment_type: String,
    pub target: ExperimentTarget,
    pub parameters: ExperimentParameters,
    pub safety_checks: Vec<SafetyCheck>,
    pub rollback_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experiment {
    pub id: Uuid,
    pub name: String,
    pub experiment_type: String,
    pub status: String,
    pub config: serde_json::Value,
    pub target: serde_json::Value,
    pub parameters: serde_json::Value,
    pub safety_checks: serde_json::Value,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub results: Option<serde_json::Value>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub timestamp: DateTime<Utc>,
    pub error_rate: f64,
    pub latency_p50_ms: f64,
    pub latency_p99_ms: f64,
    pub throughput_rps: f64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentResults {
    pub success: bool,
    pub metrics_before: MetricSnapshot,
    pub metrics_during: Option<MetricSnapshot>,
    pub metrics_after: Option<MetricSnapshot>,
    pub safety_violations: Vec<String>,
    pub observations: Vec<String>,
    pub recommendations: Vec<String>,
}

// ── Alert / Notification ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub severity: String,
    pub title: String,
    pub message: String,
    pub component: String,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

// ── DB Row types (for sqlx::query_as::<_, T>) ──────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BackupRow {
    pub id: Uuid,
    pub backup_type: String,
    pub status: String,
    pub size_bytes: i64,
    pub tables_included: Option<serde_json::Value>,
    pub location: Option<String>,
    pub checksum: Option<String>,
    pub encrypted: bool,
    pub compressed: bool,
    pub compression_ratio: Option<f64>,
    pub wal_start_lsn: Option<String>,
    pub wal_end_lsn: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub parent_backup_id: Option<Uuid>,
    pub metadata: Option<serde_json::Value>,
}

impl BackupRow {
    pub fn into_backup(self) -> Backup {
        let tables: Option<Vec<String>> = self
            .tables_included
            .and_then(|v| serde_json::from_value(v).ok());
        Backup {
            id: self.id,
            backup_type: self.backup_type,
            status: self.status,
            size_bytes: self.size_bytes,
            tables_included: tables,
            location: self.location,
            checksum: self.checksum,
            encrypted: self.encrypted,
            compressed: self.compressed,
            compression_ratio: self.compression_ratio,
            wal_start_lsn: self.wal_start_lsn,
            wal_end_lsn: self.wal_end_lsn,
            started_at: self.started_at,
            completed_at: self.completed_at,
            duration_ms: self.duration_ms,
            parent_backup_id: self.parent_backup_id,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FailoverRow {
    pub id: Uuid,
    pub from_node: String,
    pub to_node: String,
    pub failover_type: String,
    pub state: String,
    pub reason: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub data_loss: bool,
    pub metadata: Option<serde_json::Value>,
}

impl FailoverRow {
    pub fn into_event(self) -> FailoverEvent {
        FailoverEvent {
            id: self.id,
            from_node: self.from_node,
            to_node: self.to_node,
            failover_type: self.failover_type,
            state: self.state,
            reason: self.reason,
            started_at: self.started_at,
            completed_at: self.completed_at,
            duration_ms: self.duration_ms,
            data_loss: self.data_loss,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegionRow {
    pub id: Uuid,
    pub name: String,
    pub endpoint: String,
    pub status: String,
    pub role: String,
    pub is_primary: bool,
    pub health_score: f64,
    pub latency_ms: Option<f64>,
    pub replication_lag_ms: Option<f64>,
    pub weight: i32,
    pub last_health_check: Option<DateTime<Utc>>,
    pub availability_zone: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl RegionRow {
    pub fn into_info(self) -> RegionInfo {
        RegionInfo {
            id: self.id,
            name: self.name,
            endpoint: self.endpoint,
            status: self.status,
            role: self.role,
            is_primary: self.is_primary,
            health_score: self.health_score,
            latency_ms: self.latency_ms,
            replication_lag_ms: self.replication_lag_ms,
            weight: self.weight,
            last_health_check: self.last_health_check,
            availability_zone: self.availability_zone,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GeoRoutingRuleRow {
    pub id: Uuid,
    pub name: String,
    pub source_region: String,
    pub target_region: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Option<serde_json::Value>,
}

impl GeoRoutingRuleRow {
    pub fn into_rule(self) -> GeoRoutingRule {
        GeoRoutingRule {
            id: self.id,
            name: self.name,
            source_region: self.source_region,
            target_region: self.target_region,
            priority: self.priority,
            enabled: self.enabled,
            conditions: self.conditions,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExperimentRow {
    pub id: Uuid,
    pub name: String,
    pub experiment_type: String,
    pub status: String,
    pub config: serde_json::Value,
    pub target: serde_json::Value,
    pub parameters: serde_json::Value,
    pub safety_checks: serde_json::Value,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub results: Option<serde_json::Value>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ExperimentRow {
    pub fn into_experiment(self) -> Experiment {
        Experiment {
            id: self.id,
            name: self.name,
            experiment_type: self.experiment_type,
            status: self.status,
            config: self.config,
            target: self.target,
            parameters: self.parameters,
            safety_checks: self.safety_checks,
            started_at: self.started_at,
            completed_at: self.completed_at,
            duration_ms: self.duration_ms,
            results: self.results,
            created_by: self.created_by,
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CountRow {
    pub count: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LagRow {
    pub lag_ms: Option<f64>,
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_round_trip() {
        let h = HealthStatus::Degraded;
        assert_eq!(HealthStatus::parse(&h.to_string()), HealthStatus::Degraded);
    }

    #[test]
    fn test_failover_state_round_trip() {
        for state in &[
            FailoverState::Normal,
            FailoverState::Detecting,
            FailoverState::FailingOver,
            FailoverState::FailedOver,
            FailoverState::FailingBack,
            FailoverState::SplitBrain,
        ] {
            assert_eq!(FailoverState::parse(&state.to_string()), *state);
        }
    }

    #[test]
    fn test_backup_type_parse() {
        assert_eq!(BackupType::parse("wal"), BackupType::Wal);
        assert_eq!(BackupType::parse("incremental"), BackupType::Incremental);
        assert_eq!(BackupType::parse("unknown"), BackupType::Full);
    }

    #[test]
    fn test_backup_status_round_trip() {
        for s in &[
            BackupStatus::Pending,
            BackupStatus::InProgress,
            BackupStatus::Completed,
            BackupStatus::Failed,
            BackupStatus::Expired,
            BackupStatus::Cancelled,
        ] {
            assert_eq!(BackupStatus::parse(&s.to_string()), *s);
        }
    }

    #[test]
    fn test_circuit_state_round_trip() {
        for s in &[
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            assert_eq!(CircuitState::parse(&s.to_string()), *s);
        }
    }

    #[test]
    fn test_region_status_parse() {
        assert_eq!(RegionStatus::parse("draining"), RegionStatus::Draining);
        assert_eq!(RegionStatus::parse("fenced"), RegionStatus::Fenced);
        assert_eq!(RegionStatus::parse("unknown"), RegionStatus::Inactive);
    }

    #[test]
    fn test_experiment_type_parse() {
        assert!(ExperimentType::parse("dns_failure").is_some());
        assert_eq!(
            ExperimentType::parse("latency"),
            Some(ExperimentType::LatencyInjection)
        );
        assert!(ExperimentType::parse("nope").is_none());
    }

    #[test]
    fn test_circuit_config_default() {
        let c = CircuitConfig::default();
        assert_eq!(c.failure_threshold, 5);
        assert_eq!(c.success_threshold, 2);
        assert!(c.enabled);
    }

    #[test]
    fn test_region_role_parse() {
        assert_eq!(RegionRole::parse("primary"), RegionRole::Primary);
        assert_eq!(RegionRole::parse("witness"), RegionRole::Witness);
        assert_eq!(RegionRole::parse("???"), RegionRole::Secondary);
    }

    #[test]
    fn test_experiment_status_round_trip() {
        for s in &[
            ExperimentStatus::Pending,
            ExperimentStatus::Running,
            ExperimentStatus::Completed,
            ExperimentStatus::Failed,
            ExperimentStatus::Aborted,
        ] {
            assert_eq!(ExperimentStatus::parse(&s.to_string()), *s);
        }
    }
}
