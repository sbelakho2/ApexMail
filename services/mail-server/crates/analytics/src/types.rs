//! Shared types for the analytics service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── query types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsQuery {
    pub tenant_id: String,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub dimensions: Option<Vec<String>>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub dimension: String,
    pub count: i64,
    pub percentage: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunnelStage {
    pub stage: String,
    pub count: i64,
    pub dropoff: f64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverabilityMetrics {
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
    pub unsubscribe_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementBucket {
    pub range: String,
    pub count: i64,
}

// ── event row (for compaction serialization) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EventRow {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub message_id: String,
    pub event_type: String,
    pub recipient: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub link_id: Option<String>,
    pub bounce_type: Option<String>,
    pub bounce_subtype: Option<String>,
    pub provider: Option<String>,
    pub region: Option<String>,
    pub campaign_id: Option<String>,
}

// ── compaction types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionStatus {
    pub rows_migrated: i64,
    pub rows_deleted: i64,
    pub bytes_written: u64,
    pub checksum: String,
    pub completed: bool,
}

// ── reconciliation types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationResult {
    pub discrepancies_found: i64,
    pub discrepancies: Vec<DiscrepancyDetail>,
    pub health_check: serde_json::Value,
    pub run_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancyDetail {
    pub message_id: String,
    pub tenant_id: String,
    pub expected_events: Vec<String>,
    pub actual_events: Vec<String>,
    pub missing_events: Vec<String>,
}

// ── STO types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourDistribution {
    pub hours: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayDistribution {
    pub days: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimalSendWindow {
    pub hour: u32,
    pub day: u32,
    pub score: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientProfile {
    pub hour_distribution: HourDistribution,
    pub day_distribution: DayDistribution,
    pub total_events: i64,
    pub profile_age_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOptimizationResult {
    pub email_hash: String,
    pub windows: Vec<OptimalSendWindow>,
    pub confidence: f64,
    pub profile_age_days: u32,
}

// ── churn types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskTier {
    Critical,
    High,
    Medium,
    Low,
}

impl RiskTier {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.75 {
            Self::Critical
        } else if score >= 0.50 {
            Self::High
        } else if score >= 0.25 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChurnPrediction {
    pub email: String,
    pub tenant_id: String,
    pub probability: f64,
    pub risk_tier: RiskTier,
    pub signals: Vec<ChurnSignal>,
    pub engagement_velocity: f64,
    pub predicted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChurnSignal {
    pub name: String,
    pub value: f64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantHealthMetrics {
    pub tenant_id: String,
    pub delivery_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub engagement_velocity: f64,
}

// ── subject analysis types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenCategory {
    Urgency,
    Exclusivity,
    Benefit,
    Curiosity,
    SocialProof,
    Personalization,
    Question,
    Number,
    Emoji,
    Neutral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAnalysis {
    pub token: String,
    pub category: TokenCategory,
    pub sentiment: f64,
    pub lift: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectLineScore {
    pub overall_score: f64,
    pub length_score: f64,
    pub urgency_score: f64,
    pub personalization_score: f64,
    pub clarity_score: f64,
    pub spam_score: f64,
    pub predicted_open_rate: f64,
    pub token_analysis: Vec<TokenAnalysis>,
    pub emoji_count: usize,
    pub word_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudienceInsights {
    pub tenant_id: String,
    pub baseline_open_rate: f64,
    pub total_subjects: i64,
    pub top_power_words: Vec<TokenAnalysis>,
    pub optimal_length: usize,
}

// ── campaign autopilot types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateArm {
    pub template_id: String,
    pub state: BanditState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanditState {
    pub alpha: f64,
    pub beta: f64,
    pub trials: i64,
    pub successes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSelection {
    pub selected_arm: usize,
    pub template_id: String,
    pub selection_probabilities: Vec<f64>,
    pub credible_intervals: Vec<(f64, f64)>,
    pub expected_regret: f64,
    pub converged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub campaign_id: String,
    pub arms: Vec<BanditState>,
    pub selection_probabilities: Vec<f64>,
    pub credible_intervals: Vec<(f64, f64)>,
    pub total_trials: i64,
    pub converged: bool,
    pub recommended_arm: usize,
}

// ── bot detection types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotType {
    SearchEngine,
    LinkPreview,
    SecurityScanner,
    Crawler,
    ClickFarm,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickEvent {
    pub message_id: String,
    pub link_id: String,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub click_delay_ms: Option<u64>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectionResult {
    pub is_bot: bool,
    pub score: f64,
    pub bot_type: Option<BotType>,
    pub signals: Vec<String>,
}

// ── inbox placement types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementSummary {
    pub overall_inbox_rate: f64,
    pub inbox_count: i64,
    pub spam_count: i64,
    pub bounce_count: i64,
    pub by_provider: Vec<crate::inbox_placement::ProviderPlacement>,
    pub recommendations: Vec<String>,
}

// ── reply tracking types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplySentiment {
    Positive,
    Negative,
    Neutral,
    Inquiry,
    Unsubscribe,
    OutOfOffice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyEvent {
    pub message_id: String,
    pub in_reply_to: String,
    pub tenant_id: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub headers: std::collections::HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyMetrics {
    pub total_replies: i64,
    pub auto_replies: i64,
    pub human_replies: i64,
    pub reply_rate: f64,
    pub avg_thread_depth: f64,
}

// ── engagement trust types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberEngagement {
    pub email: String,
    pub open_rate: f64,
    pub click_rate: f64,
    pub spam_rate: f64,
    pub unsubscribe_rate: f64,
    pub reply_rate: f64,
    pub bounce_rate: f64,
    pub total_sent: i64,
    pub total_delivered: i64,
    pub total_opened: i64,
    pub total_clicked: i64,
    pub preference_compliance: f64,
    pub send_frequency_compliance: f64,
    pub recency_score: f64,
    pub nps_score: Option<f64>,
    pub survey_score: Option<f64>,
    pub feedback_count: i64,
    pub last_engagement: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub score: f64,
    pub grade: String,
    pub risk_level: String,
    pub credibility: f64,
    pub reliability: f64,
    pub intimacy: f64,
    pub self_orientation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTrustMetrics {
    pub campaign_id: String,
    pub average_trust_score: f64,
    pub grade: String,
    pub risk_level: String,
    pub subscriber_count: i64,
    pub grade_distribution: std::collections::HashMap<String, i64>,
}
