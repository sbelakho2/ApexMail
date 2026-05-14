use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ── Seed Providers ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderName {
    Gmail,
    Outlook,
    Yahoo,
    Icloud,
    Aol,
    Zoho,
    Protonmail,
    Gmx,
    Yandex,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SeedProvider {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub inbox_types: Vec<String>,
    pub icon_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub active_accounts: i64,
    pub inbox_types: Vec<String>,
}

// ── Seed Accounts ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SeedAccount {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub email: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<i32>,
    pub imap_username: Option<String>,
    // NOTE: imap_password_encrypted is NEVER selected in queries to avoid leaking
    pub is_active: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub health_status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedAccountResponse {
    pub id: Uuid,
    pub provider: String,
    pub email: String,
    pub is_active: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub health_status: String,
}

// ── Placement Tests ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PlacementTest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: Option<String>,
    pub status: String,
    pub from_email: String,
    pub subject: String,
    pub total_accounts: i32,
    pub completed_accounts: i32,
    pub seed_accounts_used: Vec<Uuid>,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementTestSummary {
    pub inbox_pct: f64,
    pub promotions_pct: f64,
    pub spam_pct: f64,
    pub absent_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementTestResponse {
    pub id: Uuid,
    pub name: Option<String>,
    pub status: String,
    pub from_email: String,
    pub subject: String,
    pub total_accounts: i32,
    pub completed_accounts: i32,
    pub summary: Option<PlacementTestSummary>,
    pub overall_score: Option<u16>,
    pub results: Vec<ProviderResult>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResult {
    pub provider: String,
    pub accounts_tested: i32,
    pub inbox: i32,
    pub promotions: i32,
    pub spam: i32,
    pub absent: i32,
    pub avg_delivery_time_ms: f64,
    pub spf_pass_rate: f64,
    pub dkim_pass_rate: f64,
    pub dmarc_pass_rate: f64,
    pub recommendation: String,
}

// ── Placement Results ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PlacementResult {
    pub id: Uuid,
    pub test_id: Uuid,
    pub seed_account_id: Uuid,
    pub inbox_type: Option<String>,
    pub delivery_time_ms: Option<i32>,
    pub raw_headers: Option<String>,
    pub spf_pass: Option<bool>,
    pub dkim_pass: Option<bool>,
    pub dmarc_pass: Option<bool>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementTrend {
    pub date: String,
    pub inbox_pct: f64,
    pub promotions_pct: f64,
    pub spam_pct: f64,
}

// ── API Request Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTestRequest {
    pub name: Option<String>,
    pub from_email: String,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub target_providers: Option<Vec<String>>,
    pub schedule_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestListQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestListResponse {
    pub tests: Vec<PlacementTestListItem>,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementTestListItem {
    pub id: Uuid,
    pub name: Option<String>,
    pub status: String,
    pub from_email: String,
    pub subject: String,
    pub total_accounts: i32,
    pub completed_accounts: i32,
    pub summary: Option<PlacementTestSummary>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendsQuery {
    pub days: Option<u32>,
    pub provider: Option<String>,
}

// ── Scoring ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementScore {
    pub overall: u16,
    pub inbox_rate_score: u16,
    pub promotions_score: u16,
    pub spam_penalty: u16,
    pub absent_penalty: u16,
    pub auth_score: u16,
    pub speed_score: u16,
}

impl PlacementScore {
    /// Calculate placement score from per-provider results.
    /// Weights: Inbox 40%, Promotions 20%, Spam -25%, Absent -15%, Auth 20%, Speed 10%
    pub fn calculate(results: &[ProviderResult]) -> Self {
        if results.is_empty() {
            return Self {
                overall: 0,
                inbox_rate_score: 0,
                promotions_score: 0,
                spam_penalty: 0,
                absent_penalty: 0,
                auth_score: 0,
                speed_score: 0,
            };
        }

        let total_accounts: i32 = results.iter().map(|r| r.accounts_tested).sum();
        if total_accounts == 0 {
            return Self {
                overall: 0,
                inbox_rate_score: 0,
                promotions_score: 0,
                spam_penalty: 0,
                absent_penalty: 0,
                auth_score: 0,
                speed_score: 0,
            };
        }

        let total_inbox: i32 = results.iter().map(|r| r.inbox).sum();
        let total_promotions: i32 = results.iter().map(|r| r.promotions).sum();
        let total_spam: i32 = results.iter().map(|r| r.spam).sum();
        let total_absent: i32 = results.iter().map(|r| r.absent).sum();

        let inbox_pct = (total_inbox as f64 / total_accounts as f64) * 100.0;
        let promotions_pct = (total_promotions as f64 / total_accounts as f64) * 100.0;
        let spam_pct = (total_spam as f64 / total_accounts as f64) * 100.0;
        let absent_pct = (total_absent as f64 / total_accounts as f64) * 100.0;

        let avg_auth = results
            .iter()
            .map(|r| (r.spf_pass_rate + r.dkim_pass_rate + r.dmarc_pass_rate) / 3.0)
            .sum::<f64>()
            / results.len() as f64;
        let avg_speed_ms =
            results.iter().map(|r| r.avg_delivery_time_ms).sum::<f64>() / results.len() as f64;

        let inbox_rate_score = (inbox_pct * 0.4) as u16;
        let promotions_score = (promotions_pct * 0.2) as u16;
        let spam_penalty = ((spam_pct * 2.5).min(100.0)) as u16;
        let absent_penalty = ((absent_pct * 1.67).min(100.0)) as u16;
        let auth_score = (avg_auth * 0.2) as u16;
        let speed_score = ((100.0 - (avg_speed_ms / 100.0) * 2.0).clamp(0.0, 100.0) * 0.1) as u16;

        let raw = inbox_rate_score as i32 + promotions_score as i32
            - spam_penalty as i32
            - absent_penalty as i32
            + auth_score as i32
            + speed_score as i32;

        let overall = raw.clamp(0, 100) as u16;

        Self {
            overall,
            inbox_rate_score,
            promotions_score,
            spam_penalty,
            absent_penalty,
            auth_score,
            speed_score,
        }
    }
}
