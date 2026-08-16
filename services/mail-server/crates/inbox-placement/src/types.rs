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
    ///
    /// A perfect run (100 % inbox, full auth, instant delivery) scores
    /// exactly 100; no combination can exceed 100:
    /// - Inbox rate: 60 % (max 60)
    /// - Promotions rate: 20 % — *partial credit* for tabbed placement, so a
    ///   mixed run scores less than pure inbox but is not treated as failure
    /// - Authentication (SPF/DKIM/DMARC avg): 20 %
    /// - Speed (linear falloff, 0 at ≥ 5 s): 20 %
    ///
    /// The placement component is bounded at 60 because `inbox_pct ≤ 100`
    /// on its own caps it (promotions credit is extra, but a 100 %-promotions
    /// run only earns 20 of it), so `60 + 20 + 20 = 100` is the ceiling.
    ///
    /// Penalties subtract from the total:
    /// - Spam penalty: up to 25 (spam rate × 0.25)
    /// - Absent penalty: up to 15 (absent rate × 0.15)
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

        // avg_auth is a 0.0–1.0 rate: convert to a percentage before weighting.
        let avg_auth = results
            .iter()
            .map(|r| (r.spf_pass_rate + r.dkim_pass_rate + r.dmarc_pass_rate) / 3.0)
            .sum::<f64>()
            / results.len() as f64;
        let avg_speed_ms =
            results.iter().map(|r| r.avg_delivery_time_ms).sum::<f64>() / results.len() as f64;

        // Speed curve: 100 % at 0 ms falling linearly to 0 % at 5 s
        // (anything slower than 5 s scores 0).
        let speed_pct = if avg_speed_ms >= 5000.0 {
            0.0
        } else {
            100.0 * (1.0 - avg_speed_ms / 5000.0)
        };

        let inbox_rate_score = (inbox_pct * 0.60) as u16; // max 60
        let promotions_score = (promotions_pct * 0.20) as u16; // max 20 (partial credit)
        let spam_penalty = (spam_pct * 0.25) as u16; // max 25
        let absent_penalty = (absent_pct * 0.15) as u16; // max 15
        let auth_score = (avg_auth * 100.0 * 0.20) as u16; // max 20
        let speed_score = (speed_pct * 0.20) as u16; // max 20

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

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_result(inbox: i32, promotions: i32, spam: i32, absent: i32) -> ProviderResult {
        ProviderResult {
            provider: "gmail".into(),
            accounts_tested: inbox + promotions + spam + absent,
            inbox,
            promotions,
            spam,
            absent,
            avg_delivery_time_ms: 0.0,
            spf_pass_rate: 1.0,
            dkim_pass_rate: 1.0,
            dmarc_pass_rate: 1.0,
            recommendation: String::new(),
        }
    }

    #[test]
    fn perfect_run_scores_100() {
        let score = PlacementScore::calculate(&[provider_result(10, 0, 0, 0)]);
        assert_eq!(score.inbox_rate_score, 60);
        assert_eq!(score.promotions_score, 0);
        assert_eq!(score.auth_score, 20);
        assert_eq!(score.speed_score, 20);
        assert_eq!(score.spam_penalty, 0);
        assert_eq!(score.absent_penalty, 0);
        assert_eq!(score.overall, 100);
    }

    #[test]
    fn promotions_only_run_earns_partial_credit() {
        // Everything tabbed into Promotions: placement credit is only the
        // 20-point promotions component (never more than pure inbox).
        let score = PlacementScore::calculate(&[provider_result(0, 10, 0, 0)]);
        assert_eq!(score.inbox_rate_score, 0);
        assert_eq!(score.promotions_score, 20);
        assert_eq!(score.overall, 60); // 20 + auth 20 + speed 20
    }

    #[test]
    fn auth_score_is_percentage_weighted() {
        // avg_auth = 0.5 → auth_score = 0.5 * 100 * 0.2 = 10 (not 0).
        let mut r = provider_result(0, 0, 0, 10);
        r.spf_pass_rate = 1.0;
        r.dkim_pass_rate = 0.5;
        r.dmarc_pass_rate = 0.0;
        let score = PlacementScore::calculate(&[r]);
        assert_eq!(score.auth_score, 10);
    }

    #[test]
    fn speed_falls_off_linearly_to_zero_at_5s() {
        let mut r = provider_result(0, 0, 0, 1);
        r.avg_delivery_time_ms = 2500.0; // half-way → speed_pct 50 → score 10
        assert_eq!(PlacementScore::calculate(&[r.clone()]).speed_score, 10);

        r.avg_delivery_time_ms = 5000.0; // exactly 5 s → 0
        assert_eq!(PlacementScore::calculate(&[r.clone()]).speed_score, 0);

        r.avg_delivery_time_ms = 60_000.0; // way past 5 s → still 0
        assert_eq!(PlacementScore::calculate(&[r]).speed_score, 0);
    }

    #[test]
    fn spam_and_absent_penalties_are_capped() {
        let score = PlacementScore::calculate(&[provider_result(0, 0, 10, 0)]);
        assert_eq!(score.spam_penalty, 25);
        assert_eq!(score.absent_penalty, 0);

        let score = PlacementScore::calculate(&[provider_result(0, 0, 0, 10)]);
        assert_eq!(score.spam_penalty, 0);
        assert_eq!(score.absent_penalty, 15);
    }

    #[test]
    fn empty_results_score_zero() {
        let score = PlacementScore::calculate(&[]);
        assert_eq!(score.overall, 0);
    }
}
