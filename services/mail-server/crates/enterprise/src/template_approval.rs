use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

/// Template Approval Service:multi-stage review with spam scoring
pub struct TemplateApprovalService {
    db: PgPool,
    auto_approve_threshold: i32,
    auto_reject_threshold: i32,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct TemplateSubmissionDbRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    html_content: String,
    text_content: Option<String>,
    subject: String,
    status: String,
    submitted_by: String,
    reviewed_by: Option<String>,
    review_notes: Option<String>,
    spam_score: Option<f64>,
    spam_details: Option<serde_json::Value>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<TemplateSubmissionDbRow> for TemplateSubmission {
    fn from(row: TemplateSubmissionDbRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id.to_string(),
            name: row.name,
            description: row.description,
            html_content: row.html_content,
            text_content: row.text_content,
            subject: row.subject,
            status: row.status,
            submitted_by: row.submitted_by,
            reviewed_by: row.reviewed_by,
            review_notes: row.review_notes,
            spam_score: row.spam_score,
            spam_details: row.spam_details,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

fn parse_tenant_id(tenant_id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(tenant_id).map_err(|error| format!("Invalid tenant id '{tenant_id}': {error}"))
}

impl TemplateApprovalService {
    pub fn new(db: PgPool, auto_approve_threshold: i32, auto_reject_threshold: i32) -> Self {
        Self { db, auto_approve_threshold, auto_reject_threshold }
    }

/// Submit a template for approval, including spam scoring
    pub async fn submit(
        &self, tenant_id: String, name: &str, subject: &str,
        html_content: &str, text_content: Option<&str>, submitted_by: &str,
    ) -> Result<ApiResult<TemplateSubmission>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let id = Uuid::new_v4();
        let spam_result = calculate_spam_score(html_content, subject);

// Auto-approve or auto-reject based on score thresholds
        let status = if spam_result.score <= self.auto_approve_threshold as f64 {
            "approved"
        } else if spam_result.score >= self.auto_reject_threshold as f64 {
            "rejected"
        } else {
            "pending"
        };

        let spam_json = serde_json::to_value(&spam_result)
            .map_err(|e| format!("failed to serialize spam result: {e}"))?;

        let row = sqlx::query_as::<_, TemplateSubmissionDbRow>(
            "INSERT INTO ent_template_submissions (id, tenant_id, name, subject, html_content, text_content, status, submitted_by, spam_score, spam_details, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(tenant_uuid).bind(name).bind(subject)
        .bind(html_content).bind(text_content)
        .bind(status).bind(submitted_by)
        .bind(spam_result.score).bind(&spam_json)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Submit template: {e}"))?;

        info!(template_id = %id, score = spam_result.score, status = status, "Template submitted");
        Ok(ApiResult::ok(row.into()))
    }

/// Get a template submission by ID
    pub async fn get_submission(&self, id: Uuid) -> Result<ApiResult<TemplateSubmission>, String> {
        let row = sqlx::query_as::<_, TemplateSubmissionDbRow>(
            "SELECT * FROM ent_template_submissions WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get submission: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Submission not found", "NOT_FOUND")),
        }
    }

/// List submissions for a tenant
    pub async fn list_submissions(
        &self, tenant_id: String, status: Option<&str>, limit: i64, offset: i64,
    ) -> Result<ApiResult<Vec<TemplateSubmission>>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let rows = if let Some(s) = status {
            sqlx::query_as::<_, TemplateSubmissionDbRow>(
                "SELECT * FROM ent_template_submissions WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
            )
            .bind(tenant_uuid).bind(s).bind(limit).bind(offset)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as::<_, TemplateSubmissionDbRow>(
                "SELECT * FROM ent_template_submissions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(tenant_uuid).bind(limit).bind(offset)
            .fetch_all(&self.db)
            .await
        }.map_err(|e| format!("List submissions: {e}"))?;

        Ok(ApiResult::ok(rows.into_iter().map(Into::into).collect()))
    }

/// Approve a template
    pub async fn approve(
        &self, id: Uuid, reviewed_by: &str, notes: Option<&str>,
    ) -> Result<ApiResult<TemplateSubmission>, String> {
        let row = sqlx::query_as::<_, TemplateSubmissionDbRow>(
            "UPDATE ent_template_submissions SET status = 'approved', reviewed_by = $2, review_notes = $3, updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(reviewed_by).bind(notes)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Approve template: {e}"))?;

        match row {
            Some(r) => {
                info!(template_id = %id, "Template approved");
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err("Submission not found", "NOT_FOUND")),
        }
    }

/// Reject a template
    pub async fn reject(
        &self, id: Uuid, reviewed_by: &str, reason: &str,
    ) -> Result<ApiResult<TemplateSubmission>, String> {
        let row = sqlx::query_as::<_, TemplateSubmissionDbRow>(
            "UPDATE ent_template_submissions SET status = 'rejected', reviewed_by = $2, review_notes = $3, updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(reviewed_by).bind(reason)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Reject template: {e}"))?;

        match row {
            Some(r) => {
                info!(template_id = %id, reason = reason, "Template rejected");
                Ok(ApiResult::ok(r.into()))
            }
            None => Ok(ApiResult::err("Submission not found", "NOT_FOUND")),
        }
    }

/// Request changes on a template
    pub async fn request_changes(
        &self, id: Uuid, reviewed_by: &str, notes: &str,
    ) -> Result<ApiResult<TemplateSubmission>, String> {
        let row = sqlx::query_as::<_, TemplateSubmissionDbRow>(
            "UPDATE ent_template_submissions SET status = 'changes_requested', reviewed_by = $2, review_notes = $3, updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(reviewed_by).bind(notes)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Request changes: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r.into())),
            None => Ok(ApiResult::err("Submission not found", "NOT_FOUND")),
        }
    }

/// Get approval stats for a tenant
    pub async fn get_stats(
        &self, tenant_id: String,
    ) -> Result<ApiResult<serde_json::Value>, String> {
        let tenant_uuid = parse_tenant_id(&tenant_id)?;
        let row: (i64, i64, i64, i64, i64, Option<f64>) = sqlx::query_as(
            "SELECT
             COUNT(*),
             COUNT(*) FILTER (WHERE status = 'pending'),
             COUNT(*) FILTER (WHERE status = 'approved'),
             COUNT(*) FILTER (WHERE status = 'rejected'),
             COUNT(*) FILTER (WHERE status = 'changes_requested'),
             AVG(spam_score)::float8
             FROM ent_template_submissions WHERE tenant_id = $1"
        )
           .bind(tenant_uuid)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Get template stats: {e}"))?;

        Ok(ApiResult::ok(serde_json::json!({
            "total": row.0,
            "pending": row.1,
            "approved": row.2,
            "rejected": row.3,
            "changes_requested": row.4,
            "avg_spam_score": row.5.unwrap_or(0.0),
        })))
    }
}

// ── Spam Scoring Algorithm ─────────────────────────────────────────────

/// Score trigger words found in content
static TRIGGER_WORDS: &[&str] = &[
    "free", "winner", "congratulations", "act now", "limited time",
    "urgent", "click here", "buy now", "discount", "offer expires",
    "no obligation", "risk free", "guaranteed", "credit card",
    "make money", "earn extra", "cash bonus", "double your",
    "no cost", "special promotion",
];

/// Calculate a spam score for HTML email content and subject line
pub fn calculate_spam_score(html: &str, subject: &str) -> SpamScoreResult {
    let mut score = 0.0_f64;
    let mut details = Vec::new();
    let combined = format!("{} {}", subject, html);
    let lower = combined.to_lowercase();

// 1. Trigger words (+5 each)
    let mut trigger_count = 0;
    for word in TRIGGER_WORDS {
        if lower.contains(word) {
            trigger_count += 1;
        }
    }
    if trigger_count > 0 {
        let pts = trigger_count as f64 * 5.0;
        score += pts;
        details.push(SpamScoreDetail {
            rule: "trigger_words".into(),
            points: pts,
            description: format!("Found {} trigger words", trigger_count),
        });
    }

// 2. ALL CAPS > 30% of subject (+10)
    let alpha_chars: Vec<char> = subject.chars().filter(|c| c.is_alphabetic()).collect();
    if !alpha_chars.is_empty() {
        let upper_count = alpha_chars.iter().filter(|c| c.is_uppercase()).count();
        let upper_pct = (upper_count as f64 / alpha_chars.len() as f64) * 100.0;
        if upper_pct > 30.0 {
            score += 10.0;
            details.push(SpamScoreDetail {
                rule: "excessive_caps".into(),
                points: 10.0,
                description: format!("{:.0}% uppercase in subject", upper_pct),
            });
        }
    }

// 3. Excessive punctuation (!! or ??) (+5 each occurrence)
    let excl_runs = html.matches("!!").count() + subject.matches("!!").count();
    let quest_runs = html.matches("??").count() + subject.matches("??").count();
    let punct_count = excl_runs + quest_runs;
    if punct_count > 0 {
        let pts = punct_count as f64 * 5.0;
        score += pts;
        details.push(SpamScoreDetail {
            rule: "excessive_punctuation".into(),
            points: pts,
            description: format!("{} instances of excessive punctuation", punct_count),
        });
    }

// 4. URL count > 3 (+2 each extra)
    let url_count = count_urls(html);
    if url_count > 3 {
        let extra = (url_count - 3) as f64;
        let pts = extra * 2.0;
        score += pts;
        details.push(SpamScoreDetail {
            rule: "excessive_urls".into(),
            points: pts,
            description: format!("{} URLs (threshold: 3)", url_count),
        });
    }

// 5. Image-to-text ratio > 60% (+10)
    let img_ratio = image_to_text_ratio(html);
    if img_ratio > 60.0 {
        score += 10.0;
        details.push(SpamScoreDetail {
            rule: "high_image_ratio".into(),
            points: 10.0,
            description: format!("{:.0}% image-to-text ratio", img_ratio),
        });
    }

// 6. Missing unsubscribe link (+15)
    if !lower.contains("unsubscribe") {
        score += 15.0;
        details.push(SpamScoreDetail {
            rule: "missing_unsubscribe".into(),
            points: 15.0,
            description: "No unsubscribe link found".into(),
        });
    }

// 7. Deceptive subject patterns (+10)
    let deceptive_patterns = ["re:", "fw:", "fwd:"];
    let subj_lower = subject.to_lowercase();
    for pattern in deceptive_patterns {
        if subj_lower.starts_with(pattern) {
            score += 10.0;
            details.push(SpamScoreDetail {
                rule: "deceptive_subject".into(),
                points: 10.0,
                description: format!("Subject starts with '{}'", pattern),
            });
            break;
        }
    }

    SpamScoreResult { score, details }
}

/// Count URLs (href="http..." patterns) in HTML
fn count_urls(html: &str) -> usize {
    let lower = html.to_lowercase();
    lower.matches("href=\"http").count() + lower.matches("href='http").count()
}

/// Estimate image-to-text ratio (% of content that is images)
fn image_to_text_ratio(html: &str) -> f64 {
    let img_count = html.to_lowercase().matches("<img").count();
    if img_count == 0 {
        return 0.0;
    }
    let text_len = strip_tags(html).len();
    if text_len == 0 {
        return 100.0;
    }
    let img_chars = img_count * 5000;
    let total = img_chars + text_len;
    (img_chars as f64 / total as f64) * 100.0
}

/// Simple HTML tag stripper
fn strip_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_email() {
        let result = calculate_spam_score(
            "<p>Hello, here is your monthly update. <a href=\"#\">Unsubscribe</a></p>",
            "Monthly Newsletter",
        );
        assert!(result.score <= 10.0, "Clean email score should be low, got {}", result.score);
    }

    #[test]
    fn test_trigger_words() {
        let result = calculate_spam_score(
            "<p>Free winner! Act now for a limited time offer! Unsubscribe</p>",
            "Congratulations!",
        );
        assert!(result.score > 0.0);
        assert!(result.details.iter().any(|d| d.rule == "trigger_words"));
    }

    #[test]
    fn test_excessive_caps() {
        let result = calculate_spam_score(
            "<p>Hello unsubscribe</p>",
            "THIS IS ALL CAPS SUBJECT LINE",
        );
        assert!(result.details.iter().any(|d| d.rule == "excessive_caps"));
    }

    #[test]
    fn test_excessive_punctuation() {
        let result = calculate_spam_score(
            "<p>Act now!! Buy now!! Don't miss out!! unsubscribe</p>",
            "Amazing deal!!",
        );
        assert!(result.details.iter().any(|d| d.rule == "excessive_punctuation"));
    }

    #[test]
    fn test_missing_unsubscribe() {
        let result = calculate_spam_score(
            "<p>Please check out our product</p>",
            "Product Update",
        );
        assert!(result.details.iter().any(|d| d.rule == "missing_unsubscribe"));
        assert!((result.details.iter().find(|d| d.rule == "missing_unsubscribe").unwrap().points - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_deceptive_subject() {
        let result = calculate_spam_score(
            "<p>Some content unsubscribe</p>",
            "Re: Your account",
        );
        assert!(result.details.iter().any(|d| d.rule == "deceptive_subject"));
    }

    #[test]
    fn test_excessive_urls() {
        let html = r#"<p>
            <a href="http://a.com">a</a>
            <a href="http://b.com">b</a>
            <a href="http://c.com">c</a>
            <a href="http://d.com">d</a>
            <a href="http://e.com">e</a>
            unsubscribe
        </p>"#;
        let result = calculate_spam_score(html, "Links");
        assert!(result.details.iter().any(|d| d.rule == "excessive_urls"));
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags("<p>Hello <b>world</b></p>"), "Hello world");
        assert_eq!(strip_tags("no tags here"), "no tags here");
        assert_eq!(strip_tags("<>"), "");
    }

    #[test]
    fn test_count_urls() {
        let html = r#"<a href="http://a.com">a</a><a href='http://b.com'>b</a>"#;
        assert_eq!(count_urls(html), 2);
    }

    #[test]
    fn test_image_ratio_no_images() {
        assert_eq!(image_to_text_ratio("<p>Just text</p>"), 0.0);
    }

    #[test]
    fn test_image_ratio_high() {
        let ratio = image_to_text_ratio("<img src='x.png'/>");
        assert!(ratio > 60.0);
    }

    #[test]
    fn test_spam_score_result_serialization() {
        let r = SpamScoreResult {
            score: 25.0,
            details: vec![SpamScoreDetail {
                rule: "trigger_words".into(),
                points: 25.0,
                description: "5 trigger words".into(),
            }],
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["score"], 25.0);
        assert_eq!(json["details"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_spam_verdict_thresholds() {
// score 0 → clean
        let r1 = calculate_spam_score("<p>Simple text. Unsubscribe</p>", "Hello");
        assert!(r1.score <= 10.0);

// Stack enough to be high score (>30)
// Missing unsubscribe (15) + deceptive subject (10) + trigger words (~10) > 30
        let r2 = calculate_spam_score(
            "<p>FREE WINNER click here</p>",
            "Re: Urgent!!!",
        );
        assert!(r2.score > 30.0, "Expected spam score > 30, got {}", r2.score);
    }
}
