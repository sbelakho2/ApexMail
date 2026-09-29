use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{is_automation_confidence, InboxMessage, MessageCategory, SalesError};

/// Inbox monitoring / sentinel service backed by PostgreSQL.
/// Categorises inbound messages into Lead / Customer / Support / Spam /
/// Unsubscribe / NeedsReview using weighted keyword heuristics scored for
/// confidence (Fix #19): only a classification whose confidence reaches
/// [`crate::types::AUTOMATION_CONFIDENCE_THRESHOLD`] is treated as decided;
/// anything weaker lands in [`MessageCategory::NeedsReview`] for human review
/// and can never drive downstream automation.
#[derive(Debug, Clone)]
pub struct InboxManager {
    db: PgPool,
}

/// A scored classification decision (Fix #19).
///
/// `category` is [`MessageCategory::NeedsReview`] whenever `confidence` is
/// below [`crate::types::AUTOMATION_CONFIDENCE_THRESHOLD`] — the confidence
/// is preserved so callers/logs can show HOW ambiguous the message was.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationDecision {
    pub category: MessageCategory,
    /// 0.0–1.0 keyword-hit strength for the winning category.
    pub confidence: f32,
}

/// A heuristic keyword and the strength of its signal (Fix #19).
///
/// Weights encode specificity: an explicit, unambiguous phrase ("invoice",
/// "unsubscribe", "viagra") is strong; a generic word ("help", "issue",
/// "interested") is weak and only decides a category when it accumulates
/// past the threshold together with other hits.
type Keyword = (&'static str, f32);

/// Opt-out language is legally significant (CAN-SPAM, Fix I-5) and always
/// explicit: any single hit is decisive.
const UNSUBSCRIBE_KEYWORDS: &[Keyword] = &[
    ("unsubscribe", 1.0),
    ("remove me", 1.0),
    ("take me off", 1.0),
    ("stop emailing", 1.0),
    ("opt out", 1.0),
    ("opt-out", 1.0),
];

/// Explicit spam vocabulary.
const SPAM_KEYWORDS: &[Keyword] = &[("viagra", 1.0), ("lottery", 1.0)];
/// Transactional/system sender addresses — a strong but not explicit signal.
const SPAM_SENDER_KEYWORDS: &[Keyword] = &[("noreply", 0.75)];

const SUPPORT_KEYWORDS: &[Keyword] = &[
    ("ticket", 0.8),
    ("support", 0.7),
    ("issue", 0.35),
    ("help", 0.35),
];

const CUSTOMER_KEYWORDS: &[Keyword] = &[
    ("invoice", 0.8),
    ("payment", 0.7),
    ("subscription", 0.7),
    ("renewal", 0.7),
];

const LEAD_KEYWORDS: &[Keyword] = &[
    ("demo", 0.8),
    ("pricing", 0.8),
    ("trial", 0.7),
    ("interested", 0.35),
];

impl InboxManager {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Classify a message without persisting it.
    pub fn classify_message(tenant_id: String, from: String, subject: String) -> InboxMessage {
        let decision = Self::classify_scored(&subject, &from);
        if !decision.category.is_concrete() {
            // Alert-grade for the review bucket: the message is deliberately
            // NOT decided, so no downstream automation may act on it (Fix #19).
            tracing::info!(
                category = %decision.category,
                confidence = decision.confidence,
                "inbox message below automation confidence — routed to human review (Fix #19)"
            );
        }
        InboxMessage {
            id: Uuid::new_v4(),
            tenant_id,
            from,
            subject,
            received_at: Utc::now(),
            category: decision.category,
            replied: false,
        }
    }

    /// Classify and store a message, returning the assigned category.
    pub async fn categorize_message(
        &self,
        tenant_id: &str,
        from: String,
        subject: String,
    ) -> InboxMessage {
        let msg = Self::classify_message(tenant_id.to_string(), from, subject);

        let _ = sqlx::query(
            "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, received_at, category, replied) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(msg.id)
        .bind(&msg.tenant_id)
        .bind(&msg.from)
        .bind(&msg.subject)
        .bind(msg.received_at)
        .bind(msg.category.to_string())
        .bind(msg.replied)
        .execute(&self.db)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "failed to persist inbox message"));

        msg
    }

    /// Heuristic classification with confidence scoring (Fix #19).
    ///
    /// Deterministic scoring model:
    /// - each category sums the weights of its keywords that appear in the
    ///   (lowercased) subject, capped at 1.0; Spam also matches sender
    ///   keywords;
    /// - the winner is the highest-scoring category, ties broken by the fixed
    ///   check order below (Unsubscribe → Spam → Support → Customer → Lead);
    /// - a winner below
    ///   [`crate::types::AUTOMATION_CONFIDENCE_THRESHOLD`] — including the
    ///   no-hit case — is demoted to [`MessageCategory::NeedsReview`] with
    ///   its score preserved: ambiguity must be a distinct category, so the
    ///   structural guard (no irreversible action from a non-concrete
    ///   category) holds at every consumer.
    pub fn classify_scored(subject: &str, from: &str) -> ClassificationDecision {
        let s = subject.to_lowercase();
        let f = from.to_lowercase();

        // Scored in a FIXED order — the tie-break is "first in this order"
        // (strictly-greater comparison keeps the earlier category on ties).
        let scored: [(MessageCategory, f32); 5] = [
            (
                MessageCategory::Unsubscribe,
                Self::score(&s, UNSUBSCRIBE_KEYWORDS),
            ),
            (
                MessageCategory::Spam,
                Self::score(&s, SPAM_KEYWORDS).max(Self::score(&f, SPAM_SENDER_KEYWORDS)),
            ),
            (MessageCategory::Support, Self::score(&s, SUPPORT_KEYWORDS)),
            (MessageCategory::Customer, Self::score(&s, CUSTOMER_KEYWORDS)),
            (MessageCategory::Lead, Self::score(&s, LEAD_KEYWORDS)),
        ];

        let mut best = (MessageCategory::Unsubscribe, 0.0_f32);
        for (category, score) in scored {
            if score > best.1 {
                best = (category, score);
            }
        }
        let (category, confidence) = best;

        if is_automation_confidence(confidence) {
            ClassificationDecision {
                category,
                confidence,
            }
        } else {
            ClassificationDecision {
                category: MessageCategory::NeedsReview,
                confidence,
            }
        }
    }

    /// Sum the weights of matched keywords, capped at 1.0.
    fn score(haystack: &str, keywords: &[Keyword]) -> f32 {
        let total: f32 = keywords
            .iter()
            .filter(|(phrase, _)| haystack.contains(phrase))
            .map(|(_, weight)| weight)
            .sum();
        total.min(1.0)
    }

    /// List messages belonging to a given category, scoped to tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list.
    pub async fn list_by_category(
        &self,
        tenant_id: &str,
        cat: MessageCategory,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboxMessage>, SalesError> {
        let rows = sqlx::query_as::<_, InboxMessageRow>(
            "SELECT id, tenant_id, sender, subject, received_at, category, replied FROM sales_inbox_messages WHERE tenant_id = $1 AND category = $2 ORDER BY received_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(cat.to_string())
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_message()).collect())
    }

    /// List all messages regardless of category, scoped to tenant.
    ///
    /// Returns `Err` on database failure — previously errors were logged and
    /// silently converted into an empty list.
    pub async fn list_all(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InboxMessage>, SalesError> {
        let rows = sqlx::query_as::<_, InboxMessageRow>(
            "SELECT id, tenant_id, sender, subject, received_at, category, replied FROM sales_inbox_messages WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_message()).collect())
    }

    /// Mark a message as replied (scoped to tenant).
    ///
    /// Returns `Err(SalesError::MessageNotFound)` when no matching message
    /// exists for this tenant, and `Err(SalesError::Database(..))` on
    /// database failure — previously both cases collapsed into a bare
    /// `false` that callers could not distinguish.
    pub async fn mark_replied(&self, tenant_id: &str, id: Uuid) -> Result<(), SalesError> {
        let result = sqlx::query(
            "UPDATE sales_inbox_messages SET replied = true WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SalesError::MessageNotFound(id));
        }
        Ok(())
    }

    /// Return the reply rate (0.0–1.0) scoped to a tenant.
    pub async fn get_reply_rate(&self, tenant_id: &str) -> f64 {
        let counts: Result<(i64, i64), _> = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN replied THEN 1 ELSE 0 END), 0) FROM sales_inbox_messages WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await;

        match counts {
            Ok((total, replied)) if total > 0 => replied as f64 / total as f64,
            _ => 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal row type for sqlx mapping
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InboxMessageRow {
    id: Uuid,
    tenant_id: String,
    sender: String,
    subject: String,
    received_at: chrono::DateTime<chrono::Utc>,
    category: String,
    replied: bool,
}

impl InboxMessageRow {
    fn into_message(self) -> InboxMessage {
        InboxMessage {
            id: self.id,
            tenant_id: self.tenant_id,
            from: self.sender,
            subject: self.subject,
            received_at: self.received_at,
            category: MessageCategory::from_str(&self.category),
            replied: self.replied,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::{canonical_test_pool, unique_test_tenant};

    /// Manager on the canonical provisioned test database (fresh pool per
    /// test); `None` means the environment is unconfigured → soft-skip.
    async fn make_mgr(test_name: &str) -> Option<InboxManager> {
        let db = canonical_test_pool(test_name).await?;
        Some(InboxManager::new(db))
    }

    /// Fix I-5: unsubscribe/opt-out subjects must classify as Unsubscribe
    /// (handled with priority), NOT Spam. Pure test — no database required.
    #[test]
    fn unsubscribe_subjects_classify_as_unsubscribe_not_spam() {
        for subject in [
            "Please unsubscribe me from your list",
            "Unsubscribe",
            "Remove me from this newsletter",
            "Take me off your mailing list",
            "Stop emailing me",
            "I want to opt out of marketing emails",
        ] {
            let msg = InboxManager::classify_message(
                "t".into(),
                "user@corp.example".into(),
                subject.into(),
            );
            assert_eq!(
                msg.category,
                MessageCategory::Unsubscribe,
                "subject {subject:?} must classify as Unsubscribe, got {:?}",
                msg.category
            );
        }
    }

    #[test]
    fn spam_classification_unchanged_for_real_spam() {
        let msg = InboxManager::classify_message(
            "t".into(),
            "noreply@spam.biz".into(),
            "You won the lottery!".into(),
        );
        assert_eq!(msg.category, MessageCategory::Spam);
    }

    #[test]
    fn unsubscribe_category_serializes_and_parses() {
        assert_eq!(MessageCategory::Unsubscribe.to_string(), "unsubscribe");
        assert_eq!(
            MessageCategory::from_str("unsubscribe"),
            MessageCategory::Unsubscribe
        );
        // Fix #19: the review bucket round-trips the same way.
        assert_eq!(MessageCategory::NeedsReview.to_string(), "needs_review");
        assert_eq!(
            MessageCategory::from_str("needs_review"),
            MessageCategory::NeedsReview
        );
        assert!(!MessageCategory::NeedsReview.is_concrete());
    }

    // ------------------------------------------------------------------
    // Fix #19 — confidence-scored classification: ambiguous input lands in
    // NeedsReview (no downstream automation may act on it), strong input is
    // decided, and the threshold boundary is inclusive.
    // ------------------------------------------------------------------

    /// An ambiguous message (no decisive keyword signal) must land in the
    /// NeedsReview bucket — structurally NOT a concrete category — so no
    /// consumer can drive suppression, auto-reply sends or enrollment from
    /// it. The score is preserved for the review UI/log.
    #[test]
    fn ambiguous_messages_land_in_needs_review_without_a_decided_category() {
        for (subject, from) in [
            ("Hello", "someone@example.com"),
            ("World", "someone@example.com"),
            ("quick question", "someone@example.com"),
            ("", ""),
            ("hey there, checking in", "someone@example.com"),
        ] {
            let decision = InboxManager::classify_scored(subject, from);
            assert_eq!(
                decision.category,
                MessageCategory::NeedsReview,
                "{subject:?} from {from:?} is ambiguous and must NOT be decided"
            );
            assert!(
                decision.confidence < crate::types::AUTOMATION_CONFIDENCE_THRESHOLD,
                "review-bucket confidence must be below the threshold: {decision:?}"
            );
            assert!(
                !decision.category.is_concrete(),
                "NeedsReview is never concrete"
            );
            // The persisted message carries the review category, so the
            // structural guard survives persistence.
            let msg = InboxManager::classify_message("t".into(), from.into(), subject.into());
            assert_eq!(msg.category, MessageCategory::NeedsReview);
        }
    }

    /// Strong, specific keyword signals keep their decided categories with
    /// automation-grade confidence — downstream consumers may act on these.
    #[test]
    fn strong_classifications_are_concrete_with_automation_confidence() {
        let cases: [(&str, &str, MessageCategory); 6] = [
            (
                "Interested in a demo",
                "alice@x.com",
                MessageCategory::Lead,
            ),
            ("Pricing inquiry", "a@b.com", MessageCategory::Lead),
            ("Support ticket #1234", "bob@y.com", MessageCategory::Support),
            (
                "Invoice for subscription",
                "billing@co.com",
                MessageCategory::Customer,
            ),
            (
                "You won the lottery!",
                "noreply@spam.biz",
                MessageCategory::Spam,
            ),
            (
                "Please unsubscribe me",
                "user@corp.example",
                MessageCategory::Unsubscribe,
            ),
        ];
        for (subject, from, expected) in cases {
            let decision = InboxManager::classify_scored(subject, from);
            assert_eq!(
                decision.category, expected,
                "{subject:?} from {from:?} must classify as {expected:?}"
            );
            assert!(
                crate::types::is_automation_confidence(decision.confidence),
                "{subject:?} must carry automation-grade confidence, got {decision:?}"
            );
            assert!(decision.category.is_concrete());
        }
    }

    /// The threshold boundary is inclusive (>=): a score EXACTLY at
    /// [`crate::types::AUTOMATION_CONFIDENCE_THRESHOLD`] decides the category
    /// (one specific keyword, or two weak hits summing to the threshold);
    /// one point below it stays in review.
    #[test]
    fn threshold_boundary_is_inclusive_and_deterministic() {
        // "trial" alone weighs exactly 0.70 → decided Lead.
        let at_threshold = InboxManager::classify_scored("trial access", "a@b.com");
        assert_eq!(at_threshold.category, MessageCategory::Lead);
        assert_eq!(at_threshold.confidence, 0.70);

        // Two weak hits sum to exactly 0.70 → decided Support.
        let weak_pair = InboxManager::classify_scored("need help with this issue", "a@b.com");
        assert_eq!(weak_pair.category, MessageCategory::Support);
        assert_eq!(weak_pair.confidence, 0.70);

        // One weak hit alone (0.35) is below the threshold → NeedsReview.
        let below = InboxManager::classify_scored("can you help", "a@b.com");
        assert_eq!(below.category, MessageCategory::NeedsReview);
        assert_eq!(below.confidence, 0.35);

        // Determinism: identical input → identical decision, every time.
        for _ in 0..3 {
            assert_eq!(
                InboxManager::classify_scored("trial access", "a@b.com"),
                at_threshold
            );
        }
    }

    /// Explicit opt-out language is legally significant (Fix I-5) and always
    /// decisive: it must never be demoted to NeedsReview, and it wins over
    /// any weaker concurrent signal (priority order).
    #[test]
    fn unsubscribe_phrases_carry_full_confidence_and_priority() {
        for subject in [
            "Please unsubscribe me from your list",
            "Remove me from this newsletter",
            "Stop emailing me",
            "I want to opt out of marketing emails",
        ] {
            let decision = InboxManager::classify_scored(subject, "user@corp.example");
            assert_eq!(decision.category, MessageCategory::Unsubscribe);
            assert_eq!(decision.confidence, 1.0);
        }
        // Opt-out beats a coincidental weak support signal.
        let mixed = InboxManager::classify_scored("please unsubscribe, I need no help", "a@b.com");
        assert_eq!(mixed.category, MessageCategory::Unsubscribe);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[tokio::test]
    async fn test_categorization() {
        let Some(mgr) = make_mgr("inbox::tests::test_categorization").await else {
            // coverage: justified — soft-skip arm: only taken when the shared
            // test database is not configured; this run has it configured.
            return;
        };
        let tenant = unique_test_tenant("inbox-categorization");
        let m1 = mgr
            .categorize_message(&tenant, "alice@x.com".into(), "Interested in a demo".into())
            .await;
        assert_eq!(m1.category, MessageCategory::Lead);

        let m2 = mgr
            .categorize_message(
                &tenant,
                "noreply@spam.biz".into(),
                "You won the lottery!".into(),
            )
            .await;
        assert_eq!(m2.category, MessageCategory::Spam);

        let m3 = mgr
            .categorize_message(&tenant, "bob@y.com".into(), "Support ticket #1234".into())
            .await;
        assert_eq!(m3.category, MessageCategory::Support);

        let m4 = mgr
            .categorize_message(
                &tenant,
                "billing@co.com".into(),
                "Invoice for subscription".into(),
            )
            .await;
        assert_eq!(m4.category, MessageCategory::Customer);
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[tokio::test]
    async fn test_list_by_category_and_mark_replied() {
        let Some(mgr) = make_mgr("inbox::tests::test_list_by_category_and_mark_replied").await
        else {
            // coverage: justified — soft-skip arm: only taken when the shared
            // test database is not configured; this run has it configured.
            return;
        };
        let tenant = unique_test_tenant("inbox-list");
        let m = mgr
            .categorize_message(&tenant, "a@b.com".into(), "Pricing inquiry".into())
            .await;
        assert_eq!(m.category, MessageCategory::Lead);

        let leads = mgr
            .list_by_category(&tenant, MessageCategory::Lead, 100, 0)
            .await
            .unwrap();
        assert_eq!(leads.len(), 1);

        mgr.mark_replied(&tenant, m.id).await.unwrap();
        assert!(mgr.mark_replied(&tenant, Uuid::new_v4()).await.is_err()); // non-existent
    }

    /// Integration test requiring local Postgres. Run with infrastructure.
    #[tokio::test]
    async fn test_reply_rate() {
        let Some(mgr) = make_mgr("inbox::tests::test_reply_rate").await else {
            // coverage: justified — soft-skip arm: only taken when the shared
            // test database is not configured; this run has it configured.
            return;
        };
        let tenant = unique_test_tenant("inbox-reply-rate");
        assert_eq!(mgr.get_reply_rate(&tenant).await, 0.0);

        let m1 = mgr
            .categorize_message(&tenant, "a@b.com".into(), "Hello".into())
            .await;
        let _m2 = mgr
            .categorize_message(&tenant, "c@d.com".into(), "World".into())
            .await;
        mgr.mark_replied(&tenant, m1.id).await.unwrap();

        let rate = mgr.get_reply_rate(&tenant).await;
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }
}
