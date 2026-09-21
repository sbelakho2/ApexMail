//! Reply handler — inbound email classification and sequence locking.
//!
//! The classifier is split into three honest layers:
//!
//! - [`deterministic`] — header/syntax-proven cases only, with exact evidence;
//! - [`ai`] — provider-agnostic semantic classification with a never-guessing
//!   fallback on outage;
//! - [`policy`] — the single decision table turning a classification into an
//!   enrollment state, suppression, rescheduling and queue cancellation.
//!
//! [`processor`] wires those layers to the `inbound_messages` claim loop and
//! to the canonical sales tables (`sales_enrollments`, `sales_actions`,
//! `sales_unsubscribes`, `sales_reply_classifications`).

pub mod ai;
mod classifier;
pub mod deterministic;
pub mod policy;
mod processor;
mod types;

pub use ai::{
    classifier_from_config, classify_or_fallback, ClassifyError, HttpReplyClassifier,
    ReplyClassifier, StaticFallbackClassifier, AI_OUTAGE_REASON_PREFIX, AI_PROMPT_VERSION,
};
pub use classifier::{classify, classify_full, CLASSIFIER_INPUT_CAP};
pub use deterministic::{
    classify as classify_deterministic, DeterministicVerdict, DEFAULT_OOO_WAIT_DAYS,
    MAX_CLASSIFIER_INPUT_BYTES, OOO_HEADER_NAMES, OOO_SUBJECT_TOKENS, STOP_REQUEST_TOKENS,
};
pub use policy::{
    decide as decide_policy, DowngradeReason, EnrollmentState, PolicyDecision, PolicyInput,
    ReschedulePlan, MIN_AUTO_ACTION_CONFIDENCE,
};
pub use processor::{
    persist_classification, record_action_outcome, record_operator_correction,
    ClassificationRecord, ReplyHandler,
};
pub use types::{
    ActionType, AiClassification, ClassificationOutcome, ClassificationResult, ClassifierKind,
    Evidence, ExtractedData, InboundMessage, ProcessedReply, ReplyClassification, ReplyDisposition,
    ReplyInput, Sentiment, SuggestedAction, Urgency,
};

#[cfg(test)]
mod handoff_outage_tests {
    //! Loop-level failure injection lives HERE rather than in
    //! `processor.rs` because that file is guarded by a source scan that
    //! (rightly) forbids schema statements in the worker's own source; this
    //! test only SIMULATES an outage of the reply-analytics store from the
    //! outside, through the processor's public API.

    use crate::reply_handler::processor::ReplyHandler;
    use std::sync::Arc;
    use std::time::Duration;

    /// With `reply_events` gone, every processed message fails at the
    /// analytics handoff: the loop must keep resetting claims (messages stay
    /// retryable, nothing is marked processed) and still stop cleanly.
    #[tokio::test]
    async fn loop_keeps_resetting_claims_while_the_analytics_store_is_down() {
        crate::test_support::install_test_tracing();
        let Some(pool) = migrator::test_support::fresh_canonical_pool(
            "reply_handoff_outage",
            "reply_handoff_outage",
        )
        .await
        .expect("provision") else {
            return;
        };
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..12];
        let tenant = format!("rho-{suffix}");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'RHO', $2, 'free', 'active')",
        )
        .bind(&tenant)
        .bind(format!("rho-{suffix}"))
        .execute(&pool)
        .await
        .expect("tenant");
        let msg_id = format!("rho-{suffix}");
        sqlx::query(
            "INSERT INTO inbound_messages \
                 (id, tenant_id, from_email, to_email, subject, body_text, headers, received_at) \
             VALUES ($1, $2, $3, 'sales@apex.example', 'Re: hi', 'body', '{}', NOW())",
        )
        .bind(&msg_id)
        .bind(&tenant)
        .bind(format!("sender-{suffix}@example.com"))
        .execute(&pool)
        .await
        .expect("inbound");

        // Simulate the analytics store outage.
        sqlx::query("DROP TABLE reply_events")
            .execute(&pool)
            .await
            .expect("simulate outage");

        let config = crate::common::ReplyHandlerConfig {
            base: crate::common::ProcessorConfig {
                name: "reply-outage".into(),
                concurrency: 2,
                poll_interval: Duration::from_millis(20),
                ..Default::default()
            },
            ..Default::default()
        };
        let handler = Arc::new(ReplyHandler::new(pool.clone(), config));
        let start_handle = {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move { handler.start().await })
        };
        // Give the loop a few poll cycles of claim → fail → reset.
        tokio::time::sleep(Duration::from_millis(150)).await;
        handler.stop().await.expect("stop");
        tokio::time::timeout(Duration::from_secs(10), start_handle)
            .await
            .expect("start returns after stop")
            .expect("join")
            .expect("start clean");

        let (processed, processing): (
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT processed_at, processing_at FROM inbound_messages WHERE id = $1",
        )
        .bind(&msg_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(
            processed.is_none(),
            "messages failing the handoff must never be marked processed"
        );
        assert!(
            processing.is_none(),
            "the loop must reset the claim so the next poll retries"
        );
        pool.close().await;
    }
}
