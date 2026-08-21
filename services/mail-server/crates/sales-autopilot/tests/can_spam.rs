//! CAN-SPAM regression tests for the campaign dispatch path (fix I-2).
//!
//! These tests exercise `CampaignManager::start_campaign` end-to-end against
//! a real Postgres instance when one is available (`SALES_TEST_DATABASE_URL`,
//! default `postgres://127.0.0.1:5432/apexmail_test`). Without Postgres the
//! tests soft-skip so `cargo test` stays green everywhere.
//!
//! `mod common` also applies the PLATFORM schema (tools/migrations) — the
//! due-recipient query reads the platform `suppressions` table, exactly like
//! the REST send path does.

mod common;

use std::sync::Arc;

use sales_autopilot::campaigns::{
    CampaignEmailDispatcher, CampaignManager, DispatchRecipient,
};
use sales_autopilot::types::SalesError;
use uuid::Uuid;

/// Records every dispatch call for inspection.
#[derive(Debug, Default)]
struct RecordingDispatcher {
    calls: std::sync::Mutex<Vec<Vec<DispatchRecipient>>>,
}

impl CampaignEmailDispatcher for RecordingDispatcher {
    fn dispatch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipients: &[DispatchRecipient],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>,
    > {
        let _ = (tenant_id, campaign_id, template_id);
        self.calls
            .lock()
            .unwrap()
            .push(recipients.to_vec());
        let count = recipients.len();
        Box::pin(async move { Ok(count) })
    }

    fn unsubscribe_link(&self, tenant_id: &str, campaign_id: Uuid, email: &str) -> String {
        format!("https://sales.apexmail.ee/unsubscribe/{tenant_id}/{campaign_id}/{email}")
    }
}

async fn setup() -> Option<(CampaignManager, Arc<RecordingDispatcher>, sqlx::PgPool)> {
    let db = common::test_pool("can_spam").await?;

    let dispatcher = Arc::new(RecordingDispatcher::default());
    let manager = CampaignManager::new(50, db.clone())
        .with_email_dispatcher(dispatcher.clone() as Arc<dyn CampaignEmailDispatcher>);
    Some((manager, dispatcher, db))
}

#[tokio::test]
async fn suppressed_recipients_are_excluded_and_footer_attached() {
    let Some((manager, dispatcher, db)) = setup().await else {
        return;
    };
    let tenant = format!("spam-t-{}", &Uuid::new_v4().simple().to_string()[..16]);

    let campaign = manager
        .create_campaign(tenant.clone(), "wave".into(), "tmpl".into(), String::new())
        .await
        .unwrap();
    manager
        .add_recipients(
            &tenant,
            campaign.id,
            vec!["keep@corp.example".into(), "opted-out@corp.example".into()],
        )
        .await
        .unwrap();

    // Recipient opts out (suppression list) — must never be mailed.
    manager
        .suppress_recipient(&tenant, "opted-out@corp.example")
        .await
        .unwrap();
    assert!(manager
        .is_recipient_suppressed(&tenant, "opted-out@corp.example")
        .await
        .unwrap());

    manager.start_campaign(&tenant, campaign.id).await.unwrap();

    let calls = dispatcher.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "one dispatch batch: {calls:?}");
    let sent = &calls[0];
    assert_eq!(sent.len(), 1, "suppressed recipient must be excluded: {sent:?}");
    assert_eq!(sent[0].email, "keep@corp.example");
    // CAN-SPAM unsubscribe footer link is attached to every dispatch.
    assert!(
        sent[0].unsubscribe_link.contains("/unsubscribe/"),
        "footer link missing: {}",
        sent[0].unsubscribe_link
    );

    // The suppressed address never lands in the send ledger.
    let sent_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_campaign_recipients \
         WHERE campaign_id = $1 AND email = 'opted-out@corp.example' AND sent_at IS NOT NULL",
    )
    .bind(campaign.id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(sent_rows, 0);
}

#[tokio::test]
async fn frequency_cap_blocks_over_mailing() {
    let Some((manager, dispatcher, db)) = setup().await else {
        return;
    };
    let tenant = format!("cap-t-{}", &Uuid::new_v4().simple().to_string()[..16]);
    let heavy = "heavy@corp.example";

    // Simulate the recipient already having been mailed 3 campaigns in the
    // last 7 days (the weekly cap) plus a fresh recipient at zero.
    for _ in 0..3 {
        let prior = manager
            .create_campaign(tenant.clone(), "prior".into(), "tmpl".into(), String::new())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sales_campaign_recipients (campaign_id, email, sent_at) \
             VALUES ($1, $2, NOW())",
        )
        .bind(prior.id)
        .bind(heavy)
        .execute(&db)
        .await
        .unwrap();
    }

    let campaign = manager
        .create_campaign(tenant.clone(), "new-wave".into(), "tmpl".into(), String::new())
        .await
        .unwrap();
    manager
        .add_recipients(&tenant, campaign.id, vec![heavy.to_string(), "fresh@corp.example".into()])
        .await
        .unwrap();

    manager.start_campaign(&tenant, campaign.id).await.unwrap();

    let calls = dispatcher.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let sent = &calls[0];
    assert_eq!(sent.len(), 1, "capped recipient must be excluded: {sent:?}");
    assert_eq!(sent[0].email, "fresh@corp.example");

    // The capped recipient is not stamped as sent by this campaign.
    let stamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_campaign_recipients \
         WHERE campaign_id = $1 AND email = $2 AND sent_at IS NOT NULL",
    )
    .bind(campaign.id)
    .bind(heavy)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(stamped, 0);
}

#[tokio::test]
async fn start_without_dispatcher_service_fails_loudly() {
    let Some((_, _, db)) = setup().await else {
        return;
    };
    let tenant = format!("nodisp-{}", &Uuid::new_v4().simple().to_string()[..16]);
    // Production-shape manager: NO dispatcher wired.
    let manager = CampaignManager::new(50, db.clone());
    assert!(!manager.has_email_dispatcher());

    let campaign = manager
        .create_campaign(tenant.clone(), "x".into(), "t".into(), String::new())
        .await
        .unwrap();
    let err = manager
        .start_campaign(&tenant, campaign.id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SalesError::ServiceUnavailable(_)),
        "start without dispatcher must be a loud ServiceUnavailable, got {err:?}"
    );
}
