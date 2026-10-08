//! Wave G (dogfood 2026-10-06 R-6): the four zero-writer/zero-reader schema
//! orphans are dropped by migration 249, and the live dead-letter store the
//! operator runbook queries (`email_dlq`, migration 088) remains.
//!
//! Can-fail by construction: before 249 each `to_regclass` probe returns the
//! table, so every assertion below fails.

use sqlx::PgPool;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

#[tokio::test]
async fn orphan_tables_are_dropped_and_the_live_dlq_remains() {
    let Some(pool) = canonical_pool("orphan_tables_dropped").await else {
        return;
    };

    for table in [
        "dead_letter_queue",
        "alert_webhook_queue",
        "ip_provisioning_queue",
        "report_history",
    ] {
        let exists: Option<Option<String>> =
            sqlx::query_scalar("SELECT to_regclass($1)::text")
                .bind(format!("public.{table}"))
                .fetch_one(&pool)
                .await
                .expect("to_regclass probe");
        assert!(
            exists.flatten().is_none(),
            "{table} must be gone after migration 249 (schema orphan: no writer, no reader)"
        );
    }

    // The live dead-letter queue the MTA runbook now queries.
    let live_dlq: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.email_dlq')::text")
        .fetch_one(&pool)
        .await
        .expect("email_dlq probe");
    assert!(
        live_dlq.is_some(),
        "email_dlq (migration 088) is the live dead-letter store and must remain"
    );

    pool.close().await;
}
