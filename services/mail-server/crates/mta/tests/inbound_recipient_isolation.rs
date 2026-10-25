//! Invariant I27, cross-tenant recipient isolation on the inbound path.
//!
//! A single SMTP envelope can name recipients of several tenants' domains.
//! Each tenant's view of that message, the stored row's `rcpt_to` and the
//! `message.inbound` webhook payload queued to ITS queue, must carry only
//! that tenant's own addresses. The pre-fix implementation bound the row to
//! the FIRST resolved tenant but stored/enqueued the union, disclosing the
//! other tenant's recipients to that tenant's webhook consumer.

use std::collections::BTreeMap;

/// Seed a tenant with a verified domain. Returns the tenant id.
async fn seed_tenant_domain(pool: &sqlx::PgPool, tenant: &str, domain: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'free', 'active') \
         ON CONFLICT (id) DO UPDATE SET plan = 'free'",
    )
    .bind(tenant)
    .bind(format!("I27 {tenant}"))
    .execute(pool)
    .await
    .expect("seed tenant");
    sqlx::query(
        "INSERT INTO domains (tenant_id, name, status) \
         VALUES ($1, $2, 'verified') ON CONFLICT DO NOTHING",
    )
    .bind(tenant)
    .bind(domain)
    .execute(pool)
    .await
    .expect("seed domain");
}

async fn cleanup(pool: &sqlx::PgPool, tenant_a: &str, tenant_b: &str) {
    for statement in [
        "DELETE FROM webhook_queue WHERE tenant_id = ANY($1)",
        "DELETE FROM webhooks WHERE tenant_id = ANY($1)",
        "DELETE FROM domains WHERE tenant_id = ANY($1)",
        "DELETE FROM audit_logs WHERE tenant_id = ANY($1)",
        "DELETE FROM tenants WHERE id = ANY($1)",
    ] {
        sqlx::query(statement)
            .bind([tenant_a, tenant_b])
            .execute(pool)
            .await
            .ok();
    }
}

#[tokio::test]
async fn each_tenant_sees_only_its_own_recipients() {
    let Some(pool) =
        migrator::test_support::fresh_canonical_pool("i27_recipient_isolation", "group")
            .await
            .expect("configured TEST_DATABASE_URL must provision")
    else {
        eprintln!("skipping: set TEST_DATABASE_URL to run the I27 isolation test");
        return;
    };

    let tenant_a = "ten_i27_alpha";
    let tenant_b = "ten_i27_bravo";
    seed_tenant_domain(&pool, tenant_a, "alpha.example").await;
    seed_tenant_domain(&pool, tenant_b, "bravo.example").await;

    let envelope = vec![
        "alice@alpha.example".to_string(),
        "bob@bravo.example".to_string(),
        "carol@unowned.example".to_string(),
        "alice+tag@alpha.example".to_string(),
    ];

    // 1. Grouping: each tenant's group holds exactly its own addresses; the
    //    unowned domain belongs to no tenant's group.
    let grouped = mta::servers::inbound::group_recipients_by_tenant(&pool, &envelope)
        .await
        .expect("grouping");
    let expected: BTreeMap<String, Vec<String>> = [
        (
            tenant_a.to_string(),
            vec![
                "alice@alpha.example".to_string(),
                "alice+tag@alpha.example".to_string(),
            ],
        ),
        (tenant_b.to_string(), vec!["bob@bravo.example".to_string()]),
    ]
    .into_iter()
    .collect();
    assert_eq!(grouped, expected, "per-tenant grouping must be exact");
    assert!(
        !grouped.values().any(|recipients| {
            recipients
                .iter()
                .any(|r| r.contains("bravo.example") && r.contains("alice"))
                || recipients
                    .iter()
                    .any(|r| r.contains("alpha.example") && r.contains("bob"))
        }),
        "no tenant group may carry another tenant's address"
    );

    // 2. Queued webhooks: one event per tenant, each with only its own
    //    recipients under `data.recipients`.
    for tenant in [tenant_a, tenant_b] {
        sqlx::query(
            "INSERT INTO webhooks (id, tenant_id, name, url, secret, events, enabled, status) \
             VALUES ($1, $2, 'i27', 'https://example.invalid/hook', 'secret', \
                     '[\"message.inbound\"]'::jsonb, true, 'active') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("whk_{}", tenant))
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("seed webhook");
    }
    mta::servers::inbound::queue_inbound_events_for_tenants(
        &pool,
        "msg_i27_1",
        "sender@external.example",
        &grouped,
        Some(tenant_a),
    )
    .await;

    for (tenant, own) in [
        (tenant_a, &expected[tenant_a]),
        (tenant_b, &expected[tenant_b]),
    ] {
        let payloads: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM webhook_queue WHERE tenant_id = $1 AND event_type = 'message.inbound'",
        )
        .bind(tenant)
        .fetch_all(&pool)
        .await
        .expect("queued payloads");
        assert!(!payloads.is_empty(), "{tenant} received its own event");
        let mut recipients_seen: Vec<String> = Vec::new();
        for payload in &payloads {
            let list = payload["data"]["recipients"]
                .as_array()
                .expect("recipients array in the payload");
            for address in list {
                recipients_seen.push(address.as_str().expect("string").to_string());
            }
        }
        recipients_seen.sort();
        let mut own = own.clone();
        own.sort();
        assert_eq!(
            recipients_seen, own,
            "{tenant} must see exactly its own recipients"
        );
    }

    cleanup(&pool, tenant_a, tenant_b).await;
}
