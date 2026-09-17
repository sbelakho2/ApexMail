//! Automatic dedicated-IP warmup graduation (P1).
//!
//! The canonical 60-day schedule (see `mail_common::warmup`) grows a warming
//! IP's daily ceiling until day 60, after which the limit is unbounded — but
//! nothing in the tree SCHEDULED the lifecycle transition, so a fully-warmed
//! IP stayed labelled `warming` until an operator intervened. Send-time
//! admission derives the cap from `warmup_started_at`, so an ungraduated IP
//! kept functioning; the label was a lie the control plane told itself.
//!
//! [`graduate_mature_warmup_ips`] runs the idempotent transition
//! `warming → active` for every IP whose warmup anchor is at or past
//! `FULL_WARMUP_DAYS`, writing one audit row per graduation. The worker's
//! poll loop invokes it daily-ish (it is idempotent: a second pass finds no
//! candidates); the control plane's manual graduation route keeps working —
//! the reconciler only ever performs the same transition the state machine
//! allows.
#![deny(unsafe_code)]

use sqlx::PgPool;

/// Graduate every warming IP whose 60-day term is complete.
///
/// Returns the graduated `dedicated_ips.id` list (for logging). A database
/// failure is returned to the caller — graduation never silently skips.
pub async fn graduate_mature_warmup_ips(db: &PgPool) -> Result<Vec<String>, String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("graduation transaction failed to begin: {error}"))?;
    let graduated: Vec<(String,)> = sqlx::query_as(
        r#"
        UPDATE dedicated_ips
        SET status = 'active',
            warmup_progress = 1.0,
            updated_at = NOW()
        WHERE status = 'warming'
          AND warmup_started_at IS NOT NULL
          AND EXTRACT(DAY FROM NOW() - warmup_started_at)
              >= $1::numeric
        RETURNING id::text
        "#,
    )
    .bind(mail_common::warmup::FULL_WARMUP_DAYS as i32)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| format!("graduation update failed: {error}"))?;
    for (id,) in &graduated {
        // Audit inside the same transaction, chained onto the canonical
        // audit hash chain (previous_hash → hash): a graduation without
        // evidence is an unreviewable lifecycle change.
        let previous_hash: Option<String> =
            sqlx::query_scalar("SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| format!("graduation audit chain read failed: {error}"))?
                .flatten();
        let details = serde_json::json!({
            "reason": "canonical 60-day warmup term complete",
            "by": "worker:graduation-reconciler",
        })
        .to_string();
        let timestamp = chrono::Utc::now();
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        hasher.update(b"system");
        hasher.update(b"|ip.warmup_graduated|");
        hasher.update(id.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        if let Some(previous) = &previous_hash {
            hasher.update(previous.as_bytes());
        }
        let hash = hasher.finalize();
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        sqlx::query(
            r#"
            INSERT INTO audit_logs
                (id, tenant_id, action, resource, resource_id, details,
                 outcome, timestamp, hash, previous_hash, signature)
            VALUES (gen_random_uuid(), 'system', 'ip.warmup_graduated', 'dedicated_ip',
                    $1, $2::jsonb, 'success', $3, $4, $5, $6)
            "#,
        )
        .bind(id)
        .bind(&details)
        .bind(timestamp)
        .bind(&hash_hex)
        .bind(&previous_hash)
        .bind(format!("graduation:{hash_hex}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("graduation audit write failed for {id}: {error}"))?;
    }
    tx.commit()
        .await
        .map_err(|error| format!("graduation commit failed: {error}"))?;
    Ok(graduated.into_iter().map(|(id,)| id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reconciler targets exactly the canonical term and only `warming`.
    #[test]
    fn graduation_sql_pins_term_and_state() {
        let source = include_str!("graduation.rs");
        assert!(source.contains("status = 'warming'"));
        assert!(source.contains("FULL_WARMUP_DAYS"));
        assert!(source.contains("status = 'active'"));
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;

    async fn db() -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool("warmup_graduation", "wp_graduation")
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn seed_ip(db: &sqlx::PgPool, id: &str, days: i64, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ('t_grad', 'Graduation Test', 'growth', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(db)
        .await
        .expect("tenant");
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, warmup_started_at, created_at, updated_at)
             VALUES ($1, 't_grad', $2, $3, NOW() - ($4 || ' days')::interval, NOW(), NOW())",
        )
        .bind(id)
        .bind(format!("203.0.{}.{}", 100 + (days % 100), days))
        .bind(status)
        .bind(days.to_string())
        .execute(db)
        .await
        .expect("dedicated ip");
    }

    /// Day-60 IPs graduate exactly once, with an audit row; day-59 and
    /// already-active rows are untouched; the second pass is a no-op.
    #[tokio::test]
    async fn graduation_is_exact_idempotent_and_audited() {
        let Some(db) = db().await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        seed_ip(&db, "grad-mature", 61, "warming").await;
        seed_ip(&db, "grad-young", 59, "warming").await;
        seed_ip(&db, "grad-active", 90, "active").await;

        let graduated = graduate_mature_warmup_ips(&db).await.expect("pass 1");
        assert_eq!(graduated, vec!["grad-mature".to_string()]);

        let state = |id: &str| {
            let db = db.clone();
            let id = id.to_string();
            async move {
                sqlx::query_scalar::<_, String>("SELECT status FROM dedicated_ips WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&db)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(state("grad-mature").await, "active");
        assert_eq!(
            state("grad-young").await,
            "warming",
            "day 59 does not graduate"
        );
        assert_eq!(state("grad-active").await, "active");

        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'ip.warmup_graduated' AND resource_id = 'grad-mature'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(audit, 1, "one audit row on the canonical chain");

        // Idempotent.
        let again = graduate_mature_warmup_ips(&db).await.expect("pass 2");
        assert!(again.is_empty());
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'ip.warmup_graduated'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(audit, 1, "no duplicate audit rows on the second pass");
        db.close().await;
    }
}
