//! Adversarial tests for relay-owned warmup admission (the P0 ownership
//! fix): the component that can transmit SMTP DATA owns the warming-IP
//! daily cap, so inline submissions AND durable daemon retries are admitted
//! at the effect boundary.
//!
//! Canonical Postgres (the real `dedicated_ips` lifecycle) + the real test
//! Redis; the SMTP side is the loopback fake server.

use std::net::IpAddr;
use std::sync::Arc;

use outbound_mta::test_support::{FakeSmtpConfig, FakeSmtpServer, StaticMxResolver};
use outbound_mta::warmup::{RedisWarmupGate, WarmupAdmission, WarmupGate};
use outbound_mta::{Relay, RelayConfig, SubmitRequest};

/// One SHARED canonical database for the suite (rows are scoped per test
/// via UNIQUE source IPs and send units — the real `dedicated_ips` table,
/// the real `outbound_relay_ledger`, the real Redis counters).
async fn test_db() -> Option<sqlx::PgPool> {
    let url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let (_, db_part) = url.rsplit_once('/')?;
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    match migrator::test_support::shared_canonical_db(&url, &format!("{db_only}_obm_warmup")).await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn redis_pool() -> Option<deadpool_redis::Pool> {
    let url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    // A DEDICATED logical DB so parallel runs never share counters.
    let url = url.trim().trim_end_matches('/');
    let url = match url.rsplit_once('/') {
        Some((server, last)) if last.parse::<u32>().is_ok() => format!("{server}/7"),
        None => return None,
        _ => format!("{url}/7"),
    };
    deadpool_redis::Config::from_url(url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .ok()
}

async fn seed_warming_ip(pool: &sqlx::PgPool, ip: &str, warmup_started_days_ago: i64) {
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
         VALUES ('t_warm', 'warmup gate test', 'growth', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("tenant");
    // One row PER source address (the shared database is addressed by IP):
    // the id is derived from the address so sibling tests never overwrite
    // each other's lifecycle rows, and any stale row on the same address is
    // cleared first (the unique active-ip index).
    let id = format!("dip-gate-{}", ip.replace('.', "-"));
    sqlx::query("DELETE FROM dedicated_ips WHERE ip_address = $1 OR id = $2")
        .bind(ip)
        .bind(&id)
        .execute(pool)
        .await
        .expect("clear stale row");
    sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, warmup_started_at, created_at, updated_at)
         VALUES ($3, 't_warm', $1, 'warming', NOW() - ($2 || ' days')::interval, NOW(), NOW())",
    )
    .bind(ip)
    .bind(warmup_started_days_ago.to_string())
    .bind(&id)
    .execute(pool)
    .await
    .expect("dedicated ip");
}

/// Counters/markers are keyed by (unique-per-test IP, day, send unit): no
/// cross-test clearing is needed, and FLUSHDB on the shared logical DB
/// would wipe a sibling test's accounting mid-flight.
async fn clear_warmup_keys(_redis: &deadpool_redis::Pool) {}

/// The suite's ledger is the SHARED canonical database: send units must be
/// unique per RUN (a failed prior run leaves its pending rows behind).
fn unit(prefix: &str) -> String {
    format!("{prefix}:{}", uuid::Uuid::new_v4().simple())
}

fn request(unit: &str, ip: Option<IpAddr>) -> SubmitRequest {
    SubmitRequest {
        send_unit: unit.to_string(),
        tenant_id: Some("t_warm".into()),
        queue_id: None,
        envelope_from: Some("sender@apexmail.ee".into()),
        recipients: vec!["user@example.com".into()],
        message: b"From: sender@apexmail.ee\r\nTo: user@example.com\r\nSubject: hi\r\n\r\nbody"
            .to_vec(),
        requested_source_ip: ip,
    }
}

fn relay_with_gate(
    db: &sqlx::PgPool,
    redis: &deadpool_redis::Pool,
    server: &FakeSmtpServer,
) -> Relay {
    let ledger: Arc<dyn outbound_mta::ledger::RelayLedger> =
        Arc::new(outbound_mta::ledger::PgLedger::new(db.clone()));
    let resolver = Arc::new(
        StaticMxResolver::new()
            .with_target("example.com", vec![server.addr()])
            .with_target("apexmail.ee", vec![server.addr()]),
    );
    let gate = WarmupGate::new(Arc::new(RedisWarmupGate::new(redis.clone())));
    Relay::with_warmup_gate(ledger, resolver, RelayConfig::default(), gate)
}
/// Below the cap: the attempt is admitted, delivered, and the counter the
/// quota tooling reads is exactly 1 — the WORKER no longer increments.
#[tokio::test]
async fn warming_attempt_is_admitted_and_counted_at_the_boundary() {
    let (Some(db), Some(redis)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    // Serialize with the active-IP test (both drive the one locally
    // bindable address through OPPOSITE lifecycle states) — the lock is
    // taken BEFORE seeding so the row's lifecycle state cannot flip
    // mid-test.
    let guard = sqlx::query("SELECT pg_advisory_lock(hashtext('obm-warmup-gate:127.0.0.1'))")
        .execute(&db)
        .await
        .expect("advisory lock");
    seed_warming_ip(&db, "127.0.0.1", 0).await;
    // Counters persist on the shared logical DB: reset THIS test's key.
    {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut conn = redis.get().await.unwrap();
        let _: () = deadpool_redis::redis::cmd("DEL")
            .arg(format!("apexmail:warmup:ip:127.0.0.1:{today}"))
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let relay = relay_with_gate(&db, &redis, &server);
    let record = relay
        .submit(request(
            &unit("wg:admit:1"),
            Some("127.0.0.1".parse().unwrap()),
        ))
        .await
        .expect("admitted and delivered");
    assert_eq!(record.recipients.len(), 1);
    assert_eq!(server.messages().len(), 1);

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut conn = redis.get().await.unwrap();
    let count: Option<i64> = deadpool_redis::redis::cmd("GET")
        .arg(format!("apexmail:warmup:ip:127.0.0.1:{today}"))
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(count, Some(1), "exactly one slot consumed at the boundary");
    let _ = guard;
    db.close().await;
}

/// THE P0 regression: a transient failure persists the send for retry and
/// the slot STAYS consumed — the daemon's later retry cannot ride a slot the
/// outer worker "released". The retry re-admits via the same-day marker
/// without a second increment.
#[tokio::test]
async fn durable_retry_keeps_the_slot_and_same_day_marker_admits_once() {
    let (Some(db), Some(redis)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    clear_warmup_keys(&redis).await;
    seed_warming_ip(&db, "203.0.113.78", 0).await;
    let ip: IpAddr = "203.0.113.78".parse().unwrap();
    // Counters persist on the shared logical DB: reset THIS test's key.
    {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut conn = redis.get().await.unwrap();
        let _: () = deadpool_redis::redis::cmd("DEL")
            .arg(format!("apexmail:warmup:ip:203.0.113.78:{today}"))
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    // The first server REFUSES EHLO permanently → the whole unit fails
    // permanently... no: use a dropping server so the failure is transient
    // and the relay persists a retry.
    let drop_server = FakeSmtpServer::start(FakeSmtpConfig {
        close_after_greeting: true,
        ..FakeSmtpConfig::default()
    })
    .await;
    let ledger: Arc<dyn outbound_mta::ledger::RelayLedger> =
        Arc::new(outbound_mta::ledger::PgLedger::new(db.clone()));
    let resolver = Arc::new(
        StaticMxResolver::new()
            .with_target("example.com", vec![drop_server.addr()])
            .with_target("apexmail.ee", vec![drop_server.addr()]),
    );
    let gate = WarmupGate::new(Arc::new(RedisWarmupGate::new(redis.clone())));
    let relay = Relay::with_warmup_gate(ledger, resolver, RelayConfig::default(), gate);

    let u1 = unit("wg:retry:1");
    let error = relay
        .submit(request(&u1, Some(ip)))
        .await
        .expect_err("the dropped connection is transient");
    assert!(
        matches!(error, outbound_mta::RelayError::RetryScheduled { .. }),
        "{error:?}"
    );

    // The slot is CONSUMED and stays consumed: no worker exists to release
    // it, and the daemon retry must not need a second one today.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let counter = format!("apexmail:warmup:ip:203.0.113.78:{today}");
    let mut conn = redis.get().await.unwrap();
    let count: Option<i64> = deadpool_redis::redis::cmd("GET")
        .arg(&counter)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(count, Some(1), "the failed attempt still consumed its slot");

    // A same-day re-attempt of the SAME send unit is admitted by the marker
    // WITHOUT a second increment.
    let gate: Arc<dyn outbound_mta::warmup::WarmupAdmit> =
        Arc::new(RedisWarmupGate::new(redis.clone()));
    let verdict = gate.admit(&u1, ip, &db).await.expect("store available");
    assert_eq!(verdict, WarmupAdmission::Admitted);
    let count: Option<i64> = deadpool_redis::redis::cmd("GET")
        .arg(&counter)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(count, Some(1), "same-day retry must not double-count");

    // A DIFFERENT send unit on the same IP still needs its own slot.
    let verdict = gate
        .admit(&unit("wg:retry:2"), ip, &db)
        .await
        .expect("store available");
    assert_eq!(verdict, WarmupAdmission::Admitted);
    let count: Option<i64> = deadpool_redis::redis::cmd("GET")
        .arg(&counter)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(count, Some(2));
    db.close().await;
}

/// Day-0 cap is 50: with the counter pre-filled to 50, a warming attempt is
/// refused BEFORE any connection is opened (the fake server sees nothing),
/// and the send is durably scheduled for retry.
#[tokio::test]
async fn at_cap_attempt_defers_before_any_connection() {
    let (Some(db), Some(redis)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    clear_warmup_keys(&redis).await;
    seed_warming_ip(&db, "203.0.113.79", 0).await;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    {
        let mut conn = redis.get().await.unwrap();
        let _: () = deadpool_redis::redis::cmd("SET")
            .arg(format!("apexmail:warmup:ip:203.0.113.79:{today}"))
            .arg(50_i64)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let relay = relay_with_gate(&db, &redis, &server);
    let error = relay
        .submit(request(
            &unit("wg:cap:1"),
            Some("203.0.113.79".parse().unwrap()),
        ))
        .await
        .expect_err("at-cap must defer");
    match error {
        outbound_mta::RelayError::RetryScheduled { reason, .. } => {
            assert!(reason.contains("daily cap"), "{reason}");
        }
        other => panic!("expected RetryScheduled, got {other:?}"),
    }
    assert!(
        server.messages().is_empty(),
        "an at-cap attempt must not reach the wire"
    );
    db.close().await;
}

/// Fail closed: an unreachable admission store defers instead of letting an
/// unaccounted attempt hit the wire.
#[tokio::test]
async fn admission_store_outage_fails_closed() {
    let (Some(db), Some(_)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    seed_warming_ip(&db, "203.0.113.80", 0).await;
    let dead = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap();

    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let relay = relay_with_gate(&db, &dead, &server);
    let error = relay
        .submit(request(
            &unit("wg:down:1"),
            Some("203.0.113.80".parse().unwrap()),
        ))
        .await
        .expect_err("outage must defer");
    assert!(
        matches!(error, outbound_mta::RelayError::RetryScheduled { .. }),
        "{error:?}"
    );
    assert!(server.messages().is_empty());
    db.close().await;
}

/// Graduated/active IPs carry no quota: admission is free even with the
/// counter store dead.
#[tokio::test]
async fn active_ip_admits_without_quota() {
    let (Some(db), Some(_)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
         VALUES ('t_warm', 'warmup gate test', 'growth', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await
    .expect("tenant");
    // Serialize with the warming-admit test (opposite lifecycle states on
    // the one locally bindable address).
    let guard = sqlx::query("SELECT pg_advisory_lock(hashtext('obm-warmup-gate:127.0.0.1'))")
        .execute(&db)
        .await
        .expect("advisory lock");
    // The unique non-retired index forbids two rows on one address: the
    // warming row is REPLACED by the graduated one (a real transition).
    sqlx::query("UPDATE dedicated_ips SET status = 'active' WHERE ip_address = '127.0.0.1'")
        .execute(&db)
        .await
        .expect("graduate the loopback ip");

    let dead = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap();
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let relay = relay_with_gate(&db, &dead, &server);
    let record = relay
        .submit(request(
            &unit("wg:active:1"),
            Some("127.0.0.1".parse().unwrap()),
        ))
        .await
        .expect("an active IP needs no quota");
    assert_eq!(record.recipients.len(), 1);
    assert_eq!(server.messages().len(), 1);
    let _ = guard;
    db.close().await;
}

/// A dedicated IP that vanished from the control plane defers with a named
/// reason (route re-selection is the caller's job, never silent re-routing).
#[tokio::test]
async fn vanished_ip_defers_with_a_named_reason() {
    let (Some(db), Some(redis)) = (test_db().await, redis_pool()) else {
        eprintln!("skipping: set TEST_DATABASE_URL + TEST_REDIS_URL");
        return;
    };
    clear_warmup_keys(&redis).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let relay = relay_with_gate(&db, &redis, &server);
    let error = relay
        .submit(request(
            &unit("wg:ghost:1"),
            Some("198.51.100.199".parse().unwrap()),
        ))
        .await
        .expect_err("a vanished IP must defer");
    match error {
        outbound_mta::RelayError::RetryScheduled { reason, .. } => {
            assert!(reason.contains("no longer exists"), "{reason}");
        }
        other => panic!("expected RetryScheduled, got {other:?}"),
    }
    assert!(server.messages().is_empty());
    db.close().await;
}

/// The schema itself guarantees a `warming` IP always carries its anchor
/// (`dedicated_ips_warming_anchor_check`): the gate's unanchored-refusal arm
/// is defense-in-depth for a state the database cannot produce.
#[tokio::test]
async fn schema_forbids_an_unanchored_warming_ip() {
    let Some(db) = test_db().await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
         VALUES ('t_warm', 'warmup gate test', 'growth', 'active', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await
    .expect("tenant");
    let rejected = sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, created_at, updated_at)
         VALUES (gen_random_uuid(), 't_warm', '203.0.113.199'::text::inet, 'warming', NOW(), NOW())",
    )
    .execute(&db)
    .await;
    let error = rejected.expect_err("an unanchored warming row must be rejected");
    assert!(
        error
            .to_string()
            .contains("dedicated_ips_warming_anchor_check"),
        "{error}"
    );
    db.close().await;
}

/// ── Migration 230: the delivery-contract fingerprint ─────────────────────
mod fingerprint_tests {
    use super::*;
    use outbound_mta::ledger::NewSubmission;
    use outbound_mta::ledger::PgLedger;
    use outbound_mta::ledger::RelayLedger;
    use outbound_mta::SubmitRequest;

    async fn fp_db() -> Option<sqlx::PgPool> {
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        match migrator::test_support::shared_canonical_db(&url, "apexmail_scratch_base_obm_fp")
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn fp_request(unit: &str, ip: Option<IpAddr>, body: &[u8]) -> SubmitRequest {
        SubmitRequest {
            send_unit: unit.to_string(),
            tenant_id: Some("t_fp".into()),
            queue_id: None,
            envelope_from: Some("fp@apexmail.ee".into()),
            recipients: vec!["fp@example.com".into()],
            message: body.to_vec(),
            requested_source_ip: ip,
        }
    }

    fn unit(prefix: &str) -> String {
        format!("{prefix}:{}", uuid::Uuid::new_v4().simple())
    }

    /// The fingerprint is a pure function of the DELIVERY CONTRACT: message
    /// bytes, envelope, recipients, tenant, and the requested route.
    #[test]
    fn fingerprint_is_contract_deterministic_and_route_sensitive() {
        let base = fp_request("u", Some("203.0.113.9".parse().unwrap()), b"m");
        let relay = outbound_mta::Relay::new(
            std::sync::Arc::new(outbound_mta::test_support::MemoryLedger::new()),
            std::sync::Arc::new(outbound_mta::test_support::StaticMxResolver::new()),
            outbound_mta::RelayConfig::default(),
        );
        let _ = relay; // fingerprint is an associated fn — call via the crate path
        let f1 = outbound_mta::relay_fingerprint(&base);
        let f2 = outbound_mta::relay_fingerprint(&base);
        assert_eq!(f1, f2, "deterministic");
        assert_eq!(f1.len(), 64, "sha256 hex");

        // Route sensitivity (stickiness): a different requested IP changes it.
        let other_ip = fp_request("u", Some("203.0.113.10".parse().unwrap()), b"m");
        assert_ne!(f1, outbound_mta::relay_fingerprint(&other_ip));

        // Message sensitivity.
        let other_body = fp_request("u", Some("203.0.113.9".parse().unwrap()), b"x");
        assert_ne!(f1, outbound_mta::relay_fingerprint(&other_body));

        // Recipient-order insensitivity (canonical recipients are sorted).
        let mut swapped = base.clone();
        swapped.recipients = vec!["b@example.com".into(), "a@example.com".into()];
        let mut canonical = base.clone();
        canonical.recipients = vec!["a@example.com".into(), "b@example.com".into()];
        assert_eq!(
            outbound_mta::relay_fingerprint(&swapped),
            outbound_mta::relay_fingerprint(&canonical)
        );

        // Envelope sensitivity.
        let mut other_env = base.clone();
        other_env.envelope_from = Some("other@apexmail.ee".into());
        assert_ne!(f1, outbound_mta::relay_fingerprint(&other_env));
    }

    /// The typed conflict: the same send_unit with a different contract is
    /// REFUSED (never a silent inheritance of the stored state).
    #[tokio::test]
    async fn same_unit_with_a_different_contract_is_a_typed_conflict() {
        let Some(db) = fp_db().await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let ledger = PgLedger::new(db.clone());
        let unit = unit("fp:conflict");
        let first = NewSubmission {
            send_unit: unit.clone(),
            tenant_id: Some("t_fp".into()),
            queue_id: None,
            request_fingerprint: Some("fingerprint-a".into()),
            envelope_from: Some("fp@apexmail.ee".into()),
            recipients: vec!["fp@example.com".into()],
            message: b"body-a".to_vec(),
            requested_source_ip: Some("203.0.113.9".parse().unwrap()),
            max_attempts: 3,
        };
        use outbound_mta::ledger::ClaimOutcome;
        let outcome = ledger
            .claim_submission(
                first,
                chrono::Utc::now(),
                std::time::Duration::from_secs(60),
            )
            .await
            .expect("first claim");
        assert!(matches!(outcome, ClaimOutcome::Claimed(_)));
        // release the lease so the row is not InFlight
        let _ = sqlx::query(
            "UPDATE outbound_relay_ledger SET state='pending', lease_until=NULL WHERE send_unit=$1",
        )
        .bind(&unit)
        .execute(&db)
        .await;

        let second = NewSubmission {
            request_fingerprint: Some("fingerprint-b".into()),
            send_unit: unit.clone(),
            ..duplicate_of(&unit)
        };
        let conflict = ledger
            .claim_submission(
                second,
                chrono::Utc::now(),
                std::time::Duration::from_secs(60),
            )
            .await
            .expect_err("a different contract under the same key must conflict");
        assert!(
            conflict.to_string().contains("idempotency conflict"),
            "{conflict}"
        );
        db.close().await;
    }

    fn duplicate_of(unit: &str) -> NewSubmission {
        NewSubmission {
            send_unit: unit.to_string(),
            tenant_id: Some("t_fp".into()),
            queue_id: None,
            request_fingerprint: None,
            envelope_from: Some("fp@apexmail.ee".into()),
            recipients: vec!["fp@example.com".into()],
            message: b"body-a".to_vec(),
            requested_source_ip: Some("203.0.113.9".parse().unwrap()),
            max_attempts: 3,
        }
    }

    /// Pin-on-first-replay: a pre-230 row (NULL fingerprint) adopts the
    /// incoming fingerprint once, then enforces the contract.
    #[tokio::test]
    async fn legacy_null_fingerprint_is_pinned_on_first_replay() {
        let Some(db) = fp_db().await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let ledger = PgLedger::new(db.clone());
        let unit = unit("fp:legacy");
        // A pre-230 row: claimed WITHOUT a fingerprint.
        let legacy = NewSubmission {
            request_fingerprint: None,
            ..duplicate_of(&unit)
        };
        use outbound_mta::ledger::ClaimOutcome;
        let outcome = ledger
            .claim_submission(
                legacy,
                chrono::Utc::now(),
                std::time::Duration::from_secs(60),
            )
            .await
            .expect("legacy claim");
        assert!(matches!(outcome, ClaimOutcome::Claimed(_)));
        let _ = sqlx::query("UPDATE outbound_relay_ledger SET state='pending', lease_until=NULL, request_fingerprint=NULL WHERE send_unit=$1")
            .bind(&unit)
            .execute(&db)
            .await;

        // First replay PINS the incoming fingerprint and classifies.
        let replay = NewSubmission {
            request_fingerprint: Some("pinned".into()),
            ..duplicate_of(&unit)
        };
        let outcome = ledger
            .claim_submission(
                replay,
                chrono::Utc::now(),
                std::time::Duration::from_secs(60),
            )
            .await
            .expect("pin-on-replay claim");
        assert!(matches!(outcome, ClaimOutcome::AlreadyQueued { .. }));
        let pinned: Option<String> = sqlx::query_scalar(
            "SELECT request_fingerprint FROM outbound_relay_ledger WHERE send_unit=$1",
        )
        .bind(&unit)
        .fetch_one(&db)
        .await
        .expect("read pin");
        assert_eq!(pinned.as_deref(), Some("pinned"));

        // A third submission with a DIFFERENT fingerprint now conflicts.
        let mut conflict = duplicate_of(&unit);
        conflict.request_fingerprint = Some("different".into());
        let error = ledger
            .claim_submission(
                conflict,
                chrono::Utc::now(),
                std::time::Duration::from_secs(60),
            )
            .await
            .expect_err("post-pin contract enforcement");
        assert!(
            error.to_string().contains("idempotency conflict"),
            "{error}"
        );
        db.close().await;
    }

    /// The SAME contract replays cleanly (the fingerprint never breaks
    /// legitimate idempotency).
    #[tokio::test]
    async fn same_contract_replays_cleanly() {
        let Some(db) = fp_db().await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let ledger = PgLedger::new(db.clone());
        let unit = unit("fp:replay");
        let first = NewSubmission {
            request_fingerprint: Some("same".into()),
            ..duplicate_of(&unit)
        };
        use outbound_mta::ledger::ClaimOutcome;
        assert!(matches!(
            ledger
                .claim_submission(
                    first,
                    chrono::Utc::now(),
                    std::time::Duration::from_secs(60)
                )
                .await
                .expect("first"),
            ClaimOutcome::Claimed(_)
        ));
        let _ = sqlx::query(
            "UPDATE outbound_relay_ledger SET state='pending', lease_until=NULL WHERE send_unit=$1",
        )
        .bind(&unit)
        .execute(&db)
        .await;
        let second = NewSubmission {
            request_fingerprint: Some("same".into()),
            ..duplicate_of(&unit)
        };
        assert!(matches!(
            ledger
                .claim_submission(
                    second,
                    chrono::Utc::now(),
                    std::time::Duration::from_secs(60)
                )
                .await
                .expect("clean replay"),
            ClaimOutcome::AlreadyQueued { .. }
        ));
        db.close().await;
    }
}

/// ── The ledger→acceptance reconciler (two-ledger projector) ───────────────
mod reconcile_tests {
    use outbound_mta::reconcile::reconcile_acceptances;

    async fn db() -> Option<sqlx::PgPool> {
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        match migrator::test_support::shared_canonical_db(&url, "apexmail_scratch_base_obm_rec")
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn unit(prefix: &str) -> String {
        format!("{prefix}:{}", uuid::Uuid::new_v4().simple())
    }

    /// A daemon-accepted send settles its `reserved` acceptance row without
    /// any worker involvement; already-settled and failed rows are untouched;
    /// a second pass is a no-op.
    #[tokio::test]
    async fn daemon_acceptance_settles_the_reserved_row_exactly_once() {
        let Some(db) = db().await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let settled = unit("rec:settled");
        let already = unit("rec:already");
        let failed = unit("rec:failed");
        let still_pending = unit("rec:pending");

        sqlx::query(
            "INSERT INTO sales_delivery_acceptances (send_unit, tenant_id, state)
             VALUES ($1, 't_rec', 'reserved'), ($2, 't_rec', 'accepted'),
                    ($3, 't_rec', 'failed'), ($4, 't_rec', 'reserved')",
        )
        .bind(&settled)
        .bind(&already)
        .bind(&failed)
        .bind(&still_pending)
        .execute(&db)
        .await
        .expect("acceptance rows");

        // Relay rows: `settled` accepted, `already` accepted, `failed`
        // accepted (its acceptance row is terminal-failed → untouched),
        // `still_pending` still pending (no projection yet).
        for (unit, state) in [
            (&settled, "accepted"),
            (&already, "accepted"),
            (&failed, "accepted"),
            (&still_pending, "pending"),
        ] {
            sqlx::query(
                "INSERT INTO outbound_relay_ledger
                 (send_unit, tenant_id, request_fingerprint, state, envelope_from, recipients,
                  message, requested_source_ip, attempt, max_attempts, next_attempt_at,
                  accepted_at, updated_at)
                 VALUES ($1, 't_rec', NULL, $2, NULL, '[\"r@example.com\"]'::jsonb, '\x66',
                         NULL, 1, 3, NOW(), NOW(), NOW())",
            )
            .bind(unit)
            .bind(state)
            .execute(&db)
            .await
            .expect("relay row");
        }

        let reconciled = reconcile_acceptances(&db).await.expect("pass 1");
        assert_eq!(reconciled.len(), 1, "only the reserved+accepted pair moves");
        assert_eq!(reconciled[0].send_unit, settled);

        let state = |unit: &str| {
            let db = db.clone();
            let unit = unit.to_string();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT state FROM sales_delivery_acceptances WHERE send_unit = $1",
                )
                .bind(&unit)
                .fetch_one(&db)
                .await
                .unwrap()
            }
        };
        assert_eq!(state(&settled).await, "accepted");
        assert_eq!(state(&already).await, "accepted");
        assert_eq!(state(&failed).await, "failed", "a terminal row never flips");
        assert_eq!(
            state(&still_pending).await,
            "reserved",
            "no relay acceptance yet"
        );

        // Idempotent: the second pass is a no-op.
        let again = reconcile_acceptances(&db).await.expect("pass 2");
        assert!(again.is_empty(), "nothing left to project: {again:?}");
        db.close().await;
    }
}
