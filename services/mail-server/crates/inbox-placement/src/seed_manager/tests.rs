//! Adversarial canonical-schema tests for the seed-account manager
//! (`src/seed_manager.rs`): full lifecycle (list / assign / rotate / retire),
//! hostile failure reasons, permanent-vs-transient health classification,
//! exponential backoff, and the envelope-encrypted password rotation path.

use super::*;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

async fn seed_account(db: &PgPool, provider: &str, email: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, 'pw', true FROM seed_providers p WHERE p.name = $2 RETURNING id",
    )
    .bind(email)
    .bind(provider)
    .fetch_one(db)
    .await
    .expect("seed account");
    id
}

fn unique(label: &str) -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..10])
}

// ── Unit: failure classification & backoff ──────────────────────────────────

#[test]
fn permanent_failure_reasons_disable_immediately() {
    for reason in [
        "IMAP login error: authentication failed",
        "invalid credentials supplied",
        "AUTHENTICATIONFAILED: login rejected",
        "account disabled by administrator",
        "mailbox not found on this server",
        "user unknown",
        "no IMAP password configured",
        "permission denied",
        "application-specific password required",
    ] {
        assert!(is_permanent_failure(reason), "{reason} must be permanent");
    }
    // Mixed case still matches.
    assert!(is_permanent_failure("LOGIN REJECTED by server"));
}

#[test]
fn transient_failure_reasons_back_off_instead_of_disabling() {
    for reason in [
        "connection timed out",
        "connection reset by peer",
        "DNS lookup failed",
        "",
    ] {
        assert!(!is_permanent_failure(reason), "{reason:?} is transient");
    }
}

#[test]
fn backoff_doubles_and_caps_at_24h() {
    assert_eq!(backoff_seconds(1), 300);
    assert_eq!(backoff_seconds(2), 600);
    assert_eq!(backoff_seconds(3), 1_200);
    assert_eq!(backoff_seconds(6), 9_600);
    // Capped at 24 h.
    assert_eq!(backoff_seconds(10), 86_400);
    // Overflow-proof: huge counters never panic and stay capped.
    assert_eq!(backoff_seconds(31), 86_400);
    assert_eq!(backoff_seconds(u32::MAX), 86_400);
}

// ── Providers & accounts ────────────────────────────────────────────────────

#[tokio::test]
async fn providers_and_accounts_lifecycle() {
    let Some(db) = canonical_pool("ipx_seed_providers").await else {
        return;
    };
    let mgr = SeedManager::new(db.clone());

    // Providers are seeded by migration 033 with active-account counts.
    let providers = mgr.list_providers().await.expect("providers");
    assert!(providers.iter().any(|p| p.name == "gmail"));
    let gmail = providers.iter().find(|p| p.name == "gmail").unwrap();

    let by_id = mgr.get_provider(gmail.id).await.expect("by id");
    assert_eq!(by_id.map(|p| p.name), Some("gmail".into()));
    let by_name = mgr.get_provider_by_name("gmail").await.expect("by name");
    assert_eq!(by_name.map(|p| p.id), Some(gmail.id));
    assert!(
        mgr.get_provider_by_name("no-such").await.unwrap().is_none(),
        "unknown provider"
    );

    // Accounts: create two on gmail, one on yahoo; one gmail deactivated.
    let a = seed_account(&db, "gmail", &unique("a@seed.example")).await;
    let b = seed_account(&db, "gmail", &unique("b@seed.example")).await;
    let y = seed_account(&db, "yahoo", &unique("y@seed.example")).await;
    sqlx::query("UPDATE seed_accounts SET is_active = false WHERE id = $1")
        .bind(b)
        .execute(&db)
        .await
        .expect("deactivate");

    let active = mgr.list_active_accounts().await.expect("active");
    assert!(active.iter().any(|x| x.id == a));
    assert!(active.iter().all(|x| x.id != b), "deactivated excluded");

    let gmail_accounts = mgr
        .list_accounts_by_provider(gmail.id)
        .await
        .expect("by provider");
    assert!(gmail_accounts.iter().any(|x| x.id == a));
    assert!(gmail_accounts.iter().all(|x| x.id != b));
    assert!(gmail_accounts.iter().all(|x| x.id != y));

    assert_eq!(mgr.get_account(a).await.unwrap().map(|x| x.id), Some(a));
    assert!(mgr.get_account(Uuid::new_v4()).await.unwrap().is_none());

    let count = mgr.count_active_accounts().await.expect("count");
    assert!(count >= 2);

    // By provider names: empty → ALL active; unknown → none; mixed → subset.
    let all = mgr.get_accounts_by_provider_names(&[]).await.unwrap();
    assert_eq!(all.len(), usize::try_from(count).unwrap());
    let none = mgr
        .get_accounts_by_provider_names(&["no-such".to_string()])
        .await
        .unwrap();
    assert!(none.is_empty());
    let mixed = mgr
        .get_accounts_by_provider_names(&["yahoo".to_string()])
        .await
        .unwrap();
    assert!(mixed.iter().any(|x| x.id == y));
    assert!(mixed.iter().all(|x| x.provider_id != gmail.id));

    // Health update writes both columns.
    mgr.update_account_health(a, "ok", chrono::Utc::now())
        .await
        .expect("update");
    let (health,): (String,) =
        sqlx::query_as("SELECT health_status FROM seed_accounts WHERE id=$1")
            .bind(a)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(health, "ok");
}

// ── record_health_failure / success ─────────────────────────────────────────

#[tokio::test]
async fn transient_failures_back_off_then_disable_at_the_threshold() {
    let Some(db) = canonical_pool("ipx_seed_transient").await else {
        return;
    };
    let mgr = SeedManager::new(db.clone());
    let acct = seed_account(&db, "gmail", &unique("t@seed.example")).await;

    // Failures 1..=2 are transient: exponential backoff lands in the future.
    for expected_failures in [1u32, 2] {
        let disabled = mgr
            .record_health_failure(acct, "connection timed out", 3)
            .await
            .expect("record");
        assert!(
            !disabled,
            "transient failure {expected_failures} disables nothing"
        );
        let (failures, checked): (i32, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT consecutive_failures, last_checked_at FROM seed_accounts WHERE id=$1",
        )
        .bind(acct)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(failures, expected_failures as i32);
        let at = checked.expect("backoff timestamp");
        assert!(
            at > chrono::Utc::now(),
            "last_checked_at pushed into the future (backoff): {at}"
        );
    }

    // Failure 3 hits the threshold → the account is auto-disabled.
    let disabled = mgr
        .record_health_failure(acct, "connection timed out", 3)
        .await
        .expect("record");
    assert!(disabled, "threshold reached → disabled");
    let (is_active,): (bool,) = sqlx::query_as("SELECT is_active FROM seed_accounts WHERE id=$1")
        .bind(acct)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(!is_active, "account retired");
}

#[tokio::test]
async fn permanent_failures_disable_immediately_and_success_resets() {
    let Some(db) = canonical_pool("ipx_seed_permanent").await else {
        return;
    };
    let mgr = SeedManager::new(db.clone());
    let acct = seed_account(&db, "gmail", &unique("p@seed.example")).await;

    // A single PERMANENT failure disables even at failures=1.
    let disabled = mgr
        .record_health_failure(acct, "authentication failed", 5)
        .await
        .expect("record");
    assert!(disabled, "permanent failure → immediate disable");
    let (is_active, reason): (bool, String) =
        sqlx::query_as("SELECT is_active, last_failure_reason FROM seed_accounts WHERE id=$1")
            .bind(acct)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(!is_active);
    assert!(reason.contains("authentication failed"));

    // A failed check on a MISSING account answers false (nothing disabled).
    let disabled = mgr
        .record_health_failure(Uuid::new_v4(), "authentication failed", 3)
        .await
        .expect("record");
    assert!(!disabled);

    // Success clears the counters and the failure reason.
    seed_account(&db, "gmail", &unique("q@seed.example")).await;
    let acct2 = seed_account(&db, "gmail", &unique("r@seed.example")).await;
    mgr.record_health_failure(acct2, "connection reset", 50)
        .await
        .unwrap();
    mgr.record_health_success(acct2).await.unwrap();
    let (failures, reason, status): (i32, Option<String>, String) = sqlx::query_as(
        "SELECT consecutive_failures, last_failure_reason, health_status \
         FROM seed_accounts WHERE id=$1",
    )
    .bind(acct2)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        failures, 0,
        "success resets the consecutive-failure counter"
    );
    assert_eq!(reason, None);
    assert_eq!(status, "ok");
}

// ── Health-check scheduling query ───────────────────────────────────────────

#[tokio::test]
async fn due_accounts_are_ordered_oldest_first_and_capped() {
    let Some(db) = canonical_pool("ipx_seed_due").await else {
        return;
    };
    let mgr = SeedManager::new(db.clone());
    // NULL last_checked_at sorts first, then oldest timestamp.
    let null_acct = seed_account(&db, "gmail", &unique("n@seed.example")).await;
    let old_acct = seed_account(&db, "gmail", &unique("o@seed.example")).await;
    let fresh_acct = seed_account(&db, "gmail", &unique("f@seed.example")).await;
    sqlx::query(
        "UPDATE seed_accounts SET last_checked_at = NOW() - INTERVAL '2 hours' WHERE id=$1",
    )
    .bind(old_acct)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query("UPDATE seed_accounts SET last_checked_at = NOW() WHERE id=$1")
        .bind(fresh_acct)
        .execute(&db)
        .await
        .unwrap();

    let due = mgr
        .list_accounts_due_for_health_check(600, 50)
        .await
        .expect("due");
    let pos = |id: Uuid| due.iter().position(|a| a.id == id);
    let (n, o) = (pos(null_acct), pos(old_acct));
    assert!(n.is_some(), "NULL last_checked_at is due");
    assert!(o.is_some(), "2h-old check is due");
    assert!(n.unwrap() < o.unwrap(), "NULL first, then oldest");
    assert!(
        !due.iter().any(|a| a.id == fresh_acct),
        "freshly checked account is not due"
    );

    // LIMIT is honoured.
    let limited = mgr
        .list_accounts_due_for_health_check(600, 1)
        .await
        .unwrap();
    assert!(limited.len() <= 1);
}

// ── Password rotation (envelope encryption) ─────────────────────────────────

#[tokio::test]
async fn password_rotation_encrypts_and_decrypts() {
    let Some(db) = canonical_pool("ipx_seed_rotate").await else {
        return;
    };
    let mgr = SeedManager::new(db.clone());
    let acct = seed_account(&db, "gmail", &unique("rot@seed.example")).await;
    let encryptor = enterprise::field_encryption::encryptor_from_secret(
        "rotation-secret",
        "inbox-placement::imap-password",
    )
    .expect("encryptor");

    // Rotate: plaintext never lands in the column.
    mgr.encrypt_account_password(acct, "hunter2-rotated", &encryptor)
        .await
        .expect("rotate");
    let (stored,): (String,) =
        sqlx::query_as("SELECT imap_password_encrypted FROM seed_accounts WHERE id=$1")
            .bind(acct)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(!stored.contains("hunter2"), "ciphertext only: {stored}");
    assert!(stored.starts_with("ENC:"), "envelope format: {stored}");

    // Round-trip.
    let decrypted = mgr
        .decrypt_account_password(acct, &encryptor)
        .await
        .expect("decrypt");
    assert_eq!(decrypted.as_deref(), Some("hunter2-rotated"));

    // Missing row → None (not an error); empty column → None.
    let missing = mgr
        .decrypt_account_password(Uuid::new_v4(), &encryptor)
        .await
        .expect("missing row");
    assert_eq!(missing, None);
    let empty_acct = seed_account(&db, "gmail", &unique("empty@seed.example")).await;
    sqlx::query("UPDATE seed_accounts SET imap_password_encrypted='' WHERE id=$1")
        .bind(empty_acct)
        .execute(&db)
        .await
        .unwrap();
    let empty = mgr
        .decrypt_account_password(empty_acct, &encryptor)
        .await
        .expect("empty pw");
    assert_eq!(empty, None);

    // A wrong secret cannot decrypt (fails with a typed error, not a panic).
    let other = enterprise::field_encryption::encryptor_from_secret(
        "different-secret",
        "inbox-placement::imap-password",
    )
    .unwrap();
    assert!(mgr.decrypt_account_password(acct, &other).await.is_err());
}
