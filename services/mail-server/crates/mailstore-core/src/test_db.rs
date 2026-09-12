//! Canonical DB fixture for the DB-gated mailstore tests.
//!
//! The workspace convention is that `TEST_DATABASE_URL` names a BASE database
//! from which each test provisions `<base>_<suffix>` through the production
//! migrator (`migrator::test_support::fresh_canonical_pool`). These tests used
//! to connect straight to the base database, which made them depend on that
//! database's own history: the shared `apexmail` dev database still carries
//! `idx_mail_messages_account_message_id`, the account-wide
//! UNIQUE(account_id, message_id) index that migration 097 drops precisely
//! because RFC 3501 COPY/APPEND must be able to place the same Message-ID in a
//! second mailbox. Against that database the COPY tests failed with a
//! duplicate-key error; against a canonical database they exercise the real
//! per-mailbox dedup contract.
//!
//! `Ok(None)` means the suite is explicitly unconfigured (soft skip); a
//! configured-but-broken provisioning panics, as the audit requires.

#![deny(unsafe_code)]

use sqlx::PgPool;

/// Provision the canonical database for one test, or `None` when
/// `TEST_DATABASE_URL` is unset (the caller soft-skips).
pub(crate) async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        test_name,
        &format!("mailstore_{test_name}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}
