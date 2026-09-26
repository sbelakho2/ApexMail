//! Shared fixtures for the crate's adversarial unit tests.
//!
//! Only compiled into the unit-test target.  The DB helper follows the
//! workspace contract: `TEST_DATABASE_URL` unset ⇒ soft skip (`None`); a
//! CONFIGURED provisioning failure panics with the failing stage named.

#![cfg(test)]

use std::sync::Arc;

use axum::http::{header, HeaderMap};
use sqlx::PgPool;

use crate::config::{
    AuditConfig, ComplianceConfig, ContentScanningConfig, DsarRateLimitConfig, GdprConfig,
    RiskScoringConfig, RiskThresholds, RiskWeights, SecretsConfig,
};
use crate::routes::AppState;

/// A private canonical database for one test.  `suffix` must be unique per
/// test so parallel tests never share rows.
pub async fn canonical_pool(test_name: &str, suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// The real broker when `TEST_REDIS_URL` is configured (workspace convention);
/// `None` means the test must soft-skip. Used only by tests that exercise
/// Redis-backed flows (DSR enqueue), never by tests that merely need the type.
pub fn configured_redis() -> Option<deadpool_redis::Pool> {
    let url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    deadpool_redis::Config::from_url(url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .ok()
}

pub fn redis_pool() -> deadpool_redis::Pool {
    let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1/99");
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("fake redis pool")
}

pub fn config(auth_token: &str) -> ComplianceConfig {
    ComplianceConfig {
        port: 0,
        database_url: String::new(),
        redis_url: String::new(),
        auth_token: auth_token.to_owned(),
        cors_origin: String::new(),
        risk: RiskScoringConfig {
            spam_threshold: 0.8,
            phishing_threshold: 0.7,
            abuse_threshold: 0.9,
            max_daily_emails: 10_000,
            new_tenant_daily_limit: 1_000,
            warmup_days: 14,
            weights: RiskWeights {
                spam_complaints: 0.25,
                bounce_rate: 0.2,
                phishing_detection: 0.2,
                content_violation: 0.1,
                sending_pattern: 0.1,
                account_age: 0.05,
                verification_status: 0.05,
                payment_history: 0.03,
                list_quality: 0.01,
                engagement_rate: 0.01,
            },
            thresholds: RiskThresholds {
                spam_complaint_rate: 0.5,
                bounce_rate: 0.05,
            },
            base_limits: crate::config::BaseLimits {
                max_daily_emails: 10_000,
                max_hourly_emails: 1_000,
                max_recipients: 500,
                max_attachment_size_mb: 25,
            },
        },
        content: ContentScanningConfig {
            enabled: false,
            ocr_enabled: false,
            spam_threshold: 0.5,
            max_attachment_size: 1024 * 1024,
            max_ocr_images: 4,
            banned_domains: vec![],
        },
        audit: AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "unit-test-audit-key-0123456789abcdef".into(),
        },
        gdpr: gdpr_config(),
        secrets: SecretsConfig {
            encryption_key: "unit-test-master-key-0123456789abcdef".into(),
            rotation_days: 90,
            max_versions_to_keep: 10,
        },
        dsar_rate_limit: DsarRateLimitConfig::default(),
        breach_notification_emails: vec![],
    }
}

pub fn gdpr_config() -> GdprConfig {
    GdprConfig {
        data_retention_days: 730,
        export_format: "json".into(),
        deletion_grace_period_days: 30,
        request_expiration_days: 30,
        export_expiration_days: 7,
        export_base_url: "https://gdpr.test.local".into(),
        verify_base_url: "https://gdpr.test.local".into(),
        consent_signing_key: "unit-test-consent-key-0123456789".into(),
        access_request_max_messages: 10_000,
        system_from_address: "noreply@apexmail.ee".into(),
        outbox_flush_batch: 25,
        outbox_flush_max_attempts: 5,
        clickhouse_erasure_enabled: false,
        clickhouse_url: String::new(),
        clickhouse_database: "apexmail".into(),
        clickhouse_user: "default".into(),
        clickhouse_password: String::new(),
    }
}

/// KDF salt required by [`crate::secret_manager::SecretManager::new`].
pub fn ensure_kdf_salt() {
    if std::env::var("SECRETS_KDF_SALT").is_err() {
        std::env::set_var("SECRETS_KDF_SALT", "unit-test-kdf-salt-0123456789");
    }
}

pub fn audit_logger(pool: &PgPool) -> Arc<crate::audit_logger::AuditLogger> {
    Arc::new(crate::audit_logger::AuditLogger::new(
        pool.clone(),
        AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "unit-test-audit-key-0123456789abcdef".into(),
        },
    ))
}

pub fn app_state(pool: PgPool, auth_token: &str) -> Arc<AppState> {
    app_state_with_config(pool, config(auth_token))
}

/// [`Self::app_state`] with a caller-supplied config (CORS arms etc.).
pub fn app_state_with_config(pool: PgPool, cfg: crate::config::ComplianceConfig) -> Arc<AppState> {
    ensure_kdf_salt();
    let logger = audit_logger(&pool);
    Arc::new(AppState {
        risk_engine: crate::risk_scoring::RiskScoringEngine::new(pool.clone(), cfg.clone()),
        content_scanner: crate::content_scanner::ContentScanner::new(
            pool.clone(),
            cfg.content.clone(),
        ),
        audit_logger: logger.clone(),
        secret_manager: crate::secret_manager::SecretManager::new(
            pool.clone(),
            cfg.secrets.clone(),
        )
        .expect("SecretManager with test salt and master key"),
        gdpr: crate::gdpr_automation::GdprAutomation::new(
            pool.clone(),
            redis_pool(),
            cfg.gdpr.clone(),
        ),
        soc2: crate::soc2::Soc2Service::new(pool.clone()),
        hipaa: crate::hipaa::HipaaService::new(pool.clone(), b"unit-test-baa-key".to_vec()),
        trust: crate::trust_portal::TrustPortalService::new(pool.clone()),
        breach: crate::breach_notification::BreachNotifier::new(
            pool.clone(),
            logger,
            vec![],
            b"unit-test-breach-key".to_vec(),
        ),
        retention_sweeper: crate::retention_sweep::RetentionSweeper::new(pool.clone(), 7, 30, 365),
        config: cfg,
        db: pool.clone(),
        redis: redis_pool(),
        http_client: reqwest::Client::new(),
        dsar_rate_limiter: crate::dsar_rate_limit::DsarRateLimiter::new(
            DsarRateLimitConfig::default(),
            None,
        ),
    })
}

pub fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("valid bearer header"),
    );
    headers
}

/// A short unique id that fits the crate's `VARCHAR(26)` id columns.
pub fn short_id(prefix: &str) -> String {
    let simple = uuid::Uuid::new_v4().simple().to_string();
    let keep = 25usize.saturating_sub(prefix.len());
    format!("{prefix}{}", &simple[..keep])
}

pub fn unique_tenant() -> String {
    // Canonical tables type tenant_id as VARCHAR(26).
    format!("t-{}", &uuid::Uuid::new_v4().simple().to_string()[..23])
}
