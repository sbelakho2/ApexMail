//! Service bootstrap — the one construction path shared by the HTTP binary
//! and the release test that boots the service under a DML-only database
//! role.
//!
//! Everything the service does at startup must be possible with SELECT /
//! INSERT / UPDATE / DELETE alone: schema is migration-owned
//! (`services/mail-server/migrations`, applied by the `migrator` deploy gate),
//! and the only writes here are idempotent DML seeds
//! (`ON CONFLICT DO NOTHING` style) for catalogs the service owns.
//!
//! `GdprAutomation`, `BreachNotifier` and `RetentionSweeper` deliberately
//! have NO `apply_migration` method any more: their tables are created by
//! migration 213.

use std::sync::Arc;
use std::time::Duration;

use deadpool_redis::{Config as RedisConfig, Runtime};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn};

use crate::audit_logger::AuditLogger;
use crate::breach_notification::BreachNotifier;
use crate::config::ComplianceConfig;
use crate::content_scanner::ContentScanner;
use crate::dsar_rate_limit::DsarRateLimiter;
use crate::gdpr_automation::GdprAutomation;
use crate::governance;
use crate::hipaa::HipaaService;
use crate::retention_sweep::RetentionSweeper;
use crate::risk_scoring::RiskScoringEngine;
use crate::routes::AppState;
use crate::secret_manager::SecretManager;
use crate::soc2::Soc2Service;
use crate::trust_portal::TrustPortalService;

/// Outcome of the seed steps, for boot logging and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootSeedReport {
    pub soc2_controls: usize,
    pub governance_activities: usize,
    pub retention_classes: usize,
    /// Catalog rows deliberately awaiting Legal input.
    pub awaiting_legal_input: usize,
}

/// Build every service the compliance server serves, run the idempotent
/// seeds, and return the complete [`AppState`].
///
/// Fails — rather than degrading — when the database schema is not the
/// migration-owned canonical one (or the role cannot write), so a broken
/// deployment cannot report "ready" while its request pipeline is dead.
pub async fn build_state(
    config: &ComplianceConfig,
) -> Result<(Arc<AppState>, BootSeedReport), String> {
    let db = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("database connection failed: {e}"))?;
    info!("Connected to database");

    let redis_cfg = RedisConfig::from_url(&config.redis_url);
    let redis = redis_cfg
        .create_pool(Some(Runtime::Tokio1))
        .map_err(|e| format!("redis pool creation failed: {e}"))?;
    info!("Redis pool created");

    // ── Service construction ────────────────────────────────────────────
    let risk_engine = RiskScoringEngine::new(db.clone(), config.clone());
    let content_scanner = ContentScanner::new(db.clone(), config.content.clone());
    let audit_logger = Arc::new(AuditLogger::new(db.clone(), config.audit.clone()));
    // F12/F3: load the per-chain hash heads (live table + archive) BEFORE any
    // append; no DDL is issued (the index is migration-owned).
    if let Err(e) = audit_logger.initialize().await {
        error!("Audit logger initialization failed (chain heads not preloaded): {e}");
    } else {
        info!("Audit hash-chain heads loaded");
    }
    let secret_manager = SecretManager::new(db.clone(), config.secrets.clone())
        .map_err(|e| format!("secret manager init failed: {e}"))?;
    let gdpr = GdprAutomation::new(db.clone(), redis.clone(), config.gdpr.clone());
    let soc2 = Soc2Service::new(db.clone());
    let hipaa = HipaaService::new(db.clone(), config.auth_token.as_bytes().to_vec());
    let trust = TrustPortalService::new(db.clone());
    let breach = BreachNotifier::new(
        db.clone(),
        audit_logger.clone(),
        config.breach_notification_emails.clone(),
        config.audit.signing_key.clone().into_bytes(),
    );
    let retention_sweeper = RetentionSweeper::new(
        db.clone(),
        config.gdpr.export_expiration_days,
        config.gdpr.request_expiration_days,
        config.audit.retention_days,
    );

    // ── Idempotent DML seeds (no schema changes) ────────────────────────
    let mut seeds = BootSeedReport::default();

    // SOC2 control catalog.
    if let Err(e) = soc2.seed_default_controls().await {
        return Err(format!(
            "SOC2 control seed failed (is the schema migrated?): {e}"
        ));
    }
    seeds.soc2_controls = soc2
        .list_controls()
        .await
        .map(|c| c.len())
        .unwrap_or_default();
    info!(
        controls = seeds.soc2_controls,
        "SOC2 control catalog seeded"
    );

    // GDPR governance registry: ROPA + retention classes. Lawful bases, DPIA
    // outcomes and transfer mechanisms are NOT seeded — they await Legal.
    let summary = governance::seed_registry(&db)
        .await
        .map_err(|e| format!("GDPR governance registry seed failed: {e}"))?;
    seeds.governance_activities = summary.activities_inserted;
    seeds.retention_classes = summary.retention_classes_inserted;
    seeds.awaiting_legal_input = summary.awaiting_legal_input;
    info!(
        activities = summary.activities_inserted,
        retention_classes = summary.retention_classes_inserted,
        awaiting_legal_input = summary.awaiting_legal_input,
        "GDPR governance registry seeded"
    );
    if summary.awaiting_legal_input > 0 {
        warn!(
            count = summary.awaiting_legal_input,
            "GDPR registry records await Legal input (lawful basis / DPIA / transfer mechanism) — \
             see processing_activities.review_status and lawful_basis_records.basis_status"
        );
    }

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client build failed: {e}"))?;
    let dsar_rate_limiter =
        DsarRateLimiter::new(config.dsar_rate_limit.clone(), Some(redis.clone()));

    let state = Arc::new(AppState {
        risk_engine,
        content_scanner,
        audit_logger,
        secret_manager,
        gdpr,
        soc2,
        hipaa,
        trust,
        breach,
        config: config.clone(),
        db,
        redis,
        http_client,
        dsar_rate_limiter,
        retention_sweeper,
    });

    Ok((state, seeds))
}
