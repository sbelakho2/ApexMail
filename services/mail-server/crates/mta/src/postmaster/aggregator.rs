//! Reputation summary aggregator.
//!
//! Reads recent rows from `postmaster_google_reputation` and
//! `postmaster_snds_reputation`, normalises them to a 0..=100 score, and
//! UPSERTs into `postmaster_reputation_summary`.  When the band of an existing
//! summary changes, an entry is appended to `postmaster_reputation_events`
//! so the alert-router can notify tenants.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::info;

use super::ReputationBand;

/// Lookback window: anything older than this is ignored when computing scores.
const LOOKBACK_DAYS: i64 = 7;

/// Recompute summary rows for every (provider, identity) seen in the lookback
/// window.  Returns `(domains_processed, ips_processed, events_emitted)`.
pub async fn recompute(db: &PgPool) -> Result<(usize, usize, usize), String> {
    let since = Utc::now().date_naive() - Duration::days(LOOKBACK_DAYS);

    // ── Google domain summaries ─────────────────────────────────────────────
    #[allow(clippy::type_complexity)]
    let domain_rows: Vec<(
        String,
        Option<String>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
    )> = sqlx::query_as(
        "SELECT domain,
                MIN(domain_reputation) FILTER (WHERE observed_at = (
                    SELECT MAX(observed_at) FROM postmaster_google_reputation
                    WHERE observed_at >= $1 AND domain = g.domain
                )) AS latest_band,
                AVG(spf_success_ratio)::float8,
                AVG(dkim_success_ratio)::float8,
                AVG(dmarc_success_ratio)::float8,
                AVG(user_reported_spam_ratio)::float8
         FROM postmaster_google_reputation g
         WHERE observed_at >= $1
         GROUP BY domain",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error (google agg): {e}"))?;

    // ── SNDS IP summaries ──────────────────────────────────────────────────
    let ip_rows: Vec<(String, Option<String>, Option<f64>, i64)> = sqlx::query_as(
        // `host(ip)` (not `ip::text`): the summary identity must be the bare
        // address so dashboard/alert consumers matching an IP literal (and
        // the snds table's own `ip` column) agree with it; `ip::text`
        // rendered the netmask suffix ("203.0.113.9/32") into the identity.
        "SELECT host(ip),
                MIN(filter_result) FILTER (WHERE observed_at = (
                    SELECT MAX(observed_at) FROM postmaster_snds_reputation
                    WHERE observed_at >= $1 AND ip = s.ip
                )) AS latest_filter,
                AVG(complaint_rate)::float8,
                -- SUM(bigint) is NUMERIC in Postgres; the decoder expects
                -- INT8 (the tuple field is i64), so the cast is load-bearing:
                -- without it every recompute failed with a decode error as
                -- soon as any SNDS row existed in the lookback window.
                COALESCE(SUM(trap_hits), 0)::bigint
         FROM postmaster_snds_reputation s
         WHERE observed_at >= $1
         GROUP BY ip",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error (snds agg): {e}"))?;

    // ── Batch upsert within a single transaction (DB-5) ─────────────────────
    //
    // **Root cause**: `upsert_summary` was called per row with its own
    // connection acquisition, creating an N+1 round-trip pattern (1 query
    // per domain/IP × 2–3 SQL statements each).
    //
    // **Fix**: Wrap all upserts in a single database transaction so all
    // SELECT, UPSERT, and event-INSERT statements share one connection and
    // commit atomically.  Band-change events are accumulated in memory and
    // INSERTed as a batch at the end rather than one-at-a-time.
    let mut tx = db
        .begin()
        .await
        .map_err(|e| format!("DB error (begin tx): {e}"))?;

    let mut events = 0usize;
    #[allow(clippy::type_complexity)]
    let mut event_rows: Vec<(
        String,            // scope
        String,            // identity
        String,            // provider
        String,            // severity
        String,            // event_type
        Option<String>,    // from_band
        String,            // to_band
        serde_json::Value, // payload
    )> = Vec::new();

    // Build every summary row in memory first, then apply them with ONE
    // prior-band SELECT and ONE multi-row UPSERT. The old form issued
    // SELECT + UPDATE (or INSERT) per domain/IP — a 2–3×N round-trip
    // pattern even though it shared one transaction.
    let mut writes: Vec<SummaryWrite> = Vec::with_capacity(domain_rows.len() + ip_rows.len());
    for (domain, latest_band, spf, dkim, dmarc, spam) in &domain_rows {
        let (score, factors) = score_google(latest_band.as_deref(), *spf, *dkim, *dmarc, *spam);
        writes.push(SummaryWrite {
            scope: "domain",
            identity: domain.clone(),
            provider: "google",
            score,
            band: ReputationBand::from_score(score),
            factors,
        });
    }
    for (ip, filter, complaint, traps) in &ip_rows {
        let (score, factors) = score_snds(filter.as_deref(), *complaint, *traps);
        writes.push(SummaryWrite {
            scope: "ip",
            identity: ip.clone(),
            provider: "microsoft",
            score,
            band: ReputationBand::from_score(score),
            factors,
        });
    }

    let prior_bands = load_prior_bands(&mut tx, &writes).await?;
    for write in &writes {
        let key = (
            write.scope.to_string(),
            write.identity.clone(),
            write.provider.to_string(),
        );
        let Some(previous) = prior_bands.get(&key) else {
            continue;
        };
        if *previous == write.band {
            continue;
        }
        events += 1;
        let severity = match write.band {
            ReputationBand::Red => "critical",
            ReputationBand::Amber => "warn",
            ReputationBand::Green => "info",
        };
        let event_type = if matches!(write.band, ReputationBand::Red) {
            "red_listed"
        } else {
            "band_drop"
        };
        let payload = serde_json::json!({
            "score": write.score,
            "factors": write.factors,
        });
        event_rows.push((
            write.scope.into(),
            write.identity.clone(),
            write.provider.into(),
            severity.into(),
            event_type.into(),
            Some(previous.as_str().into()),
            write.band.as_str().into(),
            payload,
        ));
    }

    upsert_summaries(&mut tx, &writes).await?;

    // Batch-INSERT all band-change events in a single statement.
    if !event_rows.is_empty() {
        // Every row MUST be wrapped in its own tuple parentheses. The
        // previous builder emitted `VALUES ($1, …, $9, $10, …` for multiple
        // events — PostgreSQL rejects that with "INSERT has more expressions
        // than target columns", aborting the whole recompute transaction on
        // any run with two or more band changes.
        let mut query_builder = sqlx::QueryBuilder::new(
            "INSERT INTO postmaster_reputation_events
               (tenant_id, scope, identity, provider, severity, event_type,
                from_band, to_band, payload)
             VALUES ",
        );
        for (
            index,
            (scope, identity, provider, severity, event_type, from_band, to_band, payload),
        ) in event_rows.iter().enumerate()
        {
            if index > 0 {
                query_builder.push(", ");
            }
            query_builder.push("(");
            query_builder.push_bind(None::<String>); // tenant_id (NULL for global events)
            query_builder.push(", ");
            query_builder.push_bind(scope);
            query_builder.push(", ");
            query_builder.push_bind(identity);
            query_builder.push(", ");
            query_builder.push_bind(provider);
            query_builder.push(", ");
            query_builder.push_bind(severity);
            query_builder.push(", ");
            query_builder.push_bind(event_type);
            query_builder.push(", ");
            query_builder.push_bind(from_band);
            query_builder.push(", ");
            query_builder.push_bind(to_band);
            query_builder.push(", ");
            query_builder.push_bind(payload);
            query_builder.push(")");
        }
        query_builder
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB error (batch insert events): {e}"))?;
    }

    tx.commit()
        .await
        .map_err(|e| format!("DB error (commit tx): {e}"))?;

    info!(
        domains = domain_rows.len(),
        ips = ip_rows.len(),
        events,
        "postmaster reputation summary recomputed"
    );
    Ok((domain_rows.len(), ip_rows.len(), events))
}

/// One computed summary row awaiting persistence.
struct SummaryWrite {
    scope: &'static str,
    identity: String,
    provider: &'static str,
    score: i32,
    band: ReputationBand,
    factors: Vec<String>,
}

/// Read the CURRENT band for every summary key in ONE query.
///
/// Migration 227 restored the 3-column uniqueness the `ON CONFLICT` target
/// below depends on (one current summary per scope/identity/provider); the
/// `DISTINCT ON` is defensive for databases that still carry the older
/// per-computation history rows.
async fn load_prior_bands(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    writes: &[SummaryWrite],
) -> Result<std::collections::HashMap<(String, String, String), ReputationBand>, String> {
    if writes.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let keys = serde_json::Value::Array(
        writes
            .iter()
            .map(|write| {
                serde_json::json!({
                    "scope": write.scope,
                    "identity": write.identity,
                    "provider": write.provider,
                })
            })
            .collect(),
    );
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (s.scope, s.identity, s.provider)
                s.scope, s.identity, s.provider, s.band
           FROM postmaster_reputation_summary s
           JOIN jsonb_to_recordset($1::jsonb) AS k(scope text, identity text, provider text)
             ON s.scope = k.scope AND s.identity = k.identity AND s.provider = k.provider
          ORDER BY s.scope, s.identity, s.provider, s.computed_at DESC, s.id DESC",
    )
    .bind(keys)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("DB error (prior bands): {e}"))?;

    Ok(rows
        .into_iter()
        .filter_map(|(scope, identity, provider, band)| {
            ReputationBand::parse(&band).map(|band| ((scope, identity, provider), band))
        })
        .collect())
}

/// UPSERT every summary row with ONE multi-row statement.
///
/// Returns `(band_changed, previous_band_string)` semantics from the old
/// per-row helper are handled by the caller from [`load_prior_bands`].
async fn upsert_summaries(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    writes: &[SummaryWrite],
) -> Result<(), String> {
    if writes.is_empty() {
        return Ok(());
    }
    let payload = serde_json::Value::Array(
        writes
            .iter()
            .map(|write| {
                serde_json::json!({
                    "scope": write.scope,
                    "identity": write.identity,
                    "provider": write.provider,
                    "reputation_score": write.score,
                    "band": write.band.as_str(),
                    "factors": write.factors,
                    "suggested_throttle_pct": write.band.suggested_throttle_pct(),
                    "window_days": LOOKBACK_DAYS as i32,
                })
            })
            .collect(),
    );
    sqlx::query(
        "INSERT INTO postmaster_reputation_summary
           (scope, identity, provider, reputation_score, band, factors,
            suggested_throttle_pct, window_days, computed_at)
         SELECT scope, identity, provider, reputation_score, band, factors,
                suggested_throttle_pct, window_days, NOW()
           FROM jsonb_to_recordset($1::jsonb) AS r(
                scope text,
                identity text,
                provider text,
                reputation_score integer,
                band text,
                factors jsonb,
                suggested_throttle_pct integer,
                window_days integer
           )
         ON CONFLICT (scope, identity, provider) DO UPDATE SET
           reputation_score = EXCLUDED.reputation_score,
           band = EXCLUDED.band,
           factors = EXCLUDED.factors,
           suggested_throttle_pct = EXCLUDED.suggested_throttle_pct,
           window_days = EXCLUDED.window_days,
           computed_at = NOW()",
    )
    .bind(payload)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("DB error (summary upsert): {e}"))?;
    Ok(())
}

/// Score 0..=100 from Google Postmaster signals.  Algorithm (transparent so
/// audit and customers can verify):
///   * Domain reputation bucket: HIGH=70, MEDIUM=55, LOW=35, BAD=10, UNKNOWN=50.
///   * SPF/DKIM/DMARC pass ratios contribute up to +15 points.
///   * User-reported spam: ratio>=0.003 deducts up to -25.
fn score_google(
    band: Option<&str>,
    spf: Option<f64>,
    dkim: Option<f64>,
    dmarc: Option<f64>,
    spam: Option<f64>,
) -> (i32, Vec<String>) {
    let mut factors = Vec::new();
    let base = match band {
        Some("HIGH") => 70,
        Some("MEDIUM") => 55,
        Some("LOW") => 35,
        Some("BAD") => 10,
        _ => 50,
    };
    factors.push(format!("domain_reputation={}", band.unwrap_or("UNKNOWN")));

    let mut bonus = 0.0_f64;
    if let Some(v) = spf {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("spf={:.2}", v));
    }
    if let Some(v) = dkim {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("dkim={:.2}", v));
    }
    if let Some(v) = dmarc {
        bonus += (v.clamp(0.0, 1.0)) * 5.0;
        factors.push(format!("dmarc={:.2}", v));
    }

    let mut penalty = 0.0_f64;
    if let Some(v) = spam {
        // 0.3% is Gmail's published "warning" threshold; 1% is the danger zone.
        let scaled = ((v - 0.001).max(0.0) / 0.009).min(1.0);
        penalty = scaled * 25.0;
        factors.push(format!("spam_ratio={:.4}", v));
    }
    let score = (base as f64 + bonus - penalty).round().clamp(0.0, 100.0) as i32;
    (score, factors)
}

/// Score 0..=100 from SNDS signals.
fn score_snds(filter: Option<&str>, complaint: Option<f64>, traps: i64) -> (i32, Vec<String>) {
    let mut factors = Vec::new();
    let base = match filter {
        Some("GREEN") => 75,
        Some("YELLOW") => 50,
        Some("RED") => 15,
        _ => 50,
    };
    factors.push(format!("filter={}", filter.unwrap_or("UNKNOWN")));

    let mut penalty = 0.0_f64;
    if let Some(c) = complaint {
        // 0.1% is the SNDS yellow boundary, 0.4% red.
        let scaled = ((c - 0.0005).max(0.0) / 0.0035).min(1.0);
        penalty += scaled * 20.0;
        factors.push(format!("complaint={:.4}", c));
    }
    if traps > 0 {
        let trap_penalty = (traps as f64).log10().max(0.0) * 5.0;
        penalty += trap_penalty.min(15.0);
        factors.push(format!("trap_hits={}", traps));
    }
    let score = (base as f64 - penalty).round().clamp(0.0, 100.0) as i32;
    (score, factors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_high_clean() {
        let (s, _) = score_google(Some("HIGH"), Some(1.0), Some(1.0), Some(1.0), Some(0.0));
        assert!(s >= 80, "expected high score, got {s}");
    }

    #[test]
    fn google_bad_with_spam_drops_to_red() {
        let (s, _) = score_google(Some("BAD"), Some(0.5), Some(0.5), Some(0.5), Some(0.02));
        assert_eq!(ReputationBand::from_score(s), ReputationBand::Red);
    }

    #[test]
    fn snds_red_filter_to_red_band() {
        let (s, _) = score_snds(Some("RED"), Some(0.005), 50);
        assert_eq!(ReputationBand::from_score(s), ReputationBand::Red);
    }

    #[test]
    fn snds_green_clean_high() {
        let (s, _) = score_snds(Some("GREEN"), Some(0.0001), 0);
        assert!(s >= 70);
    }
}

#[cfg(test)]
mod adversarial_db_tests {
    //! Live-DB aggregation: band changes are emitted EXACTLY once, re-runs are
    //! idempotent, and the emitted event names the transition direction.

    use super::*;

    use uuid::Uuid;

    async fn pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn insert_google(pool: &PgPool, domain: &str, day_offset: i64, band: &str) {
        sqlx::query(
            "INSERT INTO postmaster_google_reputation
                 (domain, observed_at, domain_reputation, spf_success_ratio,
                  dkim_success_ratio, dmarc_success_ratio, user_reported_spam_ratio)
             VALUES ($1, CURRENT_DATE + $2::int, $3, 1.0, 1.0, 1.0, 0.0)",
        )
        .bind(domain)
        .bind(day_offset)
        .bind(band)
        .execute(pool)
        .await
        .expect("insert google row");
    }

    async fn insert_snds(pool: &PgPool, ip: &str, day_offset: i64, filter: &str, traps: i64) {
        sqlx::query(
            "INSERT INTO postmaster_snds_reputation
                 (ip, observed_at, filter_result, complaint_rate, trap_hits)
             VALUES ($1::inet, CURRENT_DATE + $2::int, $3, 0.0001, $4)",
        )
        .bind(ip)
        .bind(day_offset)
        .bind(filter)
        .bind(traps)
        .execute(pool)
        .await
        .expect("insert snds row");
    }

    async fn summary(pool: &PgPool, identity: &str) -> (i32, String, i32) {
        sqlx::query_as(
            "SELECT reputation_score, band, suggested_throttle_pct
             FROM postmaster_reputation_summary WHERE identity = $1",
        )
        .bind(identity)
        .fetch_one(pool)
        .await
        .expect("summary row")
    }

    async fn events(
        pool: &PgPool,
        identity: &str,
    ) -> Vec<(
        Option<String>,
        String,
        String,
        String,
        Option<String>,
        String,
    )> {
        sqlx::query_as(
            "SELECT tenant_id, severity, event_type, provider, from_band, to_band
             FROM postmaster_reputation_events WHERE identity = $1 ORDER BY id",
        )
        .bind(identity)
        .fetch_all(pool)
        .await
        .expect("events")
    }

    /// The recompute must apply ALL summary rows with ONE upsert statement
    /// and emit all band-change events with ONE insert statement.
    ///
    /// The old implementation ran SELECT + UPDATE (or INSERT) per domain/IP,
    /// so this test (statement counters, pre-seeded summaries force the
    /// UPDATE path) fails with 20 UPDATE statements on that code and passes
    /// with one set-based `ON CONFLICT` upsert.
    #[tokio::test]
    async fn recompute_batches_summary_upserts_and_events() {
        let Some(pool) = pool("postmaster_summary_batch").await else {
            return;
        };

        for index in 0..10 {
            insert_google(&pool, &format!("batch-{index}.example"), 0, "BAD").await;
        }
        for last_octet in 1..=10 {
            insert_snds(&pool, &format!("198.51.100.{last_octet}"), 0, "RED", 0).await;
        }

        // Pre-seed every key with a GREEN summary so the run must update
        // existing rows (and every band change must emit an event).
        for index in 0..10 {
            sqlx::query(
                "INSERT INTO postmaster_reputation_summary
                   (scope, identity, provider, reputation_score, band, factors,
                    suggested_throttle_pct, window_days)
                 VALUES ('domain', $1, 'google', 90, 'green', '[]'::jsonb, 0, 7)",
            )
            .bind(format!("batch-{index}.example"))
            .execute(&pool)
            .await
            .expect("seed domain summary");
            sqlx::query(
                "INSERT INTO postmaster_reputation_summary
                   (scope, identity, provider, reputation_score, band, factors,
                    suggested_throttle_pct, window_days)
                 VALUES ('ip', $1, 'microsoft', 90, 'green', '[]'::jsonb, 0, 7)",
            )
            .bind(format!("198.51.100.{last_octet}", last_octet = index + 1))
            .execute(&pool)
            .await
            .expect("seed ip summary");
        }

        crate::postmaster::test_support::install_statement_counters(
            &pool,
            &[
                "postmaster_reputation_summary",
                "postmaster_reputation_events",
            ],
        )
        .await;
        crate::postmaster::test_support::reset_statement_counts(&pool).await;

        let (domains, ips, events) = recompute(&pool).await.expect("recompute");
        assert_eq!((domains, ips), (10, 10));
        assert_eq!(events, 20, "one event per band change");

        // An INSERT ... ON CONFLICT DO UPDATE fires both the INSERT and the
        // UPDATE statement trigger once, so each count is 1 for ONE upsert
        // statement. The old per-row UPDATE path produced 20 UPDATE
        // statements.
        let updates = crate::postmaster::test_support::statement_count(
            &pool,
            "postmaster_reputation_summary",
            "UPDATE",
        )
        .await;
        let inserts = crate::postmaster::test_support::statement_count(
            &pool,
            "postmaster_reputation_summary",
            "INSERT",
        )
        .await;
        assert_eq!(
            updates, 1,
            "all 20 summary rows must go through ONE upsert statement, got {updates} UPDATE triggers"
        );
        assert!(
            inserts <= 1,
            "the same single upsert must not fan out into per-row INSERTs, got {inserts}"
        );
        assert_eq!(
            crate::postmaster::test_support::statement_count(
                &pool,
                "postmaster_reputation_events",
                "INSERT"
            )
            .await,
            1,
            "all band-change events are one INSERT statement"
        );

        // Equivalence: every key now reports the recomputed RED band.
        for index in 0..10 {
            let (_, band, _) = summary(&pool, &format!("batch-{index}.example")).await;
            assert_eq!(band, "red");
        }
        for last_octet in 1..=10 {
            let (_, band, _) = summary(&pool, &format!("198.51.100.{last_octet}")).await;
            assert_eq!(band, "red");
        }

        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM postmaster_reputation_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(event_count, 20);

        pool.close().await;
    }

    /// Migration 227 regression: the summary table must carry a UNIQUE index
    /// on exactly the aggregator's key — (scope, identity, provider) — so the
    /// `ON CONFLICT (scope, identity, provider)` target resolves. Migration
    /// 061 dropped the original 3-column constraint in favour of
    /// (scope, identity, provider, computed_at), which is NOT inferrable from
    /// that conflict target; before 227 every such upsert failed with
    /// "no unique or exclusion constraint matching the ON CONFLICT
    /// specification" (PostgreSQL error 42P10).
    #[tokio::test]
    async fn summary_key_uniqueness_matches_the_aggregators_conflict_target() {
        let Some(pool) = pool("postmaster_summary_key").await else {
            return;
        };
        let ip = "198.51.100.42";

        // (1) A unique index on exactly these three columns exists.
        let matching_indexes: i64 = sqlx::query_scalar(
            "SELECT count(*)
             FROM pg_index i
             WHERE i.indrelid = 'postmaster_reputation_summary'::regclass
               AND i.indisunique
               AND i.indnatts = 3
               AND (
                     SELECT array_agg(a.attname::text ORDER BY a.attname::text)
                     FROM unnest(i.indkey) AS k(attnum)
                     JOIN pg_attribute a
                       ON a.attrelid = i.indrelid AND a.attnum = k.attnum
                   ) = ARRAY['identity', 'provider', 'scope']",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect summary indexes");
        assert_eq!(
            matching_indexes, 1,
            "migration 227 must leave exactly one UNIQUE (scope, identity, provider) index"
        );

        // (2) A second raw summary row for the same key is rejected by the
        // schema (23505 unique_violation), not silently duplicated.
        sqlx::query(
            "INSERT INTO postmaster_reputation_summary
               (scope, identity, provider, reputation_score, band, factors,
                suggested_throttle_pct, window_days)
             VALUES ('ip', $1, 'microsoft', 10, 'red', '[]'::jsonb, 90, 7)",
        )
        .bind(ip)
        .execute(&pool)
        .await
        .expect("first summary row");
        let duplicate = sqlx::query(
            "INSERT INTO postmaster_reputation_summary
               (scope, identity, provider, reputation_score, band, factors,
                suggested_throttle_pct, window_days)
             VALUES ('ip', $1, 'microsoft', 99, 'green', '[]'::jsonb, 0, 7)",
        )
        .bind(ip)
        .execute(&pool)
        .await
        .expect_err("a second summary row for the same key must violate the unique index");
        let db_error = duplicate
            .as_database_error()
            .expect("duplicate insert must be a database error");
        assert_eq!(
            db_error.code().as_deref(),
            Some("23505"),
            "expected unique_violation, got: {duplicate}"
        );

        // (3) The upsert clause the aggregator depends on now resolves and
        // keeps the key to a single row.
        for score in [20, 30] {
            sqlx::query(
                "INSERT INTO postmaster_reputation_summary
                   (scope, identity, provider, reputation_score, band, factors,
                    suggested_throttle_pct, window_days)
                 VALUES ('ip', $1, 'microsoft', $2, 'red', '[]'::jsonb, 90, 7)
                 ON CONFLICT (scope, identity, provider) DO UPDATE SET
                   reputation_score = EXCLUDED.reputation_score,
                   computed_at = NOW()",
            )
            .bind(ip)
            .bind(score)
            .execute(&pool)
            .await
            .expect("ON CONFLICT (scope, identity, provider) must resolve to the restored index");
        }
        let (rows, score): (i64, i32) = sqlx::query_as(
            "SELECT count(*), max(reputation_score)
             FROM postmaster_reputation_summary
             WHERE scope = 'ip' AND identity = $1 AND provider = 'microsoft'",
        )
        .bind(ip)
        .fetch_one(&pool)
        .await
        .expect("read back the upserted summary");
        assert_eq!(rows, 1, "upserts on the key must not create duplicate rows");
        assert_eq!(score, 30);

        pool.close().await;
    }

    /// Every source row for one (scope, identity, provider) must collapse into
    /// exactly ONE summary row whose signals cover all of them, and re-running
    /// the recompute must be a no-op (the migration 227 regression test
    /// requested by the ON CONFLICT incident).
    #[tokio::test]
    async fn recompute_merges_same_key_rows_into_one_summary_and_is_idempotent() {
        let Some(pool) = pool("postmaster_summary_merge").await else {
            return;
        };
        let ip = "198.51.100.43";

        // (a) Two SNDS days for the SAME (scope='ip', identity, provider):
        // trap_hits sum to 40 + 60 = 100, and the newest filter (YELLOW)
        // decides the base score.
        insert_snds(&pool, ip, 0, "GREEN", 40).await;
        insert_snds(&pool, ip, 1, "YELLOW", 60).await;

        // (b) Recompute.
        let (domains, ips, events) = recompute(&pool).await.expect("recompute");
        assert_eq!(domains, 0, "no Google data in this database");
        assert_eq!(ips, 1, "one SNDS identity in the lookback window");
        assert_eq!(events, 0, "first computation is not a band change");

        // (c) Exactly one summary row for the key, carrying the SUM of both
        // source rows: base 50 (YELLOW) - 10 penalty for trap_hits=100 = 40.
        let rows: Vec<(i32, String, serde_json::Value, i32)> = sqlx::query_as(
            "SELECT reputation_score, band, factors, suggested_throttle_pct
             FROM postmaster_reputation_summary
             WHERE scope = 'ip' AND identity = $1 AND provider = 'microsoft'",
        )
        .bind(ip)
        .fetch_all(&pool)
        .await
        .expect("summary rows");
        assert_eq!(rows.len(), 1, "two source days must yield ONE summary row");
        let (score, band, factors, throttle) = &rows[0];
        assert_eq!(*score, 40, "the summed trap_hits must drive the score");
        assert_eq!(band, "amber");
        assert_eq!(*throttle, 50);
        assert!(
            factors.to_string().contains("trap_hits=100"),
            "the summary must factor in BOTH source rows: {factors}"
        );

        // (d) A replay recomputes the same row and stays idempotent.
        let (domains, ips, again) = recompute(&pool).await.expect("replay");
        assert_eq!((domains, ips, again), (0, 1, 0));
        let replay: Vec<(i64, i32, String, i32)> = sqlx::query_as(
            "SELECT count(*), max(reputation_score), max(band)::text,
                    max(suggested_throttle_pct)
             FROM postmaster_reputation_summary
             WHERE scope = 'ip' AND identity = $1 AND provider = 'microsoft'",
        )
        .bind(ip)
        .fetch_all(&pool)
        .await
        .expect("replayed summary");
        assert_eq!(
            replay,
            vec![(1, 40, "amber".to_string(), 50)],
            "the replay must neither duplicate nor mutate the summary"
        );
        let event_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM postmaster_reputation_events WHERE identity = $1",
        )
        .bind(ip)
        .fetch_one(&pool)
        .await
        .expect("event count");
        assert_eq!(event_rows, 0, "no band change happened across the replay");

        pool.close().await;
    }

    #[tokio::test]
    async fn recompute_emits_band_changes_exactly_once_and_is_idempotent() {
        let Some(pool) = pool("postmaster_recompute").await else {
            return;
        };
        let domain = format!("agg-{}.example", &Uuid::new_v4().simple().to_string()[..8]);
        let ip = format!("203.0.113.{}", 10 + (std::process::id() % 200) as u8);

        insert_google(&pool, &domain, 0, "HIGH").await;
        insert_snds(&pool, &ip, 0, "GREEN", 0).await;

        let (domains, ips, new_events) = recompute(&pool).await.expect("first recompute");
        assert!(domains >= 1 && ips >= 1);
        assert_eq!(new_events, 0, "the first computation is not a band CHANGE");
        let (score, band, throttle) = summary(&pool, &domain).await;
        assert!(score >= 70, "HIGH + clean auth must be green, got {score}");
        assert_eq!(band, "green");
        assert_eq!(throttle, 0);
        let (ip_score, ip_band, ip_throttle) = summary(&pool, &ip).await;
        assert!(ip_score >= 70, "GREEN SNDS must be green, got {ip_score}");
        assert_eq!(ip_band, "green");
        assert_eq!(ip_throttle, 0);
        assert!(events(&pool, &ip).await.is_empty());

        // Re-running without new data changes nothing and emits nothing.
        let (_, _, again) = recompute(&pool).await.expect("idempotent recompute");
        assert_eq!(again, 0);
        assert!(events(&pool, &ip).await.is_empty());

        // A newer RED SNDS day demotes the IP; the transition is recorded once.
        insert_snds(&pool, &ip, 1, "RED", 1000).await;
        let (_, _, demoted) = recompute(&pool).await.expect("demote recompute");
        assert_eq!(demoted, 1, "one band change must emit one event");
        let (score, band, throttle) = summary(&pool, &ip).await;
        assert!(score < 40, "RED SNDS must be red, got {score}");
        assert_eq!(band, "red");
        assert_eq!(throttle, 90);
        let rows = events(&pool, &ip).await;
        assert_eq!(rows.len(), 1);
        let (tenant, severity, event_type, provider, from_band, to_band) = &rows[0];
        assert!(tenant.is_none(), "global summary events have no tenant");
        assert_eq!(severity, "critical");
        assert_eq!(event_type, "red_listed");
        assert_eq!(provider, "microsoft");
        assert_eq!(from_band.as_deref(), Some("green"));
        assert_eq!(to_band, "red");

        // A further recompute keeps the red band and emits nothing more.
        let (_, _, stable) = recompute(&pool).await.expect("stable recompute");
        assert_eq!(stable, 0);
        assert_eq!(events(&pool, &ip).await.len(), 1);

        // A demoted DOMAIN emits the warn-level band_drop event.
        insert_google(&pool, &domain, 1, "LOW").await;
        let (_, _, dropped) = recompute(&pool).await.expect("domain drop");
        assert_eq!(dropped, 1);
        let rows = events(&pool, &domain).await;
        assert_eq!(rows.len(), 1);
        let (_, severity, event_type, provider, from_band, to_band) = &rows[0];
        assert_eq!(severity, "warn", "amber is a warn-level transition");
        assert_eq!(event_type, "band_drop");
        assert_eq!(provider, "google");
        assert_eq!(from_band.as_deref(), Some("green"));
        assert_eq!(to_band, "amber");
        let (score, band, throttle) = summary(&pool, &domain).await;
        assert!(
            (40..70).contains(&score),
            "LOW + clean auth is amber: {score}"
        );
        assert_eq!(band, "amber");
        assert_eq!(throttle, 50);

        pool.close().await;
    }

    #[tokio::test]
    async fn every_band_transition_severity_and_event_type_is_emitted_per_provider() {
        // The severity/event_type matrix: red -> critical/red_listed,
        // amber -> warn/band_drop, green -> info/band_drop — for BOTH the
        // google and the microsoft provider paths.
        let Some(pool) = pool("postmaster_severity_matrix").await else {
            return;
        };
        let domain = format!("sev-{}.example", &Uuid::new_v4().simple().to_string()[..8]);
        let ip = format!("203.0.113.{}", 10 + (std::process::id() % 200) as u8);

        // --- Google domain: green -> red -> green -> amber -> green.
        insert_google(&pool, &domain, 0, "HIGH").await;
        let _ = recompute(&pool).await.expect("seed recompute");
        assert!(events(&pool, &domain).await.is_empty());

        insert_google(&pool, &domain, 1, "BAD").await;
        let (_, _, red_events) = recompute(&pool).await.expect("red recompute");
        assert_eq!(red_events, 1);
        let rows = events(&pool, &domain).await;
        let (_, severity, event_type, provider, from, to) = &rows[rows.len() - 1];
        assert_eq!(severity, "critical", "red is critical: {rows:?}");
        assert_eq!(event_type, "red_listed");
        assert_eq!(provider, "google", "the GOOGLE red arm");
        assert_eq!(from.as_deref(), Some("green"));
        assert_eq!(to, "red");

        // red -> amber: warn-level band_drop on the google path.
        insert_google(&pool, &domain, 2, "LOW").await;
        let _ = recompute(&pool).await.expect("amber recompute");
        let rows = events(&pool, &domain).await;
        let (_, severity, event_type, _, from, to) = &rows[rows.len() - 1];
        assert_eq!(severity, "warn");
        assert_eq!(event_type, "band_drop");
        assert_eq!(from.as_deref(), Some("red"));
        assert_eq!(to, "amber");

        // amber -> green: the recovery transition is INFO level.
        insert_google(&pool, &domain, 3, "HIGH").await;
        let (_, _, recovered) = recompute(&pool).await.expect("green recompute");
        assert_eq!(recovered, 1, "recovery to green is still a band change");
        let rows = events(&pool, &domain).await;
        let (_, severity, event_type, _, from, to) = &rows[rows.len() - 1];
        assert_eq!(severity, "info", "recovery to green is informational");
        assert_eq!(event_type, "band_drop");
        assert_eq!(from.as_deref(), Some("amber"));
        assert_eq!(to, "green");

        // --- SNDS IP: green -> amber (warn) -> green (info), microsoft path.
        insert_snds(&pool, &ip, 0, "GREEN", 0).await;
        let _ = recompute(&pool).await.expect("ip seed recompute");

        insert_snds(&pool, &ip, 1, "YELLOW", 0).await;
        let (_, _, amber_events) = recompute(&pool).await.expect("ip amber recompute");
        assert_eq!(amber_events, 1);
        let rows = events(&pool, &ip).await;
        let (_, severity, event_type, provider, from, to) = &rows[rows.len() - 1];
        assert_eq!(severity, "warn", "the SNDS amber arm");
        assert_eq!(event_type, "band_drop");
        assert_eq!(provider, "microsoft");
        assert_eq!(from.as_deref(), Some("green"));
        assert_eq!(to, "amber");

        insert_snds(&pool, &ip, 2, "GREEN", 0).await;
        let (_, _, ip_recovered) = recompute(&pool).await.expect("ip green recompute");
        assert_eq!(ip_recovered, 1);
        let rows = events(&pool, &ip).await;
        let (_, severity, event_type, _, from, to) = &rows[rows.len() - 1];
        assert_eq!(severity, "info", "the SNDS green-recovery arm");
        assert_eq!(event_type, "band_drop");
        assert_eq!(from.as_deref(), Some("amber"));
        assert_eq!(to, "green");

        pool.close().await;
    }
}
