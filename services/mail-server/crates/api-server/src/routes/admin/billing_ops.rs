//! Control-plane billing operations surface.
//!
//! The operator's single view of the Mollie lifecycle: money (MRR/ARR, plan
//! and interval mix, MRR movement), entitlement (active/trialing/past_due/
//! unpaid, renewals due, cancel-at-period-end), collections (paid invoices,
//! outstanding/overdue, refunds, chargebacks, failed charges), incidents,
//! webhook health and provider settlements.
//!
//! Every number comes from a table or the provider itself; a source that
//! cannot be read is reported as unavailable in `notes` — never as a
//! fabricated zero. The same snapshot feeds `GET /v1/admin/billing/*` and the
//! SSR `/billing` page, so the two can never disagree.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Duration, Months, NaiveTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::table_exists;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/overview", get(get_overview))
        .route("/subscriptions", get(get_subscriptions))
        .route("/invoices", get(get_invoices))
        .route("/incidents", get(get_incidents))
        .route("/incidents/:id/resolve", post(resolve_incident))
        .route("/health", get(get_health))
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingOverview {
    pub generated_at: DateTime<Utc>,
    /// Catalog prices are EUR cents; the response states the unit rather than
    /// silently mixing currencies.
    pub currency: &'static str,
    pub mrr_cents: i64,
    pub arr_cents: i64,
    /// Average revenue per billable subscription (MRR / billable subscriptions).
    pub arpa_cents: i64,
    /// Subscriptions with status `active` — the ONLY status that grants the
    /// plan (see `docs/architecture/billing-lifecycle.md`).
    pub active_subscriptions: i64,
    /// Subscriptions whose MRR is counted: active + trialing + past_due.
    pub billable_subscriptions: i64,
    pub trialing_subscriptions: i64,
    pub past_due_subscriptions: i64,
    pub unpaid_subscriptions: i64,
    pub canceled_subscriptions_30d: i64,
    pub new_subscriptions_30d: i64,
    pub churn_rate_30d: f64,
    pub upgrades_30d: i64,
    pub downgrades_30d: i64,
    pub expansion_mrr_cents_30d: i64,
    pub renewals_due_7d: i64,
    pub renewals_due_30d: i64,
    pub cancel_at_period_end: i64,
    pub plan_mix: Vec<MixRow>,
    pub interval_mix: Vec<MixRow>,
    pub movement: Vec<MovementRow>,
    pub collections: Collections,
    pub incidents: IncidentSummary,
    pub webhook: WebhookHealth,
    pub settlements: SettlementsView,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MixRow {
    pub key: String,
    pub subscriptions: i64,
    pub mrr_cents: i64,
    /// Share of total MRR (0..1).
    pub share: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MovementRow {
    /// `YYYY-MM`.
    pub month: String,
    pub activations: i64,
    pub new_mrr_cents: i64,
    pub cancellations: i64,
    pub churned_mrr_cents: i64,
    pub net_mrr_cents: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Collections {
    /// Paid invoices in the last 30 days.
    pub paid_30d_cents: i64,
    pub paid_30d_count: i64,
    /// Non-terminal invoices not yet paid (sum of `total`).
    pub outstanding_cents: i64,
    pub outstanding_count: i64,
    /// Outstanding invoices whose due date has passed.
    pub overdue_cents: i64,
    pub overdue_count: i64,
    /// Refund objects created in the last 30 days.
    pub refunded_30d_cents: i64,
    pub refunded_30d_count: i64,
    pub chargebacks_30d: i64,
    pub chargeback_30d_cents: i64,
    /// Failed recurring charges in the last 30 days.
    pub failed_payments_30d: i64,
    /// Payments that settled into an allocation in the last 30 days.
    pub allocations_30d_cents: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IncidentSummary {
    pub open: i64,
    pub acknowledged: i64,
    pub resolved_30d: i64,
    pub by_severity: Vec<SeverityCount>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WebhookHealth {
    pub configured: bool,
    pub events_24h: i64,
    pub processed_24h: i64,
    pub failed_24h: i64,
    pub pending: i64,
    /// Provider events accepted in the last 24 hours that have no claim row
    /// (they are acknowledged without a dedupe record only when unknown).
    pub last_processed_at: Option<DateTime<Utc>>,
    /// Locally canceled subscriptions whose provider object may still be
    /// charging; the reconciliation sweep retries these every hour.
    pub reconciliation_pending: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettlementsView {
    pub configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub settlements: Vec<SettlementRow>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettlementRow {
    pub id: String,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub settled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRow {
    pub id: String,
    pub tenant_id: String,
    pub plan: String,
    pub interval: String,
    pub status: String,
    pub provider_subscription_id: Option<String>,
    pub mandate_present: bool,
    pub mrr_cents: i64,
    pub billing_cycle_start: Option<DateTime<Utc>>,
    pub billing_cycle_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionPage {
    pub rows: Vec<SubscriptionRow>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Default, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceRow {
    pub id: String,
    pub invoice_number: Option<String>,
    pub tenant_id: String,
    pub status: String,
    pub currency: String,
    pub net_cents: i64,
    pub vat_cents: i64,
    pub us_tax_cents: i64,
    pub total_cents: i64,
    pub provider_payment_id: Option<String>,
    pub allocation_present: bool,
    pub issued_at: Option<DateTime<Utc>>,
    pub due_at: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoicePage {
    pub rows: Vec<InvoiceRow>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Default, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IncidentRow {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub status: String,
    pub tenant_id: Option<String>,
    pub local_invoice_id: Option<String>,
    pub provider_payment_id: Option<String>,
    pub currency: Option<String>,
    pub expected_total_cents: Option<i64>,
    pub observed_total_cents: Option<i64>,
    pub delta_cents: Option<i64>,
    pub detail: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionQuery {
    pub status: Option<String>,
    pub plan: Option<String>,
    /// Tenant id substring.
    pub query: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceQuery {
    pub status: Option<String>,
    /// Tenant id substring.
    pub tenant: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentQuery {
    /// `open` (default: open + acknowledged), `all`, or an exact status.
    pub status: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveIncidentBody {
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn operator_guard(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    crate::middleware::auth::require_scopes(auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(state, auth).await
}

async fn get_overview(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<BillingOverview>, ApiError> {
    operator_guard(&state, &auth).await?;
    Ok(Json(load_overview(&state).await?))
}

async fn get_subscriptions(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<SubscriptionQuery>,
) -> Result<Json<SubscriptionPage>, ApiError> {
    operator_guard(&state, &auth).await?;
    Ok(Json(load_subscriptions(&state, &query).await?))
}

async fn get_invoices(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<InvoiceQuery>,
) -> Result<Json<InvoicePage>, ApiError> {
    operator_guard(&state, &auth).await?;
    Ok(Json(load_invoices(&state, &query).await?))
}

async fn get_incidents(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<IncidentQuery>,
) -> Result<Json<Vec<IncidentRow>>, ApiError> {
    operator_guard(&state, &auth).await?;
    Ok(Json(load_incidents(&state, &query).await?))
}

async fn get_health(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<WebhookHealth>, ApiError> {
    operator_guard(&state, &auth).await?;
    Ok(Json(load_webhook_health(&state).await?))
}

/// Resolve a finance incident with an operator note. The status transition is
/// guarded (`status <> 'resolved'`) so a replay cannot overwrite the original
/// resolution, and the action is audited like every other operator mutation.
async fn resolve_incident(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<ResolveIncidentBody>,
) -> Result<Json<IncidentRow>, ApiError> {
    operator_guard(&state, &auth).await?;
    let incident_id: uuid::Uuid = id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid incident id".into()))?;
    let note = body
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if note.is_some_and(|value| value.chars().count() > 2_000) {
        return Err(ApiError::BadRequest(
            "resolution note must be at most 2000 characters".into(),
        ));
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| ApiError::Internal(format!("incident transaction failed: {error}")))?;
    let updated: Option<(uuid::Uuid, String)> = sqlx::query_as(
        "UPDATE finance_incidents \
            SET status = 'resolved', resolved_at = NOW(), resolution_note = $2 \
          WHERE id = $1 AND status IN ('open', 'acknowledged') \
          RETURNING id, kind",
    )
    .bind(incident_id)
    .bind(note)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| ApiError::Internal(format!("incident resolve failed: {error}")))?;
    let Some((resolved_id, kind)) = updated else {
        tx.rollback().await.ok();
        return Err(ApiError::NotFound(
            "no open or acknowledged incident with that id".into(),
        ));
    };
    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(&auth.tenant_id),
        auth.user_id.as_deref(),
        "billing.finance_incident_resolved",
        "finance_incident",
        Some(&resolved_id.to_string()),
        serde_json::json!({ "kind": kind, "note": note }),
        None,
        None,
        Utc::now(),
    )
    .await
    .map_err(|error| ApiError::Internal(format!("incident audit failed: {error}")))?;
    tx.commit()
        .await
        .map_err(|error| ApiError::Internal(format!("incident commit failed: {error}")))?;

    let rows = load_incidents(
        &state,
        &IncidentQuery {
            status: Some(resolved_id.to_string()),
            limit: Some(1),
        },
    )
    .await?;
    rows.into_iter()
        .next()
        .map(Json)
        .ok_or_else(|| ApiError::Internal("resolved incident could not be re-read".into()))
}

// ---------------------------------------------------------------------------
// Loaders (shared by the JSON endpoints and the SSR page)
// ---------------------------------------------------------------------------

fn monthly_cents(interval: &str, price_monthly: i64, price_yearly: i64) -> i64 {
    if interval.eq_ignore_ascii_case("yearly") || interval.eq_ignore_ascii_case("year") {
        (price_yearly + 6) / 12
    } else {
        price_monthly
    }
}

fn is_billable(status: &str) -> bool {
    matches!(status, "active" | "trialing" | "past_due")
}

fn month_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .date_naive()
        .with_day(1)
        .unwrap_or(timestamp.date_naive())
        .and_time(NaiveTime::MIN)
        .and_utc()
}

fn recent_months(now: DateTime<Utc>, count: u32) -> Vec<DateTime<Utc>> {
    let anchor = month_start(now).date_naive();
    (0..count)
        .rev()
        .map(|offset| {
            anchor
                .checked_sub_months(Months::new(offset))
                .unwrap_or(anchor)
                .and_time(NaiveTime::MIN)
                .and_utc()
        })
        .collect()
}

#[derive(Debug, sqlx::FromRow)]
struct LifecycleRow {
    row_id: String,
    tenant_id: String,
    plan: String,
    interval: String,
    status: String,
    provider_subscription_id: Option<String>,
    mandate_present: bool,
    billing_cycle_start: Option<DateTime<Utc>>,
    billing_cycle_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
    canceled_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    price_monthly: i64,
    price_yearly: i64,
}

const LIFECYCLE_SQL: &str = r#"
    SELECT s.id::text AS row_id,
           s.tenant_id::text AS tenant_id,
           COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free') AS plan,
           COALESCE(NULLIF(s.billing_interval, ''), 'monthly') AS interval,
           COALESCE(s.status, '') AS status,
           s.mollie_subscription_id AS provider_subscription_id,
           COALESCE(NULLIF(s.mollie_mandate_id, ''), '') <> '' AS mandate_present,
           s.billing_cycle_start,
           s.billing_cycle_end,
           COALESCE(s.cancel_at_period_end, false) AS cancel_at_period_end,
           COALESCE(s.canceled_at, CASE WHEN s.status = 'canceled' THEN s.updated_at END) AS canceled_at,
           s.created_at,
           COALESCE(p.price_monthly, 0) AS price_monthly,
           COALESCE(p.price_yearly, 0) AS price_yearly
    FROM mollie_subscriptions s
    JOIN tenants t ON t.id = s.tenant_id
    LEFT JOIN plans p ON p.name = COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''))
"#;

async fn load_lifecycle_rows(state: &AppState) -> Result<Vec<LifecycleRow>, ApiError> {
    if !table_exists(&state.db, "mollie_subscriptions").await? {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, LifecycleRow>(LIFECYCLE_SQL)
        .fetch_all(&state.db)
        .await
        .map_err(|error| ApiError::Internal(format!("billing lifecycle load failed: {error}")))
}

pub async fn load_overview(state: &AppState) -> Result<BillingOverview, ApiError> {
    let now = Utc::now();
    let cutoff_30 = now - Duration::days(30);
    let rows = load_lifecycle_rows(state).await?;
    let mut notes: Vec<String> = Vec::new();

    let active_parents: Vec<&LifecycleRow> =
        rows.iter().filter(|row| is_billable(&row.status)).collect();
    let mrr_cents: i64 = active_parents
        .iter()
        .map(|row| monthly_cents(&row.interval, row.price_monthly, row.price_yearly))
        .sum();
    let billable_subscriptions = active_parents.len() as i64;
    let active_subscriptions = rows.iter().filter(|r| r.status == "active").count() as i64;
    let trialing_subscriptions = rows.iter().filter(|r| r.status == "trialing").count() as i64;
    let past_due_subscriptions = rows.iter().filter(|r| r.status == "past_due").count() as i64;
    let unpaid_subscriptions = rows.iter().filter(|r| r.status == "unpaid").count() as i64;
    let canceled_subscriptions_30d = rows
        .iter()
        .filter(|r| r.canceled_at.is_some_and(|at| at >= cutoff_30))
        .count() as i64;
    let new_subscriptions_30d = rows.iter().filter(|r| r.created_at >= cutoff_30).count() as i64;
    let starting = rows
        .iter()
        .filter(|r| {
            r.created_at < cutoff_30
                && (is_billable(&r.status) || r.canceled_at.is_some_and(|at| at >= cutoff_30))
        })
        .count() as i64;
    let churn_rate_30d = if starting > 0 {
        canceled_subscriptions_30d as f64 / starting as f64
    } else {
        0.0
    };

    let mut plan_mix: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
    let mut interval_mix: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
    for row in &active_parents {
        let mrr = monthly_cents(&row.interval, row.price_monthly, row.price_yearly);
        let plan_entry = plan_mix.entry(row.plan.clone()).or_insert((0, 0));
        plan_entry.0 += 1;
        plan_entry.1 += mrr;
        let interval_entry = interval_mix.entry(row.interval.clone()).or_insert((0, 0));
        interval_entry.0 += 1;
        interval_entry.1 += mrr;
    }
    let mix_rows = |map: std::collections::BTreeMap<String, (i64, i64)>| {
        let mut out: Vec<MixRow> = map
            .into_iter()
            .map(|(key, (subscriptions, cents))| MixRow {
                key,
                subscriptions,
                mrr_cents: cents,
                share: if mrr_cents > 0 {
                    cents as f64 / mrr_cents as f64
                } else {
                    0.0
                },
            })
            .collect();
        out.sort_by(|a, b| b.mrr_cents.cmp(&a.mrr_cents).then(a.key.cmp(&b.key)));
        out
    };
    let plan_mix = mix_rows(plan_mix);
    let interval_mix = mix_rows(interval_mix);

    let renewals_due_7d = rows
        .iter()
        .filter(|r| {
            is_billable(&r.status)
                && r.billing_cycle_end
                    .is_some_and(|end| end >= now && end <= now + Duration::days(7))
        })
        .count() as i64;
    let renewals_due_30d = rows
        .iter()
        .filter(|r| {
            is_billable(&r.status)
                && r.billing_cycle_end
                    .is_some_and(|end| end >= now && end <= now + Duration::days(30))
        })
        .count() as i64;
    let cancel_at_period_end = rows.iter().filter(|r| r.cancel_at_period_end).count() as i64;

    let movement = load_movement(state, now).await?;
    let (upgrades_30d, downgrades_30d, expansion_mrr_cents_30d) =
        load_plan_change_velocity(state, cutoff_30).await?;
    let collections = load_collections(state, cutoff_30, now).await?;
    let incidents = load_incident_summary(state, cutoff_30).await?;
    let webhook = load_webhook_health(state).await?;
    let settlements = load_settlements().await;
    if !settlements.configured {
        notes.push("settlements unavailable: Mollie is not configured on this deployment".into());
    } else if settlements.error.is_some() {
        notes.push("settlements unavailable: the provider read failed (see health)".into());
    }

    Ok(BillingOverview {
        generated_at: now,
        currency: "EUR",
        mrr_cents,
        arr_cents: mrr_cents * 12,
        arpa_cents: if billable_subscriptions > 0 {
            mrr_cents / billable_subscriptions
        } else {
            0
        },
        active_subscriptions,
        billable_subscriptions,
        trialing_subscriptions,
        past_due_subscriptions,
        unpaid_subscriptions,
        canceled_subscriptions_30d,
        new_subscriptions_30d,
        churn_rate_30d,
        upgrades_30d,
        downgrades_30d,
        expansion_mrr_cents_30d,
        renewals_due_7d,
        renewals_due_30d,
        cancel_at_period_end,
        plan_mix,
        interval_mix,
        movement,
        collections,
        incidents,
        webhook,
        settlements,
        notes,
    })
}

/// MRR movement by month: activations from the verified-activation audit (the
/// same facts the revenue endpoint uses), cancellations from the three
/// cancellation audit actions joined to the subscription row they ended.
async fn load_movement(state: &AppState, now: DateTime<Utc>) -> Result<Vec<MovementRow>, ApiError> {
    let db = &state.db;
    let mut out: Vec<MovementRow> = recent_months(now, 6)
        .into_iter()
        .map(|start| MovementRow {
            month: start.format("%Y-%m").to_string(),
            ..Default::default()
        })
        .collect();
    if !table_exists(db, "audit_logs").await? {
        return Ok(out);
    }

    let activations: Vec<(DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT timestamp, \
                CASE WHEN jsonb_typeof(details->'newMrrCents') = 'number' \
                     THEN (details->>'newMrrCents')::bigint ELSE 0 END \
           FROM audit_logs \
          WHERE action = 'billing.subscription_activated' AND details IS NOT NULL \
            AND timestamp >= $1",
    )
    .bind(now - Duration::days(190))
    .fetch_all(db)
    .await
    .map_err(|error| ApiError::Internal(format!("activation movement load failed: {error}")))?;
    for (at, cents) in activations {
        let key = at.format("%Y-%m").to_string();
        if let Some(row) = out.iter_mut().find(|row| row.month == key) {
            row.activations += 1;
            row.new_mrr_cents += cents;
        }
    }

    // Cancellation audits are keyed by the subscription row id, which is
    // retained after cancellation — so the plan/interval that produced the
    // churned MRR is still readable. The regex guard keeps a non-uuid resource
    // id from failing the cast.
    let cancellations: Vec<(DateTime<Utc>, String, String, i64, i64)> = sqlx::query_as(
        "SELECT a.timestamp, \
                COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free'), \
                COALESCE(NULLIF(s.billing_interval, ''), 'monthly'), \
                COALESCE(p.price_monthly, 0)::bigint, \
                COALESCE(p.price_yearly, 0)::bigint \
           FROM audit_logs a \
           JOIN mollie_subscriptions s \
             ON a.resource_id ~ '^[0-9a-fA-F-]{36}$' AND s.id = a.resource_id::uuid \
           JOIN tenants t ON t.id = s.tenant_id \
           LEFT JOIN plans p ON p.name = COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, '')) \
          WHERE a.action IN ( \
                'billing.subscription_canceled', \
                'billing.subscription_canceled_at_period_end', \
                'billing.subscription_ended_at_period_end') \
            AND a.timestamp >= $1",
    )
    .bind(now - Duration::days(190))
    .fetch_all(db)
    .await
    .map_err(|error| ApiError::Internal(format!("churn movement load failed: {error}")))?;
    for (at, _plan, interval, monthly, yearly) in cancellations {
        let key = at.format("%Y-%m").to_string();
        if let Some(row) = out.iter_mut().find(|row| row.month == key) {
            row.cancellations += 1;
            row.churned_mrr_cents += monthly_cents(&interval, monthly, yearly);
        }
    }
    for row in &mut out {
        row.net_mrr_cents = row.new_mrr_cents - row.churned_mrr_cents;
    }
    Ok(out)
}

async fn load_plan_change_velocity(
    state: &AppState,
    cutoff: DateTime<Utc>,
) -> Result<(i64, i64, i64), ApiError> {
    if !table_exists(&state.db, "audit_logs").await? {
        return Ok((0, 0, 0));
    }
    let changes: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT CASE WHEN jsonb_typeof(details->'previousMrrCents') = 'number' \
                     THEN (details->>'previousMrrCents')::bigint ELSE 0 END, \
                CASE WHEN jsonb_typeof(details->'newMrrCents') = 'number' \
                     THEN (details->>'newMrrCents')::bigint ELSE 0 END \
           FROM audit_logs \
          WHERE action = 'billing.subscription_activated' AND details IS NOT NULL \
            AND timestamp >= $1",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .map_err(|error| ApiError::Internal(format!("plan velocity load failed: {error}")))?;
    let mut upgrades = 0;
    let mut downgrades = 0;
    let mut expansion = 0;
    for (previous, new) in changes {
        if previous <= 0 {
            continue;
        }
        if new > previous {
            upgrades += 1;
            expansion += new - previous;
        } else if new < previous {
            downgrades += 1;
        }
    }
    Ok((upgrades, downgrades, expansion))
}

async fn load_collections(
    state: &AppState,
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Collections, ApiError> {
    let db = &state.db;
    let mut out = Collections::default();
    if table_exists(db, "invoices").await? {
        let paid: (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(total), 0)::bigint, COUNT(*)::bigint \
               FROM invoices WHERE status = 'paid' AND paid_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("paid invoice totals failed: {error}")))?;
        out.paid_30d_cents = paid.0;
        out.paid_30d_count = paid.1;

        let outstanding: (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(total), 0)::bigint, COUNT(*)::bigint \
               FROM invoices \
              WHERE status::text NOT IN ('paid', 'void', 'draft', 'uncollectible')",
        )
        .fetch_one(db)
        .await
        .map_err(|error| {
            ApiError::Internal(format!("outstanding invoice totals failed: {error}"))
        })?;
        out.outstanding_cents = outstanding.0;
        out.outstanding_count = outstanding.1;

        let overdue: (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(total), 0)::bigint, COUNT(*)::bigint \
               FROM invoices \
              WHERE status::text NOT IN ('paid', 'void', 'draft', 'uncollectible') \
                AND due_at IS NOT NULL AND due_at < $1",
        )
        .bind(now)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("overdue invoice totals failed: {error}")))?;
        out.overdue_cents = overdue.0;
        out.overdue_count = overdue.1;
    }

    if table_exists(db, "mollie_refunds").await? {
        let refunds: (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(amount_cents), 0)::bigint, COUNT(*)::bigint \
               FROM mollie_refunds WHERE created_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("refund totals failed: {error}")))?;
        out.refunded_30d_cents = refunds.0;
        out.refunded_30d_count = refunds.1;
    }

    if table_exists(db, "invoice_payment_allocations").await? {
        out.allocations_30d_cents = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_cents), 0)::bigint \
               FROM invoice_payment_allocations WHERE created_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("allocation totals failed: {error}")))?;
    }

    if table_exists(db, "audit_logs").await? {
        out.failed_payments_30d = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
              WHERE action = 'billing.subscription_payment_failed' AND timestamp >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("failed payment count failed: {error}")))?;

        let chargebacks: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::bigint, \
                    COALESCE(SUM(CASE WHEN jsonb_typeof(details->'amountMinorUnits') = 'number' \
                                      THEN (details->>'amountMinorUnits')::bigint ELSE 0 END), 0)::bigint \
               FROM audit_logs \
              WHERE action = 'billing.mollie_chargeback_recorded' AND timestamp >= $1",
        )
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("chargeback totals failed: {error}")))?;
        out.chargebacks_30d = chargebacks.0;
        out.chargeback_30d_cents = chargebacks.1;
    }
    Ok(out)
}

async fn load_incident_summary(
    state: &AppState,
    cutoff: DateTime<Utc>,
) -> Result<IncidentSummary, ApiError> {
    let db = &state.db;
    let mut out = IncidentSummary::default();
    if !table_exists(db, "finance_incidents").await? {
        return Ok(out);
    }
    let by_severity: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*)::bigint FROM finance_incidents \
          WHERE status = 'open' GROUP BY severity ORDER BY severity",
    )
    .fetch_all(db)
    .await
    .map_err(|error| ApiError::Internal(format!("incident severity load failed: {error}")))?;
    out.by_severity = by_severity
        .into_iter()
        .map(|(severity, count)| SeverityCount { severity, count })
        .collect();
    out.open = out.by_severity.iter().map(|row| row.count).sum();
    out.acknowledged = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM finance_incidents WHERE status = 'acknowledged'",
    )
    .fetch_one(db)
    .await
    .map_err(|error| ApiError::Internal(format!("incident count failed: {error}")))?;
    out.resolved_30d = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM finance_incidents \
          WHERE status = 'resolved' AND resolved_at >= $1",
    )
    .bind(cutoff)
    .fetch_one(db)
    .await
    .map_err(|error| ApiError::Internal(format!("resolved incident count failed: {error}")))?;
    Ok(out)
}

pub async fn load_webhook_health(state: &AppState) -> Result<WebhookHealth, ApiError> {
    let db = &state.db;
    let now = Utc::now();
    let mut out = WebhookHealth {
        configured: billing_service::mollie_client::MollieClient::from_env().is_ok(),
        ..Default::default()
    };
    if table_exists(db, "mollie_webhook_events").await? {
        let since = now - Duration::hours(24);
        let counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, COUNT(*)::bigint FROM mollie_webhook_events \
              WHERE created_at >= $1 GROUP BY status",
        )
        .bind(since)
        .fetch_all(db)
        .await
        .map_err(|error| ApiError::Internal(format!("webhook health load failed: {error}")))?;
        for (status, count) in counts {
            out.events_24h += count;
            if status == "processed" {
                out.processed_24h = count;
            } else if status == "failed" || status == "dead_lettered" {
                out.failed_24h += count;
            }
        }
        out.pending = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM mollie_webhook_events WHERE status = 'pending'",
        )
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("pending webhook count failed: {error}")))?;
        out.last_processed_at = sqlx::query_scalar(
            "SELECT MAX(processed_at) FROM mollie_webhook_events WHERE processed_at IS NOT NULL",
        )
        .fetch_one(db)
        .await
        .map_err(|error| ApiError::Internal(format!("last webhook load failed: {error}")))?;
    }
    if table_exists(db, "mollie_subscriptions").await? {
        out.reconciliation_pending = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM mollie_subscriptions \
              WHERE status = 'canceled' AND left(mollie_subscription_id, 4) = 'sub_'",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);
    }
    Ok(out)
}

async fn load_settlements() -> SettlementsView {
    let client = match billing_service::mollie_client::MollieClient::from_env() {
        Ok(client) => client,
        Err(_) => {
            return SettlementsView {
                configured: false,
                error: None,
                settlements: Vec::new(),
            }
        }
    };
    match client.list_settlements(None).await {
        Ok(settlements) => SettlementsView {
            configured: true,
            error: None,
            settlements: settlements
                .iter()
                .map(|settlement| SettlementRow {
                    id: settlement.id.clone(),
                    status: settlement.status.clone(),
                    amount_cents: settlement.amount.as_ref().map(|m| m.cents).unwrap_or(0),
                    currency: settlement
                        .amount
                        .as_ref()
                        .map(|m| m.currency.clone())
                        .unwrap_or_else(|| "EUR".into()),
                    settled_at: settlement.settled_at.clone(),
                })
                .collect(),
        },
        Err(error) => SettlementsView {
            configured: true,
            error: Some(error.to_string()),
            settlements: Vec::new(),
        },
    }
}

pub async fn load_subscriptions(
    state: &AppState,
    query: &SubscriptionQuery,
) -> Result<SubscriptionPage, ApiError> {
    if !table_exists(&state.db, "mollie_subscriptions").await? {
        return Ok(SubscriptionPage {
            rows: Vec::new(),
            total: 0,
        });
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let status = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let plan = query
        .plan
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let needle = query
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{}%", value.to_ascii_lowercase()));

    let sql = format!(
        "{LIFECYCLE_SQL} \
         WHERE ($1::text IS NULL OR s.status = $1) \
           AND ($2::text IS NULL OR COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, '')) = $2) \
           AND ($3::text IS NULL OR lower(s.tenant_id) LIKE $3) \
         ORDER BY s.created_at DESC LIMIT $4 OFFSET $5"
    );
    let rows: Vec<LifecycleRow> = sqlx::query_as(&sql)
        .bind(status.as_deref())
        .bind(plan.as_deref())
        .bind(needle.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|error| ApiError::Internal(format!("subscription list failed: {error}")))?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mollie_subscriptions s JOIN tenants t ON t.id = s.tenant_id \
          WHERE ($1::text IS NULL OR s.status = $1) \
            AND ($2::text IS NULL OR COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, '')) = $2) \
            AND ($3::text IS NULL OR lower(s.tenant_id) LIKE $3)",
    )
    .bind(status.as_deref())
    .bind(plan.as_deref())
    .bind(needle.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|error| ApiError::Internal(format!("subscription count failed: {error}")))?;

    Ok(SubscriptionPage {
        rows: rows
            .into_iter()
            .map(|row| SubscriptionRow {
                id: row.row_id,
                tenant_id: row.tenant_id,
                plan: row.plan,
                mrr_cents: monthly_cents(&row.interval, row.price_monthly, row.price_yearly),
                interval: row.interval,
                status: row.status,
                provider_subscription_id: row.provider_subscription_id,
                mandate_present: row.mandate_present,
                billing_cycle_start: row.billing_cycle_start,
                billing_cycle_end: row.billing_cycle_end,
                cancel_at_period_end: row.cancel_at_period_end,
                canceled_at: row.canceled_at,
                created_at: row.created_at,
            })
            .collect(),
        total,
    })
}

pub async fn load_invoices(
    state: &AppState,
    query: &InvoiceQuery,
) -> Result<InvoicePage, ApiError> {
    if !table_exists(&state.db, "invoices").await? {
        return Ok(InvoicePage {
            rows: Vec::new(),
            total: 0,
        });
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let status = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let tenant = query
        .tenant
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{}%", value.to_ascii_lowercase()));
    let rows: Vec<InvoiceRow> = sqlx::query_as(
        "SELECT id::text AS id, invoice_number, tenant_id, status::text AS status, currency, \
                COALESCE(subtotal, 0)::bigint AS net_cents, \
                COALESCE(vat_total, 0)::bigint AS vat_cents, \
                COALESCE(us_sales_tax_cents, 0)::bigint AS us_tax_cents, \
                COALESCE(total, subtotal + vat_total, amount, 0)::bigint AS total_cents, \
                mollie_payment_id AS provider_payment_id, \
                EXISTS (SELECT 1 FROM invoice_payment_allocations a WHERE a.invoice_id = invoices.id) \
                    AS allocation_present, \
                issued_at, due_at, paid_at, created_at \
           FROM invoices \
          WHERE ($1::text IS NULL OR status::text = $1) \
            AND ($2::text IS NULL OR lower(tenant_id) LIKE $2) \
          ORDER BY created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(status.as_deref())
    .bind(tenant.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|error| ApiError::Internal(format!("invoice list failed: {error}")))?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM invoices \
          WHERE ($1::text IS NULL OR status::text = $1) \
            AND ($2::text IS NULL OR lower(tenant_id) LIKE $2)",
    )
    .bind(status.as_deref())
    .bind(tenant.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|error| ApiError::Internal(format!("invoice count failed: {error}")))?;
    Ok(InvoicePage { rows, total })
}

pub async fn load_incidents(
    state: &AppState,
    query: &IncidentQuery,
) -> Result<Vec<IncidentRow>, ApiError> {
    if !table_exists(&state.db, "finance_incidents").await? {
        return Ok(Vec::new());
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let status = query.status.as_deref().map(str::trim).unwrap_or("open");
    let filter = if status.eq_ignore_ascii_case("all") {
        None
    } else if status.eq_ignore_ascii_case("open") {
        Some("open|acknowledged")
    } else {
        Some(status)
    };
    // A resolved-id lookup uses the exact uuid; other filters use the status
    // words. Both are bound, never interpolated.
    let exact = filter.and_then(|value| uuid::Uuid::parse_str(value).ok());
    let rows: Vec<IncidentRow> = if let Some(id) = exact {
        sqlx::query_as(
            "SELECT id::text AS id, kind, severity, status, tenant_id, \
                    local_invoice_id::text AS local_invoice_id, \
                    mollie_payment_id AS provider_payment_id, currency, \
                    expected_total_cents, observed_total_cents, delta_cents, detail, \
                    created_at, acknowledged_at, resolved_at, resolution_note \
               FROM finance_incidents WHERE id = $1",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await
    } else {
        let statuses: Vec<String> = match filter {
            Some("open|acknowledged") => vec!["open".into(), "acknowledged".into()],
            Some(other) => vec![other.to_string()],
            None => Vec::new(),
        };
        sqlx::query_as(
            "SELECT id::text AS id, kind, severity, status, tenant_id, \
                    local_invoice_id::text AS local_invoice_id, \
                    mollie_payment_id AS provider_payment_id, currency, \
                    expected_total_cents, observed_total_cents, delta_cents, detail, \
                    created_at, acknowledged_at, resolved_at, resolution_note \
               FROM finance_incidents \
              WHERE (cardinality($1::text[]) = 0 OR status = ANY($1)) \
              ORDER BY created_at DESC LIMIT $2",
        )
        .bind(&statuses)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|error| ApiError::Internal(format!("incident list failed: {error}")))?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// SSR snapshot (the `/billing` page)
// ---------------------------------------------------------------------------

/// Group cents into a euro string with thousands separators.
pub(crate) fn format_eur(cents: i64) -> String {
    let negative = cents < 0;
    let absolute = cents.unsigned_abs();
    let euros = absolute / 100;
    let fraction = absolute % 100;
    let digits = euros.to_string();
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    let grouped: String = grouped.chars().rev().collect();
    format!(
        "{}€{}.{:02}",
        if negative { "-" } else { "" },
        grouped,
        fraction
    )
}

fn percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

fn date(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|at| at.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "—".into())
}

fn short(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let prefix: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{prefix}…")
    }
}

/// Build the SSR `/billing` snapshot from the SAME loaders the JSON endpoints
/// serve. `None` means a source could not be read: the page renders its
/// explicit unavailable state rather than a zero-filled dashboard.
pub async fn load_page_data(
    state: &AppState,
) -> Option<ui_foundation::view_data::BillingOpsPageData> {
    use ui_foundation::view_data::{
        BillingIncidentRow, BillingInvoiceRow, BillingMixRow, BillingMovementRow,
        BillingOpsPageData, BillingSettlementRow, BillingSubscriptionRow, KpiCardData,
    };

    let overview = load_overview(state).await.ok()?;
    let subscriptions = load_subscriptions(
        state,
        &SubscriptionQuery {
            limit: Some(25),
            ..Default::default()
        },
    )
    .await
    .ok()?;
    let invoices = load_invoices(
        state,
        &InvoiceQuery {
            limit: Some(25),
            ..Default::default()
        },
    )
    .await
    .ok()?;
    let incidents = load_incidents(
        state,
        &IncidentQuery {
            status: Some("all".into()),
            limit: Some(25),
        },
    )
    .await
    .ok()?;

    let kpis = vec![
        KpiCardData::new("MRR", format_eur(overview.mrr_cents))
            .with_hint(&format!("ARR {}", format_eur(overview.arr_cents))),
        KpiCardData::new(
            "Active subscriptions",
            overview.active_subscriptions.to_string(),
        )
        .with_hint(&format!(
            "billable {} · ARPA {}",
            overview.billable_subscriptions,
            format_eur(overview.arpa_cents)
        )),
        KpiCardData::new("Past due", overview.past_due_subscriptions.to_string())
            .with_hint(&format!("unpaid {}", overview.unpaid_subscriptions)),
        KpiCardData::new("Renewals ≤ 7d", overview.renewals_due_7d.to_string())
            .with_hint(&format!("≤ 30d {}", overview.renewals_due_30d)),
        KpiCardData::new("Churn 30d", percent(overview.churn_rate_30d))
            .with_hint(&format!("{} canceled", overview.canceled_subscriptions_30d)),
        KpiCardData::new(
            "Plan changes 30d",
            format!("+{} / -{}", overview.upgrades_30d, overview.downgrades_30d),
        )
        .with_hint(&format!(
            "expansion {}",
            format_eur(overview.expansion_mrr_cents_30d)
        )),
    ];

    let collections = &overview.collections;
    let collection_kpis = vec![
        KpiCardData::new("Paid 30d", format_eur(collections.paid_30d_cents))
            .with_hint(&format!("{} invoices", collections.paid_30d_count)),
        KpiCardData::new("Outstanding", format_eur(collections.outstanding_cents))
            .with_hint(&format!("{} invoices", collections.outstanding_count)),
        KpiCardData::new("Overdue", format_eur(collections.overdue_cents))
            .with_hint(&format!("{} invoices", collections.overdue_count)),
        KpiCardData::new("Refunded 30d", format_eur(collections.refunded_30d_cents))
            .with_hint(&format!("{} refunds", collections.refunded_30d_count)),
        KpiCardData::new("Chargebacks 30d", collections.chargebacks_30d.to_string())
            .with_hint(&format_eur(collections.chargeback_30d_cents)),
        KpiCardData::new(
            "Failed charges 30d",
            collections.failed_payments_30d.to_string(),
        )
        .with_hint(&format!(
            "allocated {}",
            format_eur(collections.allocations_30d_cents)
        )),
    ];

    let webhook = &overview.webhook;
    let health_kpis = vec![
        KpiCardData::new("Webhook events 24h", webhook.events_24h.to_string())
            .with_hint(&format!("{} processed", webhook.processed_24h)),
        KpiCardData::new("Failed 24h", webhook.failed_24h.to_string())
            .with_hint(&format!("{} pending total", webhook.pending)),
        KpiCardData::new("Open incidents", overview.incidents.open.to_string())
            .with_hint(&format!("{} acknowledged", overview.incidents.acknowledged)),
        KpiCardData::new(
            "Provider",
            if webhook.configured {
                "configured"
            } else {
                "not configured"
            },
        )
        .with_hint(&format!(
            "last processed {}",
            date(webhook.last_processed_at)
        )),
    ];

    let map_mix = |rows: Vec<MixRow>| {
        rows.into_iter()
            .map(|row| BillingMixRow {
                key: row.key,
                subscriptions: row.subscriptions,
                mrr: format_eur(row.mrr_cents),
                share: percent(row.share),
            })
            .collect::<Vec<_>>()
    };

    Some(BillingOpsPageData {
        generated_at: overview
            .generated_at
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        kpis,
        collection_kpis,
        health_kpis,
        plan_mix: map_mix(overview.plan_mix),
        interval_mix: map_mix(overview.interval_mix),
        movement: overview
            .movement
            .into_iter()
            .map(|row| BillingMovementRow {
                month: row.month,
                activations: row.activations,
                new_mrr: format_eur(row.new_mrr_cents),
                cancellations: row.cancellations,
                churned_mrr: format_eur(row.churned_mrr_cents),
                net_mrr: format_eur(row.net_mrr_cents),
            })
            .collect(),
        subscriptions: subscriptions
            .rows
            .into_iter()
            .map(|row| BillingSubscriptionRow {
                tenant: row.tenant_id,
                plan: row.plan,
                interval: row.interval,
                status: row.status,
                provider_id: row.provider_subscription_id.unwrap_or_default(),
                cycle_end: date(row.billing_cycle_end),
                cancel_at_period_end: row.cancel_at_period_end,
                mrr: format_eur(row.mrr_cents),
            })
            .collect(),
        invoices: invoices
            .rows
            .into_iter()
            .map(|row| BillingInvoiceRow {
                number: row.invoice_number.unwrap_or_else(|| short(&row.id, 8)),
                tenant: row.tenant_id,
                status: row.status,
                total: format_eur(row.total_cents),
                tax: format_eur(row.vat_cents + row.us_tax_cents),
                provider_payment_id: row.provider_payment_id.unwrap_or_default(),
                paid_at: date(row.paid_at),
            })
            .collect(),
        incidents: incidents
            .into_iter()
            .map(|row| BillingIncidentRow {
                created_at: row.created_at.format("%Y-%m-%d %H:%M").to_string(),
                kind: row.kind,
                severity: row.severity,
                status: row.status,
                tenant: row.tenant_id.unwrap_or_else(|| "—".into()),
                detail: short(&row.detail.to_string(), 120),
            })
            .collect(),
        settlements: overview
            .settlements
            .settlements
            .into_iter()
            .map(|row| BillingSettlementRow {
                id: row.id,
                status: row.status,
                amount: format_eur(row.amount_cents),
                settled_at: row.settled_at.unwrap_or_else(|| "—".into()),
            })
            .collect(),
        settlements_error: overview.settlements.error,
        notes: overview.notes,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::test_state_over;
    use axum::http::StatusCode;

    fn operator_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Seed one tenant's lifecycle: an active subscription due in 5 days, a
    /// paid invoice, a refund, an open incident and two webhook events.
    async fn seed_lifecycle(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'starter', 'active') \
             ON CONFLICT (id) DO UPDATE SET plan = 'starter'",
        )
        .bind(tenant)
        .bind(format!("Billing ops {tenant}"))
        .execute(pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO plans (name, display_name, price_monthly, price_yearly) \
             VALUES ('starter', 'Developer', 2000, 20000) \
             ON CONFLICT (name) DO UPDATE SET price_monthly = 2000, price_yearly = 20000",
        )
        .execute(pool)
        .await
        .expect("seed plan");
        sqlx::query(
            "INSERT INTO mollie_subscriptions (tenant_id, mollie_subscription_id, plan, status, \
                billing_interval, billing_cycle_start, billing_cycle_end, mollie_customer_id, \
                mollie_mandate_id, mollie_sequence_type) \
             VALUES ($1, $2, 'starter', 'active', 'monthly', NOW() - INTERVAL '25 days', \
                     NOW() + INTERVAL '5 days', $3, $4, 'recurring')",
        )
        .bind(tenant)
        .bind(format!("sub_{tenant}"))
        .bind(format!("cst_{tenant}"))
        .bind(format!("mdt_{tenant}"))
        .execute(pool)
        .await
        .expect("seed subscription");
        sqlx::query(
            "INSERT INTO mollie_subscriptions (tenant_id, mollie_subscription_id, plan, status, \
                billing_interval, billing_cycle_start, billing_cycle_end, mollie_customer_id, \
                mollie_mandate_id, mollie_sequence_type) \
             VALUES ($1, $2, 'starter', 'past_due', 'monthly', NOW() - INTERVAL '35 days', \
                     NOW() - INTERVAL '5 days', $3, $4, 'recurring')",
        )
        .bind(tenant)
        .bind(format!("sub2_{tenant}"))
        .bind(format!("cst2_{tenant}"))
        .bind(format!("mdt2_{tenant}"))
        .execute(pool)
        .await
        .expect("seed past-due subscription");
        sqlx::query(
            "INSERT INTO invoices (tenant_id, mollie_payment_id, invoice_number, status, currency, \
                amount, subtotal, vat_total, total, issued_at, due_at, paid_at) \
             VALUES ($1, $2, $3, 'paid', 'EUR', 2000, 1613, 387, 2000, NOW(), NOW(), NOW())",
        )
        .bind(tenant)
        .bind(format!("tr_{tenant}"))
        .bind(format!("INV-{tenant}"))
        .execute(pool)
        .await
        .expect("seed paid invoice");
        sqlx::query(
            "INSERT INTO mollie_refunds (id, payment_id, amount_cents, currency, status) \
             VALUES ($1, $2, 500, 'EUR', 'refunded')",
        )
        .bind(format!("re_{tenant}"))
        .bind(format!("tr_{tenant}"))
        .execute(pool)
        .await
        .expect("seed refund");
        sqlx::query(
            "INSERT INTO finance_incidents (kind, severity, status, tenant_id, detail) \
             VALUES ('mollie_subscription_amount_drift', 'high', 'open', $1, '{}'::jsonb)",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed incident");
        for (status, suffix) in [("processed", "a"), ("failed", "b")] {
            sqlx::query(
                "INSERT INTO mollie_webhook_events (mollie_event_id, mollie_payment_id, event_type, status, processed_at) \
                 VALUES ($1, $2, 'AUTHORISATION', $3, CASE WHEN $3 = 'processed' THEN NOW() ELSE NULL END)",
            )
            .bind(format!("mollie:tr_{tenant}:{suffix}"))
            .bind(format!("tr_{tenant}"))
            .bind(status)
            .execute(pool)
            .await
            .expect("seed webhook event");
        }
    }

    async fn cleanup_lifecycle(pool: &sqlx::PgPool, tenant: &str) {
        for statement in [
            "DELETE FROM mollie_webhook_events WHERE mollie_payment_id = $1",
            "DELETE FROM finance_incidents WHERE tenant_id = $1",
            "DELETE FROM mollie_refunds WHERE payment_id = $1",
            "DELETE FROM invoice_payment_allocations WHERE tenant_id = $1",
            "DELETE FROM invoices WHERE tenant_id = $1",
            "DELETE FROM mollie_subscriptions WHERE tenant_id = $1",
            "DELETE FROM audit_logs WHERE tenant_id = $1",
            "DELETE FROM tenants WHERE id = $1",
        ] {
            let bind = if statement.contains("mollie_refunds")
                || statement.contains("mollie_webhook_events")
            {
                format!("tr_{tenant}")
            } else {
                tenant.to_string()
            };
            sqlx::query(statement).bind(bind).execute(pool).await.ok();
        }
    }

    #[tokio::test]
    async fn overview_and_lists_see_the_seeded_lifecycle() {
        let Some(pool) = crate::test_db::canonical_pool("billing_ops_overview").await else {
            return;
        };
        let state = test_state_over(pool.clone()).await;
        let tenant = format!("tbo{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        let before = load_overview(&state).await.expect("overview before");
        seed_lifecycle(&pool, &tenant).await;

        let after = load_overview(&state).await.expect("overview after");
        assert_eq!(
            after.active_subscriptions,
            before.active_subscriptions + 1,
            "the active subscription is counted"
        );
        assert_eq!(
            after.past_due_subscriptions,
            before.past_due_subscriptions + 1,
            "the past-due subscription is counted separately"
        );
        assert_eq!(
            after.billable_subscriptions,
            before.billable_subscriptions + 2,
            "MRR counts active and past-due subscriptions"
        );
        assert!(
            after.mrr_cents >= before.mrr_cents + 4_000,
            "both seeded starter subscriptions add their catalog MRR"
        );
        assert_eq!(
            after.renewals_due_7d,
            before.renewals_due_7d + 1,
            "the cycle ending in 5 days is due within 7"
        );
        assert_eq!(
            after.collections.paid_30d_count,
            before.collections.paid_30d_count + 1
        );
        assert!(after.collections.paid_30d_cents >= before.collections.paid_30d_cents + 2_000);
        assert!(
            after.collections.refunded_30d_cents >= before.collections.refunded_30d_cents + 500
        );
        assert_eq!(after.incidents.open, before.incidents.open + 1);
        assert!(after.webhook.events_24h >= before.webhook.events_24h + 2);
        assert!(after.webhook.failed_24h > before.webhook.failed_24h);
        assert!(
            after.plan_mix.iter().any(|row| row.key == "starter"),
            "the plan mix names the active plan"
        );

        let subscriptions = load_subscriptions(
            &state,
            &SubscriptionQuery {
                query: Some(tenant.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("subscriptions");
        assert_eq!(subscriptions.total, 2);
        let active = load_subscriptions(
            &state,
            &SubscriptionQuery {
                query: Some(tenant.clone()),
                status: Some("active".into()),
                ..Default::default()
            },
        )
        .await
        .expect("filtered subscriptions");
        assert_eq!(active.total, 1);
        assert_eq!(active.rows[0].mrr_cents, 2_000);
        assert!(active.rows[0].mandate_present);

        let invoices = load_invoices(
            &state,
            &InvoiceQuery {
                tenant: Some(tenant.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("invoices");
        assert_eq!(invoices.total, 1);
        assert_eq!(invoices.rows[0].total_cents, 2_000);
        assert_eq!(invoices.rows[0].vat_cents, 387);
        assert_eq!(
            invoices.rows[0].provider_payment_id.as_deref(),
            Some(format!("tr_{tenant}").as_str())
        );

        let incidents = load_incidents(
            &state,
            &IncidentQuery {
                status: Some("all".into()),
                limit: Some(500),
            },
        )
        .await
        .expect("incidents");
        let incident = incidents
            .iter()
            .find(|row| row.tenant_id.as_deref() == Some(tenant.as_str()))
            .expect("seeded incident is listed");
        assert_eq!(incident.severity, "high");

        cleanup_lifecycle(&pool, &tenant).await;
    }

    #[tokio::test]
    async fn resolve_incident_is_audited_and_idempotent() {
        let Some(pool) = crate::test_db::canonical_pool("billing_ops_resolve").await else {
            return;
        };
        let state = test_state_over(pool.clone()).await;
        let tenant = format!("tbo{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        seed_lifecycle(&pool, &tenant).await;
        let incident_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM finance_incidents WHERE tenant_id = $1 AND status = 'open'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("seeded incident id");

        let resolved = resolve_incident(
            State(state.clone()),
            operator_auth(),
            Path(incident_id.to_string()),
            Json(ResolveIncidentBody {
                note: Some("verified against the provider".into()),
            }),
        )
        .await
        .expect("resolve");
        assert_eq!(resolved.0.status, "resolved");
        assert_eq!(
            resolved.0.resolution_note.as_deref(),
            Some("verified against the provider")
        );

        // A replay cannot overwrite the original resolution.
        let replay = resolve_incident(
            State(state.clone()),
            operator_auth(),
            Path(incident_id.to_string()),
            Json(ResolveIncidentBody {
                note: Some("different note".into()),
            }),
        )
        .await;
        assert!(matches!(replay, Err(ApiError::NotFound(_))));

        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
              WHERE action = 'billing.finance_incident_resolved' AND resource_id = $1",
        )
        .bind(incident_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert_eq!(audits, 1);

        cleanup_lifecycle(&pool, &tenant).await;
    }

    #[tokio::test]
    async fn billing_ops_routes_are_mounted_and_fail_closed_without_auth() {
        let Some(pool) = crate::test_db::canonical_pool("billing_ops_mount").await else {
            return;
        };
        let state = test_state_over(pool.clone()).await;
        let app = crate::app::build_app(state);
        for uri in [
            "/v1/admin/billing/overview",
            "/v1/admin/billing/subscriptions",
            "/v1/admin/billing/invoices",
            "/v1/admin/billing/incidents",
            "/v1/admin/billing/health",
        ] {
            let response = tower::ServiceExt::oneshot(
                app.clone(),
                axum::http::Request::get(uri)
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router is infallible");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} must be mounted behind auth (404 would mean unmounted)"
            );
        }
    }

    #[test]
    fn format_eur_groups_thousands_and_keeps_cents() {
        assert_eq!(format_eur(0), "€0.00");
        assert_eq!(format_eur(2_000), "€20.00");
        assert_eq!(format_eur(123_456_789), "€1,234,567.89");
        assert_eq!(format_eur(-1_500), "-€15.00");
    }

    #[test]
    fn monthly_mrr_rounds_yearly_half_up() {
        assert_eq!(monthly_cents("monthly", 2_000, 20_000), 2_000);
        assert_eq!(monthly_cents("yearly", 0, 20_000), 1_667);
        assert_eq!(monthly_cents("year", 0, 25_000), 2_083);
    }

    #[test]
    fn billable_statuses_match_the_revenue_endpoint() {
        for status in ["active", "trialing", "past_due"] {
            assert!(is_billable(status), "{status}");
        }
        for status in ["unpaid", "canceled", "", "pending"] {
            assert!(!is_billable(status), "{status}");
        }
    }

    #[test]
    fn recent_months_are_ordered_and_end_with_the_current_month() {
        let now = DateTime::parse_from_rfc3339("2026-03-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let months = recent_months(now, 3);
        assert_eq!(months.len(), 3);
        assert_eq!(months[0].format("%Y-%m").to_string(), "2026-01");
        assert_eq!(months[2].format("%Y-%m").to_string(), "2026-03");
    }
}
