use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, error, info, warn};

use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

const DEADLETTER_EVENT_PREFIX: &str = "stripe:deadletter:event:";
const DEADLETTER_INDEX_KEY: &str = "stripe:deadletter:index";
const DEADLETTER_RETENTION_SECONDS: usize = 35 * 24 * 60 * 60;
const DEADLETTER_RETENTION_MS: i64 = (DEADLETTER_RETENTION_SECONDS as i64) * 1000;
const STRIPE_WEBHOOK_TOLERANCE_SECONDS: i64 = 300;
const DUNNING_STATUS_CACHE_TTL_SECONDS: u64 = 300;

static DUNNING_CONFIG_TABLE_ENSURED: OnceLock<()> = OnceLock::new();

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/webhooks/stripe", post(handle_stripe_webhook))
}

async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        record_deadletter(
            &state,
            DeadletterEntry {
                reason: "missing_signature".into(),
                occurred_at: None,
                event_id: None,
                error: None,
                payload_length: None,
            },
        )
        .await;

        return json_error(StatusCode::BAD_REQUEST, "Missing stripe-signature header");
    };

    let event_id = match extract_event_id(&body) {
        Ok(event_id) => event_id,
        Err(RouteValidationError::InvalidJson(error_message)) => {
            record_deadletter(
                &state,
                DeadletterEntry {
                    reason: "invalid_json_payload".into(),
                    occurred_at: None,
                    event_id: None,
                    error: Some(error_message),
                    payload_length: Some(body.len()),
                },
            )
            .await;

            return json_error(StatusCode::BAD_REQUEST, "Invalid JSON payload");
        }
        Err(RouteValidationError::MissingEventId) => {
            record_deadletter(
                &state,
                DeadletterEntry {
                    reason: "missing_event_id".into(),
                    occurred_at: None,
                    event_id: None,
                    error: None,
                    payload_length: Some(body.len()),
                },
            )
            .await;

            return json_error(StatusCode::BAD_REQUEST, "Missing event ID");
        }
    };

    match process_webhook(&state, &body, signature).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "received": true }))).into_response(),
        Err(error_message) => {
            record_deadletter(
                &state,
                DeadletterEntry {
                    reason: "processing_failed".into(),
                    occurred_at: None,
                    event_id: Some(event_id.clone()),
                    error: Some(error_message.clone()),
                    payload_length: None,
                },
            )
            .await;

            error!(event_id = %event_id, error = %error_message, "stripe webhook processing failed");
            json_error(StatusCode::BAD_REQUEST, "Webhook processing failed")
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn extract_event_id(body: &[u8]) -> Result<String, RouteValidationError> {
    let envelope = serde_json::from_slice::<EventIdEnvelope>(body)
        .map_err(|error| RouteValidationError::InvalidJson(error.to_string()))?;

    let Some(event_id) = envelope.id.map(|value| value.trim().to_string()) else {
        return Err(RouteValidationError::MissingEventId);
    };

    if event_id.is_empty() {
        return Err(RouteValidationError::MissingEventId);
    }

    Ok(event_id)
}

async fn record_deadletter(state: &AppState, entry: DeadletterEntry) {
    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let occurred_at = entry
        .occurred_at
        .clone()
        .unwrap_or_else(|| now.to_rfc3339());
    let event_key = format!(
        "{}{}:{}",
        DEADLETTER_EVENT_PREFIX,
        sanitize_event_id(entry.event_id.as_deref()),
        now_ms
    );

    let payload = match serde_json::to_string(&DeadletterEntry {
        occurred_at: Some(occurred_at),
        ..entry
    }) {
        Ok(payload) => payload,
        Err(error) => {
            error!(error = %error, "failed to serialize stripe dead letter");
            return;
        }
    };

    let mut conn = match state.redis.get().await {
        Ok(conn) => conn,
        Err(error) => {
            error!(error = %error, "failed to acquire redis connection for stripe dead letter");
            return;
        }
    };

    let cleanup_before = now_ms - DEADLETTER_RETENTION_MS;
    let redis_result = redis::pipe()
        .atomic()
        .cmd("SETEX")
        .arg(&event_key)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .arg(payload)
        .ignore()
        .cmd("ZADD")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(now_ms)
        .arg(&event_key)
        .ignore()
        .cmd("ZREMRANGEBYSCORE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(0)
        .arg(cleanup_before)
        .ignore()
        .cmd("EXPIRE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .ignore()
        .query_async::<()>(&mut conn)
        .await;

    if let Err(error) = redis_result {
        error!(error = %error, "failed to write stripe dead letter");
    }
}

fn sanitize_event_id(event_id: Option<&str>) -> String {
    let Some(event_id) = event_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return "unknown".into();
    };

    event_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn process_webhook(
    state: &AppState,
    payload: &[u8],
    signature: &str,
) -> Result<ProcessWebhookResult, String> {
    let event = verify_and_parse_event(state, payload, signature)?;

    let existing_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = $1",
    )
    .bind(&event.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load Stripe webhook event: {error}"))?;

    if let Some(status) = existing_status.as_deref() {
        if status == "processed" {
            info!(event_id = %event.id, event_type = %event.event_type, "duplicate stripe webhook already processed");
            return Ok(ProcessWebhookResult {
                event_type: event.event_type,
                processed: false,
            });
        }

        info!(event_id = %event.id, event_type = %event.event_type, previous_status = %status, "retrying stripe webhook event");
    }

    sqlx::query(
        r#"
        INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
        ON CONFLICT (stripe_event_id) DO UPDATE SET status = 'pending', updated_at = NOW()
        "#,
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to upsert Stripe webhook event: {error}"))?;

    let event_id = event.id.clone();
    let event_type = event.event_type.clone();

    match handle_stripe_event(state, &event).await {
        Ok(()) => {
            sqlx::query(
                r#"
                UPDATE stripe_webhook_events
                SET status = 'processed', processed_at = NOW(), updated_at = NOW()
                WHERE stripe_event_id = $1
                "#,
            )
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|error| format!("Failed to mark Stripe webhook as processed: {error}"))?;

            Ok(ProcessWebhookResult {
                event_type,
                processed: true,
            })
        }
        Err(error_message) => {
            let failed_update = sqlx::query(
                r#"
                UPDATE stripe_webhook_events
                SET status = 'failed', error = $2, updated_at = NOW()
                WHERE stripe_event_id = $1
                "#,
            )
            .bind(&event_id)
            .bind(&error_message)
            .execute(&state.db)
            .await;

            if let Err(update_error) = failed_update {
                error!(event_id = %event_id, error = %update_error, "failed to mark stripe webhook as failed");
            }

            Err(error_message)
        }
    }
}

fn verify_and_parse_event(
    state: &AppState,
    payload: &[u8],
    signature: &str,
) -> Result<StripeEventPayload, String> {
    let secret = state.config.stripe_webhook_secret.trim();
    if secret.is_empty() {
        return Err("Stripe webhook secret is not configured".into());
    }

    let (timestamp, signatures) = parse_signature_header(signature)?;
    if (Utc::now().timestamp() - timestamp).abs() > STRIPE_WEBHOOK_TOLERANCE_SECONDS {
        return Err("Invalid webhook signature".into());
    }

    let timestamp_value = timestamp.to_string();
    let verified = signatures.into_iter().filter_map(|candidate| hex::decode(candidate).ok()).any(|expected| {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(timestamp_value.as_bytes());
        mac.update(b".");
        mac.update(payload);
        mac.verify_slice(&expected).is_ok()
    });

    if !verified {
        return Err("Invalid webhook signature".into());
    }

    serde_json::from_slice(payload)
        .map_err(|error| format!("Failed to decode Stripe event payload: {error}"))
}

fn parse_signature_header(signature: &str) -> Result<(i64, Vec<&str>), String> {
    let mut timestamp = None;
    let mut signatures = Vec::new();

    for segment in signature.split(',') {
        let mut parts = segment.splitn(2, '=');
        let Some(key) = parts.next().map(str::trim) else {
            continue;
        };
        let Some(value) = parts.next().map(str::trim) else {
            continue;
        };

        match key {
            "t" => {
                timestamp = value.parse::<i64>().ok();
            }
            "v1" => {
                if !value.is_empty() {
                    signatures.push(value);
                }
            }
            _ => {}
        }
    }

    match (timestamp, signatures.is_empty()) {
        (Some(timestamp), false) => Ok((timestamp, signatures)),
        _ => Err("Invalid webhook signature".into()),
    }
}

async fn handle_stripe_event(state: &AppState, event: &StripeEventPayload) -> Result<(), String> {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            let session: CheckoutSession = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode checkout session: {error}"))?;
            handle_checkout_completed(state, session).await
        }
        "customer.subscription.created" | "customer.subscription.updated" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode subscription event: {error}"))?;
            handle_subscription_change(state, subscription).await
        }
        "customer.subscription.deleted" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode subscription delete event: {error}"))?;
            handle_subscription_deleted(state, subscription).await
        }
        "invoice.paid" => {
            let invoice: InvoiceEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode invoice paid event: {error}"))?;
            handle_invoice_paid(state, invoice).await
        }
        "invoice.payment_failed" => {
            let invoice: InvoiceEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode invoice payment_failed event: {error}"))?;
            handle_payment_failed(state, invoice).await
        }
        "customer.subscription.trial_will_end" => {
            let subscription: SubscriptionEvent = serde_json::from_value(event.data.object.clone())
                .map_err(|error| format!("Failed to decode trial ending event: {error}"))?;
            handle_trial_ending(state, subscription).await
        }
        _ => {
            debug!(event_type = %event.event_type, "unhandled stripe webhook event");
            Ok(())
        }
    }
}

async fn handle_checkout_completed(state: &AppState, session: CheckoutSession) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(session.metadata.as_ref()) else {
        warn!(session_id = %session.id, "stripe checkout session missing tenant_id metadata");
        return Ok(());
    };

    sqlx::query(
        "UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1",
    )
    .bind(tenant_id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to update tenant status after checkout: {error}"))?;

    info!(tenant_id = %tenant_id, session_id = %session.id, "stripe checkout completed");
    Ok(())
}

async fn handle_subscription_change(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        warn!(subscription_id = %subscription.id, "stripe subscription missing tenant_id metadata");
        return Ok(());
    };

    let current_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = $1",
    )
    .bind(&subscription.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load current subscription status: {error}"))?;

    if let Some(current_status) = current_status.as_deref() {
        if current_status != subscription.status.as_str()
            && !subscription.status.can_transition_from(current_status)
        {
            return Err(format!(
                "Invalid subscription status transition: {current_status} -> {}",
                subscription.status.as_str()
            ));
        }
    } else if !subscription.status.is_valid_initial_status() {
        return Err(format!(
            "Invalid initial subscription state: {}",
            subscription.status.as_str()
        ));
    }

    let Some(primary_item) = subscription.items.data.first() else {
        return Err(format!(
            "Subscription {} has no line items",
            subscription.id
        ));
    };
    let Some(price) = primary_item.price.as_ref() else {
        return Err(format!(
            "Subscription {} has no line-item price",
            subscription.id
        ));
    };
    let Some(price_id) = price.id.as_deref() else {
        return Err(format!(
            "Subscription {} has no valid line-item price",
            subscription.id
        ));
    };
    let Some(interval) = price
        .recurring
        .as_ref()
        .and_then(|recurring| recurring.interval)
    else {
        return Err(format!(
            "Subscription {} has an unsupported billing interval",
            subscription.id
        ));
    };

    sqlx::query(
        r#"
        WITH upsert_subscription AS (
            INSERT INTO stripe_subscriptions (
                id, tenant_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
                status, billing_interval, billing_cycle_start, billing_cycle_end,
                cancel_at_period_end, canceled_at, trial_end, created_at, updated_at
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3, $4, $5, $6,
                to_timestamp($7), to_timestamp($8), $9, to_timestamp($10), to_timestamp($11), NOW(), NOW()
            )
            ON CONFLICT (stripe_subscription_id) DO UPDATE SET
                status = $5,
                billing_interval = $6,
                billing_cycle_start = to_timestamp($7),
                billing_cycle_end = to_timestamp($8),
                cancel_at_period_end = $9,
                canceled_at = to_timestamp($10),
                trial_end = to_timestamp($11),
                updated_at = NOW()
            RETURNING tenant_id
        ),
        plan_lookup AS (
            SELECT name FROM plans
            WHERE stripe_price_id_monthly = $4 OR stripe_price_id_yearly = $4
            LIMIT 1
        ),
        update_tenant AS (
            UPDATE tenants
            SET plan = COALESCE((SELECT name FROM plan_lookup), plan), updated_at = NOW()
            WHERE id = $1
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&subscription.id)
    .bind(subscription.customer.id())
    .bind(price_id)
    .bind(subscription.status.as_str())
    .bind(interval.as_db_value())
    .bind(subscription.current_period_start)
    .bind(subscription.current_period_end)
    .bind(subscription.cancel_at_period_end)
    .bind(subscription.canceled_at)
    .bind(subscription.trial_end)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to upsert Stripe subscription: {error}"))?;

    info!(
        tenant_id = %tenant_id,
        subscription_id = %subscription.id,
        status = %subscription.status.as_str(),
        "stripe subscription updated"
    );

    if matches!(subscription.status, SubscriptionStatus::Active) {
        auto_provision_dedicated_ips(state, tenant_id).await?;
    }

    Ok(())
}

async fn auto_provision_dedicated_ips(state: &AppState, tenant_id: &str) -> Result<(), String> {
    let included_count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COALESCE((p.features->>'dedicated_ip_count')::int, 0) AS included_count
        FROM stripe_subscriptions s
        JOIN plans p ON p.name = (
            SELECT plan FROM tenants WHERE id = s.tenant_id
        )
        WHERE s.tenant_id = $1 AND s.status = 'active'
        ORDER BY s.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load dedicated IP allowance: {error}"))?
    .unwrap_or(0);

    if included_count <= 0 {
        return Ok(());
    }

    let active_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::bigint
        FROM dedicated_ips
        WHERE tenant_id = $1::uuid AND status NOT IN ('retired', 'releasing')
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to load active dedicated IP count: {error}"))?;

    let to_allocate = i64::from(included_count) - active_count;
    if to_allocate <= 0 {
        info!(tenant_id = %tenant_id, active_count, included_count, "tenant already has sufficient dedicated IPs");
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO dedicated_ip_provisioning_requests
            (id, tenant_id, requested_count, status, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
        ON CONFLICT (tenant_id) WHERE status = 'pending'
        DO UPDATE SET requested_count = $2, updated_at = NOW()
        "#,
    )
    .bind(tenant_id)
    .bind(to_allocate)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to record dedicated IP provisioning request: {error}"))?;

    let client = reqwest::Client::new();
    let api_base_url = state.config.api_base_url.trim_end_matches('/');
    let mut success_count = 0_i64;
    let mut failure_count = 0_i64;

    for _ in 0..to_allocate {
        let response = client
            .post(format!("{api_base_url}/v1/dedicated-ips"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", state.config.service_auth_token))
            .header("X-Internal-Service", "billing")
            .header("X-Tenant-Id", tenant_id)
            .json(&serde_json::json!({ "auto_provisioned": true }))
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => {
                success_count += 1;
            }
            Ok(response) => {
                failure_count += 1;
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                warn!(tenant_id = %tenant_id, status = %status, error = %body, "dedicated IP auto-provision request failed");
            }
            Err(error) => {
                failure_count += 1;
                error!(tenant_id = %tenant_id, error = %error, "dedicated IP auto-provision request errored");
            }
        }
    }

    let final_status = if failure_count == 0 {
        "completed"
    } else if success_count > 0 {
        "partial"
    } else {
        "failed"
    };

    sqlx::query(
        r#"
        UPDATE dedicated_ip_provisioning_requests
        SET status = $2, success_count = $3, failure_count = $4, updated_at = NOW()
        WHERE tenant_id = $1 AND status = 'pending'
        "#,
    )
    .bind(tenant_id)
    .bind(final_status)
    .bind(success_count)
    .bind(failure_count)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to update dedicated IP provisioning request: {error}"))?;

    if failure_count > 0 {
        error!(
            tenant_id = %tenant_id,
            requested_count = to_allocate,
            success_count,
            failure_count,
            final_status,
            "dedicated IP provisioning had failures"
        );
    }

    Ok(())
}

async fn handle_subscription_deleted(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        return Ok(());
    };

    sqlx::query(
        r#"
        WITH cancel_subscription AS (
            UPDATE stripe_subscriptions
            SET status = 'canceled', updated_at = NOW()
            WHERE stripe_subscription_id = $1
            RETURNING tenant_id
        ),
        downgrade_tenant AS (
            UPDATE tenants
            SET plan = 'free', updated_at = NOW()
            WHERE id = $2
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(&subscription.id)
    .bind(tenant_id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to cancel Stripe subscription: {error}"))?;

    info!(tenant_id = %tenant_id, subscription_id = %subscription.id, "stripe subscription canceled");
    Ok(())
}

async fn handle_invoice_paid(state: &AppState, invoice: InvoiceEvent) -> Result<(), String> {
    let mut tenant_id = tenant_id_from_metadata(
        invoice
            .subscription_details
            .as_ref()
            .and_then(|details| details.metadata.as_ref()),
    )
    .map(str::to_string);

    if tenant_id.is_none() {
        if let Some(subscription_id) = invoice.subscription.as_ref().map(ExpandableId::id) {
            tenant_id = sqlx::query_scalar::<_, String>(
                r#"
                SELECT tenant_id
                FROM stripe_subscriptions
                WHERE stripe_subscription_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(subscription_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|error| format!("Failed to resolve tenant from Stripe subscription: {error}"))?;
        }
    }

    let Some(tenant_id) = tenant_id else {
        return Ok(());
    };

    sqlx::query(
        "UPDATE invoices SET status = 'paid', paid_at = NOW(), updated_at = NOW() WHERE stripe_invoice_id = $1",
    )
    .bind(&invoice.id)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to mark invoice as paid: {error}"))?;

    info!(tenant_id = %tenant_id, invoice_id = %invoice.id, "stripe invoice marked as paid");
    Ok(())
}

async fn handle_payment_failed(state: &AppState, invoice: InvoiceEvent) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(
        invoice
            .subscription_details
            .as_ref()
            .and_then(|details| details.metadata.as_ref()),
    )
    else {
        return Ok(());
    };

    let dunning = record_failed_payment(state, tenant_id, &invoice.id, invoice.amount_due).await?;

    sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(serde_json::json!({
        "invoiceId": invoice.id,
        "amount": invoice.amount_due,
        "attemptCount": invoice.attempt_count.unwrap_or_default(),
        "dunningStatus": dunning.status,
        "nextRetryAt": dunning.next_retry_at.map(|value| value.to_rfc3339()),
    }))
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to enqueue payment_failed notification: {error}"))?;

    warn!(tenant_id = %tenant_id, invoice_id = %invoice.id, "stripe invoice payment failed");
    Ok(())
}

async fn handle_trial_ending(
    state: &AppState,
    subscription: SubscriptionEvent,
) -> Result<(), String> {
    let Some(tenant_id) = tenant_id_from_metadata(subscription.metadata.as_ref()) else {
        return Ok(());
    };

    sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, 'trial_ending', $2, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(serde_json::json!({
        "subscriptionId": subscription.id,
        "trialEnd": subscription.trial_end,
    }))
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to enqueue trial_ending notification: {error}"))?;

    info!(tenant_id = %tenant_id, subscription_id = %subscription.id, "stripe trial ending notification queued");
    Ok(())
}

async fn record_failed_payment(
    state: &AppState,
    tenant_id: &str,
    invoice_id: &str,
    amount: i64,
) -> Result<DunningResult, String> {
    let config = get_dunning_config_for_tenant(state, tenant_id).await;
    let now = Utc::now();

    let existing = sqlx::query_as::<_, DunningRecordRow>(
        r#"
        SELECT failed_payment_count, first_failed_at, status
        FROM dunning_records
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load dunning record: {error}"))?;

    let is_first_failure = existing
        .as_ref()
        .map(|row| row.status == "healthy")
        .unwrap_or(true);
    let first_failed_at = if is_first_failure {
        now
    } else {
        existing
            .as_ref()
            .and_then(|row| row.first_failed_at)
            .unwrap_or(now)
    };
    let failed_payment_count = if is_first_failure {
        1
    } else {
        existing
            .as_ref()
            .map(|row| row.failed_payment_count + 1)
            .unwrap_or(1)
    };

    let next_retry_at = calculate_next_retry(first_failed_at, failed_payment_count, &config);
    let days_since_first_failure = (now - first_failed_at).num_days().max(0);

    let mut new_status = "warning".to_string();
    let mut suspended_at = None;
    let mut grace_period_ends_at = None;

    if days_since_first_failure >= i64::from(config.hard_suspend_after_days) {
        new_status = "hard_suspended".into();
        if existing.as_ref().map(|row| row.status.as_str()) != Some("hard_suspended") {
            suspended_at = Some(now);
            grace_period_ends_at = Some(
                now + TimeDelta::days(i64::from(config.grace_period_days)),
            );
        }
    } else if days_since_first_failure >= i64::from(config.soft_suspend_after_days) {
        new_status = "soft_suspended".into();
        let already_suspended = existing
            .as_ref()
            .map(|row| row.status.contains("suspended"))
            .unwrap_or(false);
        if !already_suspended {
            suspended_at = Some(now);
        }
    }

    sqlx::query(
        r#"
        WITH upsert_dunning AS (
            INSERT INTO dunning_records (
                id, tenant_id, status, failed_payment_count, first_failed_at,
                last_failed_at, next_retry_at, suspended_at, grace_period_ends_at,
                created_at, updated_at
            )
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                status = $2,
                failed_payment_count = $3,
                last_failed_at = $5,
                next_retry_at = $6,
                suspended_at = COALESCE(dunning_records.suspended_at, $7),
                grace_period_ends_at = COALESCE($8, dunning_records.grace_period_ends_at),
                updated_at = NOW()
            RETURNING tenant_id
        ),
        log_event AS (
            INSERT INTO dunning_events (
                id, tenant_id, event_type, invoice_id, amount, metadata, created_at
            )
            VALUES (gen_random_uuid(), $1, 'payment_failed', $9, $10, $11, NOW())
            RETURNING tenant_id
        ),
        suspend_tenant AS (
            UPDATE tenants
            SET status = 'suspended', updated_at = NOW()
            WHERE id = $1 AND $12 = true
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&new_status)
    .bind(failed_payment_count)
    .bind(first_failed_at)
    .bind(now)
    .bind(next_retry_at)
    .bind(suspended_at)
    .bind(grace_period_ends_at)
    .bind(invoice_id)
    .bind(amount)
    .bind(serde_json::json!({
        "attempt": failed_payment_count,
        "daysSinceFirstFailure": days_since_first_failure,
    }))
    .bind(new_status == "hard_suspended")
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to upsert dunning state: {error}"))?;

    send_dunning_notification(
        state,
        tenant_id,
        &new_status,
        serde_json::json!({
            "failedCount": failed_payment_count,
            "daysSinceFirstFailure": days_since_first_failure,
            "nextRetryAt": next_retry_at.map(|value| value.to_rfc3339()),
        }),
    )
    .await;

    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let cache_result: Result<(), _> = redis::AsyncCommands::set_ex(
            &mut conn,
            &cache_key,
            &new_status,
            DUNNING_STATUS_CACHE_TTL_SECONDS,
        )
        .await;
        if let Err(error) = cache_result {
            warn!(tenant_id = %tenant_id, error = %error, "failed to cache dunning status");
        }
    }

    Ok(DunningResult {
        status: new_status,
        next_retry_at,
    })
}

async fn get_dunning_config_for_tenant(state: &AppState, tenant_id: &str) -> DunningConfig {
    if let Err(error) = ensure_dunning_config_table(state).await {
        warn!(tenant_id = %tenant_id, error = %error, "failed to ensure dunning_config table; using defaults");
        return DunningConfig::default();
    }

    let result = sqlx::query_as::<_, DunningConfigRow>(
        r#"
        SELECT retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days
        FROM dunning_config
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => DunningConfig {
            retry_schedule_days: row.retry_schedule_days,
            soft_suspend_after_days: row.soft_suspend_after_days,
            hard_suspend_after_days: row.hard_suspend_after_days,
            grace_period_days: row.grace_period_days,
        },
        Ok(None) => DunningConfig::default(),
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to load dunning config; using defaults");
            DunningConfig::default()
        }
    }
}

async fn ensure_dunning_config_table(state: &AppState) -> Result<(), String> {
    if DUNNING_CONFIG_TABLE_ENSURED.get().is_some() {
        return Ok(());
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dunning_config (
            tenant_id VARCHAR(36) PRIMARY KEY,
            retry_schedule_days INTEGER[] NOT NULL,
            soft_suspend_after_days INTEGER NOT NULL,
            hard_suspend_after_days INTEGER NOT NULL,
            grace_period_days INTEGER NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to ensure dunning_config table: {error}"))?;

    let _ = DUNNING_CONFIG_TABLE_ENSURED.set(());
    Ok(())
}

fn calculate_next_retry(
    first_failed_at: DateTime<Utc>,
    attempt_count: i32,
    config: &DunningConfig,
) -> Option<DateTime<Utc>> {
    let index = usize::try_from(attempt_count.saturating_sub(1)).ok()?;
    let days_to_add = *config.retry_schedule_days.get(index)?;
    Some(first_failed_at + TimeDelta::days(i64::from(days_to_add)))
}

async fn send_dunning_notification(
    state: &AppState,
    tenant_id: &str,
    status: &str,
    payload: serde_json::Value,
) {
    let notification_type = match status {
        "warning" => "payment_reminder",
        "soft_suspended" => "account_soft_suspended",
        _ => "account_hard_suspended",
    };

    let result = sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(notification_type)
    .bind(payload)
    .execute(&state.db)
    .await;

    if let Err(error) = result {
        error!(tenant_id = %tenant_id, error = %error, "failed to enqueue dunning notification");
    }
}

fn tenant_id_from_metadata(metadata: Option<&HashMap<String, String>>) -> Option<&str> {
    metadata
        .and_then(|values| values.get("tenant_id"))
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Deserialize)]
struct EventIdEnvelope {
    id: Option<String>,
}

#[derive(Debug)]
enum RouteValidationError {
    InvalidJson(String),
    MissingEventId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeadletterEntry {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_length: Option<usize>,
}

#[derive(Debug)]
struct ProcessWebhookResult {
    #[allow(dead_code)]
    event_type: String,
    #[allow(dead_code)]
    processed: bool,
}

#[derive(Debug, Deserialize)]
struct StripeEventPayload {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CheckoutSession {
    id: String,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionEvent {
    id: String,
    customer: ExpandableId,
    status: SubscriptionStatus,
    metadata: Option<HashMap<String, String>>,
    current_period_start: i64,
    current_period_end: i64,
    cancel_at_period_end: bool,
    canceled_at: Option<i64>,
    trial_end: Option<i64>,
    items: SubscriptionItems,
}

#[derive(Debug, Deserialize)]
struct SubscriptionItems {
    data: Vec<SubscriptionItem>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionItem {
    price: Option<SubscriptionPrice>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionPrice {
    id: Option<String>,
    recurring: Option<SubscriptionRecurring>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionRecurring {
    interval: Option<StripeBillingInterval>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubscriptionStatus {
    Active,
    PastDue,
    Unpaid,
    Canceled,
    Incomplete,
    IncompleteExpired,
    Trialing,
    Paused,
}

impl SubscriptionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Unpaid => "unpaid",
            Self::Canceled => "canceled",
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
            Self::Trialing => "trialing",
            Self::Paused => "paused",
        }
    }

    fn is_valid_initial_status(&self) -> bool {
        matches!(self, Self::Incomplete | Self::Trialing | Self::Active)
    }

    fn can_transition_from(&self, current_status: &str) -> bool {
        match current_status {
            "incomplete" => matches!(self, Self::Active | Self::IncompleteExpired),
            "incomplete_expired" => false,
            "trialing" => matches!(self, Self::Active | Self::PastDue | Self::Canceled | Self::Unpaid | Self::Paused),
            "active" => matches!(self, Self::PastDue | Self::Canceled | Self::Unpaid | Self::Paused),
            "past_due" => matches!(self, Self::Active | Self::Canceled | Self::Unpaid),
            "unpaid" => matches!(self, Self::Active | Self::Canceled),
            "canceled" => false,
            "paused" => matches!(self, Self::Active | Self::Canceled),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum StripeBillingInterval {
    #[serde(rename = "month")]
    Month,
    #[serde(rename = "year")]
    Year,
}

impl StripeBillingInterval {
    fn as_db_value(self) -> &'static str {
        match self {
            Self::Month => "monthly",
            Self::Year => "yearly",
        }
    }
}

#[derive(Debug, Deserialize)]
struct InvoiceEvent {
    id: String,
    amount_due: i64,
    #[serde(default)]
    attempt_count: Option<i64>,
    #[serde(default)]
    subscription_details: Option<InvoiceSubscriptionDetails>,
    #[serde(default)]
    subscription: Option<ExpandableId>,
}

#[derive(Debug, Deserialize)]
struct InvoiceSubscriptionDetails {
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExpandableId {
    Id(String),
    Object { id: String },
}

impl ExpandableId {
    fn id(&self) -> &str {
        match self {
            Self::Id(id) => id,
            Self::Object { id } => id,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DunningRecordRow {
    failed_payment_count: i32,
    first_failed_at: Option<DateTime<Utc>>,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DunningConfigRow {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

#[derive(Debug, Clone)]
struct DunningConfig {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

impl Default for DunningConfig {
    fn default() -> Self {
        Self {
            retry_schedule_days: vec![1, 3, 7, 14],
            soft_suspend_after_days: 7,
            hard_suspend_after_days: 21,
            grace_period_days: 7,
        }
    }
}

#[derive(Debug)]
struct DunningResult {
    status: String,
    next_retry_at: Option<DateTime<Utc>>,
}