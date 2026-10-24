//! Mollie API client — the ONE place this repository speaks to the payment
//! provider.
//!
//! Mollie's API (https://docs.mollie.com/reference) differs from a
//! notification-signature processor in three ways that shape this module:
//!
//! 1. **Authentication is the secret key itself** — `Authorization: Bearer
//!    <key>` on every call. A webhook carries no signature; the only way to
//!    know what happened is to FETCH the object with this key.
//! 2. **Amounts are decimal strings** (`{"currency":"EUR","value":"12.34"}`),
//!    never minor units. Conversion is exact and lives in
//!    [`Money`] — no floats, ever.
//! 3. **Creates are idempotent by header** (`Idempotency-Key`), and a payment
//!    is a *redirect* (`_links.checkout.href`), not a client session.
//!
//! The client is deliberately total over the fields ApexMail needs and keeps
//! the raw JSON on every object (`raw`) so a webhook's dead letter is the
//! provider's own document, not our lossy summary.

use std::time::Duration;

use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "https://api.mollie.com/v2";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum MollieError {
    #[error("Mollie is not configured: {0}")]
    Config(String),
    /// Transport / 5xx / 429: the caller should retry later, never treat this
    /// as a business refusal.
    #[error("Mollie is unavailable: {0}")]
    Unavailable(String),
    /// 4xx with a provider explanation (validation, refused, unknown id).
    #[error("Mollie refused the request ({status}): {detail}")]
    Rejected { status: u16, detail: String },
    #[error("Mollie returned a body this client cannot read: {0}")]
    Malformed(String),
}

/// An exact amount of money. `cents` is minor units; `currency` is an ISO
/// 4217 code. No float participates anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub currency: String,
    pub cents: i64,
}

impl Money {
    pub fn new(currency: &str, cents: i64) -> Self {
        Self {
            currency: currency.trim().to_ascii_uppercase(),
            cents,
        }
    }

    /// Mollie's wire value: a decimal string with the currency's exponent.
    /// All supported currencies (EUR/USD/GBP, …) use two decimals; GBP-style
    /// two-decimal currencies are the platform's whole billing surface.
    pub fn wire_value(&self) -> String {
        format!(
            "{}.{:02}",
            self.cents.div_euclid(100),
            self.cents.rem_euclid(100)
        )
    }

    /// Parse Mollie's decimal string without floating point. Rejects more
    /// than two decimals (the provider does not send them) rather than
    /// rounding money silently.
    pub fn parse(currency: &str, value: &str) -> Option<Self> {
        let value = value.trim();
        let (whole, fraction) = match value.split_once('.') {
            Some((whole, fraction)) => (whole, fraction),
            None => (value, ""),
        };
        if whole.is_empty() && fraction.is_empty() {
            return None;
        }
        if fraction.len() > 2 {
            return None;
        }
        let whole: i64 = if whole.is_empty() {
            0
        } else {
            whole.parse().ok()?
        };
        if whole < 0 {
            return None;
        }
        let fraction = format!("{fraction:0<2}");
        let fraction: i64 = fraction.parse().ok()?;
        Some(Self::new(currency, whole * 100 + fraction))
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "currency": self.currency, "value": self.wire_value() })
    }

    fn from_json(value: &serde_json::Value) -> Option<Self> {
        let currency = value.get("currency")?.as_str()?;
        let raw = value.get("value")?;
        let text = raw
            .as_str()
            .map(str::to_string)
            .or_else(|| raw.as_f64().map(|number| format!("{number:.2}")))?;
        Self::parse(currency, &text)
    }
}

// ---------------------------------------------------------------------------
// Wire objects (the fields ApexMail reads; `raw` keeps the document)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Payment {
    pub id: String,
    /// open | pending | authorized | paid | failed | canceled | expired |
    /// refunded | charged_back
    pub status: String,
    pub amount: Option<Money>,
    pub amount_refunded: Option<Money>,
    /// first | recurring | oneoff (or absent for one-off payments)
    pub sequence_type: Option<String>,
    pub customer_id: Option<String>,
    pub mandate_id: Option<String>,
    pub paid_at: Option<String>,
    pub method: Option<String>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct PaymentLink {
    pub id: String,
    pub status: String,
    pub checkout_url: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Refund {
    pub id: String,
    pub payment_id: String,
    /// queued | pending | processing | refunded | failed | canceled
    pub status: String,
    pub amount: Option<Money>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Customer {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Mandate {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    pub method: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Subscription {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    pub amount: Option<Money>,
    pub interval: Option<String>,
    pub next_payment_date: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Settlement {
    pub id: String,
    pub status: String,
    pub amount: Option<Money>,
    pub settled_at: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CreatePayment {
    pub amount: Money,
    pub description: String,
    pub redirect_url: String,
    pub webhook_url: Option<String>,
    pub metadata: serde_json::Value,
    /// Optional forced method (e.g. `ideal`, `creditcard`); None lets Mollie
    /// show its own method picker.
    pub method: Option<String>,
    pub customer_id: Option<String>,
    pub mandate_id: Option<String>,
    /// `first` / `recurring` for stored-mandate flows.
    pub sequence_type: Option<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct CreateSubscription {
    pub customer_id: String,
    pub mandate_id: Option<String>,
    pub amount: Money,
    pub interval: String,
    pub description: String,
    pub webhook_url: Option<String>,
    pub metadata: serde_json::Value,
    pub start_date: Option<String>,
    pub idempotency_key: String,
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

pub struct MollieClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    webhook_url: Option<String>,
}

impl std::fmt::Debug for MollieClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MollieClient")
            .field("base_url", &self.base_url)
            // The key never reaches a log line.
            .field("api_key", &"[redacted]")
            .field("webhook_url", &self.webhook_url)
            .finish()
    }
}

impl MollieClient {
    /// Resolve the client from the environment. `MOLLIE_API_KEY` is the only
    /// mandatory value; `MOLLIE_API_BASE_URL` exists for local/test stacks and
    /// `MOLLIE_WEBHOOK_URL` overrides the derived webhook endpoint.
    pub fn from_env() -> Result<Self, MollieError> {
        let api_key = std::env::var("MOLLIE_API_KEY")
            .ok()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| MollieError::Config("MOLLIE_API_KEY is not set".into()))?;
        let base_url = std::env::var("MOLLIE_API_BASE_URL")
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let webhook_url = std::env::var("MOLLIE_WEBHOOK_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self::new(api_key, base_url, webhook_url)
    }

    pub fn new(
        api_key: String,
        base_url: String,
        webhook_url: Option<String>,
    ) -> Result<Self, MollieError> {
        // A production deployment must never drive real customer billing
        // through the test endpoint or a test key: refuse unless the operator
        // deliberately opts in (the local stack does).
        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let production = environment.eq_ignore_ascii_case("production")
            || std::env::var("APP_ENV")
                .map(|value| value.eq_ignore_ascii_case("production"))
                .unwrap_or(false);
        if production {
            let test_base = base_url.contains("test") || base_url.contains("localhost");
            // Mollie's test API keys are prefixed `test_`; live keys `live_`.
            let test_key = api_key.starts_with("test_");
            let opted_in = std::env::var("MOLLIE_ALLOW_TEST_KEY").as_deref() == Ok("true");
            if (test_base || test_key) && !opted_in {
                return Err(MollieError::Config(
                    "Mollie test credentials in production: set the live key and \
                     https://api.mollie.com/v2, or MOLLIE_ALLOW_TEST_KEY=true deliberately"
                        .into(),
                ));
            }
        }
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| MollieError::Config(format!("HTTP client: {error}")))?;
        Ok(Self {
            http,
            base_url,
            api_key,
            webhook_url,
        })
    }

    #[cfg(test)]
    pub fn for_tests(base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            api_key: "test_dummy".into(),
            webhook_url: None,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The webhook endpoint Mollie will call. Derived from
    /// `MOLLIE_WEBHOOK_URL`, else `APP_BASE_URL`/`PUBLIC_BASE_URL` plus
    /// `/webhooks/mollie`; absent means "do not advertise one" (local stacks
    /// drive the webhook themselves).
    pub fn webhook_url(&self) -> Option<String> {
        if let Some(url) = &self.webhook_url {
            return Some(url.clone());
        }
        let base = std::env::var("APP_BASE_URL")
            .or_else(|_| std::env::var("PUBLIC_BASE_URL"))
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())?;
        Some(format!("{base}/webhooks/mollie"))
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value, MollieError> {
        let response = request
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|error| MollieError::Unavailable(format!("request failed: {error}")))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(MollieError::Unavailable(format!(
                "{status}: {}",
                truncate(&body, 300)
            )));
        }
        if !status.is_success() {
            return Err(MollieError::Rejected {
                status: status.as_u16(),
                detail: truncate(&body, 300),
            });
        }
        serde_json::from_str(&body)
            .map_err(|error| MollieError::Malformed(format!("{error}: {}", truncate(&body, 200))))
    }

    // ---- payments -------------------------------------------------------

    pub async fn create_payment(&self, request: CreatePayment) -> Result<PaymentLink, MollieError> {
        let mut body = serde_json::json!({
            "amount": request.amount.to_json(),
            "description": request.description,
            "metadata": request.metadata,
        });
        // A browser redirect only exists for customer-initiated payments;
        // API-initiated recurring charges must omit the field entirely
        // (an empty string would be rejected as an invalid URL).
        if !request.redirect_url.trim().is_empty() {
            body["redirectUrl"] = serde_json::Value::String(request.redirect_url);
        }
        if let Some(webhook) = request.webhook_url.or_else(|| self.webhook_url()) {
            body["webhookUrl"] = serde_json::Value::String(webhook);
        }
        if let Some(method) = request.method {
            body["method"] = serde_json::Value::String(method);
        }
        if let Some(customer) = request.customer_id {
            body["customerId"] = serde_json::Value::String(customer);
        }
        if let Some(mandate) = request.mandate_id {
            body["mandateId"] = serde_json::Value::String(mandate);
        }
        if let Some(sequence) = request.sequence_type {
            body["sequenceType"] = serde_json::Value::String(sequence);
        }
        let created = self
            .send(
                self.http
                    .post(self.url("payments"))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", request.idempotency_key)
                    .body(body.to_string()),
            )
            .await?;
        Ok(payment_link_from_json(created))
    }

    pub async fn get_payment(&self, id: &str) -> Result<Payment, MollieError> {
        let document = self
            .send(self.http.get(self.url(&format!("payments/{id}"))))
            .await?;
        Ok(payment_from_json(&document))
    }

    /// Every refund of one payment (Mollie has no top-level refund fetch).
    pub async fn payment_refunds(&self, payment_id: &str) -> Result<Vec<Refund>, MollieError> {
        let document = self
            .send(self.http.get(self.url(&format!("payments/{payment_id}/refunds"))))
            .await?;
        let embedded = document
            .get("_embedded")
            .and_then(|value| value.get("refunds"))
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(embedded
            .iter()
            .map(|refund| refund_from_json(payment_id, refund))
            .collect())
    }

    pub async fn create_refund(
        &self,
        payment_id: &str,
        amount: Money,
        description: &str,
        idempotency_key: &str,
    ) -> Result<Refund, MollieError> {
        let document = self
            .send(
                self.http
                    .post(self.url(&format!("payments/{payment_id}/refunds")))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", idempotency_key)
                    .body(
                        serde_json::json!({
                            "amount": amount.to_json(),
                            "description": description,
                        })
                        .to_string(),
                    ),
            )
            .await?;
        Ok(refund_from_json(payment_id, &document))
    }

    // ---- customers, mandates, subscriptions -----------------------------

    pub async fn get_customer(&self, id: &str) -> Result<Customer, MollieError> {
        let document = self
            .send(self.http.get(self.url(&format!("customers/{id}"))))
            .await?;
        Ok(Customer {
            id: document
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or(id)
                .to_string(),
            name: document.get("name").and_then(|value| value.as_str()).map(str::to_string),
            email: document.get("email").and_then(|value| value.as_str()).map(str::to_string),
            raw: document,
        })
    }

    pub async fn create_customer(
        &self,
        name: &str,
        email: &str,
        idempotency_key: &str,
    ) -> Result<Customer, MollieError> {
        let document = self
            .send(
                self.http
                    .post(self.url("customers"))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", idempotency_key)
                    .body(serde_json::json!({ "name": name, "email": email }).to_string()),
            )
            .await?;
        Ok(Customer {
            id: document
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            name: document.get("name").and_then(|value| value.as_str()).map(str::to_string),
            email: document.get("email").and_then(|value| value.as_str()).map(str::to_string),
            raw: document,
        })
    }

    pub async fn get_mandate(&self, customer_id: &str, mandate_id: &str) -> Result<Mandate, MollieError> {
        let document = self
            .send(
                self.http
                    .get(self.url(&format!("customers/{customer_id}/mandates/{mandate_id}"))),
            )
            .await?;
        Ok(Mandate {
            id: document
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or(mandate_id)
                .to_string(),
            customer_id: customer_id.to_string(),
            status: document
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            method: document.get("method").and_then(|value| value.as_str()).map(str::to_string),
            raw: document,
        })
    }

    /// Revoke a mandate at Mollie. After this call the mandate can never be
    /// charged again — the only provider-side guarantee that a canceled
    /// account stops generating recurring charges.
    pub async fn revoke_mandate(&self, customer_id: &str, mandate_id: &str) -> Result<(), MollieError> {
        self.send(
            self.http
                .delete(self.url(&format!("customers/{customer_id}/mandates/{mandate_id}"))),
        )
        .await
        .map(|_| ())
        .or_else(|error| match error {
            // 204 No Content has no body; the status was already checked.
            MollieError::Malformed(_) => Ok(()),
            other => Err(other),
        })
    }

    pub async fn create_subscription(
        &self,
        request: CreateSubscription,
    ) -> Result<Subscription, MollieError> {
        let mut body = serde_json::json!({
            "amount": request.amount.to_json(),
            "interval": request.interval,
            "description": request.description,
            "metadata": request.metadata,
        });
        if let Some(webhook) = request.webhook_url.or_else(|| self.webhook_url()) {
            body["webhookUrl"] = serde_json::Value::String(webhook);
        }
        if let Some(mandate) = request.mandate_id {
            body["mandateId"] = serde_json::Value::String(mandate);
        }
        if let Some(start) = request.start_date {
            body["startDate"] = serde_json::Value::String(start);
        }
        let document = self
            .send(
                self.http
                    .post(self.url(&format!("customers/{}/subscriptions", request.customer_id)))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", request.idempotency_key)
                    .body(body.to_string()),
            )
            .await?;
        Ok(subscription_from_json(&request.customer_id, &document))
    }

    pub async fn get_subscription(
        &self,
        customer_id: &str,
        id: &str,
    ) -> Result<Subscription, MollieError> {
        let document = self
            .send(
                self.http
                    .get(self.url(&format!("customers/{customer_id}/subscriptions/{id}"))),
            )
            .await?;
        Ok(subscription_from_json(customer_id, &document))
    }

    pub async fn cancel_subscription(&self, customer_id: &str, id: &str) -> Result<(), MollieError> {
        self.send(
            self.http
                .delete(self.url(&format!("customers/{customer_id}/subscriptions/{id}"))),
        )
        .await
        .map(|_| ())
        .or_else(|error| match error {
            // Mollie answers 204 No Content: `send` cannot parse an empty
            // body, so a successful delete arrives here as Malformed. The
            // status was already checked, so an empty body is success.
            MollieError::Malformed(message) if message.contains("EOF") => Ok(()),
            MollieError::Malformed(_) => Ok(()),
            other => Err(other),
        })
    }

    // ---- settlements (payout reconciliation) ----------------------------

    pub async fn list_settlements(&self, from: Option<&str>) -> Result<Vec<Settlement>, MollieError> {
        let mut url = self.url("settlements");
        if let Some(from) = from {
            url.push_str(&format!("?from={from}"));
        }
        let document = self.send(self.http.get(url)).await?;
        let embedded = document
            .get("_embedded")
            .and_then(|value| value.get("settlements"))
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(embedded.iter().map(settlement_from_json).collect())
    }

    pub async fn get_settlement(&self, id: &str) -> Result<Settlement, MollieError> {
        let document = self
            .send(self.http.get(self.url(&format!("settlements/{id}"))))
            .await?;
        Ok(settlement_from_json(&document))
    }
}

fn truncate(text: &str, max: usize) -> String {
    let mut text = text.to_string();
    if text.len() > max {
        // Never split a UTF-8 code point.
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

fn string_at(document: &serde_json::Value, pointer: &str) -> Option<String> {
    document
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

pub fn payment_from_json(document: &serde_json::Value) -> Payment {
    let metadata = document
        .get("metadata")
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    Payment {
        id: string_at(document, "/id").unwrap_or_default(),
        status: string_at(document, "/status").unwrap_or_default(),
        amount: document.get("amount").and_then(Money::from_json),
        amount_refunded: document.get("amountRefunded").and_then(Money::from_json),
        sequence_type: string_at(document, "/sequenceType"),
        customer_id: string_at(document, "/customerId"),
        mandate_id: string_at(document, "/mandateId"),
        paid_at: string_at(document, "/paidAt"),
        method: string_at(document, "/method"),
        metadata,
        raw: document.clone(),
    }
}

pub fn payment_link_from_json(document: serde_json::Value) -> PaymentLink {
    PaymentLink {
        id: string_at(&document, "/id").unwrap_or_default(),
        status: string_at(&document, "/status").unwrap_or_default(),
        checkout_url: string_at(&document, "/_links/checkout/href"),
        raw: document,
    }
}

pub fn refund_from_json(payment_id: &str, document: &serde_json::Value) -> Refund {
    Refund {
        id: string_at(document, "/id").unwrap_or_default(),
        payment_id: string_at(document, "/paymentId").unwrap_or_else(|| payment_id.to_string()),
        status: string_at(document, "/status").unwrap_or_default(),
        amount: document.get("amount").and_then(Money::from_json),
        raw: document.clone(),
    }
}

fn subscription_from_json(customer_id: &str, document: &serde_json::Value) -> Subscription {
    Subscription {
        id: string_at(document, "/id").unwrap_or_default(),
        customer_id: string_at(document, "/customerId").unwrap_or_else(|| customer_id.to_string()),
        status: string_at(document, "/status").unwrap_or_default(),
        amount: document.get("amount").and_then(Money::from_json),
        interval: string_at(document, "/interval"),
        next_payment_date: string_at(document, "/nextPaymentDate"),
        raw: document.clone(),
    }
}

fn settlement_from_json(document: &serde_json::Value) -> Settlement {
    Settlement {
        id: string_at(document, "/id").unwrap_or_default(),
        status: string_at(document, "/status").unwrap_or_default(),
        amount: document.get("amount").and_then(Money::from_json),
        settled_at: string_at(document, "/settledAt"),
        raw: document.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_wire_values_are_exact_decimals() {
        assert_eq!(Money::new("eur", 1234).wire_value(), "12.34");
        assert_eq!(Money::new("USD", 5).wire_value(), "0.05");
        assert_eq!(Money::new("EUR", 0).wire_value(), "0.00");
        assert_eq!(Money::new("EUR", 100_000).wire_value(), "1000.00");
    }

    #[test]
    fn money_parsing_refuses_to_round() {
        assert_eq!(Money::parse("EUR", "12.34"), Some(Money::new("EUR", 1234)));
        assert_eq!(Money::parse("EUR", "12.3"), Some(Money::new("EUR", 1230)));
        assert_eq!(Money::parse("EUR", "12"), Some(Money::new("EUR", 1200)));
        assert_eq!(Money::parse("EUR", "0.05"), Some(Money::new("EUR", 5)));
        // Three decimals is not a Mollie amount: refuse, never round.
        assert_eq!(Money::parse("EUR", "12.345"), None);
        assert_eq!(Money::parse("EUR", "-1.00"), None);
        assert_eq!(Money::parse("EUR", ""), None);
        // The value may arrive as a JSON number in a tolerant mock.
        let document = serde_json::json!({ "currency": "EUR", "value": 12.34 });
        assert_eq!(Money::from_json(&document), Some(Money::new("EUR", 1234)));
    }

    #[test]
    fn payment_document_maps_the_fields_the_webhook_needs() {
        let document = serde_json::json!({
            "id": "tr_7UhSN1zuXS",
            "status": "paid",
            "amount": { "currency": "EUR", "value": "12.34" },
            "amountRefunded": { "currency": "EUR", "value": "0.00" },
            "sequenceType": "recurring",
            "customerId": "cst_8wmqcHMN4U",
            "mandateId": "mdt_pWUnw6pkBN",
            "paidAt": "2026-10-24T10:00:00+00:00",
            "method": "ideal",
            "metadata": { "tenant_id": "t1", "invoice_id": "i1" }
        });
        let payment = payment_from_json(&document);
        assert_eq!(payment.id, "tr_7UhSN1zuXS");
        assert_eq!(payment.status, "paid");
        assert_eq!(payment.amount, Some(Money::new("EUR", 1234)));
        assert_eq!(payment.sequence_type.as_deref(), Some("recurring"));
        assert_eq!(payment.customer_id.as_deref(), Some("cst_8wmqcHMN4U"));
        assert_eq!(payment.mandate_id.as_deref(), Some("mdt_pWUnw6pkBN"));
        assert_eq!(
            payment.metadata.get("tenant_id").and_then(|v| v.as_str()),
            Some("t1")
        );
        assert_eq!(payment.raw["id"], "tr_7UhSN1zuXS");
    }

    #[test]
    fn payment_link_reads_the_checkout_href() {
        let document = serde_json::json!({
            "id": "tr_7UhSN1zuXS",
            "status": "open",
            "_links": { "checkout": { "href": "https://www.mollie.com/checkout/select-method/7UhSN1zuXS" } }
        });
        let link = payment_link_from_json(document);
        assert_eq!(link.id, "tr_7UhSN1zuXS");
        assert_eq!(link.status, "open");
        assert_eq!(
            link.checkout_url.as_deref(),
            Some("https://www.mollie.com/checkout/select-method/7UhSN1zuXS")
        );
    }

    #[test]
    fn refund_document_maps_id_and_amount() {
        let document = serde_json::json!({
            "id": "re_4qqhO89gsT",
            "status": "pending",
            "amount": { "currency": "EUR", "value": "5.00" }
        });
        let refund = refund_from_json("tr_7UhSN1zuXS", &document);
        assert_eq!(refund.id, "re_4qqhO89gsT");
        assert_eq!(refund.payment_id, "tr_7UhSN1zuXS");
        assert_eq!(refund.status, "pending");
        assert_eq!(refund.amount, Some(Money::new("EUR", 500)));
    }

    #[test]
    fn base_url_joining_never_doubles_slashes() {
        let client = MollieClient::for_tests("http://127.0.0.1:1/v2/".into());
        assert_eq!(client.url("payments"), "http://127.0.0.1:1/v2/payments");
        assert_eq!(
            client.url("/payments/tr_1"),
            "http://127.0.0.1:1/v2/payments/tr_1"
        );
    }

    #[test]
    fn truncation_never_splits_a_code_point() {
        let text = "żółć".repeat(200);
        let truncated = truncate(&text, 5);
        assert!(truncated.is_char_boundary(truncated.len() - '…'.len_utf8()));
    }
}
