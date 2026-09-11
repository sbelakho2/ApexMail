//! Enrichment as a provider waterfall with per-field provenance.
//!
//! # Why a waterfall
//!
//! The previous implementation held exactly one [`EnrichmentProvider`] and
//! flattened its answer straight into a `Company`. That made three audit
//! problems structural rather than fixable in a handler:
//!
//! 1. no fallback — when the one provider failed, enrichment failed;
//! 2. no provenance — a field's origin provider was lost the moment it was
//!    written to `enriched_companies`;
//! 3. no cost control — every lookup used the same provider regardless of
//!    observed fill rate or price.
//!
//! This module replaces it with an ordered waterfall:
//!
//! ```text
//! provider 1 → fields still missing → provider 2 → … → internal research
//! ```
//!
//! Rules the implementation guarantees:
//!
//! * A field filled by a higher-priority provider is never requested from a
//!   lower-priority one (fields are assigned to exactly one provider before
//!   any call is made).
//! * Provider calls that do not depend on each other run concurrently
//!   (`futures::future::join_all`).
//! * Every fact keeps its provenance in [`EnrichedFact`] and is persisted to
//!   `sales_enrichment_facts` (migration
//!   `200_sales_autopilot_v2_unification.sql:336-354`). The flat
//!   `enriched_companies` row is only a convenience projection derived from
//!   the facts.
//! * A provider failure is recorded in `sales_provider_stats`, never aborts
//!   the run: remaining providers still fill their fields and the outcome
//!   reports partial coverage.
//!
//! Provider selection is delegated to [`router`] (cost-aware, §10).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Company, SalesError};

pub mod providers;
pub mod router;

pub use providers::{HttpEnrichmentProvider, MockEnrichmentProvider, ResearchEnrichmentProvider};

// ---------------------------------------------------------------------------
// Field inventory — the single place field names are declared.
// ---------------------------------------------------------------------------

/// Canonical field names produced by enrichment providers.
///
/// Every provider declares a subset of these, every fact is keyed by one of
/// these, and `sales_enrichment_facts.field` stores exactly these strings.
pub mod fields {
    // Company firmographics.
    pub const COMPANY_NAME: &str = "company_name";
    pub const DOMAIN: &str = "domain";
    pub const INDUSTRY: &str = "industry";
    pub const EMPLOYEE_COUNT: &str = "employee_count";
    pub const REVENUE_BAND: &str = "revenue_band";
    pub const FUNDING_STAGE: &str = "funding_stage";
    pub const HEADQUARTERS: &str = "headquarters";
    pub const FOUNDED_YEAR: &str = "founded_year";
    pub const DESCRIPTION: &str = "description";
    pub const LINKEDIN_URL: &str = "linkedin_url";

    // Tech stack and current ESP evidence.
    pub const TECHNOLOGIES: &str = "technologies";
    /// Current email service provider observed for the account (ESP evidence,
    /// never asserted as an eternal fact — it carries an expiry).
    pub const EMAIL_PROVIDER: &str = "email_provider";

    // People and deliverability.
    pub const CONTACT_FULL_NAME: &str = "contact_full_name";
    pub const CONTACT_JOB_TITLE: &str = "contact_job_title";
    /// A provider observed/verified that the named person currently holds the
    /// role at the account.
    pub const CONTACT_PERSON_VERIFIED: &str = "contact_person_verified";
    pub const EMAIL_VERIFIED: &str = "email_verified";
    pub const EMAIL_STATUS: &str = "email_status";

    // Language / location.
    pub const LANGUAGE: &str = "language";
    pub const LOCATION_COUNTRY: &str = "location_country";
    pub const LOCATION_CITY: &str = "location_city";
    pub const TIMEZONE: &str = "timezone";

    // Change signals.
    pub const FUNDING_SIGNAL: &str = "funding_signal";
    pub const CHANGE_SIGNAL: &str = "change_signal";

    /// Every field this module knows about, for documentation and tests.
    pub const ALL: &[&str] = &[
        COMPANY_NAME,
        DOMAIN,
        INDUSTRY,
        EMPLOYEE_COUNT,
        REVENUE_BAND,
        FUNDING_STAGE,
        HEADQUARTERS,
        FOUNDED_YEAR,
        DESCRIPTION,
        LINKEDIN_URL,
        TECHNOLOGIES,
        EMAIL_PROVIDER,
        CONTACT_FULL_NAME,
        CONTACT_JOB_TITLE,
        CONTACT_PERSON_VERIFIED,
        EMAIL_VERIFIED,
        EMAIL_STATUS,
        LANGUAGE,
        LOCATION_COUNTRY,
        LOCATION_CITY,
        TIMEZONE,
        FUNDING_SIGNAL,
        CHANGE_SIGNAL,
    ];
}

/// Default freshness (in days) for a field when a provider does not override
/// [`EnrichmentProvider::ttl_days`].
///
/// Fast-moving observations (signals, deliverability) expire quickly;
/// firmographics live longer. The task intentionally forces every fact to
/// carry an explicit expiry rather than pretending any observation is eternal.
pub fn default_ttl_days(field: &str) -> Option<i64> {
    match field {
        fields::FUNDING_SIGNAL | fields::CHANGE_SIGNAL => Some(7),
        fields::EMAIL_VERIFIED | fields::EMAIL_STATUS | fields::EMAIL_PROVIDER => Some(30),
        fields::TECHNOLOGIES | fields::CONTACT_PERSON_VERIFIED => Some(90),
        fields::EMPLOYEE_COUNT | fields::REVENUE_BAND | fields::FUNDING_STAGE => Some(180),
        fields::COMPANY_NAME
        | fields::DOMAIN
        | fields::INDUSTRY
        | fields::HEADQUARTERS
        | fields::FOUNDED_YEAR
        | fields::DESCRIPTION
        | fields::LINKEDIN_URL
        | fields::LANGUAGE
        | fields::LOCATION_COUNTRY
        | fields::LOCATION_CITY
        | fields::TIMEZONE
        | fields::CONTACT_FULL_NAME
        | fields::CONTACT_JOB_TITLE => Some(365),
        _ => Some(90),
    }
}

/// Minimum confidence ever persisted for a supplied fact. A provider that
/// supplies a value has, by definition, *some* evidence; storing 0 would make
/// the confidence column indistinguishable from "no fact".
pub const MIN_FACT_CONFIDENCE: f32 = 0.01;

/// Maximum number of fields requested from one waterfall run; protects the
/// database and the provider calls from a malformed request.
pub const MAX_REQUESTED_FIELDS: usize = 64;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Stable identifier of an enrichment provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(pub &'static str);

impl ProviderId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A single enriched field together with its provenance.
///
/// This is the unit of truth: it is what `sales_enrichment_facts` stores.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrichedFact<T> {
    pub value: T,
    pub provider: ProviderId,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// `sales_evidence.id` row that grounds this fact.
    pub evidence_id: Uuid,
}

/// A named fact ready for persistence (field name + provenance + the source
/// kind and cost needed by `sales_evidence` / `sales_provider_stats`).
#[derive(Debug, Clone)]
pub struct NamedFact {
    pub field: String,
    pub fact: EnrichedFact<Value>,
    /// `sales_evidence.source_kind` value for this provider.
    pub source_kind: &'static str,
    /// Marginal cost charged for this field's lookup.
    pub cost_eur: f64,
}

/// What a provider returned for one lookup.
#[derive(Debug, Clone)]
pub struct RawFact {
    pub value: Value,
    pub confidence: f32,
}

impl RawFact {
    pub fn new(value: Value, confidence: f32) -> Self {
        Self { value, confidence }
    }
}

/// The provider's answer: a set of field → value observations.
#[derive(Debug, Clone, Default)]
pub struct ProviderPayload {
    pub facts: HashMap<String, RawFact>,
}

impl ProviderPayload {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, field: &str, value: Value, confidence: f32) {
        self.facts
            .insert(field.to_string(), RawFact::new(value, confidence));
    }

    pub fn with(mut self, field: &str, value: Value, confidence: f32) -> Self {
        self.insert(field, value, confidence);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }
}

/// Errors a provider may return. Mapped to [`SalesError`] only when the whole
/// waterfall has nothing to report.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EnrichmentError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("provider rate limited: {0}")]
    RateLimited(String),
    #[error("provider had no data: {0}")]
    NotFound(String),
    #[error("provider rejected input: {0}")]
    InvalidInput(String),
    #[error("provider failed: {0}")]
    Other(String),
}

impl From<EnrichmentError> for SalesError {
    fn from(error: EnrichmentError) -> Self {
        match error {
            EnrichmentError::InvalidInput(message) => SalesError::InvalidInput(message),
            EnrichmentError::RateLimited(message) => SalesError::RateLimited(message),
            other => SalesError::EnrichmentFailed(other.to_string()),
        }
    }
}

/// Input to one waterfall run.
#[derive(Debug, Clone)]
pub struct EnrichmentRequest<'a> {
    pub tenant_id: &'a str,
    /// Company domain (required; email-only callers extract it first).
    pub domain: &'a str,
    /// Contact email, when the caller has one (enables person/email fields).
    pub email: Option<&'a str>,
    /// Known company name, when already available.
    pub company_name: Option<&'a str>,
    /// Fields to attempt. Empty = every field declared by the providers.
    pub requested_fields: Vec<String>,
}

impl<'a> EnrichmentRequest<'a> {
    pub fn new(tenant_id: &'a str, domain: &'a str) -> Self {
        Self {
            tenant_id,
            domain,
            email: None,
            company_name: None,
            requested_fields: Vec::new(),
        }
    }

    pub fn with_email(mut self, email: &'a str) -> Self {
        self.email = Some(email);
        self
    }

    pub fn with_company_name(mut self, company_name: &'a str) -> Self {
        self.company_name = Some(company_name);
        self
    }

    pub fn with_fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requested_fields = fields.into_iter().map(Into::into).collect();
        self
    }
}

/// Subject the facts are attached to (mirrors the CHECK constraint in
/// `sales_enrichment_facts.subject_type`,
/// `200_sales_autopilot_v2_unification.sql:339`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    Account,
    Contact,
    ContactPoint,
}

impl SubjectType {
    pub const fn as_str(self) -> &'static str {
        match self {
            SubjectType::Account => "account",
            SubjectType::Contact => "contact",
            SubjectType::ContactPoint => "contact_point",
        }
    }
}

/// One provider that failed during the waterfall. The run still completes.
#[derive(Debug, Clone)]
pub struct ProviderFailure {
    pub provider: ProviderId,
    pub error: String,
    /// Fields this provider was supposed to attempt.
    pub fields: Vec<String>,
}

/// Result of a waterfall run.
#[derive(Debug, Clone)]
pub struct EnrichmentOutcome {
    pub facts: Vec<NamedFact>,
    pub requested_fields: Vec<String>,
    pub missing_fields: Vec<String>,
    pub provider_failures: Vec<ProviderFailure>,
    pub provider_calls: usize,
}

impl EnrichmentOutcome {
    /// Look up a fact by field name.
    pub fn fact(&self, field: &str) -> Option<&NamedFact> {
        self.facts.iter().find(|fact| fact.field == field)
    }

    /// `filled / requested`, in `[0, 1]` (1.0 when nothing was requested).
    pub fn coverage_ratio(&self) -> f64 {
        if self.requested_fields.is_empty() {
            return 1.0;
        }
        self.facts.len() as f64 / self.requested_fields.len() as f64
    }

    /// True when at least one provider failed or at least one requested field
    /// could not be filled.
    pub fn is_partial(&self) -> bool {
        !self.missing_fields.is_empty() || !self.provider_failures.is_empty()
    }
}

/// Outcome of an enrichment that was written through to the database.
#[derive(Debug, Clone)]
pub struct PersistedEnrichment {
    pub company: Company,
    pub outcome: EnrichmentOutcome,
    pub account_id: Uuid,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// One source in the enrichment waterfall.
///
/// Implementations must be cheap to call concurrently (they are invoked from
/// `futures::future::join_all`).
#[async_trait::async_trait]
pub trait EnrichmentProvider: Send + Sync + std::fmt::Debug {
    fn id(&self) -> ProviderId;

    /// Fields this provider can supply (e.g. `"employee_count"`,
    /// `"industry"`, `"email_provider"`). Declare only fields you may return.
    fn fields(&self) -> &[&'static str];

    /// Cost in EUR per successful lookup, for routing decisions.
    fn cost_eur(&self) -> f64;

    async fn fetch(
        &self,
        request: &EnrichmentRequest<'_>,
    ) -> Result<ProviderPayload, EnrichmentError>;

    /// `sales_evidence.source_kind` recorded for this provider's facts.
    /// Defaults to `provider_api`; first-party heuristics override it.
    fn source_kind(&self) -> &'static str {
        "provider_api"
    }

    /// Freshness of a field supplied by this provider. Defaults to
    /// [`default_ttl_days`].
    fn ttl_days(&self, field: &str) -> Option<i64> {
        default_ttl_days(field)
    }
}

// ---------------------------------------------------------------------------
// Retry helper (kept from the single-provider implementation)
// ---------------------------------------------------------------------------

/// Maximum number of retry attempts for enrichment API calls.
const MAX_RETRIES: u32 = 3;
/// Initial backoff delay (doubles each retry).
const INITIAL_BACKOFF_MS: u64 = 200;

/// Execute a fallible async operation with exponential backoff retry.
/// Returns `Ok(value)` on success, or the last error after exhausting retries.
pub async fn with_retry<F, Fut, T, E>(f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = Duration::from_millis(INITIAL_BACKOFF_MS);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if attempt >= MAX_RETRIES {
                    return Err(e);
                }
                tracing::debug!(
                    attempt,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    backoff_ms = delay.as_millis(),
                    "enrichment API call failed, retrying"
                );
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EnrichmentService
// ---------------------------------------------------------------------------

/// Company enrichment service: an ordered provider waterfall.
///
/// Backwards compatible with the single-provider API used across the
/// workspace: [`EnrichmentService::new`] wraps one provider,
/// [`EnrichmentService::mock`] builds the deterministic mock waterfall, and
/// `enrich_company` / `enrich_lead` / `batch_enrich` keep returning a
/// [`Company`] projection so existing callers (the CP reads
/// `enriched_companies`) keep working.
#[derive(Debug, Clone)]
pub struct EnrichmentService {
    /// Providers in priority order; index 0 wins ties.
    providers: Vec<Arc<dyn EnrichmentProvider>>,
}

impl EnrichmentService {
    /// Wrap a single provider as a one-step waterfall.
    pub fn new(provider: Arc<dyn EnrichmentProvider>) -> Self {
        Self {
            providers: vec![provider],
        }
    }

    /// Build the waterfall from an ordered provider list.
    pub fn from_providers(providers: Vec<Arc<dyn EnrichmentProvider>>) -> Self {
        Self { providers }
    }

    /// Convenience constructor for tests: the deterministic mock provider
    /// followed by internal research, matching the historical mock output.
    pub fn mock() -> Self {
        Self::from_providers(vec![
            Arc::new(MockEnrichmentProvider),
            Arc::new(ResearchEnrichmentProvider::new()),
        ])
    }

    /// Number of providers in the waterfall.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Extract the domain portion from an email address.
    /// Returns `None` if the address is malformed.
    pub fn extract_domain(email: &str) -> Option<String> {
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        if parts.len() == 2 && !parts[1].is_empty() {
            Some(parts[1].to_lowercase())
        } else {
            None
        }
    }

    /// Enrich a lead by email – extracts the domain and delegates to
    /// [`enrich_company`](Self::enrich_company).
    pub async fn enrich_lead(&self, email: &str) -> Result<Company, SalesError> {
        let domain = Self::extract_domain(email)
            .ok_or_else(|| SalesError::InvalidInput(format!("bad email: {email}")))?;
        self.enrich_company(&domain).await
    }

    /// Look up company data for a domain through the waterfall, returning the
    /// legacy [`Company`] projection. No database writes.
    pub async fn enrich_company(&self, domain: &str) -> Result<Company, SalesError> {
        let request = EnrichmentRequest::new("", domain);
        let outcome = self.run_waterfall(&request).await;
        self.project_company(domain, &outcome)
    }

    /// Enrich multiple emails in batch (convenience wrapper).
    pub async fn batch_enrich(&self, emails: &[String]) -> Vec<Result<Company, SalesError>> {
        let mut results = Vec::with_capacity(emails.len());
        for email in emails {
            results.push(self.enrich_lead(email).await);
        }
        results
    }

    /// Run the waterfall without routing statistics (priority order).
    pub async fn run_waterfall(&self, request: &EnrichmentRequest<'_>) -> EnrichmentOutcome {
        self.execute_waterfall(request, None).await
    }

    /// Run the waterfall with cost-aware routing and `sales_provider_stats`
    /// recording. Facts are not persisted here — call
    /// [`enrich_persisted`](Self::enrich_persisted) for the full durable path.
    pub async fn run_waterfall_routed(
        &self,
        db: &PgPool,
        request: &EnrichmentRequest<'_>,
    ) -> EnrichmentOutcome {
        self.execute_waterfall(request, Some(db)).await
    }

    /// Full durable enrichment path used by `POST /enrich`:
    ///
    /// 1. resolve (find-or-create) the `sales_accounts` row for the domain;
    /// 2. run the routed waterfall;
    /// 3. persist one `sales_evidence` row per fact and upsert the fact into
    ///    `sales_enrichment_facts` (provenance preserved);
    /// 4. refresh the `enriched_companies` convenience projection from the
    ///    facts (non-fatal).
    pub async fn enrich_persisted(
        &self,
        db: &PgPool,
        tenant_id: &str,
        domain: &str,
        email: Option<&str>,
        company_name: Option<&str>,
    ) -> Result<PersistedEnrichment, SalesError> {
        let domain = normalize_domain(domain)
            .ok_or_else(|| SalesError::InvalidInput(format!("invalid domain: {domain:?}")))?;

        let mut request = EnrichmentRequest::new(tenant_id, &domain);
        request.email = email;
        request.company_name = company_name;

        let outcome = self.run_waterfall_routed(db, &request).await;
        if outcome.facts.is_empty() {
            return Err(SalesError::EnrichmentFailed(no_data_reason(&outcome)));
        }

        let account_id = find_or_create_account(db, tenant_id, &domain, company_name).await?;
        persist_facts(db, tenant_id, account_id, &outcome).await?;

        let company = self.project_company(&domain, &outcome)?;
        // Convenience projection derived from the facts. A failure here must
        // not lose the facts, which are already persisted.
        if let Err(error) = project_enriched_company(db, tenant_id, &company, &outcome).await {
            tracing::warn!(
                tenant_id = %tenant_id,
                domain = %domain,
                error = %error,
                "failed to refresh enriched_companies projection (non-fatal)"
            );
        }

        Ok(PersistedEnrichment {
            company,
            outcome,
            account_id,
        })
    }

    // -- internals ----------------------------------------------------------

    /// Union of the fields declared by the providers (priority order).
    fn requested_fields(&self, request: &EnrichmentRequest<'_>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if !request.requested_fields.is_empty() {
            for field in &request.requested_fields {
                let field = field.trim();
                if !field.is_empty()
                    && field.len() <= 64
                    && !out.iter().any(|existing| existing == field)
                    && out.len() < MAX_REQUESTED_FIELDS
                {
                    out.push(field.to_string());
                }
            }
            return out;
        }
        for provider in &self.providers {
            for field in provider.fields() {
                if !out.iter().any(|existing| existing == field) {
                    out.push((*field).to_string());
                }
            }
        }
        out.truncate(MAX_REQUESTED_FIELDS);
        out
    }

    async fn execute_waterfall(
        &self,
        request: &EnrichmentRequest<'_>,
        db: Option<&PgPool>,
    ) -> EnrichmentOutcome {
        let requested = self.requested_fields(request);

        // Phase 1 — assign each field to exactly one provider. This is what
        // guarantees a field filled by a higher-priority provider is never
        // requested from a lower one: a provider is only called when it owns
        // at least one still-missing field.
        let mut assigned: Vec<Vec<String>> = vec![Vec::new(); self.providers.len()];
        for field in &requested {
            let declaring: Vec<usize> = self
                .providers
                .iter()
                .enumerate()
                .filter(|(_, provider)| provider.fields().iter().any(|f| *f == field.as_str()))
                .map(|(index, _)| index)
                .collect();
            if declaring.is_empty() {
                continue;
            }
            let chosen = if let Some(db) = db {
                let candidates: Vec<&dyn EnrichmentProvider> = declaring
                    .iter()
                    .map(|index| self.providers[*index].as_ref())
                    .collect();
                match router::choose_provider(db, request.tenant_id, field, &candidates).await {
                    Ok(Some(choice)) => declaring
                        .iter()
                        .copied()
                        .find(|index| self.providers[*index].id() == choice.provider)
                        .unwrap_or(declaring[0]),
                    Ok(None) => declaring[0],
                    Err(error) => {
                        // Routing statistics are an optimisation, never a
                        // correctness dependency: degrade to priority order.
                        tracing::warn!(
                            field = %field,
                            error = %error,
                            "provider routing failed — falling back to waterfall priority order"
                        );
                        declaring[0]
                    }
                }
            } else {
                declaring[0]
            };
            assigned[chosen].push(field.clone());
        }

        // Phase 2 — call every selected provider concurrently. Calls are
        // independent: each one is responsible for a disjoint field set.
        let calls =
            self.providers
                .iter()
                .zip(assigned.iter())
                .filter_map(|(provider, owned_fields)| {
                    if owned_fields.is_empty() {
                        return None;
                    }
                    let provider = provider.clone();
                    let owned_fields = owned_fields.clone();
                    Some(async move {
                        let started = std::time::Instant::now();
                        let result = provider.fetch(request).await;
                        let latency_ms = started.elapsed().as_millis() as i64;
                        (provider, owned_fields, result, latency_ms)
                    })
                });
        let results = futures::future::join_all(calls).await;

        // Phase 3 — apply results (concurrent completion order is irrelevant:
        // each field has exactly one owner).
        let mut facts: Vec<NamedFact> = Vec::new();
        let mut missing: Vec<String> = requested.clone();
        let mut provider_failures: Vec<ProviderFailure> = Vec::new();
        let mut provider_calls = 0usize;

        for (provider, owned_fields, result, latency_ms) in results {
            provider_calls += 1;
            let provider_id = provider.id();
            match result {
                Ok(payload) => {
                    if let Some(db) = db {
                        for field in &owned_fields {
                            record_stat(
                                router::record_attempt(db, request.tenant_id, provider_id, field)
                                    .await,
                            );
                        }
                    }
                    let mut filled: Vec<String> = Vec::new();
                    for field in &owned_fields {
                        if facts.iter().any(|fact| fact.field == *field) {
                            continue;
                        }
                        let Some(raw) = payload.facts.get(field.as_str()) else {
                            continue;
                        };
                        let observed_at = Utc::now();
                        let confidence = normalize_confidence(raw.confidence);
                        let expires_at = provider
                            .ttl_days(field)
                            .map(|days| observed_at + ChronoDuration::days(days));
                        facts.push(NamedFact {
                            field: field.clone(),
                            fact: EnrichedFact {
                                value: raw.value.clone(),
                                provider: provider_id,
                                confidence,
                                observed_at,
                                expires_at,
                                evidence_id: Uuid::new_v4(),
                            },
                            source_kind: provider.source_kind(),
                            cost_eur: provider.cost_eur(),
                        });
                        missing.retain(|candidate| candidate != field);
                        filled.push(field.clone());
                    }
                    if let Some(db) = db {
                        for field in &filled {
                            record_stat(
                                router::record_fill(db, request.tenant_id, provider_id, field)
                                    .await,
                            );
                            if provider.cost_eur() > 0.0 {
                                record_stat(
                                    router::record_cost(
                                        db,
                                        request.tenant_id,
                                        provider_id,
                                        field,
                                        provider.cost_eur(),
                                    )
                                    .await,
                                );
                            }
                            record_stat(
                                router::record_latency(
                                    db,
                                    request.tenant_id,
                                    provider_id,
                                    field,
                                    latency_ms,
                                )
                                .await,
                            );
                        }
                    }
                }
                Err(error) => {
                    if let Some(db) = db {
                        for field in &owned_fields {
                            record_stat(
                                router::record_attempt(db, request.tenant_id, provider_id, field)
                                    .await,
                            );
                            record_stat(
                                router::record_error(db, request.tenant_id, provider_id, field)
                                    .await,
                            );
                        }
                    }
                    provider_failures.push(ProviderFailure {
                        provider: provider_id,
                        error: error.to_string(),
                        fields: owned_fields,
                    });
                }
            }
        }

        facts.sort_by(|a, b| a.field.cmp(&b.field));
        EnrichmentOutcome {
            facts,
            requested_fields: requested,
            missing_fields: missing,
            provider_failures,
            provider_calls,
        }
    }

    /// Project the facts into the legacy flat [`Company`] shape.
    fn project_company(
        &self,
        domain: &str,
        outcome: &EnrichmentOutcome,
    ) -> Result<Company, SalesError> {
        if outcome.facts.is_empty() {
            return Err(SalesError::EnrichmentFailed(no_data_reason(outcome)));
        }
        let string_fact = |field: &str| -> Option<String> {
            outcome
                .fact(field)
                .and_then(|fact| fact.fact.value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let name = string_fact(fields::COMPANY_NAME)
            .unwrap_or_else(|| capitalize(domain.split('.').next().unwrap_or(domain)));
        let industry = string_fact(fields::INDUSTRY).unwrap_or_else(|| "Unknown".to_string());
        let size = string_fact(fields::EMPLOYEE_COUNT).unwrap_or_else(|| "Unknown".to_string());
        let revenue_range =
            string_fact(fields::REVENUE_BAND).unwrap_or_else(|| "Unknown".to_string());

        Ok(Company {
            id: Uuid::new_v4(),
            name,
            domain: domain.to_owned(),
            industry,
            size,
            revenue_range,
            enriched_at: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

/// Normalize and minimally validate a domain before using it as a subject
/// key. Returns `None` for empty/oversized/hostile input.
pub(crate) fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(trimmed)
}

fn normalize_confidence(raw: f32) -> f32 {
    if !raw.is_finite() || raw <= 0.0 {
        MIN_FACT_CONFIDENCE
    } else {
        raw.clamp(MIN_FACT_CONFIDENCE, 1.0)
    }
}

fn record_stat(result: Result<(), SalesError>) {
    if let Err(error) = result {
        tracing::warn!(error = %error, "failed to record provider statistics (non-fatal)");
    }
}

fn no_data_reason(outcome: &EnrichmentOutcome) -> String {
    if outcome.provider_failures.is_empty() {
        "no provider supplied any requested field".to_string()
    } else {
        let failed: Vec<String> = outcome
            .provider_failures
            .iter()
            .map(|failure| format!("{}: {}", failure.provider, failure.error))
            .collect();
        format!("all providers failed: {}", failed.join("; "))
    }
}

/// Find the `sales_accounts` row for `(tenant_id, domain)` or create it.
///
/// `ON CONFLICT … DO UPDATE SET updated_at = NOW()` makes this idempotent and
/// never clobbers an existing canonical account.
async fn find_or_create_account(
    db: &PgPool,
    tenant_id: &str,
    domain: &str,
    company_name: Option<&str>,
) -> Result<Uuid, SalesError> {
    let company = company_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(domain);
    let id = Uuid::new_v4();
    let account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_accounts (id, tenant_id, company, domain, lifecycle, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'discovered', NOW(), NOW())
         ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()
         RETURNING id",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(company)
    .bind(domain)
    .fetch_one(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(account_id)
}

/// Persist evidence + facts for a completed waterfall run.
async fn persist_facts(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    outcome: &EnrichmentOutcome,
) -> Result<(), SalesError> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    for named in &outcome.facts {
        let proposition = format!(
            "{} = {}",
            named.field,
            truncate_chars(&compact_json(&named.fact.value), 400)
        );
        sqlx::query(
            "INSERT INTO sales_evidence (
                id, tenant_id, account_id, contact_id, proposition, confidence,
                source_kind, source_ref, source_hash, observed_at, expires_at
             ) VALUES ($1, $2, $3, NULL, $4, $5, $6, $7, NULL, $8, $9)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(named.fact.evidence_id)
        .bind(tenant_id)
        .bind(account_id)
        .bind(&proposition)
        .bind(f64::from(named.fact.confidence))
        .bind(named.source_kind)
        .bind(named.fact.provider.as_str())
        .bind(named.fact.observed_at)
        .bind(named.fact.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        sqlx::query(
            "INSERT INTO sales_enrichment_facts (
                id, tenant_id, subject_type, subject_id, field, value, provider,
                confidence, observed_at, expires_at, evidence_id, cost_eur, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::float8::numeric, NOW())
             ON CONFLICT (tenant_id, subject_type, subject_id, field, provider) DO UPDATE SET
                value = EXCLUDED.value,
                confidence = EXCLUDED.confidence,
                observed_at = EXCLUDED.observed_at,
                expires_at = EXCLUDED.expires_at,
                evidence_id = EXCLUDED.evidence_id,
                cost_eur = EXCLUDED.cost_eur",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(SubjectType::Account.as_str())
        .bind(account_id)
        .bind(&named.field)
        .bind(&named.fact.value)
        .bind(named.fact.provider.as_str())
        .bind(f64::from(named.fact.confidence))
        .bind(named.fact.observed_at)
        .bind(named.fact.expires_at)
        .bind(named.fact.evidence_id)
        .bind(named.cost_eur.max(0.0))
        .execute(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Refresh the legacy flat projection from the facts.
async fn project_enriched_company(
    db: &PgPool,
    tenant_id: &str,
    company: &Company,
    outcome: &EnrichmentOutcome,
) -> Result<(), SalesError> {
    let confidence = outcome
        .facts
        .iter()
        .map(|fact| f64::from(fact.fact.confidence))
        .fold(0.0_f64, f64::max);
    sqlx::query(
        "INSERT INTO enriched_companies (
            id, tenant_id, domain, company_name, industry, employee_count,
            annual_revenue, confidence_score, last_enriched_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)
         ON CONFLICT (tenant_id, domain) DO UPDATE SET
            company_name = EXCLUDED.company_name,
            industry = EXCLUDED.industry,
            employee_count = EXCLUDED.employee_count,
            annual_revenue = EXCLUDED.annual_revenue,
            confidence_score = EXCLUDED.confidence_score,
            last_enriched_at = EXCLUDED.last_enriched_at,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(company.id)
    .bind(tenant_id)
    .bind(&company.domain)
    .bind(&company.name)
    .bind(&company.industry)
    .bind(&company.size)
    .bind(&company.revenue_range)
    .bind(confidence)
    .bind(company.enriched_at)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string())
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max_chars).collect();
    out.push('…');
    out
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Counting provider double: returns a fixed payload, counts calls.
    #[derive(Debug)]
    struct CountingProvider {
        id: ProviderId,
        fields: Vec<&'static str>,
        payload: ProviderPayload,
        cost: f64,
        calls: Arc<AtomicUsize>,
        error: Option<String>,
    }

    impl CountingProvider {
        fn new(
            id: &'static str,
            fields: Vec<&'static str>,
            payload: ProviderPayload,
            cost: f64,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                id: ProviderId(id),
                fields,
                payload,
                cost,
                calls,
                error: None,
            }
        }

        fn failing(id: &'static str, fields: Vec<&'static str>, calls: Arc<AtomicUsize>) -> Self {
            Self {
                id: ProviderId(id),
                fields,
                payload: ProviderPayload::new(),
                cost: 0.0,
                calls,
                error: Some("upstream 500".into()),
            }
        }
    }

    #[async_trait::async_trait]
    impl EnrichmentProvider for CountingProvider {
        fn id(&self) -> ProviderId {
            self.id
        }

        fn fields(&self) -> &[&'static str] {
            &self.fields
        }

        fn cost_eur(&self) -> f64 {
            self.cost
        }

        async fn fetch(
            &self,
            _request: &EnrichmentRequest<'_>,
        ) -> Result<ProviderPayload, EnrichmentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.error {
                Some(error) => Err(EnrichmentError::Unavailable(error.clone())),
                None => Ok(self.payload.clone()),
            }
        }
    }

    fn payload(pairs: &[(&str, &str, f32)]) -> ProviderPayload {
        let mut payload = ProviderPayload::new();
        for (field, value, confidence) in pairs {
            payload.insert(field, Value::String((*value).into()), *confidence);
        }
        payload
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            EnrichmentService::extract_domain("alice@acme.com"),
            Some("acme.com".into())
        );
        assert_eq!(
            EnrichmentService::extract_domain("BOB@Beta.IO"),
            Some("beta.io".into())
        );
        assert_eq!(EnrichmentService::extract_domain("nodomain"), None);
        assert_eq!(EnrichmentService::extract_domain("@"), None);
        assert_eq!(EnrichmentService::extract_domain(""), None);
    }

    #[tokio::test]
    async fn test_enrich_known_domain() {
        let svc = EnrichmentService::mock();
        let company = svc.enrich_company("acme.com").await.unwrap();
        assert_eq!(company.name, "Acme Corp");
        assert_eq!(company.industry, "SaaS");
        assert_eq!(company.size, "50-200");
    }

    #[tokio::test]
    async fn test_enrich_unknown_and_batch() {
        let svc = EnrichmentService::mock();

        // unknown domain still succeeds with fallback
        let c = svc.enrich_company("startup.xyz").await.unwrap();
        assert!(c.name.contains("Startup"));
        assert_eq!(c.industry, "Unknown");

        // batch
        let results = svc
            .batch_enrich(&["a@acme.com".into(), "b@beta.io".into(), "bad-email".into()])
            .await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err()); // invalid email
    }

    /// Waterfall rule: a field already filled by provider 1 is never requested
    /// from provider 2 — and a provider with nothing left to do is not called
    /// at all.
    #[tokio::test]
    async fn waterfall_does_not_refetch_filled_fields() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let provider_a = CountingProvider::new(
            "provider_a",
            vec![fields::INDUSTRY, fields::EMPLOYEE_COUNT],
            payload(&[
                (fields::INDUSTRY, "SaaS", 0.9),
                (fields::EMPLOYEE_COUNT, "50-200", 0.9),
            ]),
            0.0,
            calls_a.clone(),
        );
        let provider_b = CountingProvider::new(
            "provider_b",
            vec![fields::INDUSTRY, fields::EMPLOYEE_COUNT],
            payload(&[("industry", "Wrong", 0.9)]),
            0.0,
            calls_b.clone(),
        );
        let service =
            EnrichmentService::from_providers(vec![Arc::new(provider_a), Arc::new(provider_b)]);

        let request = EnrichmentRequest::new("tenant-a", "acme.com");
        let outcome = service.run_waterfall(&request).await;

        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls_b.load(Ordering::SeqCst),
            0,
            "provider 2 must not be called when provider 1 already owns every field"
        );
        assert_eq!(outcome.fact(fields::INDUSTRY).unwrap().fact.value, "SaaS");
        assert!(outcome.missing_fields.is_empty());
    }

    /// A provider is still called for the missing fields it uniquely owns.
    #[tokio::test]
    async fn waterfall_calls_lower_provider_for_missing_fields_only() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let provider_a = CountingProvider::new(
            "provider_a",
            vec![fields::COMPANY_NAME],
            payload(&[(fields::COMPANY_NAME, "Acme Corp", 0.9)]),
            0.0,
            calls_a.clone(),
        );
        let provider_b = CountingProvider::new(
            "provider_b",
            vec![fields::COMPANY_NAME, fields::EMAIL_PROVIDER],
            payload(&[
                (fields::COMPANY_NAME, "SHOULD NOT WIN", 0.9),
                (fields::EMAIL_PROVIDER, "google", 0.7),
            ]),
            0.0,
            calls_b.clone(),
        );
        let service =
            EnrichmentService::from_providers(vec![Arc::new(provider_a), Arc::new(provider_b)]);

        let outcome = service
            .run_waterfall(&EnrichmentRequest::new("tenant-a", "acme.com"))
            .await;

        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 1, "provider 2 runs once");
        assert_eq!(
            outcome.fact(fields::COMPANY_NAME).unwrap().fact.value,
            "Acme Corp"
        );
        assert_eq!(
            outcome.fact(fields::EMAIL_PROVIDER).unwrap().fact.provider,
            ProviderId("provider_b")
        );
    }

    /// Provider 1 fails; provider 2 still fills its fields and the outcome
    /// reports partial coverage instead of failing the whole enrichment.
    #[tokio::test]
    async fn partial_failure_is_survivable() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let failing = CountingProvider::failing("flaky", vec![fields::COMPANY_NAME], calls_a);
        let healthy = CountingProvider::new(
            "healthy",
            vec![fields::INDUSTRY, fields::COMPANY_NAME],
            payload(&[(fields::INDUSTRY, "FinTech", 0.8)]),
            0.0,
            calls_b.clone(),
        );
        let service = EnrichmentService::from_providers(vec![Arc::new(failing), Arc::new(healthy)]);

        let outcome = service
            .run_waterfall(&EnrichmentRequest::new("tenant-a", "beta.io"))
            .await;

        assert!(outcome.is_partial());
        assert_eq!(outcome.provider_failures.len(), 1);
        assert_eq!(outcome.provider_failures[0].provider, ProviderId("flaky"));
        assert_eq!(
            outcome.fact(fields::INDUSTRY).unwrap().fact.provider,
            ProviderId("healthy")
        );
        assert!(outcome
            .missing_fields
            .contains(&fields::COMPANY_NAME.to_string()));
        assert_eq!(outcome.provider_calls, 2);
    }

    /// Provenance: the fact names the provider that actually supplied it.
    #[tokio::test]
    async fn provenance_is_preserved_per_field() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let provider_a = CountingProvider::new(
            "provider_a",
            vec![fields::INDUSTRY],
            payload(&[(fields::INDUSTRY, "SaaS", 0.9)]),
            0.0,
            calls_a,
        );
        let provider_b = CountingProvider::new(
            "provider_b",
            vec![fields::FUNDING_STAGE],
            payload(&[(fields::FUNDING_STAGE, "Series A", 0.6)]),
            0.0,
            calls_b,
        );
        let service =
            EnrichmentService::from_providers(vec![Arc::new(provider_a), Arc::new(provider_b)]);

        let outcome = service
            .run_waterfall(&EnrichmentRequest::new("tenant-a", "acme.com"))
            .await;

        let industry = outcome.fact(fields::INDUSTRY).unwrap();
        assert_eq!(industry.fact.provider, ProviderId("provider_a"));
        let funding = outcome.fact(fields::FUNDING_STAGE).unwrap();
        assert_eq!(
            funding.fact.provider,
            ProviderId("provider_b"),
            "field filled by provider 2 must be attributed to provider 2, not the waterfall"
        );
        assert!(funding.fact.confidence > 0.0);
        assert!(industry.fact.confidence > 0.0);
        assert!(
            industry.fact.expires_at.is_some(),
            "facts must carry an expiry"
        );
        assert_ne!(industry.fact.evidence_id, funding.fact.evidence_id);
    }

    /// A provider that answers with nothing still counts as an attempt but
    /// adds no facts, and the result is partial rather than an error.
    #[tokio::test]
    async fn empty_payload_is_partial_not_fatal() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider::new(
            "empty",
            vec![fields::INDUSTRY],
            ProviderPayload::new(),
            0.0,
            calls.clone(),
        );
        let service = EnrichmentService::from_providers(vec![Arc::new(provider)]);
        let outcome = service
            .run_waterfall(&EnrichmentRequest::new("tenant-a", "acme.com"))
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(outcome.is_partial());
        assert!(outcome.provider_failures.is_empty());
        assert!(outcome
            .missing_fields
            .contains(&fields::INDUSTRY.to_string()));
    }

    /// Provider calls for independent field sets happen concurrently: with two
    /// providers each sleeping 100 ms, the run takes well under 200 ms.
    #[tokio::test]
    async fn independent_provider_calls_run_concurrently() {
        #[derive(Debug)]
        struct SleepingProvider {
            id: ProviderId,
            field: &'static str,
        }

        #[async_trait::async_trait]
        impl EnrichmentProvider for SleepingProvider {
            fn id(&self) -> ProviderId {
                self.id
            }
            fn fields(&self) -> &[&'static str] {
                std::slice::from_ref(&self.field)
            }
            fn cost_eur(&self) -> f64 {
                0.0
            }
            async fn fetch(
                &self,
                _request: &EnrichmentRequest<'_>,
            ) -> Result<ProviderPayload, EnrichmentError> {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(ProviderPayload::new().with(self.field, Value::Bool(true), 0.5))
            }
        }

        let service = EnrichmentService::from_providers(vec![
            Arc::new(SleepingProvider {
                id: ProviderId("sleep_a"),
                field: fields::FUNDING_SIGNAL,
            }),
            Arc::new(SleepingProvider {
                id: ProviderId("sleep_b"),
                field: fields::CHANGE_SIGNAL,
            }),
        ]);
        let started = std::time::Instant::now();
        let outcome = service
            .run_waterfall(&EnrichmentRequest::new("tenant-a", "acme.com"))
            .await;
        let elapsed = started.elapsed();
        assert_eq!(outcome.facts.len(), 2);
        assert!(
            elapsed < Duration::from_millis(180),
            "independent provider calls must overlap, took {elapsed:?}"
        );
    }

    #[test]
    fn field_inventory_covers_required_categories() {
        // Company data, tech stack, people verification, email verification,
        // language/location, signals and ESP evidence must all be declared.
        for required in [
            fields::COMPANY_NAME,
            fields::DOMAIN,
            fields::INDUSTRY,
            fields::EMPLOYEE_COUNT,
            fields::REVENUE_BAND,
            fields::FUNDING_STAGE,
            fields::TECHNOLOGIES,
            fields::CONTACT_PERSON_VERIFIED,
            fields::EMAIL_VERIFIED,
            fields::LANGUAGE,
            fields::LOCATION_COUNTRY,
            fields::FUNDING_SIGNAL,
            fields::CHANGE_SIGNAL,
            fields::EMAIL_PROVIDER,
        ] {
            assert!(fields::ALL.contains(&required), "missing field {required}");
        }
    }

    #[test]
    fn confidence_floor_prevents_zero_confidence_facts() {
        assert_eq!(normalize_confidence(0.0), MIN_FACT_CONFIDENCE);
        assert_eq!(normalize_confidence(-1.0), MIN_FACT_CONFIDENCE);
        assert_eq!(normalize_confidence(f32::NAN), MIN_FACT_CONFIDENCE);
        assert_eq!(normalize_confidence(0.42), 0.42);
        assert_eq!(normalize_confidence(2.0), 1.0);
    }

    #[test]
    fn normalize_domain_rejects_hostile_input() {
        assert_eq!(normalize_domain("  Acme.COM. "), Some("acme.com".into()));
        assert_eq!(normalize_domain("acme.com/path"), None);
        assert_eq!(normalize_domain("a b.com"), None);
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain(&"x".repeat(300)), None);
    }
}
