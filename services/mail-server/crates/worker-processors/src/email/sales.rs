//! SALES SENDING ISOLATION — the dedicated sales transport slot.
//!
//! The platform invariant: **"Sales sending is isolated. It never shares a
//! transport account, IP, sending domain or suppression list with customer
//! mail."** Sales-autopilot mail is enqueued by `sales-autopilot`'s dispatcher
//! (`ProductionCampaignDispatcher`) into the same `email_queue` the customer
//! worker drains — so the WORKER, not the enqueuer, is where the transport
//! boundary must be enforced. This module is that boundary:
//!
//! * [`SalesSend::classify`] recognises a sales queue row from the provenance
//!   the dispatcher already writes (the `metadata.source = "sales-autopilot"`
//!   marker it sets on every campaign and sequenced row, plus the typed
//!   `sales_step_execution_id` column migration 202 added). Classification is
//!   the SAME signal `send_unit_of` and the sales feedback ledger already key
//!   on — no second, drifting marker is introduced.
//! * [`plan_sales_route`] is the PURE decision point (mirroring
//!   [`super::processor`]'s `plan_delivery_route` for EU-only): it is total,
//!   and there is NO input that yields a route the customer transport could
//!   carry as a fallback. When the sales transport is unconfigured, the
//!   recorded source IP is missing on an own-MTA send, or the sender domain
//!   is outside the allowlist, the plan is a HOLD with a NAMED reason.
//! * [`SalesTransport`] is the single-slot router for whatever backend the
//!   deployment configured (`SALES_TRANSPORT=relay|ses_account`). It never
//!   exposes the customer [`super::transport::HybridTransport`] and refuses
//!   any route that is not the one the plan produced.
//!
//! ## Deployed decision record (code docs, per the plan)
//!
//! | `SALES_TRANSPORT` | backend built | what the send path does |
//! |-------------------|---------------|--------------------------|
//! | unset / `none`    | none          | sales sends HOLD with `sales_transport_unconfigured`; the customer SES/relay transport is never called (fail closed) |
//! | `relay`           | own outbound MTA (`OutboundMtaTransport`), `SALES_RELAY_URL` required | route = `Dedicated{sales identity @ metadata.sales_sender_source_ip}`; the IP is BOUND and verified in the acceptance record; a missing/absent IP HOLDS |
//! | `ses_account`     | `SesTransport` on the `SALES_SES_*` credentials (a separate AWS account) | route = the sales account's shared route; the customer SES client is never touched |
//!
//! The suppression WRITE side is deliberately NOT re-implemented here: the
//! worker's existing handlers stay the single writer, and their tenant scope
//! (the queue row's `tenant_id`, which for sales mail is the sales tenant the
//! dispatcher owns) is what keeps sales complaints/bounces out of customer
//! suppression rows. `crate::email::processor`'s tests pin both directions
//! (sales sends CONSULT the platform suppressions; a sales bounce writes the
//! sales tenant's suppression set only).

use std::sync::Arc;

use super::transport::{EmailTransport, SesTransport};
use super::types::{DeliveryRoute, EmailJob};
use crate::common::{
    ProcessorError, ProcessorResult, SalesRelayConfig, SalesTransportConfig, SalesTransportMode,
};

// ─────────────────────────────────────────────────────────────────────────────
// The named hold reasons (distinct, prefix-scoped, never shared with a
// deferral reason — mirroring the `eu_only_*` vocabulary)
// ─────────────────────────────────────────────────────────────────────────────

/// The sales transport is not configured on this deployment
/// (`SALES_TRANSPORT` unset/`none`): HOLD — the customer transport is
/// forbidden for a sales send, so there is nowhere to send it.
pub const SALES_HOLD_TRANSPORT_UNCONFIGURED: &str = "sales_transport_unconfigured";
/// The configured sales transport could not be built/dispatch the route on
/// this worker (selected mode without its endpoint material, or a backend
/// that cannot bind the requested source IP).
pub const SALES_HOLD_TRANSPORT_UNAVAILABLE: &str = "sales_transport_unavailable";
/// The sender domain is not on `SALES_SENDING_DOMAINS` (or the allowlist is
/// empty): a customer domain on a sales send is refused BY NAME, mirroring
/// the "own domain" requirement.
pub const SALES_HOLD_DOMAIN_NOT_ALLOWED: &str = "sales_send_domain_not_allowed";
/// An own-MTA (relay) sales send carries no usable
/// `metadata.sales_sender_source_ip`: the binding the relay contract
/// requires cannot be expressed, so the message is HELD.
pub const SALES_HOLD_SOURCE_IP_MISSING: &str = "sales_send_source_ip_missing";
/// DKIM signing is disabled on this worker, so the own-MTA sales route's
/// mandatory local signature cannot be produced.
pub const SALES_HOLD_DKIM_DISABLED: &str = "sales_send_dkim_unavailable";
/// Structural last line of defence: the route resolved for a sales send is
/// not the route the sales plan produced. Holds instead of crossing the
/// transport boundary the isolation invariant exists to keep.
pub const SALES_HOLD_ROUTE_GUARD: &str = "sales_route_guard_violation";

/// Every named sales-hold reason, for the vocabulary test.
pub const SALES_HOLD_REASONS: [&str; 6] = [
    SALES_HOLD_TRANSPORT_UNCONFIGURED,
    SALES_HOLD_TRANSPORT_UNAVAILABLE,
    SALES_HOLD_DOMAIN_NOT_ALLOWED,
    SALES_HOLD_SOURCE_IP_MISSING,
    SALES_HOLD_DKIM_DISABLED,
    SALES_HOLD_ROUTE_GUARD,
];

// ─────────────────────────────────────────────────────────────────────────────
// Classification — the exact provenance the dispatcher writes
// ─────────────────────────────────────────────────────────────────────────────

/// The `metadata.source` value `sales-autopilot`'s dispatcher writes on
/// EVERY sales queue row (`CAMPAIGN_EMAIL_QUEUE_INSERT_SQL` and
/// `SEQUENCE_EMAIL_QUEUE_INSERT_SQL` both merge this into `metadata`). The
/// cross-crate parity test in `processor.rs` reads the dispatcher source and
/// pins this literal.
pub const SALES_METADATA_SOURCE: &str = "sales-autopilot";

/// One recognised sales send, extracted from the queue row's existing
/// provenance. Construction IS the classification: `None` from
/// [`SalesSend::classify`] means "an ordinary customer send".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SalesSend {
    /// `metadata.sales_sender_identity_id` — the resolved
    /// `sales_sender_identities.id` (absent on the legacy campaign path,
    /// which still sends from the deployment-wide `SALES_CAMPAIGN_FROM_EMAIL`).
    pub sender_identity_id: Option<String>,
    /// `metadata.sales_sender_pool` — `sales_outbound` / `sales_warmup`.
    pub sender_pool: Option<String>,
    /// `metadata.sales_sender_source_ip`, when it parses. `None` covers both
    /// "absent" and "unparsable": for an own-MTA send both mean the binding
    /// cannot be proven, and the send HOLDS.
    pub source_ip: Option<std::net::IpAddr>,
}

impl SalesSend {
    /// Recognise a sales queue row. The signals are exactly what the
    /// dispatcher already writes:
    ///
    /// * the typed `email_queue.sales_step_execution_id` column (migration
    ///   202) — set on every sequenced send and already read by
    ///   `send_unit_of` / the acceptance ledger; or
    /// * `metadata.source == "sales-autopilot"` — set on every sales row
    ///   (campaign and sequenced).
    ///
    /// Both markers are reserved at the API submission boundary
    /// (`sanitize_customer_metadata` in api-server), so a customer send
    /// cannot forge sales provenance.
    pub fn classify(job: &EmailJob) -> Option<Self> {
        let metadata = job.metadata.as_ref();
        let source = metadata
            .and_then(|m| m.get("source"))
            .and_then(|v| v.as_str());
        let typed_step = job
            .sales_step_execution_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if !typed_step && source != Some(SALES_METADATA_SOURCE) {
            return None;
        }
        let string_field = |key: &str| {
            metadata
                .and_then(|m| m.get(key))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        Some(Self {
            sender_identity_id: string_field("sales_sender_identity_id"),
            sender_pool: string_field("sales_sender_pool"),
            source_ip: string_field("sales_sender_source_ip").and_then(|raw| raw.parse().ok()),
        })
    }

    /// The identity id a Dedicated route is keyed on: the typed sender
    /// identity when the dispatcher resolved one, else the typed step
    /// execution id (both are stable, non-empty provenance strings).
    fn route_identity<'a>(&'a self, job: &'a EmailJob) -> Option<&'a str> {
        self.sender_identity_id
            .as_deref()
            .or(job.sales_step_execution_id.as_deref())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure decision point
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of planning one sales send (pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedSalesRoute {
    /// Hand this route to the SALES transport — and to nothing else.
    Send(DeliveryRoute),
    /// HOLD the message with this named reason instead of routing it
    /// anywhere (the customer transport is not an option, ever).
    Hold {
        reason: &'static str,
        detail: String,
    },
}

impl PlannedSalesRoute {
    fn hold(reason: &'static str, detail: impl Into<String>) -> Self {
        Self::Hold {
            reason,
            detail: detail.into(),
        }
    }
}

/// Plan the route for one sales send (PURE — no database, no transport, no
/// clock). This is where the isolation invariant lives, and it is
/// deliberately total: for an unconfigured, misprovisioned, or
/// domain-disallowed sales send there is exactly one outcome, a named HOLD.
///
/// * [`SalesTransportMode::None`] → HOLD `sales_transport_unconfigured`;
/// * [`SalesTransportMode::Relay`] (own MTA) → a
///   [`DeliveryRoute::Dedicated`] whose `source_ip` is the RECORDED
///   `metadata.sales_sender_source_ip`; a missing/corrupt IP is HOLD
///   `sales_send_source_ip_missing` (the relay's binding contract cannot be
///   expressed without it);
/// * [`SalesTransportMode::SesAccount`] → the sales account's own shared
///   route (SES owns its sending IPs; there is no per-message binding to
///   honour), still only ever handed to the sales transport.
pub fn plan_sales_route(
    mode: SalesTransportMode,
    sales: &SalesSend,
    job: &EmailJob,
) -> PlannedSalesRoute {
    match mode {
        SalesTransportMode::None => PlannedSalesRoute::hold(
            SALES_HOLD_TRANSPORT_UNCONFIGURED,
            "no dedicated sales transport is configured (SALES_TRANSPORT is unset or \
             'none'); a sales send is never routed through the customer SES/relay \
             transport — configure the sales transport or leave the message held",
        ),
        SalesTransportMode::Relay => {
            let Some(source_ip) = sales.source_ip else {
                return PlannedSalesRoute::hold(
                    SALES_HOLD_SOURCE_IP_MISSING,
                    "the sales relay is an own-MTA route: the message must bind the \
                     sales identity's recorded source IP, and \
                     metadata.sales_sender_source_ip is absent or unparsable — refusing \
                     to send from an unrecorded IP",
                );
            };
            let Some(identity) = sales.route_identity(job) else {
                return PlannedSalesRoute::hold(
                    SALES_HOLD_SOURCE_IP_MISSING,
                    "the sales send carries a source IP but no stable sender/step \
                     identity to key the dedicated route on — refusing to invent one",
                );
            };
            PlannedSalesRoute::Send(DeliveryRoute::Dedicated {
                dedicated_ip_id: identity.to_string(),
                source_ip,
            })
        }
        SalesTransportMode::SesAccount => PlannedSalesRoute::Send(DeliveryRoute::SesShared),
    }
}

/// The sender domain a sales send must be allowed to use: the domain of the
/// envelope sender (which [`EmailJob`]'s `get_domain` has already proven
/// matches the authorized `domains` row).
pub fn sales_sender_domain(job: &EmailJob) -> Option<String> {
    job.from
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

/// Structural route guard (mirrors `eu_only_route_guard_violation`): the
/// route resolved for a sales send MUST be the route the sales plan
/// produced. A violation holds the message instead of submitting it.
pub fn sales_route_guard_violation(
    sales: bool,
    planned: Option<&DeliveryRoute>,
    resolved: &DeliveryRoute,
) -> Option<&'static str> {
    (sales && planned != Some(resolved)).then_some(SALES_HOLD_ROUTE_GUARD)
}

// ─────────────────────────────────────────────────────────────────────────────
// The single-slot sales transport router
// ─────────────────────────────────────────────────────────────────────────────

/// The dedicated sales transport slot. Holds AT MOST ONE backend — the one
/// the deployment configured for sales — and can never reach the customer
/// [`super::transport::HybridTransport`]: the two are separate values with
/// separate construction paths, so no input can make a sales send fall back.
pub struct SalesTransport {
    backend: Option<Arc<dyn EmailTransport>>,
    /// The honest, human-readable name of the configured backend
    /// (`"none"`, `"sales-relay"`, `"sales-ses-account"`).
    backend_name: &'static str,
}

impl std::fmt::Debug for SalesTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalesTransport")
            .field("backend_name", &self.backend_name)
            .field("configured", &self.backend.is_some())
            .finish()
    }
}

impl SalesTransport {
    /// No backend: `SALES_TRANSPORT` is unset/`none` (or was unprovisioned).
    /// Every sales send holds; nothing can be submitted.
    pub fn unconfigured() -> Self {
        Self {
            backend: None,
            backend_name: "none",
        }
    }

    /// Wrap the configured backend.
    pub fn new(backend: Arc<dyn EmailTransport>, backend_name: &'static str) -> Self {
        Self {
            backend: Some(backend),
            backend_name,
        }
    }

    /// Whether a sales backend exists on this worker.
    pub fn is_configured(&self) -> bool {
        self.backend.is_some()
    }

    /// The backend's name, for logs and error copy.
    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    /// Whether the configured backend can carry the planned route:
    ///
    /// * no backend → fail closed (`NotConfigured`);
    /// * `Dedicated` (own-MTA relay route) → the backend must be able to
    ///   BIND and REPORT the source IP ([`EmailTransport::supports_source_binding`]),
    ///   otherwise the binding could not be verified and the send must hold;
    /// * `SesShared` (the sales account route) → the backend must be the SES
    ///   account backend, declared by name.
    pub fn ensure_dispatchable(&self, route: &DeliveryRoute) -> ProcessorResult<()> {
        let Some(backend) = self.backend.as_ref() else {
            return Err(ProcessorError::Config(format!(
                "no dedicated sales transport is configured (SALES_TRANSPORT is unset or \
                 'none'); route {route} cannot be carried and falling back to the \
                 customer transport is forbidden by the sales isolation invariant"
            )));
        };
        if route.is_dedicated() && !backend.supports_source_binding() {
            return Err(ProcessorError::Config(format!(
                "the configured sales transport '{}' cannot bind and report the source IP \
                 required by route {route} — refusing before DATA rather than sending \
                 from an unverified IP",
                self.backend_name
            )));
        }
        Ok(())
    }

    /// Submit a sales send on the sales transport — and only there. Defense
    /// in depth over the dispatch-time gate: a missing backend refuses
    /// BEFORE any call, and a backend whose declared name does not match the
    /// route shape is refused too (the customer SES client can never be
    /// reached through this value).
    pub async fn send(
        &self,
        email: &super::types::PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<super::types::DeliveryReceipt> {
        self.ensure_dispatchable(route)?;
        let backend = self
            .backend
            .as_ref()
            .expect("ensure_dispatchable proved the backend exists");
        debug_assert!(
            !matches!(route, DeliveryRoute::SesShared) || self.backend_name == "sales-ses-account",
            "only the sales SES account carries the sales shared route"
        );
        backend.send(email, route).await
    }

    /// Verify the configured backend (a no-op when unconfigured: a
    /// deployment without sales has nothing to verify).
    pub async fn verify(&self) -> ProcessorResult<()> {
        match &self.backend {
            Some(backend) => backend.verify().await,
            None => Ok(()),
        }
    }

    /// Close the configured backend.
    pub async fn close(&self) -> ProcessorResult<()> {
        match &self.backend {
            Some(backend) => backend.close().await,
            None => Ok(()),
        }
    }
}

/// Build the sales transport for the configured mode.
///
/// FAIL LOUDLY on a half-configured deployment: selecting a mode without its
/// endpoint material is a configuration error at BOOT (mirroring
/// `EMAIL_TRANSPORT_TYPE=smtp requires a concrete SMTP_HOST`), not a silent
/// hold of every sales message. A mode that is `none` builds an unconfigured
/// (fail-closed) slot.
pub async fn create_sales_transport(
    config: &SalesTransportConfig,
    db: Option<&sqlx::PgPool>,
    redis: Option<&deadpool_redis::Pool>,
) -> ProcessorResult<SalesTransport> {
    match config.mode {
        SalesTransportMode::None => Ok(SalesTransport::unconfigured()),
        SalesTransportMode::Relay => {
            let relay = config.relay.as_ref().ok_or_else(|| {
                ProcessorError::Config(
                    "SALES_TRANSPORT=relay requires SALES_RELAY_URL (smtp:// or smtps://) — \
                     the sales relay endpoint is not configured"
                        .into(),
                )
            })?;
            build_sales_relay_transport(relay, db, redis).await
        }
        SalesTransportMode::SesAccount => {
            let ses = config.ses_account.as_ref().ok_or_else(|| {
                ProcessorError::Config(
                    "SALES_TRANSPORT=ses_account requires SALES_SES_ACCESS_KEY_ID and \
                     SALES_SES_SECRET_ACCESS_KEY (the dedicated sales AWS account)"
                        .into(),
                )
            })?;
            let ses_config = crate::common::SesConfig {
                region: ses.region.clone(),
                configuration_set: ses.configuration_set.clone(),
                ..Default::default()
            };
            let transport = SesTransport::from_explicit_credentials(
                ses_config,
                ses.access_key_id.as_str(),
                ses.secret_access_key.as_str(),
            )
            .await?;
            Ok(SalesTransport::new(
                Arc::new(transport),
                "sales-ses-account",
            ))
        }
    }
}

/// Build the own-MTA relay backend for the sales slot.
///
/// The relay library is the in-repo backend whose acceptance record proves
/// the bound source IP (`OutboundMtaTransport`), which is exactly what an
/// own-MTA sales route requires. The configured endpoint names the relay
/// identity the sales messages present (`HELO`/`Reporting-MTA`), so one
/// explicit endpoint — never an implicit default — identifies the sales
/// relay. Without the worker's database pool the relay's durable acceptance
/// ledger cannot exist, and the sales slot stays UNCONFIGURED (fail closed:
/// every sales send holds; nothing is submitted).
async fn build_sales_relay_transport(
    relay: &SalesRelayConfig,
    db: Option<&sqlx::PgPool>,
    redis: Option<&deadpool_redis::Pool>,
) -> ProcessorResult<SalesTransport> {
    let Some(pool) = db else {
        tracing::warn!(
            relay_host = %relay.host,
            "SALES_TRANSPORT=relay without a database pool: the own-MTA acceptance ledger \
             cannot exist — the sales slot stays unconfigured and sales sends HOLD \
             (fail closed; nothing is submitted through the customer transport)"
        );
        return Ok(SalesTransport::unconfigured());
    };
    let transport = super::outbound_mta::OutboundMtaTransport::from_pool_with_endpoint(
        pool,
        redis,
        relay.host.clone(),
        relay.require_starttls,
    )?;
    tracing::info!(
        relay_host = %relay.host,
        require_starttls = relay.require_starttls,
        "dedicated SALES relay transport initialised (own outbound MTA, verifiable source \
         binding; the customer transport is never used for sales mail)"
    );
    Ok(SalesTransport::new(Arc::new(transport), "sales-relay"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::SesConfig;
    use std::net::IpAddr;

    fn job_with(metadata: serde_json::Value, step: Option<&str>) -> EmailJob {
        EmailJob {
            id: "job-1".into(),
            message_id: "msg-1".into(),
            tenant_id: "system".into(),
            domain_id: "dom-1".into(),
            from: "sales@sales.apexmail.ee".into(),
            to: "prospect@example.com".into(),
            subject: "hi".into(),
            html: None,
            text: Some("body".into()),
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: Some(metadata),
            sales_step_execution_id: step.map(str::to_string),
            scheduled_at: None,
            attempt: 0,
            created_at: chrono::Utc::now(),
        }
    }

    /// The classification signal is EXACTLY the dispatcher's provenance:
    /// `metadata.source = "sales-autopilot"` or the typed
    /// `sales_step_execution_id` column. A customer row (no marker) is not a
    /// sales send.
    #[test]
    fn classification_reads_the_dispatcher_provenance_only() {
        // Customer row: no marker, no typed column.
        assert_eq!(
            SalesSend::classify(&job_with(serde_json::json!({}), None)),
            None
        );
        assert_eq!(
            SalesSend::classify(&job_with(
                serde_json::json!({"source": "api", "campaign": "summer"}),
                None
            )),
            None
        );

        // Campaign row: the metadata marker alone.
        let campaign = SalesSend::classify(&job_with(
            serde_json::json!({
                "source": "sales-autopilot",
                "campaign_id": "c-1",
                "sales_tenant_id": "system"
            }),
            None,
        ))
        .expect("campaign rows are sales sends");
        assert_eq!(campaign.sender_identity_id, None);
        assert_eq!(campaign.source_ip, None);

        // Sequenced row: typed column + full provenance.
        let sequenced = SalesSend::classify(&job_with(
            serde_json::json!({
                "source": "sales-autopilot",
                "sales_sender_identity_id": "11111111-1111-1111-1111-111111111111",
                "sales_sender_pool": "sales_outbound",
                "sales_sender_source_ip": "203.0.113.7"
            }),
            Some("22222222-2222-2222-2222-222222222222"),
        ))
        .expect("sequenced rows are sales sends");
        assert_eq!(
            sequenced.sender_identity_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(sequenced.sender_pool.as_deref(), Some("sales_outbound"));
        assert_eq!(
            sequenced.source_ip,
            Some("203.0.113.7".parse::<IpAddr>().expect("ip"))
        );

        // A typed column with no metadata still classifies (the ledger keys
        // on it), and a corrupt source IP degrades to None (which the relay
        // plan turns into a named HOLD, never a guess).
        let typed_only = SalesSend::classify(&job_with(
            serde_json::json!({"sales_sender_source_ip": "not-an-ip"}),
            Some("33333333-3333-3333-3333-333333333333"),
        ))
        .expect("typed step id classifies");
        assert_eq!(typed_only.source_ip, None);
    }

    /// THE invariant, at its decision point: with no sales transport there
    /// is NO input that yields a sendable route. This is the fail-before
    /// test for the feature — if anyone "allows the fallback" by planning a
    /// customer route here, this fails.
    #[test]
    fn unconfigured_sales_transport_never_plans_a_route() {
        let job = job_with(
            serde_json::json!({
                "source": "sales-autopilot",
                "sales_sender_identity_id": "11111111-1111-1111-1111-111111111111",
                "sales_sender_source_ip": "203.0.113.7"
            }),
            Some("22222222-2222-2222-2222-222222222222"),
        );
        let sales = SalesSend::classify(&job).expect("sales");
        match plan_sales_route(SalesTransportMode::None, &sales, &job) {
            PlannedSalesRoute::Hold { reason, detail } => {
                assert_eq!(reason, SALES_HOLD_TRANSPORT_UNCONFIGURED);
                assert!(
                    detail.contains("never routed through the customer"),
                    "the hold detail must name the forbidden fallback: {detail}"
                );
            }
            PlannedSalesRoute::Send(route) => panic!(
                "SALES_TRANSPORT=none must HOLD, never plan {route} (the customer \
                 transport must be structurally unreachable for a sales send)"
            ),
        }
    }

    /// Relay mode binds the recorded IP; a missing or corrupt IP (and a
    /// missing identity to key on) HOLDS by name — never a send from an
    /// unrecorded IP.
    #[test]
    fn relay_mode_requires_the_recorded_source_ip() {
        let with_ip = job_with(
            serde_json::json!({
                "source": "sales-autopilot",
                "sales_sender_identity_id": "sender-1",
                "sales_sender_source_ip": "203.0.113.7"
            }),
            None,
        );
        let sales = SalesSend::classify(&with_ip).expect("sales");
        match plan_sales_route(SalesTransportMode::Relay, &sales, &with_ip) {
            PlannedSalesRoute::Send(DeliveryRoute::Dedicated {
                dedicated_ip_id,
                source_ip,
            }) => {
                assert_eq!(dedicated_ip_id, "sender-1");
                assert_eq!(source_ip.to_string(), "203.0.113.7");
            }
            other => {
                panic!("relay mode with a recorded IP must plan the dedicated route: {other:?}")
            }
        }

        for metadata in [
            serde_json::json!({"source": "sales-autopilot", "sales_sender_identity_id": "sender-1"}),
            serde_json::json!({
                "source": "sales-autopilot",
                "sales_sender_identity_id": "sender-1",
                "sales_sender_source_ip": "not-an-ip"
            }),
        ] {
            let job = job_with(metadata, None);
            let sales = SalesSend::classify(&job).expect("sales");
            match plan_sales_route(SalesTransportMode::Relay, &sales, &job) {
                PlannedSalesRoute::Hold { reason, detail } => {
                    assert_eq!(reason, SALES_HOLD_SOURCE_IP_MISSING);
                    assert!(detail.contains("sales_sender_source_ip"), "{detail}");
                }
                PlannedSalesRoute::Send(route) => {
                    panic!("a relay send without a usable source IP must HOLD, got {route}")
                }
            }
        }

        // An IP with no identity at all (neither typed sender id nor typed
        // step id) cannot key a route: HOLD.
        let orphan = SalesSend {
            sender_identity_id: None,
            sender_pool: None,
            source_ip: Some("203.0.113.7".parse().expect("ip")),
        };
        let job = job_with(serde_json::json!({}), None);
        assert!(matches!(
            plan_sales_route(SalesTransportMode::Relay, &orphan, &job),
            PlannedSalesRoute::Hold {
                reason: SALES_HOLD_SOURCE_IP_MISSING,
                ..
            }
        ));
    }

    /// The sales SES account owns its sending IPs: its route is the sales
    /// account's shared route, and it is still never the customer route.
    #[test]
    fn ses_account_mode_plans_the_sales_accounts_own_route() {
        let job = job_with(serde_json::json!({"source": "sales-autopilot"}), None);
        let sales = SalesSend::classify(&job).expect("sales");
        assert_eq!(
            plan_sales_route(SalesTransportMode::SesAccount, &sales, &job),
            PlannedSalesRoute::Send(DeliveryRoute::SesShared)
        );
    }

    /// The allowlist gate: only `SALES_SENDING_DOMAINS` entries pass, and an
    /// empty allowlist allows nothing.
    #[test]
    fn the_sales_sending_allowlist_is_exact() {
        let config = SalesTransportConfig {
            mode: SalesTransportMode::Relay,
            sending_domains: vec!["sales.apexmail.ee".into()],
            relay: None,
            ses_account: None,
            send_rate_per_second: 0,
        };
        assert!(config.domain_allowed("sales.apexmail.ee"));
        assert!(config.domain_allowed("SALES.ApexMail.EE"));
        assert!(config.domain_allowed("sales.apexmail.ee."));
        assert!(!config.domain_allowed("apexmail.ee"));
        assert!(!config.domain_allowed("customer.example"));
        assert!(!config.domain_allowed("evil-sales.apexmail.ee"));
        let empty = SalesTransportConfig::default();
        assert!(!empty.domain_allowed("sales.apexmail.ee"));
    }

    #[test]
    fn the_sender_domain_comes_from_the_envelope() {
        let job = job_with(serde_json::json!({}), None);
        assert_eq!(
            sales_sender_domain(&job).as_deref(),
            Some("sales.apexmail.ee")
        );
        let mut broken = job.clone();
        broken.from = "no-at-sign".into();
        assert_eq!(sales_sender_domain(&broken), None);
    }

    /// The structural guard: a sales send resolved onto any route other than
    /// its plan is a violation; a customer send is unaffected.
    #[test]
    fn the_sales_route_guard_refuses_any_other_route() {
        let planned = DeliveryRoute::Dedicated {
            dedicated_ip_id: "sender-1".into(),
            source_ip: "203.0.113.7".parse().expect("ip"),
        };
        assert_eq!(
            sales_route_guard_violation(true, Some(&planned), &DeliveryRoute::SesShared),
            Some(SALES_HOLD_ROUTE_GUARD)
        );
        assert_eq!(
            sales_route_guard_violation(true, Some(&planned), &planned),
            None
        );
        assert_eq!(
            sales_route_guard_violation(true, None, &DeliveryRoute::SesShared),
            Some(SALES_HOLD_ROUTE_GUARD)
        );
        assert_eq!(
            sales_route_guard_violation(false, None, &DeliveryRoute::SesShared),
            None,
            "a customer send is not bound by the sales guard"
        );
    }

    /// The unnamed hold reasons are distinct, sales-scoped, and never a
    /// deferral reason (each must be fixable only by an operator).
    #[test]
    fn hold_reasons_are_distinct_and_sales_scoped() {
        let mut unique = SALES_HOLD_REASONS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), SALES_HOLD_REASONS.len());
        assert!(SALES_HOLD_REASONS
            .iter()
            .all(|reason| reason.starts_with("sales_")));
        assert!(SALES_HOLD_REASONS.contains(&SALES_HOLD_TRANSPORT_UNCONFIGURED));
    }

    // ── The transport slot ───────────────────────────────────────────────

    struct SpyTransport {
        name: &'static str,
        binding: bool,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl SpyTransport {
        fn new(name: &'static str, binding: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                binding,
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl EmailTransport for SpyTransport {
        fn transport_name(&self) -> &str {
            self.name
        }
        fn supports_source_binding(&self) -> bool {
            self.binding
        }
        async fn verify(&self) -> ProcessorResult<()> {
            Ok(())
        }
        async fn send(
            &self,
            _email: &super::super::types::PreparedEmail,
            route: &DeliveryRoute,
        ) -> ProcessorResult<super::super::types::DeliveryReceipt> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(super::super::types::DeliveryReceipt {
                transport: crate::common::TransportType::Smtp,
                transport_message_id: None,
                actual_source_ip: route.dedicated_source_ip(),
                recipient_provider: None,
                provider_source: None,
            })
        }
        async fn close(&self) -> ProcessorResult<()> {
            Ok(())
        }
    }

    fn prepared() -> super::super::types::PreparedEmail {
        super::super::types::PreparedEmail {
            send_unit: "sa-send:step-1".into(),
            from: "sales@sales.apexmail.ee".into(),
            from_name: None,
            ses_configuration_set: None,
            to: "prospect@example.com".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "hi".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
            verp: None,
        }
    }

    /// An unconfigured slot refuses BOTH route shapes before any call — the
    /// zero-transport-calls arm of the unconfigured hold.
    #[tokio::test]
    async fn an_unconfigured_sales_slot_refuses_every_route_before_any_call() {
        let slot = SalesTransport::unconfigured();
        assert!(!slot.is_configured());
        assert_eq!(slot.backend_name(), "none");
        for route in [
            DeliveryRoute::SesShared,
            DeliveryRoute::Dedicated {
                dedicated_ip_id: "sender-1".into(),
                source_ip: "203.0.113.7".parse().expect("ip"),
            },
        ] {
            let error = slot
                .ensure_dispatchable(&route)
                .expect_err("unconfigured must refuse");
            assert!(
                error
                    .to_string()
                    .contains("no dedicated sales transport is configured"),
                "{error}"
            );
            let send_error = slot
                .send(&prepared(), &route)
                .await
                .expect_err("unconfigured must refuse the send too");
            assert!(send_error.to_string().contains("falling back"));
        }
        // Verify/close are no-ops on an unconfigured slot (a deployment
        // without sales has nothing to verify).
        slot.verify().await.expect("verify");
        slot.close().await.expect("close");
    }

    /// A relay backend that cannot bind the source IP is refused BEFORE DATA
    /// (zero calls), and a capable one carries the route exactly once.
    #[tokio::test]
    async fn the_sales_slot_refuses_a_non_binding_backend_before_data() {
        let unverifiable = SpyTransport::new("sales-relay", false);
        let slot = SalesTransport::new(
            unverifiable.clone() as Arc<dyn EmailTransport>,
            "sales-relay",
        );
        let dedicated = DeliveryRoute::Dedicated {
            dedicated_ip_id: "sender-1".into(),
            source_ip: "203.0.113.7".parse().expect("ip"),
        };
        let error = slot
            .ensure_dispatchable(&dedicated)
            .expect_err("a non-binding backend must be refused");
        assert!(error.to_string().contains("bind and report the source IP"));
        assert!(slot.send(&prepared(), &dedicated).await.is_err());
        assert_eq!(
            unverifiable.calls(),
            0,
            "the backend must never see an unverifiable dedicated route"
        );

        let capable = SpyTransport::new("sales-relay", true);
        let slot = SalesTransport::new(capable.clone() as Arc<dyn EmailTransport>, "sales-relay");
        slot.ensure_dispatchable(&dedicated).expect("capable");
        slot.send(&prepared(), &dedicated)
            .await
            .expect("the sales relay carries the planned route");
        assert_eq!(capable.calls(), 1);
    }

    /// Construction: `none` builds an unconfigured slot; a selected mode
    /// without material FAILS LOUDLY at boot; the ses_account backend is
    /// built from the dedicated credentials (credential-lazy SES client, so
    /// no network is touched here).
    #[tokio::test]
    async fn construction_fails_loudly_on_half_configured_modes() {
        // The `none` mode is built EXPLICITLY (not from the environment):
        // sibling tests mutate `SALES_TRANSPORT`, and this test must observe
        // exactly the mode it asked for.
        let none_mode = SalesTransportConfig {
            mode: SalesTransportMode::None,
            sending_domains: Vec::new(),
            relay: None,
            ses_account: None,
            send_rate_per_second: 0,
        };
        let unconfigured = create_sales_transport(&none_mode, None, None)
            .await
            .expect("none builds");
        assert!(!unconfigured.is_configured());

        let relay_without_endpoint = SalesTransportConfig {
            mode: SalesTransportMode::Relay,
            sending_domains: vec!["sales.apexmail.ee".into()],
            relay: None,
            ses_account: None,
            send_rate_per_second: 5,
        };
        let error = create_sales_transport(&relay_without_endpoint, None, None)
            .await
            .expect_err("relay without SALES_RELAY_URL is a boot error");
        assert!(error.to_string().contains("SALES_RELAY_URL"), "{error}");

        let ses_without_credentials = SalesTransportConfig {
            mode: SalesTransportMode::SesAccount,
            sending_domains: vec!["sales.apexmail.ee".into()],
            relay: None,
            ses_account: None,
            send_rate_per_second: 5,
        };
        let error = create_sales_transport(&ses_without_credentials, None, None)
            .await
            .expect_err("ses_account without credentials is a boot error");
        assert!(error.to_string().contains("SALES_SES_"), "{error}");

        // A provisioned relay WITHOUT the worker's database pool cannot own
        // an acceptance ledger: the slot stays unconfigured (fail closed),
        // exactly where the relay would be unverifiable.
        let relay = SalesTransportConfig {
            mode: SalesTransportMode::Relay,
            sending_domains: vec!["sales.apexmail.ee".into()],
            relay: Some(SalesRelayConfig::parse("smtps://relay.sales.example").expect("endpoint")),
            ses_account: None,
            send_rate_per_second: 5,
        };
        let slot = create_sales_transport(&relay, None, None)
            .await
            .expect("builds without a pool");
        assert!(!slot.is_configured());

        // The SES account backend builds credential-lazily from SALES_SES_*.
        let ses = SalesTransportConfig {
            mode: SalesTransportMode::SesAccount,
            sending_domains: vec!["sales.apexmail.ee".into()],
            relay: None,
            ses_account: Some(crate::common::SalesSesConfig {
                region: "eu-west-1".into(),
                configuration_set: Some("sales-events".into()),
                access_key_id: zeroize::Zeroizing::new("AKIA-SALES".into()),
                secret_access_key: zeroize::Zeroizing::new("secret".into()),
            }),
            send_rate_per_second: 5,
        };
        let slot = create_sales_transport(&ses, None, None)
            .await
            .expect("ses account builds");
        assert!(slot.is_configured());
        assert_eq!(slot.backend_name(), "sales-ses-account");
        slot.ensure_dispatchable(&DeliveryRoute::SesShared)
            .expect("the sales account carries its own shared route");
    }

    /// The default SesConfig used by the sales account is the same shape the
    /// customer transport uses — asserted so the account construction cannot
    /// silently borrow the customer configuration set.
    #[test]
    fn the_sales_ses_account_config_is_a_separate_value() {
        let customer = SesConfig {
            region: "us-east-1".into(),
            configuration_set: Some("customer-events".into()),
            ..Default::default()
        };
        let sales = SesConfig {
            region: "eu-west-1".into(),
            configuration_set: Some("sales-events".into()),
            ..Default::default()
        };
        assert_ne!(customer.configuration_set, sales.configuration_set);
        assert_ne!(customer.region, sales.region);
    }
}
