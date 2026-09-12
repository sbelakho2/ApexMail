//! Dedicated-route transport backed by the recipient-facing outbound MTA
//! library (`crates/outbound-mta`).
//!
//! # Why the library and not the SMTP wire contract
//!
//! The worker → relay SMTP contract (`X-ApexMail-Route` on the submission,
//! `X-ApexMail-Source-IP` in the end-of-DATA reply — see
//! [`super::transport`]) is NOT complete on either side: `crates/outbound-mta`
//! owns the recipient-facing connector but exposes no SMTP submission
//! listener (its daemon only polls the durable queue and serves health), and
//! the worker's pinned mail-send 0.4.x client returns only `Result<()>` from
//! DATA, so it cannot read the reply header that would carry the bound IP.
//!
//! The MTA's idempotent acceptance protocol DOES already exist as a library
//! API, and it is exactly the contract the audit demanded — a stable send id
//! plus a requested source IP in, the verified actual source IP in the SAME
//! idempotent acceptance record:
//!
//! ```text
//! Relay::submit(SubmitRequest { send_unit, requested_source_ip, .. })
//!     -> Result<AcceptanceRecord { requested_source_ip, actual_source_ip, .. }, RelayError>
//! ```
//!
//! [`OutboundMtaTransport`] calls that API in-process and verifies the
//! record before reporting acceptance to the processor. [`RelaySubmitter`] is
//! the seam: a future SMTP/HTTP submission listener can replace the library
//! call without touching the verification or the processor contract.
//!
//! # Truthful capability
//!
//! [`OutboundMtaTransport::supports_source_binding`] is `true` because the
//! relay's `source_ip::connect_bound` binds the recipient-facing socket
//! BEFORE `connect()` and refuses before DATA on any bind/verification
//! failure, and because [`OutboundMtaTransport::send`] refuses to report
//! acceptance unless the returned record proves the reserved IP was the
//! actual bound IP. A transport that cannot make that guarantee (the legacy
//! `SmtpTransport`, SES) keeps returning `false`.

use std::sync::Arc;

use async_trait::async_trait;
use mail_send::mail_auth::common::headers::HeaderWriter;
use outbound_mta::ledger::{PgLedger, RelayLedger};
use outbound_mta::mx::DnsMxResolver;
use outbound_mta::relay::RelayError;
use outbound_mta::{AcceptanceRecord, Relay, RelayConfig, SubmitRequest};
use sqlx::PgPool;
use tracing::debug;

use super::transport::{build_dkim_signer, build_raw_mime, verp_return_path_for};
use super::types::{DeliveryReceipt, DeliveryRoute, PreparedEmail};
use crate::common::error::{ProcessorError, ProcessorResult};
use crate::common::TransportType;

/// The submission seam between the worker and the outbound MTA.
///
/// Production uses the in-process [`Relay`]; tests script acceptance records
/// to exercise the verification rules (mismatch / missing report / replayed
/// acceptance). A wire-protocol submitter (SMTP or HTTP) can be added later
/// without changing the transport's contract logic.
#[async_trait]
pub trait RelaySubmitter: Send + Sync {
    /// Submit one message. MUST be idempotent by [`SubmitRequest::send_unit`]:
    /// a replay returns the stored [`AcceptanceRecord`] instead of delivering
    /// a second copy.
    async fn submit(&self, request: SubmitRequest) -> Result<AcceptanceRecord, RelayError>;

    /// Readiness probe: the durable acceptance ledger must be reachable, or
    /// no submission can be recorded exactly once.
    async fn ready(&self) -> Result<(), String>;
}

#[async_trait]
impl RelaySubmitter for Relay {
    async fn submit(&self, request: SubmitRequest) -> Result<AcceptanceRecord, RelayError> {
        Relay::submit(self, request).await
    }

    async fn ready(&self) -> Result<(), String> {
        self.stats()
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Dedicated-route transport that submits to the outbound MTA relay and
/// verifies the source-IP binding from the returned acceptance record.
pub struct OutboundMtaTransport {
    relay: Arc<dyn RelaySubmitter>,
}

impl OutboundMtaTransport {
    /// Wrap an existing submitter (the real [`Relay`] in production, a
    /// scripted double in tests).
    pub fn new(relay: Arc<dyn RelaySubmitter>) -> Self {
        Self { relay }
    }

    /// Build the production submitter around the worker's database pool: a
    /// durable `outbound_relay_ledger` (migration 212) plus system MX
    /// resolution.
    pub fn from_pool(pool: &PgPool) -> ProcessorResult<Self> {
        let ledger: Arc<dyn RelayLedger> = Arc::new(PgLedger::new(pool.clone()));
        let resolver = DnsMxResolver::new().map_err(|error| {
            ProcessorError::Config(format!("outbound MTA MX resolver unavailable: {error}"))
        })?;
        let relay = Relay::new(ledger, Arc::new(resolver), RelayConfig::default());
        Ok(Self::new(Arc::new(relay)))
    }

    /// Build the typed submission the MTA ledger keys on.
    ///
    /// The identity is [`PreparedEmail::send_unit`] — the SAME value the
    /// processor reserved on `sales_delivery_acceptances` and the PRIMARY KEY
    /// of `outbound_relay_ledger` (migration 212), so a replayed submission
    /// returns the stored acceptance instead of delivering again.
    pub(crate) fn build_request(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<SubmitRequest> {
        if !matches!(route, DeliveryRoute::Dedicated { .. }) {
            return Err(ProcessorError::Transport(format!(
                "the outbound MTA transport only carries the dedicated delivery route; \
                 route {route} belongs to the shared SES pool — refusing before submission"
            )));
        }
        let send_unit = email.send_unit.trim();
        if send_unit.is_empty() {
            return Err(ProcessorError::Config(
                "the outbound MTA transport requires the stable send unit \
                 (PreparedEmail::send_unit) for idempotent acceptance"
                    .into(),
            ));
        }
        let recipient = email
            .to
            .trim()
            .trim_matches(|c| c == '<' || c == '>')
            .to_string();
        let envelope_from = verp_return_path_for(email).or_else(|| {
            let from = email.from.trim();
            (!from.is_empty()).then(|| from.to_string())
        });
        let (tenant_id, queue_id) = match &email.verp {
            Some(binding) => (
                Some(binding.tenant_id.clone()),
                uuid::Uuid::parse_str(&binding.queue_id).ok(),
            ),
            None => (None, None),
        };
        Ok(SubmitRequest {
            send_unit: send_unit.to_string(),
            tenant_id,
            queue_id,
            envelope_from,
            recipients: vec![recipient],
            message: Self::build_submission_message(email)?,
            requested_source_ip: route.dedicated_source_ip(),
        })
    }

    /// Serialize the message and DKIM-sign it when the route requires a
    /// local signature. The relay delivers the bytes verbatim, so signing
    /// must happen HERE (unlike the SES API path, which signs via BYODKIM).
    fn build_submission_message(email: &PreparedEmail) -> ProcessorResult<Vec<u8>> {
        let raw = build_raw_mime(email);
        if raw.is_empty() {
            return Err(ProcessorError::Transport(
                "Failed to build MIME message for the outbound MTA".into(),
            ));
        }
        match &email.dkim {
            Some(config) => {
                let signer = build_dkim_signer(config)?;
                let signature = signer.sign(&raw).map_err(|error| {
                    ProcessorError::Dkim(format!(
                        "DKIM signing for the outbound MTA failed: {error}"
                    ))
                })?;
                let mut signed = Vec::with_capacity(raw.len() + 128);
                signature.write_header(&mut signed);
                signed.extend_from_slice(&raw);
                Ok(signed)
            }
            None => Ok(raw),
        }
    }
}

/// Map a relay failure onto the processor error taxonomy.
///
/// * a terminal relay failure (`Permanent`) is carried as a 5xx-class SMTP
///   refusal so the processor takes the no-retry path (the MTA ledger is
///   already terminal — a resubmit would return the stored failure). The
///   remote diagnostics the relay folded into `reason` still decide
///   suppression through the existing address-proving rule: a 5.1.x /
///   "user unknown" diagnostic suppresses, a policy refusal does not;
/// * everything else (in-flight, already queued, retry scheduled, ledger
///   unavailable) stays an UNCLASSIFIED transport error: the processor
///   retries with backoff, and the MTA ledger's idempotency makes the retry
///   safe (a stored acceptance is returned, never a second delivery).
fn map_relay_error(error: RelayError) -> ProcessorError {
    match error {
        RelayError::Permanent { reason, .. } => ProcessorError::Smtp {
            code: 554,
            enhanced: None,
            message: format!("outbound MTA permanent delivery failure: {reason}"),
        },
        other => ProcessorError::Transport(format!("outbound MTA submission failed: {other}")),
    }
}

/// Verify the acceptance record against the dedicated route.
///
/// The record must be `accepted`, must carry the send unit that was
/// submitted, and must prove the reserved IP was the actual bound IP. A
/// missing report never verifies — there is NO optimistic success.
fn verify_acceptance_record(
    route: &DeliveryRoute,
    expected_send_unit: &str,
    record: &AcceptanceRecord,
) -> ProcessorResult<()> {
    if record.state != "accepted" {
        return Err(ProcessorError::SourceBindingUnverified(format!(
            "outbound MTA returned record for '{}' in state '{}' — refusing to treat it as accepted",
            record.send_unit, record.state
        )));
    }
    if record.send_unit != expected_send_unit {
        return Err(ProcessorError::SourceBindingUnverified(format!(
            "outbound MTA acceptance is keyed on '{}' but '{}' was submitted — idempotency \
             identity mismatch",
            record.send_unit, expected_send_unit
        )));
    }
    let DeliveryRoute::Dedicated { source_ip, .. } = route else {
        return Ok(());
    };
    match (record.requested_source_ip, record.actual_source_ip) {
        (Some(requested), Some(actual)) if requested == *source_ip && actual == *source_ip => {
            Ok(())
        }
        (requested, actual) => Err(ProcessorError::SourceBindingUnverified(format!(
            "outbound MTA acceptance for '{expected_send_unit}' does not verify the reserved \
             source IP {source_ip}: requested {requested:?}, actual {actual:?} — refusing to \
             report a verified dedicated send (and never consuming its warmup capacity)"
        ))),
    }
}

#[async_trait]
impl super::transport::EmailTransport for OutboundMtaTransport {
    fn transport_name(&self) -> &str {
        "outbound-mta"
    }

    /// TRUE — honestly: the relay binds the recipient-facing socket to the
    /// requested IP before connect and reports the kernel-bound actual IP in
    /// the same acceptance record this transport verifies before returning
    /// success (see the module docs).
    fn supports_source_binding(&self) -> bool {
        true
    }

    async fn verify(&self) -> ProcessorResult<()> {
        debug!("Verifying outbound MTA acceptance ledger");
        self.relay.ready().await.map_err(|error| {
            ProcessorError::Transport(format!(
                "outbound MTA acceptance ledger is not reachable: {error}"
            ))
        })
    }

    async fn send(
        &self,
        email: &PreparedEmail,
        route: &DeliveryRoute,
    ) -> ProcessorResult<DeliveryReceipt> {
        // Defense in depth: the dispatch layer already routes by route, but
        // the MTA path must never carry shared-pool mail.
        let request = self.build_request(email, route)?;
        let expected_send_unit = request.send_unit.clone();
        let record = self.relay.submit(request).await.map_err(map_relay_error)?;
        verify_acceptance_record(route, &expected_send_unit, &record)?;
        debug!(
            send_unit = %expected_send_unit,
            requested_source_ip = ?record.requested_source_ip,
            actual_source_ip = ?record.actual_source_ip,
            remote_mx = ?record.remote_mx,
            "outbound MTA accepted the dedicated send with a verified source binding"
        );
        Ok(DeliveryReceipt {
            transport: TransportType::Smtp,
            transport_message_id: None,
            // The verified bound IP from the acceptance record — the ONLY
            // evidence that lets the processor consume warmup capacity.
            actual_source_ip: record.actual_source_ip,
            // The relay resolved the recipient MX but the mailbox provider
            // mapping is a separate concern; unknown stays None and is never
            // inferred from the visible domain.
            recipient_provider: None,
            provider_source: None,
        })
    }

    async fn close(&self) -> ProcessorResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::transport::EmailTransport;
    use super::*;
    use crate::email::processor::warmup_reservation_must_be_released;
    use outbound_mta::test_support::{
        FakeSmtpConfig, FakeSmtpServer, MemoryLedger, StaticMxResolver,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn dedicated_route() -> DeliveryRoute {
        DeliveryRoute::Dedicated {
            dedicated_ip_id: "dip-1".into(),
            source_ip: "127.0.0.1".parse().expect("test IP"),
        }
    }

    fn email() -> PreparedEmail {
        PreparedEmail {
            send_unit: "email_queue:job-1:user@example.com".into(),
            from: "sender@apexmail.ee".into(),
            to: "user@example.com".into(),
            mime_to: vec![],
            mime_cc: vec![],
            reply_to: None,
            subject: "dedicated".into(),
            html: None,
            text: Some("body".into()),
            headers: vec![],
            attachments: vec![],
            dkim: None,
            verp: None,
        }
    }

    /// Build the REAL relay over the in-memory ledger + scripted SMTP server,
    /// exactly as `outbound-mta`'s own tests do.
    async fn real_relay_transport() -> (OutboundMtaTransport, Arc<MemoryLedger>, FakeSmtpServer) {
        let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
        let ledger = Arc::new(MemoryLedger::new());
        let resolver =
            Arc::new(StaticMxResolver::new().with_target("example.com", vec![server.addr()]));
        let relay = Arc::new(Relay::new(ledger.clone(), resolver, RelayConfig::default()));
        (OutboundMtaTransport::new(relay), ledger, server)
    }

    fn record(state: &str, requested: Option<&str>, actual: Option<&str>) -> AcceptanceRecord {
        AcceptanceRecord {
            send_unit: "email_queue:job-1:user@example.com".into(),
            state: state.into(),
            accepted_at: chrono::Utc::now(),
            attempt: 1,
            remote_mx: Some("mx.example.com".into()),
            tls_used: false,
            requested_source_ip: requested.map(|ip| ip.parse().expect("test IP")),
            actual_source_ip: actual.map(|ip| ip.parse().expect("test IP")),
            recipients: vec![],
            dsn_send_units: vec![],
        }
    }

    /// Scripted submitter: returns one canned record and counts submissions.
    struct ScriptedRelay {
        calls: AtomicUsize,
        last_request: Mutex<Option<SubmitRequest>>,
        record: AcceptanceRecord,
    }

    impl ScriptedRelay {
        fn new(record: AcceptanceRecord) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                last_request: Mutex::new(None),
                record,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn last_request(&self) -> Option<SubmitRequest> {
            self.last_request
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl RelaySubmitter for ScriptedRelay {
        async fn submit(&self, request: SubmitRequest) -> Result<AcceptanceRecord, RelayError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self
                .last_request
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(request);
            Ok(self.record.clone())
        }

        async fn ready(&self) -> Result<(), String> {
            Ok(())
        }
    }

    /// A dedicated route through the outbound-MTA-backed transport is
    /// ACCEPTED, reports the requested IP, and the settlement rule consumes
    /// (does NOT release) the reserved warmup capacity.
    #[tokio::test]
    async fn dedicated_route_verifies_and_consumes_warmup_capacity() {
        let (transport, ledger, server) = real_relay_transport().await;
        let route = dedicated_route();

        let receipt = transport
            .send(&email(), &route)
            .await
            .expect("a bindable dedicated route must be accepted");
        assert_eq!(
            receipt.actual_source_ip,
            Some("127.0.0.1".parse().expect("test IP")),
            "the acceptance must carry the verified bound IP"
        );

        // One delivery, pinned accepted on the durable ledger.
        assert_eq!(server.messages().len(), 1);
        assert_eq!(server.messages()[0].recipients, vec!["user@example.com"]);
        let row = ledger
            .get("email_queue:job-1:user@example.com")
            .await
            .expect("ledger get")
            .expect("row exists");
        assert_eq!(row.state, "accepted");
        assert_eq!(row.attempt, 1);

        // Settlement: a verified acceptance CONSUMES the reservation.
        let result = Ok(receipt);
        assert!(
            !warmup_reservation_must_be_released(&route, &result),
            "a verified dedicated acceptance keeps (consumes) the warmup reservation"
        );
    }

    /// The submitter receives EXACTLY the stable send identity the worker's
    /// acceptance ledger reserved — migration 212's ledger key.
    #[tokio::test]
    async fn submission_carries_the_shared_send_unit_identity() {
        let scripted = Arc::new(ScriptedRelay::new(record(
            "accepted",
            Some("127.0.0.1"),
            Some("127.0.0.1"),
        )));
        let transport = OutboundMtaTransport::new(scripted.clone());
        transport
            .send(&email(), &dedicated_route())
            .await
            .expect("scripted acceptance verifies");

        let request = scripted.last_request().expect("request captured");
        assert_eq!(
            request.send_unit, "email_queue:job-1:user@example.com",
            "the outbound_relay_ledger key must be the worker's send_unit_of identity"
        );
        assert_eq!(
            request.requested_source_ip,
            Some("127.0.0.1".parse().expect("test IP"))
        );
        assert_eq!(request.recipients, vec!["user@example.com".to_string()]);
        assert!(
            !request.message.is_empty(),
            "the raw RFC 5322 message must be submitted"
        );
    }

    /// A receipt whose actual IP differs from the requested one is a HARD
    /// failure and releases the capacity (the settlement rule returns true).
    #[tokio::test]
    async fn mismatched_actual_source_ip_is_a_hard_failure_and_releases_capacity() {
        let scripted = Arc::new(ScriptedRelay::new(record(
            "accepted",
            Some("127.0.0.1"),
            Some("127.0.0.2"),
        )));
        let transport = OutboundMtaTransport::new(scripted);
        let route = dedicated_route();

        let error = transport
            .send(&email(), &route)
            .await
            .expect_err("an acceptance from a different IP must not verify");
        assert!(
            matches!(error, ProcessorError::SourceBindingUnverified(ref m) if m.contains("127.0.0.2")),
            "the failure must name the mismatched actual IP: {error}"
        );
        assert_eq!(
            crate::email::processor::classify_send_failure(&error),
            crate::email::processor::SendFailureClass::Hard,
            "a binding mismatch after acceptance must not be retried"
        );
        assert!(
            !crate::email::processor::is_recipient_invalid(&error),
            "a binding mismatch says nothing about the mailbox — no suppression"
        );

        let result = Err(error);
        assert!(
            warmup_reservation_must_be_released(&route, &result),
            "an unverified binding must release the reserved capacity"
        );
    }

    /// A receipt with NO reported actual IP does not verify — no optimistic
    /// success.
    #[tokio::test]
    async fn missing_source_ip_report_never_verifies() {
        let scripted = Arc::new(ScriptedRelay::new(record(
            "accepted",
            Some("127.0.0.1"),
            None,
        )));
        let transport = OutboundMtaTransport::new(scripted);
        let route = dedicated_route();

        let error = transport
            .send(&email(), &route)
            .await
            .expect_err("a missing source-IP report must never be treated as success");
        assert!(matches!(error, ProcessorError::SourceBindingUnverified(_)));
        assert_eq!(
            crate::email::processor::classify_send_failure(&error),
            crate::email::processor::SendFailureClass::Hard
        );
        assert!(warmup_reservation_must_be_released(&route, &Err(error)));

        // Also: a record that omits the REQUESTED IP (echo mismatch) fails.
        let scripted = Arc::new(ScriptedRelay::new(record("accepted", None, None)));
        let transport = OutboundMtaTransport::new(scripted);
        let error = transport
            .send(&email(), &dedicated_route())
            .await
            .expect_err("an acceptance without the requested IP must not verify");
        assert!(matches!(error, ProcessorError::SourceBindingUnverified(_)));

        // And a record keyed on a DIFFERENT send unit is refused.
        let mut wrong_key = record("accepted", Some("127.0.0.1"), Some("127.0.0.1"));
        wrong_key.send_unit = "email_queue:other:user@example.com".into();
        let transport = OutboundMtaTransport::new(Arc::new(ScriptedRelay::new(wrong_key)));
        let error = transport
            .send(&email(), &dedicated_route())
            .await
            .expect_err("an acceptance for another send unit must not count");
        assert!(error.to_string().contains("idempotency identity mismatch"));
    }

    /// Replaying the same submission (same send_unit) returns the stored
    /// acceptance and delivers EXACTLY once.
    #[tokio::test]
    async fn replayed_submission_returns_the_stored_acceptance_and_delivers_once() {
        let (transport, ledger, server) = real_relay_transport().await;
        let route = dedicated_route();

        let first = transport
            .send(&email(), &route)
            .await
            .expect("first submission accepted");
        let second = transport
            .send(&email(), &route)
            .await
            .expect("a replayed submission returns the stored acceptance");

        assert_eq!(
            first.actual_source_ip, second.actual_source_ip,
            "the replayed submission must return the SAME acceptance evidence"
        );
        assert_eq!(
            server.messages().len(),
            1,
            "a repeated send_unit must never deliver twice"
        );
        let row = ledger
            .get("email_queue:job-1:user@example.com")
            .await
            .expect("ledger get")
            .expect("row exists");
        assert_eq!(row.state, "accepted");
        assert_eq!(row.attempt, 1, "the stored acceptance is not re-delivered");
        assert!(row.acceptance.is_some());
    }

    /// A shared (`SesShared`) route never touches the MTA path: the transport
    /// refuses it before any submission (and the hybrid dispatcher sends it
    /// to SES only).
    #[tokio::test]
    async fn shared_route_never_reaches_the_outbound_mta() {
        let scripted = Arc::new(ScriptedRelay::new(record(
            "accepted",
            Some("127.0.0.1"),
            Some("127.0.0.1"),
        )));
        let transport = OutboundMtaTransport::new(scripted.clone());

        let error = transport
            .send(&email(), &DeliveryRoute::SesShared)
            .await
            .expect_err("the MTA transport must refuse the shared route");
        assert!(
            error.to_string().contains("only carries the dedicated"),
            "the refusal must name the route invariant: {error}"
        );
        assert_eq!(
            scripted.calls(),
            0,
            "the relay must never be asked to submit shared-pool mail"
        );
        assert!(
            transport.supports_source_binding(),
            "the MTA-backed transport is the one backend that honestly claims binding"
        );
    }

    /// Regression guard for the pre-DATA refusal: a dedicated route whose
    /// configured transport cannot bind still defers BEFORE submit. The
    /// legacy SMTP transport is the production example (its client cannot
    /// read the reply header).
    #[tokio::test]
    async fn unverifiable_dedicated_transport_still_defers_before_data() {
        use super::super::transport::{HybridTransport, SmtpTransport};
        use crate::common::SmtpConfig;

        let legacy = Arc::new(SmtpTransport::new(SmtpConfig::default()));
        assert!(
            !legacy.supports_source_binding(),
            "the legacy relay client must keep declaring false"
        );
        let hybrid = HybridTransport::new(None, Some(legacy as Arc<dyn EmailTransport>));
        let route = dedicated_route();
        let error = hybrid
            .ensure_route_dispatchable(&route)
            .expect_err("an unverifiable dedicated transport must defer before DATA");
        assert!(error.to_string().contains("source binding"));
        let send_error = hybrid
            .send(&email(), &route)
            .await
            .expect_err("send must refuse before DATA");
        assert!(send_error.to_string().contains("source binding"));
    }
}
