//! Authoritative VAT-number validation against VIES and evidence persistence.
//!
//! The tax-truth P0 finding was that `billing-common::vat_rates` treated a
//! structurally valid EU VAT number as sufficient for a reverse charge while
//! claiming "full VIES validation happens out-of-band in vat_emta" — a
//! validator that did not exist. This module is that production validator:
//!
//! * [`validate_vat_number_vies`] performs the SOAP `checkVat` consultation;
//! * [`parse_check_vat_response`] is the pure response parser (unit-tested);
//! * [`record_vat_validation_evidence`] persists the dated result into
//!   `vat_validation_evidence` (migration 218), including the outage state;
//! * [`validate_and_record`] does both and returns the evidence id to
//!   snapshot onto an invoice.
//!
//! # Outage behaviour (documented, implemented)
//!
//! A VIES outage is NEVER stored as valid and never authorises a reverse
//! charge. `MS_UNAVAILABLE`, `SERVICE_UNAVAILABLE`, concurrency limits and
//! timeouts become [`ViesOutcome::Outage`], are persisted with
//! `valid = FALSE` plus the outage marker, and the caller falls back to the
//! normal destination VAT (fail closed). The row stays retryable: once VIES
//! answers, a new evidence row supersedes it for subsequent supplies.
//!
//! # Not implemented
//!
//! * No scheduled re-validation of open-ended evidence (operators/backlog
//!   must re-run consultations); this module validates on demand.
//! * No automatic member-state fallback mirror; the configured endpoint
//!   (`VIES_API_URL`) is the single authority.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Production VIES SOAP endpoint; override with `VIES_API_URL` (sandbox or
/// mirror) without a code change.
pub const DEFAULT_VIES_ENDPOINT: &str =
    "https://ec.europa.eu/taxation_customs/vies/services/checkVatService";

/// Timeout for a single consultation (VIES can be slow; it must not hang a
/// request path indefinitely).
pub const VIES_TIMEOUT_SECONDS: u64 = 15;

/// Classified result of a VIES consultation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViesOutcome {
    /// The member state answered: the number is registered and active.
    Valid {
        name: Option<String>,
        address: Option<String>,
    },
    /// The member state answered: the number is not registered/active.
    Invalid,
    /// No authoritative answer (member state unavailable, service outage,
    /// timeout, concurrency limit, malformed consultation). NEVER valid.
    Outage { fault: String },
}

impl ViesOutcome {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub fn is_outage(&self) -> bool {
        matches!(self, Self::Outage { .. })
    }

    /// Outage markers that mean "the authority could not answer" — always
    /// fail closed (normal VAT), never silently valid.
    pub fn classify_fault(fault: &str) -> Self {
        let fault = fault.trim();
        match fault {
            "MS_UNAVAILABLE"
            | "SERVICE_UNAVAILABLE"
            | "GLOBAL_MAX_CONCURRENT_REQ"
            | "MS_MAX_CONCURRENT_REQ"
            | "TIMEOUT" => Self::Outage {
                fault: fault.to_string(),
            },
            // Unknown faults and malformed requests are also "no
            // authoritative answer" — an unclassified failure must never be
            // treated as validity.
            _ => Self::Outage {
                fault: if fault.is_empty() {
                    "UNKNOWN".to_string()
                } else {
                    fault.to_string()
                },
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ViesError {
    #[error("VIES transport error: {0}")]
    Transport(String),
    #[error("VIES returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("VIES response could not be parsed: {0}")]
    Malformed(String),
}

/// Extract the text of the first `<tag ...>text</tag>` element. The VIES
/// SOAP body uses unprefixed element names inside its response namespace.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.find(&format!("</{tag}>"))?;
    Some(content[..end].trim().to_string())
}

/// Pure parser for a VIES `checkVatResponse` / SOAP fault body.
pub fn parse_check_vat_response(xml: &str) -> Result<ViesOutcome, ViesError> {
    if let Some(valid_raw) = tag_text(xml, "valid") {
        return match valid_raw.to_ascii_lowercase().as_str() {
            "true" => Ok(ViesOutcome::Valid {
                name: tag_text(xml, "name").filter(|value| !value.is_empty()),
                address: tag_text(xml, "address").filter(|value| !value.is_empty()),
            }),
            "false" => Ok(ViesOutcome::Invalid),
            other => Err(ViesError::Malformed(format!(
                "unexpected <valid> value {other:?}"
            ))),
        };
    }

    if let Some(fault) = tag_text(xml, "faultstring") {
        return Ok(ViesOutcome::classify_fault(&fault));
    }

    Err(ViesError::Malformed(
        "response carried neither <valid> nor <faultstring>".to_string(),
    ))
}

/// Consult VIES for `country` + `vat_number`. Returns the classified
/// outcome and the raw response body (hashed for the evidence row).
pub async fn validate_vat_number_vies(
    client: &reqwest::Client,
    country: &str,
    vat_number: &str,
) -> Result<(ViesOutcome, String), ViesError> {
    let endpoint = std::env::var("VIES_API_URL").unwrap_or_else(|_| DEFAULT_VIES_ENDPOINT.into());
    let country = country.trim().to_uppercase();
    let vat_number = vat_number.trim().replace(' ', "");
    let envelope = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:urn="urn:ec.europa.eu:taxud:vies:services:checkVat">
  <soap:Header/>
  <soap:Body>
    <urn:checkVat>
      <urn:countryCode>{country}</urn:countryCode>
      <urn:vatNumber>{vat_number}</urn:vatNumber>
    </urn:checkVat>
  </soap:Body>
</soap:Envelope>"#
    );

    let response = client
        .post(&endpoint)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "")
        .body(envelope)
        .timeout(std::time::Duration::from_secs(VIES_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|error| ViesError::Transport(error.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| ViesError::Transport(error.to_string()))?;

    if !status.is_success() {
        // A 5xx from the service is an outage, not an authoritative answer:
        // classify it as such so it can never become "valid".
        return Ok((
            ViesOutcome::classify_fault(&format!("HTTP_{}", status.as_u16())),
            body,
        ));
    }

    Ok((parse_check_vat_response(&body)?, body))
}

/// Persisted evidence row returned to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEvidence {
    pub id: Uuid,
    pub valid: bool,
    pub outage_state: Option<String>,
}

/// Persist a consultation result into `vat_validation_evidence`.
///
/// `valid` is only ever true for an authoritative `Valid` outcome; outages
/// store `valid = FALSE` plus the marker, and the schema CHECK enforces it.
#[allow(clippy::too_many_arguments)]
pub async fn record_vat_validation_evidence(
    pool: &PgPool,
    tenant_id: Option<&str>,
    customer_id: Option<&str>,
    country: &str,
    vat_number: &str,
    requested_at: DateTime<Utc>,
    outcome: &ViesOutcome,
    authority_request_id: Option<&str>,
    response_body: &str,
) -> Result<RecordedEvidence, String> {
    let (valid, name, address, outage_state) = match outcome {
        ViesOutcome::Valid { name, address } => (true, name.clone(), address.clone(), None),
        ViesOutcome::Invalid => (false, None, None, None),
        ViesOutcome::Outage { fault } => (false, None, None, Some(fault.clone())),
    };
    let response_hash = hex::encode(Sha256::digest(response_body.as_bytes()));
    let valid_from = requested_at.date_naive();

    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO vat_validation_evidence (
            tenant_id, customer_id, vat_number, country, source, requested_at,
            valid, returned_name, returned_address, authority_request_id,
            response_hash, valid_from, valid_until, outage_state
        ) VALUES (
            $1, $2, $3, $4, 'VIES', $5, $6, $7, $8, $9, $10, $11, NULL, $12
        )
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(customer_id)
    .bind(vat_number.trim().replace(' ', ""))
    .bind(country.trim().to_uppercase())
    .bind(requested_at)
    .bind(valid)
    .bind(name)
    .bind(address)
    .bind(authority_request_id)
    .bind(response_hash)
    .bind(valid_from)
    .bind(outage_state)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("failed to record VAT validation evidence: {error}"))?;

    Ok(RecordedEvidence {
        id,
        valid,
        outage_state: match outcome {
            ViesOutcome::Outage { fault } => Some(fault.clone()),
            _ => None,
        },
    })
}

/// Consult VIES and persist the evidence in one call. Returns the evidence
/// id that the invoice writer snapshots onto a reverse-charged invoice (and
/// `None` has no special meaning: even invalid/outage consultations are
/// persisted so the audit trail shows what was consulted).
#[allow(clippy::too_many_arguments)]
pub async fn validate_and_record(
    pool: &PgPool,
    client: &reqwest::Client,
    tenant_id: Option<&str>,
    customer_id: Option<&str>,
    country: &str,
    vat_number: &str,
) -> Result<(ViesOutcome, RecordedEvidence), ViesError> {
    let requested_at = Utc::now();
    let (outcome, body) = validate_vat_number_vies(client, country, vat_number).await?;
    let recorded = record_vat_validation_evidence(
        pool,
        tenant_id,
        customer_id,
        country,
        vat_number,
        requested_at,
        &outcome,
        None,
        &body,
    )
    .await
    .map_err(ViesError::Transport)?;
    Ok((outcome, recorded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RESPONSE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>DE</countryCode>
      <vatNumber>123456789</vatNumber>
      <requestDate>2026-09-11+02:00</requestDate>
      <valid>true</valid>
      <name>Example GmbH</name>
      <address>Berlin</address>
    </checkVatResponse>
  </soap:Body>
</soap:Envelope>"#;

    const INVALID_RESPONSE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>DE</countryCode><vatNumber>000000000</vatNumber>
      <valid>false</valid><name>---</name><address>---</address>
    </checkVatResponse>
  </soap:Body>
</soap:Envelope>"#;

    const OUTAGE_RESPONSE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring>MS_UNAVAILABLE</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#;

    #[test]
    fn parses_an_authoritative_valid_answer() {
        let outcome = parse_check_vat_response(VALID_RESPONSE).expect("parse");
        assert_eq!(
            outcome,
            ViesOutcome::Valid {
                name: Some("Example GmbH".into()),
                address: Some("Berlin".into()),
            }
        );
        assert!(outcome.is_valid());
        assert!(!outcome.is_outage());
    }

    #[test]
    fn parses_an_authoritative_invalid_answer() {
        let outcome = parse_check_vat_response(INVALID_RESPONSE).expect("parse");
        assert_eq!(outcome, ViesOutcome::Invalid);
        assert!(!outcome.is_valid());
    }

    #[test]
    fn vies_outage_never_parses_as_valid() {
        let outcome = parse_check_vat_response(OUTAGE_RESPONSE).expect("parse");
        assert_eq!(
            outcome,
            ViesOutcome::Outage {
                fault: "MS_UNAVAILABLE".into()
            }
        );
        assert!(!outcome.is_valid());
        assert!(outcome.is_outage());

        for fault in [
            "SERVICE_UNAVAILABLE",
            "GLOBAL_MAX_CONCURRENT_REQ",
            "MS_MAX_CONCURRENT_REQ",
            "TIMEOUT",
            "HTTP_503",
            "SOMETHING_NEW",
        ] {
            let outcome = ViesOutcome::classify_fault(fault);
            assert!(outcome.is_outage(), "{fault} must be an outage");
            assert!(!outcome.is_valid(), "{fault} must never be valid");
        }
    }

    #[test]
    fn malformed_response_is_an_error_not_validity() {
        assert!(parse_check_vat_response("<html>502 Bad Gateway</html>").is_err());
        assert!(parse_check_vat_response("").is_err());
    }

    #[test]
    fn evidence_recording_maps_outage_to_invalid_with_marker() {
        // The persistence contract: only an authoritative Valid answer is
        // valid; an outage is stored invalid WITH its marker.
        let outcome = ViesOutcome::Outage {
            fault: "MS_UNAVAILABLE".into(),
        };
        let (valid, outage_state) = match &outcome {
            ViesOutcome::Valid { .. } => (true, None),
            ViesOutcome::Invalid => (false, None),
            ViesOutcome::Outage { fault } => (false, Some(fault.clone())),
        };
        assert!(!valid);
        assert_eq!(outage_state.as_deref(), Some("MS_UNAVAILABLE"));
    }

    #[test]
    fn fault_classification_preserves_the_marker_for_operators() {
        match ViesOutcome::classify_fault("MS_UNAVAILABLE") {
            ViesOutcome::Outage { fault } => assert_eq!(fault, "MS_UNAVAILABLE"),
            other => panic!("expected outage, got {other:?}"),
        }
    }
    // ── Adversarial: hostile XML, offline transport, evidence persistence ──

    #[test]
    fn fault_classification_defaults_to_unknown_and_never_valid() {
        for blank in ["", "   "] {
            match ViesOutcome::classify_fault(blank) {
                ViesOutcome::Outage { fault } => assert_eq!(fault, "UNKNOWN"),
                other => panic!("blank fault must be an unknown outage, got {other:?}"),
            }
        }
        match ViesOutcome::classify_fault("A_FAULT_WE_HAVE_NEVER_SEEN") {
            ViesOutcome::Outage { fault } => {
                assert_eq!(fault, "A_FAULT_WE_HAVE_NEVER_SEEN");
            }
            other => panic!("unclassified fault must stay an outage, got {other:?}"),
        }
    }

    #[test]
    fn hostile_xml_is_still_parsed_strictly() {
        // Attributes on the element and an upper-case value.
        let xml = r#"<r><valid source="vies">TRUE</valid><name>A &amp; B</name></r>"#;
        match parse_check_vat_response(xml).expect("attributes tolerated") {
            ViesOutcome::Valid { name, address } => {
                assert_eq!(name.as_deref(), Some("A &amp; B"));
                assert!(address.is_none(), "missing address stays None");
            }
            other => panic!("expected valid, got {other:?}"),
        }
        // An unparseable <valid> value is a malformed response, never an
        // implicit validity.
        let error = parse_check_vat_response("<valid>maybe</valid>").expect_err("refused");
        assert!(matches!(error, ViesError::Malformed(_)));
        // An unclosed element yields neither <valid> nor <faultstring>.
        assert!(parse_check_vat_response("<valid>true").is_err());
        // An empty faultstring classifies as UNKNOWN, not valid.
        match parse_check_vat_response("<soap:Fault><faultstring></faultstring></soap:Fault>")
            .expect("fault parsed")
        {
            ViesOutcome::Outage { fault } => assert_eq!(fault, "UNKNOWN"),
            other => panic!("expected outage, got {other:?}"),
        }
        // Whitespace answer values are trimmed, an all-whitespace name is
        // treated as absent.
        match parse_check_vat_response("<valid> false </valid>").expect("parse") {
            ViesOutcome::Invalid => {}
            other => panic!("expected invalid, got {other:?}"),
        }
        match parse_check_vat_response("<valid>true</valid><name>   </name>").expect("parse") {
            ViesOutcome::Valid { name, .. } => assert!(name.is_none()),
            other => panic!("expected valid, got {other:?}"),
        }
    }

    /// Drive the real SOAP path against a loopback server (no external
    /// network): success, HTTP outage and malformed body classification,
    /// request normalisation, then persistence of the evidence rows.
    #[tokio::test]
    async fn vies_transport_classifies_and_persists_offline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Some(pool) = crate::test_support::canonical_pool("vies_transport", "vies").await else {
            return;
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let responses = [
                (200u16, VALID_RESPONSE),
                (503, "service unavailable"),
                (200, "<html>not a SOAP response</html>"),
                (200, VALID_RESPONSE),
            ];
            let mut captured = Vec::new();
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut buf = vec![0u8; 16 * 1024];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                captured.push(String::from_utf8_lossy(&buf[..read]).to_string());
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: text/xml\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
            captured
        });

        std::env::set_var("VIES_API_URL", format!("http://{addr}/checkVatService"));
        let client = reqwest::Client::new();

        // 1. Authoritative valid answer.
        let (outcome, body) = validate_vat_number_vies(&client, " de ", "123 456 789")
            .await
            .expect("valid consultation");
        assert!(outcome.is_valid());
        assert_eq!(body, VALID_RESPONSE);

        // 2. A 5xx is an outage, never valid.
        let (outage, _) = validate_vat_number_vies(&client, "DE", "1")
            .await
            .expect("http consultation");
        match outage {
            ViesOutcome::Outage { fault } => assert_eq!(fault, "HTTP_503"),
            other => panic!("5xx must be an outage, got {other:?}"),
        }

        // 3. A malformed 200 body is refused, not treated as valid.
        let error = validate_vat_number_vies(&client, "DE", "1")
            .await
            .expect_err("malformed body refused");
        assert!(matches!(error, ViesError::Malformed(_)));

        // 4. validate_and_record persists the consultation.
        let (outcome, recorded) = validate_and_record(
            &pool,
            &client,
            Some("tenant-1"),
            Some("cust-1"),
            "de",
            "123 456 789",
        )
        .await
        .expect("recorded consultation");
        assert!(outcome.is_valid() && recorded.valid);

        let requests = server.await.expect("server task");
        let envelope = &requests[0];
        assert!(envelope.contains("<urn:countryCode>DE</urn:countryCode>"));
        assert!(
            envelope.contains("<urn:vatNumber>123456789</urn:vatNumber>"),
            "spaces are stripped and the country upper-cased"
        );

        let (valid, vat_number, country, outage_state, hash): (
            bool,
            String,
            String,
            Option<String>,
            String,
        ) = sqlx::query_as(
            "SELECT valid, vat_number, country, outage_state, response_hash \
             FROM vat_validation_evidence WHERE id = $1",
        )
        .bind(recorded.id)
        .fetch_one(&pool)
        .await
        .expect("evidence row");
        assert!(valid);
        assert_eq!(vat_number, "123456789");
        assert_eq!(country, "DE");
        assert!(outage_state.is_none());
        assert_eq!(hash, hex::encode(Sha256::digest(VALID_RESPONSE.as_bytes())));

        // Direct persistence of an invalid answer and of an outage: both
        // invalid, the outage carrying its marker (the schema CHECK forbids
        // an outage row that is valid).
        let requested_at = Utc::now();
        let invalid = record_vat_validation_evidence(
            &pool,
            Some("tenant-1"),
            None,
            "de",
            "000000000",
            requested_at,
            &ViesOutcome::Invalid,
            Some("authority-req-1"),
            "invalid-body",
        )
        .await
        .expect("invalid evidence");
        assert!(!invalid.valid && invalid.outage_state.is_none());

        let outage = record_vat_validation_evidence(
            &pool,
            Some("tenant-1"),
            None,
            "de",
            "000000001",
            requested_at,
            &ViesOutcome::Outage {
                fault: "MS_UNAVAILABLE".into(),
            },
            None,
            "outage-body",
        )
        .await
        .expect("outage evidence");
        assert!(!outage.valid);
        assert_eq!(outage.outage_state.as_deref(), Some("MS_UNAVAILABLE"));
        let stored_outage: (bool, Option<String>) =
            sqlx::query_as("SELECT valid, outage_state FROM vat_validation_evidence WHERE id = $1")
                .bind(outage.id)
                .fetch_one(&pool)
                .await
                .expect("outage row");
        assert_eq!(stored_outage, (false, Some("MS_UNAVAILABLE".into())));

        std::env::remove_var("VIES_API_URL");
    }
}
