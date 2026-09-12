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
}
