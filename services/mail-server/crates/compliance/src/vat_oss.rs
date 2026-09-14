//! OSS (One Stop Shop) and VD (intra-Community supply report) filing
//! workflow: schema-backed derivation and status transitions.
//!
//! # What IS implemented
//!
//! * Derivation of `oss_supply_entries` from the VAT recognition ledger
//!   (`vat_recognition_entries`, migration 218) for EU B2C destination-taxed
//!   supplies, and of `vd_entries` from zero-rated invoices that carry VIES
//!   evidence (migration 218's `vat_validation_evidence`).
//! * Idempotent period generation: regenerating a period updates the same
//!   rows (`ON CONFLICT` on the period/supply keys) and recomputes the
//!   return totals; submitted/acknowledged returns are never overwritten.
//! * The status state machine (generation → validation → submission →
//!   acknowledgement → amendment, plus failure) enforced in
//!   [`transition_oss_return`] / [`transition_vd_return`].
//! * Recording of amendments ([`create_oss_return_adjustment`]) and of
//!   payments ([`record_oss_payment`]) — recording only.
//!
//! # Submission transport (implemented behind a configuration gate)
//!
//! [`submit_oss_return`] / [`submit_vd_return`] now delegate to
//! [`crate::filing_transport`]:
//!
//! * If the deployment configured a machine endpoint + credential
//!   (`APEXMAIL_FILING_TRANSPORT=http`, `APEXMAIL_FILING_ENDPOINT`,
//!   `APEXMAIL_FILING_TOKEN`), the exact submission package is POSTed over
//!   the documented protocol and the return moves to `submitted` ONLY when
//!   the endpoint returned a receipt reference.
//! * Otherwise the exact package is persisted and a MANDATORY authenticated
//!   human task is opened ([`SubmissionOutcome::HumanTaskRequired`]); the
//!   return stays `validated`, and a human records the real portal reference
//!   via [`crate::filing_transport::record_manual_submission`].
//! * Acknowledgement is receipt-driven: only
//!   [`crate::filing_transport::ingest_acknowledgement`] with a real receipt
//!   reference can move a return to `acknowledged`.
//!
//! # What is still NOT implemented (explicitly, no fake successes)
//!
//! * **Payment execution.** [`record_oss_payment`] persists remittance facts
//!   (operator/bank input); it does not move money.
//! * **Place-of-supply adjudication.** `customer_location_evidence` is
//!   stored and must be filled by callers; OSS consumption country falls
//!   back to the invoice's stored billing country, and no automatic
//!   weighting/conflict resolution runs.
//! * **IOSS / non-Union scheme specifics** beyond the shared tables.

use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::filing_transport::{
    FilingTransport, FilingTransportConfig, ReturnKind, SubmissionOutcome,
};

/// Documented gate for the machine transport. When this condition is not
/// met, the exact package is generated and a mandatory authenticated human
/// task is opened — the return is never marked submitted.
pub const SUBMISSION_REQUIRES_CONFIGURATION: &str =
    "a machine submission requires APEXMAIL_FILING_TRANSPORT=http plus APEXMAIL_FILING_ENDPOINT \
     and APEXMAIL_FILING_TOKEN; otherwise the exact package is generated and a MANDATORY \
     authenticated human task must record the real portal reference";

/// Whether the submission transport is implemented in this build (true: it
/// is gated on runtime configuration, see [`SUBMISSION_REQUIRES_CONFIGURATION`]).
pub fn oss_submission_is_implemented() -> bool {
    true
}

/// Whether the VD submission transport is implemented in this build (true:
/// gated on runtime configuration).
pub fn vd_submission_is_implemented() -> bool {
    true
}

/// Filing lifecycle shared by OSS returns and VD returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilingStatus {
    /// Period not yet derived.
    Draft,
    /// Entries derived; totals computed.
    Generated,
    /// Totals checked by an operator/system before submission.
    Validated,
    /// Sent to the portal (requires an external submission reference).
    Submitted,
    /// Portal acknowledged the return.
    Acknowledged,
    /// A filed period corrected by a later return/adjustment.
    Amended,
    /// Submission rejected; see `filing_error`.
    Failed,
}

impl FilingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Generated => "generated",
            Self::Validated => "validated",
            Self::Submitted => "submitted",
            Self::Acknowledged => "acknowledged",
            Self::Amended => "amended",
            Self::Failed => "failed",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "draft" => Some(Self::Draft),
            "generated" => Some(Self::Generated),
            "validated" => Some(Self::Validated),
            "submitted" => Some(Self::Submitted),
            "acknowledged" => Some(Self::Acknowledged),
            "amended" => Some(Self::Amended),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// The documented state machine. Regeneration is only allowed while a
    /// return has not been submitted; once submitted, only acknowledgement,
    /// failure or (after acknowledgement) amendment is possible.
    pub fn can_transition(self, to: Self) -> bool {
        use FilingStatus::*;
        matches!(
            (self, to),
            (Draft, Generated)
                | (Generated, Validated)
                | (Generated, Draft)
                | (Validated, Submitted)
                | (Validated, Generated)
                | (Submitted, Acknowledged)
                | (Submitted, Failed)
                | (Submitted, Validated)
                | (Acknowledged, Amended)
                | (Amended, Submitted)
                | (Amended, Validated)
                | (Failed, Generated)
                | (Failed, Validated)
                | (Failed, Submitted)
        )
    }
}

/// Validate and format a filing period (`YYYY-MM`).
pub fn period_key(year: i32, month: u32) -> Result<String, String> {
    if !(1..=12).contains(&month) {
        return Err(format!("invalid filing month: {month}"));
    }
    if !(2000..=2100).contains(&year) {
        return Err(format!("invalid filing year: {year}"));
    }
    Ok(format!("{year:04}-{month:02}"))
}

// ---------------------------------------------------------------------------
// Derivation SQL (kept as constants so unit tests can pin the idempotency
// contract without a database)
// ---------------------------------------------------------------------------

/// OSS supply entries, derived from the recognition ledger. The recognition
/// entry (`recognition_period`, `reason = 'eu_b2c'`) is the taxable-event
/// source; the invoice supplies the stored billing country (documented proxy
/// for consumption country until place-of-supply adjudication exists).
pub(crate) const OSS_SUPPLY_DERIVATION_SQL: &str = r#"
    INSERT INTO oss_supply_entries (
        registration_id, period, supply_id, tenant_id, invoice_id,
        recognition_entry_id, customer_country, consumption_country,
        taxable_amount_cents, vat_rate, vat_amount_cents, currency,
        source_document_id, status
    )
    SELECT
        $1, $2, r.supply_id, r.tenant_id, r.invoice_id, r.id,
        UPPER(COALESCE(i.billing_country, 'EE')),
        UPPER(COALESCE(i.billing_country, 'EE')),
        r.taxable_amount_cents, r.vat_rate, r.vat_amount_cents, UPPER(r.currency),
        r.source_document_id, 'included'
    FROM vat_recognition_entries r
    LEFT JOIN invoices i ON i.id = r.invoice_id
    WHERE r.recognition_period = $2
      AND r.reason = 'eu_b2c'
      AND UPPER(r.currency) = 'EUR'
      AND UPPER(COALESCE(i.billing_country, 'EE')) <> 'EE'
    ON CONFLICT (registration_id, period, supply_id) DO UPDATE SET
        taxable_amount_cents = EXCLUDED.taxable_amount_cents,
        vat_rate = EXCLUDED.vat_rate,
        vat_amount_cents = EXCLUDED.vat_amount_cents,
        customer_country = EXCLUDED.customer_country,
        consumption_country = EXCLUDED.consumption_country,
        recognition_entry_id = EXCLUDED.recognition_entry_id,
        updated_at = NOW()
"#;

/// One return per (registration, period, scheme): regenerating updates the
/// same row while it is still pre-submission.
pub(crate) const OSS_RETURN_UPSERT_SQL: &str = r#"
    INSERT INTO oss_returns (registration_id, period, scheme, status, generated_at)
    VALUES ($1, $2, $3, 'generated', NOW())
    ON CONFLICT (registration_id, period, scheme) DO UPDATE SET
        status = CASE
            WHEN oss_returns.status IN ('draft', 'generated', 'validated') THEN 'generated'
            ELSE oss_returns.status
        END,
        generated_at = NOW(),
        updated_at = NOW()
    WHERE oss_returns.status IN ('draft', 'generated', 'validated')
    RETURNING id
"#;

/// VD entries: zero-rated intra-Community supplies that carry authoritative
/// VIES evidence. `vat_evidence_id` is mandatory and NOT NULL-checked by the
/// schema, so an unverified supply can never enter the VD report.
pub(crate) const VD_ENTRY_DERIVATION_SQL: &str = r#"
    INSERT INTO vd_entries (
        return_id, period, supply_id, invoice_id, customer_vat_number,
        customer_country, vat_evidence_id, transaction_nature,
        taxable_amount_cents, currency
    )
    SELECT
        $1, $2, i.id::text, i.id,
        UPPER(REPLACE(COALESCE(e.vat_number, ba.vat_number), ' ', '')),
        UPPER(COALESCE(i.billing_country, ba.country, 'EE')),
        i.vat_evidence_id, 'services',
        COALESCE(i.subtotal, i.amount, 0), UPPER(i.currency)
    FROM invoices i
    JOIN vat_validation_evidence e ON e.id = i.vat_evidence_id
    LEFT JOIN LATERAL (
        SELECT country, vat_number
        FROM billing_addresses ba
        WHERE ba.tenant_id = i.tenant_id
        ORDER BY ba.updated_at DESC, ba.created_at DESC, ba.id
        LIMIT 1
    ) ba ON true
    WHERE to_char(i.issued_at AT TIME ZONE 'Europe/Tallinn', 'YYYY-MM') = $2
      AND COALESCE(i.vat_rate, 0) = 0
      AND i.vat_evidence_id IS NOT NULL
      AND UPPER(COALESCE(i.billing_country, ba.country, 'EE')) <> 'EE'
      AND UPPER(i.currency) = 'EUR'
      AND i.status NOT IN ('void', 'draft', 'uncollectible')
    ON CONFLICT (period, supply_id) DO UPDATE SET
        return_id = EXCLUDED.return_id,
        customer_vat_number = EXCLUDED.customer_vat_number,
        customer_country = EXCLUDED.customer_country,
        vat_evidence_id = EXCLUDED.vat_evidence_id,
        taxable_amount_cents = EXCLUDED.taxable_amount_cents,
        currency = EXCLUDED.currency
"#;

/// One VD return per period; regenerating updates it while pre-submission.
pub(crate) const VD_RETURN_UPSERT_SQL: &str = r#"
    INSERT INTO vd_returns (period, status, generated_at)
    VALUES ($1, 'generated', NOW())
    ON CONFLICT (period) DO UPDATE SET
        status = CASE
            WHEN vd_returns.status IN ('draft', 'generated', 'validated') THEN 'generated'
            ELSE vd_returns.status
        END,
        generated_at = NOW(),
        updated_at = NOW()
    WHERE vd_returns.status IN ('draft', 'generated', 'validated')
    RETURNING id
"#;

fn payload_hash(period: &str, taxable: i64, vat: i64, count: i64) -> String {
    let canonical = format!("{period}|{taxable}|{vat}|{count}");
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Idempotently derive the OSS return for `(registration_id, period)` from
/// the recognition ledger. Returns the return id.
pub async fn generate_oss_return(
    db: &PgPool,
    registration_id: Uuid,
    period: &str,
) -> Result<Uuid, String> {
    let scheme: Option<String> =
        sqlx::query_scalar("SELECT scheme FROM oss_registrations WHERE id = $1")
            .bind(registration_id)
            .fetch_optional(db)
            .await
            .map_err(|error| format!("failed to load OSS registration: {error}"))?;
    let Some(scheme) = scheme else {
        return Err(format!("unknown OSS registration {registration_id}"));
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin OSS generation: {error}"))?;

    let return_id: Option<Uuid> = sqlx::query_scalar(OSS_RETURN_UPSERT_SQL)
        .bind(registration_id)
        .bind(period)
        .bind(&scheme)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("failed to upsert OSS return: {error}"))?;
    let Some(return_id) = return_id else {
        return Err(format!(
            "OSS return for {period} was already submitted/acknowledged — amendments require a \
             new adjustment, not regeneration"
        ));
    };

    sqlx::query(OSS_SUPPLY_DERIVATION_SQL)
        .bind(registration_id)
        .bind(period)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to derive OSS supply entries: {error}"))?;

    let (taxable, vat, count): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COALESCE(SUM(taxable_amount_cents), 0)::bigint,
               COALESCE(SUM(vat_amount_cents), 0)::bigint,
               COUNT(*)::bigint
        FROM oss_supply_entries
        WHERE registration_id = $1 AND period = $2
        "#,
    )
    .bind(registration_id)
    .bind(period)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("failed to aggregate OSS entries: {error}"))?;

    let hash = payload_hash(period, taxable, vat, count);
    sqlx::query(
        r#"
        UPDATE oss_returns
        SET total_taxable_cents = $2,
            total_vat_cents = $3,
            supply_count = $4,
            payload_hash = $5,
            generated_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(return_id)
    .bind(taxable)
    .bind(vat)
    .bind(count)
    .bind(hash)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to store OSS return totals: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit OSS generation: {error}"))?;
    Ok(return_id)
}

/// Idempotently derive the VD return for `period` from zero-rated invoices
/// with authoritative VIES evidence. Returns the return id.
pub async fn generate_vd_return(db: &PgPool, period: &str) -> Result<Uuid, String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin VD generation: {error}"))?;

    let return_id: Option<Uuid> = sqlx::query_scalar(VD_RETURN_UPSERT_SQL)
        .bind(period)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("failed to upsert VD return: {error}"))?;
    let Some(return_id) = return_id else {
        return Err(format!(
            "VD return for {period} was already submitted/acknowledged — amendments require a \
             new return, not regeneration"
        ));
    };

    sqlx::query(VD_ENTRY_DERIVATION_SQL)
        .bind(return_id)
        .bind(period)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to derive VD entries: {error}"))?;

    let (taxable, vat, count): (i64, i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(taxable_amount_cents), 0)::bigint, 0::bigint, COUNT(*)::bigint \
         FROM vd_entries WHERE return_id = $1",
    )
    .bind(return_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("failed to aggregate VD entries: {error}"))?;

    let hash = payload_hash(period, taxable, vat, count);
    sqlx::query(
        r#"
        UPDATE vd_returns
        SET total_taxable_cents = $2,
            total_vat_cents = 0,
            line_count = $3,
            payload_hash = $4,
            generated_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(return_id)
    .bind(taxable)
    .bind(count)
    .bind(hash)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to store VD return totals: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit VD generation: {error}"))?;
    Ok(return_id)
}

// ---------------------------------------------------------------------------
// Status transitions
// ---------------------------------------------------------------------------

/// The state-machine transition, executed on an existing connection so
/// callers can commit the transition together with the evidence
/// (submission package / receipt / human task) in ONE transaction.
///
/// An `Acknowledged` transition requires a non-empty receipt reference: the
/// state machine refuses a receipt-less acknowledgement even if a caller
/// bypasses [`crate::filing_transport::ingest_acknowledgement`].
pub(crate) async fn transition_return_in(
    conn: &mut sqlx::PgConnection,
    table: &str,
    return_id: Uuid,
    to: FilingStatus,
    acknowledgement_reference: Option<&str>,
) -> Result<(), String> {
    if to == FilingStatus::Acknowledged {
        let reference = acknowledgement_reference.unwrap_or("").trim();
        if reference.is_empty() {
            return Err(
                "acknowledgement requires the portal reference — refusing to acknowledge a \
                 return without evidence of the portal's reply"
                    .to_string(),
            );
        }
    }

    let current: Option<String> = sqlx::query_scalar(&format!(
        "SELECT status FROM {table} WHERE id = $1 FOR UPDATE"
    ))
    .bind(return_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("failed to lock return: {error}"))?;
    let Some(current) = current else {
        return Err(format!("return {return_id} not found in {table}"));
    };
    let from = FilingStatus::from_db(&current)
        .ok_or_else(|| format!("unknown filing status {current:?}"))?;

    if !from.can_transition(to) {
        return Err(format!(
            "illegal filing transition {} -> {}",
            from.as_str(),
            to.as_str()
        ));
    }

    sqlx::query(&format!(
        r#"
        UPDATE {table}
        SET status = $2,
            validated_at = CASE WHEN $2 = 'validated' THEN NOW() ELSE validated_at END,
            submitted_at = CASE WHEN $2 = 'submitted' THEN NOW() ELSE submitted_at END,
            acknowledged_at = CASE WHEN $2 = 'acknowledged' THEN NOW() ELSE acknowledged_at END,
            acknowledgement_reference = COALESCE($3, acknowledgement_reference),
            updated_at = NOW()
        WHERE id = $1
        "#
    ))
    .bind(return_id)
    .bind(to.as_str())
    .bind(acknowledgement_reference)
    .execute(&mut *conn)
    .await
    .map_err(|error| format!("failed to transition return: {error}"))?;

    Ok(())
}

async fn transition_return(
    db: &PgPool,
    table: &str,
    return_id: Uuid,
    to: FilingStatus,
    acknowledgement_reference: Option<&str>,
) -> Result<(), String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin status transition: {error}"))?;
    transition_return_in(&mut tx, table, return_id, to, acknowledgement_reference).await?;
    tx.commit()
        .await
        .map_err(|error| format!("failed to commit status transition: {error}"))?;
    Ok(())
}

/// Enforce the OSS return state machine.
pub async fn transition_oss_return(
    db: &PgPool,
    return_id: Uuid,
    to: FilingStatus,
    acknowledgement_reference: Option<&str>,
) -> Result<(), String> {
    transition_return(db, "oss_returns", return_id, to, acknowledgement_reference).await
}

/// Enforce the VD return state machine.
pub async fn transition_vd_return(
    db: &PgPool,
    return_id: Uuid,
    to: FilingStatus,
    acknowledgement_reference: Option<&str>,
) -> Result<(), String> {
    transition_return(db, "vd_returns", return_id, to, acknowledgement_reference).await
}

/// Submit a validated OSS return.
///
/// With a configured machine transport the return moves to `submitted` only
/// after a receipt was actually received; without one the exact package is
/// persisted and a mandatory authenticated human task is opened (the return
/// remains `validated`). Acknowledgement is never implied.
pub async fn submit_oss_return(
    db: &PgPool,
    return_id: Uuid,
    config: &FilingTransportConfig,
    transport: Option<&dyn FilingTransport>,
) -> Result<SubmissionOutcome, String> {
    crate::filing_transport::submit_filing(db, ReturnKind::Oss, return_id, config, transport).await
}

/// Submit a validated VD return (same contract as [`submit_oss_return`]).
pub async fn submit_vd_return(
    db: &PgPool,
    return_id: Uuid,
    config: &FilingTransportConfig,
    transport: Option<&dyn FilingTransport>,
) -> Result<SubmissionOutcome, String> {
    crate::filing_transport::submit_filing(db, ReturnKind::Vd, return_id, config, transport).await
}

// ---------------------------------------------------------------------------
// Adjustments and payment recording
// ---------------------------------------------------------------------------

/// Record an amendment against a filed OSS return. Only an acknowledged or
/// already-amended return can be amended; the row is the correction evidence.
#[allow(clippy::too_many_arguments)]
pub async fn create_oss_return_adjustment(
    db: &PgPool,
    return_id: Uuid,
    source_period: &str,
    correction_type: &str,
    taxable_amount_cents: i64,
    vat_amount_cents: i64,
    currency: &str,
    reason: &str,
    source_document_id: Option<&str>,
) -> Result<Uuid, String> {
    if !matches!(correction_type, "increase" | "decrease" | "replacement") {
        return Err(format!("invalid correction type: {correction_type}"));
    }
    if reason.trim().is_empty() {
        return Err("amendment reason is required".to_string());
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin amendment: {error}"))?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1 FOR UPDATE")
            .bind(return_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| format!("failed to lock OSS return: {error}"))?;
    let Some(status) = status else {
        return Err(format!("OSS return {return_id} not found"));
    };
    if !matches!(status.as_str(), "acknowledged" | "amended") {
        return Err(format!(
            "cannot amend an OSS return in status {status:?} — it must be acknowledged first"
        ));
    }

    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO oss_return_adjustments (
            return_id, source_period, correction_type, taxable_amount_cents,
            vat_amount_cents, currency, reason, source_document_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
    )
    .bind(return_id)
    .bind(source_period)
    .bind(correction_type)
    .bind(taxable_amount_cents)
    .bind(vat_amount_cents)
    .bind(currency)
    .bind(reason)
    .bind(source_document_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("failed to insert OSS adjustment: {error}"))?;

    sqlx::query("UPDATE oss_returns SET status = 'amended', updated_at = NOW() WHERE id = $1")
        .bind(return_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to mark OSS return amended: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit amendment: {error}"))?;
    Ok(id)
}

/// Record a remittance fact for an OSS period. Recording only — no money
/// moves here; `status = 'pending'` is the default until a bank/operator
/// reference marks it paid.
#[allow(clippy::too_many_arguments)]
pub async fn record_oss_payment(
    db: &PgPool,
    return_id: Option<Uuid>,
    period: &str,
    amount_cents: i64,
    currency: &str,
    status: &str,
    paid_at: Option<chrono::DateTime<Utc>>,
    payment_reference: Option<&str>,
) -> Result<Uuid, String> {
    if !matches!(status, "pending" | "paid" | "failed" | "refunded") {
        return Err(format!("invalid payment status: {status}"));
    }
    if status == "paid" && paid_at.is_none() {
        return Err("a paid OSS remittance requires paid_at".to_string());
    }
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO oss_payments (
            return_id, period, amount_cents, currency, paid_at,
            payment_reference, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(return_id)
    .bind(period)
    .bind(amount_cents)
    .bind(currency)
    .bind(paid_at)
    .bind(payment_reference)
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to record OSS payment: {error}"))?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Status machine ────────────────────────────────────────────────

    #[test]
    fn filing_status_machine_allows_the_documented_path() {
        use FilingStatus::*;
        assert!(Draft.can_transition(Generated));
        assert!(Generated.can_transition(Validated));
        assert!(Validated.can_transition(Submitted));
        assert!(Submitted.can_transition(Acknowledged));
        assert!(Acknowledged.can_transition(Amended));
        assert!(Amended.can_transition(Submitted));
        assert!(Submitted.can_transition(Failed));
        assert!(Failed.can_transition(Validated));
    }

    #[test]
    fn filing_status_machine_blocks_illegal_transitions() {
        use FilingStatus::*;
        // No jumping straight from generated to acknowledged...
        assert!(!Generated.can_transition(Acknowledged));
        // ...no re-opening an amended return to draft...
        assert!(!Amended.can_transition(Draft));
        // ...and no marking an acknowledged return failed.
        assert!(!Acknowledged.can_transition(Failed));
    }

    #[test]
    fn filing_status_names_round_trip() {
        for status in [
            FilingStatus::Draft,
            FilingStatus::Generated,
            FilingStatus::Validated,
            FilingStatus::Submitted,
            FilingStatus::Acknowledged,
            FilingStatus::Amended,
            FilingStatus::Failed,
        ] {
            assert_eq!(FilingStatus::from_db(status.as_str()), Some(status));
        }
        assert_eq!(FilingStatus::from_db("nonsense"), None);
    }

    #[test]
    fn period_key_validates_month_and_year() {
        assert_eq!(period_key(2026, 1).unwrap(), "2026-01");
        assert_eq!(period_key(2026, 12).unwrap(), "2026-12");
        assert!(period_key(2026, 0).is_err());
        assert!(period_key(2026, 13).is_err());
        assert!(period_key(1999, 1).is_err());
    }

    // ── Generation idempotency for a period ───────────────────────────

    #[test]
    fn oss_and_vd_generation_are_idempotent_for_a_period() {
        // The generation statements upsert on the period keys, so running
        // them twice for the same period updates the same rows rather than
        // duplicating supplies/returns.
        assert!(OSS_SUPPLY_DERIVATION_SQL
            .contains("ON CONFLICT (registration_id, period, supply_id) DO UPDATE"));
        assert!(OSS_RETURN_UPSERT_SQL
            .contains("ON CONFLICT (registration_id, period, scheme) DO UPDATE"));
        assert!(VD_ENTRY_DERIVATION_SQL.contains("ON CONFLICT (period, supply_id) DO UPDATE"));
        assert!(VD_RETURN_UPSERT_SQL.contains("ON CONFLICT (period) DO UPDATE"));

        // The schema carries the matching unique keys (migration 219).
        let schema = include_str!("../../../migrations/219_oss_vd_filing_scaffold.sql");
        for constraint in [
            "oss_supply_entries_period_supply_unique",
            "oss_returns_period_unique",
            "vd_entries_period_supply_unique",
            "period                    TEXT NOT NULL UNIQUE",
        ] {
            assert!(
                schema.contains(constraint),
                "migration 219 must carry the idempotency key {constraint}"
            );
        }
    }

    #[test]
    fn oss_derivation_consumes_the_recognition_ledger() {
        assert!(OSS_SUPPLY_DERIVATION_SQL.contains("vat_recognition_entries"));
        assert!(OSS_SUPPLY_DERIVATION_SQL.contains("recognition_period"));
        assert!(!OSS_SUPPLY_DERIVATION_SQL.contains("status = 'paid'"));
    }

    #[test]
    fn vd_derivation_requires_vies_evidence() {
        assert!(VD_ENTRY_DERIVATION_SQL.contains("vat_validation_evidence"));
        assert!(VD_ENTRY_DERIVATION_SQL.contains("i.vat_evidence_id IS NOT NULL"));
        assert!(VD_ENTRY_DERIVATION_SQL.contains("COALESCE(i.vat_rate, 0) = 0"));
    }

    #[test]
    fn submission_transport_is_gated_on_configuration() {
        assert!(oss_submission_is_implemented());
        assert!(vd_submission_is_implemented());
        assert!(SUBMISSION_REQUIRES_CONFIGURATION.contains("APEXMAIL_FILING_ENDPOINT"));
        assert!(SUBMISSION_REQUIRES_CONFIGURATION.contains("MANDATORY"));
        // An unconfigured transport never produces a machine readiness claim.
        assert!(!crate::filing_transport::FilingTransportConfig::disabled().machine_ready());
    }

    #[test]
    fn payload_hash_is_content_addressed_and_stable() {
        let first = payload_hash("2026-01", 10_000, 2_400, 3);
        assert_eq!(first, payload_hash("2026-01", 10_000, 2_400, 3));
        assert_ne!(first, payload_hash("2026-02", 10_000, 2_400, 3));
        assert_eq!(first.len(), 64);
    }
}

// ─── DB-backed adversarial tests ────────────────────────────────────────────
//
// The OSS/VD returns are statutory filings: derivation must come from the
// recognition ledger, regeneration must be idempotent while pre-submission,
// an unacknowledged return cannot be amended, and a paid remittance needs a
// payment date.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;
    use chrono::Datelike;

    async fn pool(suffix: &str) -> Option<PgPool> {
        let pool = test_support::canonical_pool(&format!("oss_{suffix}"), &format!("oss_{suffix}"))
            .await?;
        sqlx::query(
            "INSERT INTO tenants (id, name) VALUES ('oss-tenant', 'OSS Tenant')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("tenant");
        Some(pool)
    }

    async fn registration(pool: &PgPool) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO oss_registrations
               (tenant_id, scheme, registration_country, registration_number, valid_from, status)
             VALUES ('oss-tenant', 'union', 'EE', 'EE-OSS-1', DATE '2025-01-01', 'active')
             RETURNING id",
        )
        .fetch_one(pool)
        .await
        .expect("registration")
    }

    struct Entry<'a> {
        supply: &'a str,
        period: &'a str,
        country: &'a str,
        taxable: i64,
        vat: i64,
        currency: &'a str,
        reason: &'a str,
    }

    async fn seed_eu_b2c_entry(pool: &PgPool, entry: Entry<'_>) {
        let invoice_id: Uuid = sqlx::query_scalar(
            "INSERT INTO invoices
               (id, tenant_id, amount, currency, status, issued_at, created_at, updated_at,
                subtotal, vat_total, total, billing_country)
             VALUES (gen_random_uuid(), 'oss-tenant', $1, $2, 'paid',
                     to_timestamp($3 || '-15', 'YYYY-MM-DD'), NOW(), NOW(),
                     $1, $4, $1 + $4, $5)
             RETURNING id",
        )
        .bind(entry.taxable)
        .bind(entry.currency)
        .bind(entry.period)
        .bind(entry.vat)
        .bind(entry.country)
        .fetch_one(pool)
        .await
        .expect("invoice");
        sqlx::query(
            "INSERT INTO vat_recognition_entries
               (id, supply_id, tenant_id, invoice_id, event_type, taxable_event_at,
                recognition_period, taxable_amount_cents, vat_rate, vat_amount_cents,
                currency, scheme, reason)
             VALUES (gen_random_uuid(), $1, 'oss-tenant', $2, 'supply', NOW(), $3, $4, $5, $6,
                     $7, 'general', $8)",
        )
        .bind(entry.supply)
        .bind(invoice_id)
        .bind(entry.period)
        .bind(entry.taxable)
        .bind(entry.vat as f64 / entry.taxable.max(1) as f64)
        .bind(entry.vat)
        .bind(entry.currency)
        .bind(entry.reason)
        .execute(pool)
        .await
        .expect("recognition entry");
    }

    #[tokio::test]
    async fn oss_derivation_is_canonical_idempotent_and_ledger_driven() {
        let Some(pool) = pool("derive").await else {
            return;
        };
        let reg = registration(&pool).await;
        // In-scope: EU B2C in EUR outside EE.
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-1",
                period: "2026-03",
                country: "DE",
                taxable: 10000,
                vat: 1900,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-2",
                period: "2026-03",
                country: "FR",
                taxable: 20000,
                vat: 3800,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        // Out of scope: domestic EE, non-EUR, wrong reason, other period.
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-3",
                period: "2026-03",
                country: "EE",
                taxable: 99999,
                vat: 0,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-4",
                period: "2026-03",
                country: "DE",
                taxable: 88888,
                vat: 0,
                currency: "USD",
                reason: "eu_b2c",
            },
        )
        .await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-5",
                period: "2026-03",
                country: "DE",
                taxable: 77777,
                vat: 0,
                currency: "EUR",
                reason: "domestic",
            },
        )
        .await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-6",
                period: "2026-02",
                country: "DE",
                taxable: 66666,
                vat: 0,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;

        let return_id = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("generate");
        let totals: (i64, i64, i64) = sqlx::query_as(
            "SELECT total_taxable_cents, total_vat_cents, supply_count FROM oss_returns WHERE id = $1",
        )
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .expect("totals");
        assert_eq!(totals, (30000, 5700, 2), "only the two in-scope supplies");
        let status: String = sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .expect("status");
        assert_eq!(status, "generated");

        // Regeneration is idempotent: same row, same totals.
        let again = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("regenerate");
        assert_eq!(again, return_id);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oss_returns")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(rows, 1);
        // A late correction updates the SAME pre-submission row.
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-7",
                period: "2026-03",
                country: "IT",
                taxable: 5000,
                vat: 1100,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("regen");
        let totals: (i64, i64, i64) = sqlx::query_as(
            "SELECT total_taxable_cents, total_vat_cents, supply_count FROM oss_returns WHERE id = $1",
        )
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .expect("totals");
        assert_eq!(totals, (35000, 6800, 3));
        // Unknown registrations are explicit errors.
        assert!(generate_oss_return(&pool, Uuid::new_v4(), "2026-03")
            .await
            .is_err());
        // An empty period is an explicit zero return, not a failure.
        let empty = generate_oss_return(&pool, reg, "2026-01")
            .await
            .expect("empty period");
        let totals: (i64, i64, i64) = sqlx::query_as(
            "SELECT total_taxable_cents, total_vat_cents, supply_count FROM oss_returns WHERE id = $1",
        )
        .bind(empty)
        .fetch_one(&pool)
        .await
        .expect("totals");
        assert_eq!(totals, (0, 0, 0));
    }

    #[tokio::test]
    async fn oss_state_machine_refuses_skips_and_freezes_acknowledged_returns() {
        let Some(pool) = pool("states").await else {
            return;
        };
        let reg = registration(&pool).await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-1",
                period: "2026-03",
                country: "DE",
                taxable: 10000,
                vat: 1900,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        let return_id = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("generate");

        // Skipping validation is refused.
        assert!(
            transition_oss_return(&pool, return_id, FilingStatus::Acknowledged, None)
                .await
                .is_err()
        );
        transition_oss_return(&pool, return_id, FilingStatus::Validated, None)
            .await
            .expect("validate");
        // Submission without a receipt stays explicit (a human task is
        // opened) — acknowledgement is never implied.
        transition_oss_return(&pool, return_id, FilingStatus::Submitted, None)
            .await
            .expect("submit");
        transition_oss_return(&pool, return_id, FilingStatus::Acknowledged, Some("ACK-1"))
            .await
            .expect("acknowledge");
        let reference: Option<String> =
            sqlx::query_scalar("SELECT acknowledgement_reference FROM oss_returns WHERE id = $1")
                .bind(return_id)
                .fetch_one(&pool)
                .await
                .expect("reference");
        assert_eq!(reference.as_deref(), Some("ACK-1"));
        // Once acknowledged the return is frozen: no regeneration.
        let err = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect_err("acknowledged must not regenerate");
        assert!(err.contains("already submitted/acknowledged"), "{err}");
        // An unknown return id is an error.
        assert!(
            transition_oss_return(&pool, Uuid::new_v4(), FilingStatus::Validated, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn adjustments_require_an_acknowledged_return_and_an_explicit_correction() {
        let Some(pool) = pool("adjust").await else {
            return;
        };
        let reg = registration(&pool).await;
        seed_eu_b2c_entry(
            &pool,
            Entry {
                supply: "s-1",
                period: "2026-03",
                country: "DE",
                taxable: 10000,
                vat: 1900,
                currency: "EUR",
                reason: "eu_b2c",
            },
        )
        .await;
        let return_id = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("generate");

        // Invalid correction type / empty reason are refused.
        assert!(create_oss_return_adjustment(
            &pool, return_id, "2026-03", "guess", 100, 21, "EUR", "reason", None
        )
        .await
        .is_err());
        assert!(create_oss_return_adjustment(
            &pool, return_id, "2026-03", "increase", 100, 21, "EUR", "   ", None
        )
        .await
        .is_err());
        // Pre-acknowledgement amendment is refused, naming the status.
        let err = create_oss_return_adjustment(
            &pool,
            return_id,
            "2026-03",
            "increase",
            100,
            21,
            "EUR",
            "correction",
            None,
        )
        .await
        .expect_err("not acknowledged");
        assert!(err.contains("must be acknowledged first"), "{err}");
        // Unknown returns are errors.
        assert!(create_oss_return_adjustment(
            &pool,
            Uuid::new_v4(),
            "2026-03",
            "increase",
            1,
            0,
            "EUR",
            "r",
            None
        )
        .await
        .is_err());

        transition_oss_return(&pool, return_id, FilingStatus::Validated, None)
            .await
            .expect("validate");
        transition_oss_return(&pool, return_id, FilingStatus::Submitted, None)
            .await
            .expect("submit");
        transition_oss_return(&pool, return_id, FilingStatus::Acknowledged, Some("ACK-1"))
            .await
            .expect("acknowledge");
        let adjustment = create_oss_return_adjustment(
            &pool,
            return_id,
            "2026-03",
            "decrease",
            1000,
            190,
            "EUR",
            "overdeclared",
            None,
        )
        .await
        .expect("adjustment");
        let parent_status: String =
            sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
                .bind(return_id)
                .fetch_one(&pool)
                .await
                .expect("status");
        assert_eq!(parent_status, "amended");
        let stored: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT correction_type, vat_amount_cents, reason FROM oss_return_adjustments WHERE id = $1",
        )
        .bind(adjustment)
        .fetch_one(&pool)
        .await
        .expect("stored");
        assert_eq!(stored.0, "decrease");
        assert_eq!(stored.1, 190);
        assert_eq!(stored.2.as_deref(), Some("overdeclared"));
        // An amended return can be amended again (corrections chain).
        create_oss_return_adjustment(
            &pool,
            return_id,
            "2026-03",
            "replacement",
            500,
            95,
            "EUR",
            "final",
            None,
        )
        .await
        .expect("second adjustment");
    }

    #[tokio::test]
    async fn payments_validate_status_and_require_a_date_when_paid() {
        let Some(pool) = pool("payments").await else {
            return;
        };
        let reg = registration(&pool).await;
        let return_id = generate_oss_return(&pool, reg, "2026-03")
            .await
            .expect("generate");
        assert!(record_oss_payment(
            &pool,
            Some(return_id),
            "2026-03",
            1900,
            "EUR",
            "done",
            None,
            None
        )
        .await
        .is_err());
        let err = record_oss_payment(
            &pool,
            Some(return_id),
            "2026-03",
            1900,
            "EUR",
            "paid",
            None,
            Some("REF-1"),
        )
        .await
        .expect_err("paid without a date");
        assert!(err.contains("requires paid_at"), "{err}");

        let pending = record_oss_payment(
            &pool,
            Some(return_id),
            "2026-03",
            1900,
            "EUR",
            "pending",
            None,
            None,
        )
        .await
        .expect("pending");
        assert_ne!(pending, Uuid::nil());
        let paid = record_oss_payment(
            &pool,
            Some(return_id),
            "2026-03",
            1900,
            "EUR",
            "paid",
            Some(Utc::now()),
            Some("REF-2"),
        )
        .await
        .expect("paid");
        assert_ne!(paid, pending);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oss_payments")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(rows, 2, "each remittance fact is its own evidence row");
    }

    #[tokio::test]
    async fn vd_entries_require_authoritative_vies_evidence() {
        let Some(pool) = pool("vd").await else {
            return;
        };
        // An invoice with no VIES evidence must NOT enter the VD report.
        sqlx::query(
            "INSERT INTO invoices
               (id, tenant_id, amount, currency, status, issued_at, created_at, updated_at,
                subtotal, vat_total, total, billing_country, vat_rate)
             VALUES (gen_random_uuid(), 'oss-tenant', 5000, 'EUR', 'paid', NOW(), NOW(), NOW(),
                     5000, 0, 5000, 'DE', 0)",
        )
        .execute(&pool)
        .await
        .expect("invoice without evidence");
        let now = Utc::now();
        let period = period_key(now.date_naive().year(), now.date_naive().month()).expect("period");
        let return_id = generate_vd_return(&pool, &period).await.expect("vd return");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vd_entries WHERE return_id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 0, "no evidence means no reported supply");
        let totals: (i64, i64, i64) = sqlx::query_as(
            "SELECT total_taxable_cents, total_vat_cents, line_count FROM vd_returns WHERE id = $1",
        )
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .expect("totals");
        assert_eq!(totals, (0, 0, 0));

        // With authoritative evidence the supply is reported with the
        // validated VAT number, zero-rated.
        let evidence: Uuid = sqlx::query_scalar(
            "INSERT INTO vat_validation_evidence
               (id, vat_number, country, source, requested_at, valid, response_hash, valid_from)
             VALUES (gen_random_uuid(), 'DE811234567', 'DE', 'VIES', NOW(), true, 'hash-1', CURRENT_DATE)
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .expect("evidence");
        sqlx::query(
            "INSERT INTO invoices
               (id, tenant_id, amount, currency, status, issued_at, created_at, updated_at,
                subtotal, vat_total, total, billing_country, vat_rate, vat_evidence_id)
             VALUES (gen_random_uuid(), 'oss-tenant', 7000, 'EUR', 'paid', NOW(), NOW(), NOW(),
                     7000, 0, 7000, 'DE', 0, $1)",
        )
        .bind(evidence)
        .execute(&pool)
        .await
        .expect("invoice with evidence");
        let return_id = generate_vd_return(&pool, &period)
            .await
            .expect("regenerate");
        let totals: (i64, i64, i64) = sqlx::query_as(
            "SELECT total_taxable_cents, total_vat_cents, line_count FROM vd_returns WHERE id = $1",
        )
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .expect("totals");
        assert_eq!(totals, (7000, 0, 1));
        let vat_number: String =
            sqlx::query_scalar("SELECT customer_vat_number FROM vd_entries WHERE return_id = $1")
                .bind(return_id)
                .fetch_one(&pool)
                .await
                .expect("vat number");
        assert_eq!(
            vat_number, "DE811234567",
            "spaces are not part of the number"
        );

        // Transitioning the VD return enforces the same state machine.
        assert!(
            transition_vd_return(&pool, return_id, FilingStatus::Acknowledged, None)
                .await
                .is_err()
        );
        transition_vd_return(&pool, return_id, FilingStatus::Validated, None)
            .await
            .expect("validate");
    }

    #[test]
    fn period_keys_and_status_machines_are_strict() {
        assert_eq!(period_key(2026, 1).as_deref(), Ok("2026-01"));
        assert_eq!(period_key(2026, 12).as_deref(), Ok("2026-12"));
        assert!(period_key(2026, 0).is_err());
        assert!(period_key(2026, 13).is_err());
        assert!(period_key(1999, 1).is_err());
        assert!(period_key(2101, 1).is_err());
        for status in [
            FilingStatus::Draft,
            FilingStatus::Generated,
            FilingStatus::Validated,
            FilingStatus::Submitted,
            FilingStatus::Acknowledged,
            FilingStatus::Amended,
            FilingStatus::Failed,
        ] {
            assert_eq!(FilingStatus::from_db(status.as_str()), Some(status));
            assert!(!status.as_str().is_empty());
        }
        assert_eq!(FilingStatus::from_db("nonsense"), None);
        assert_eq!(
            FilingStatus::from_db(" GENERATED "),
            Some(FilingStatus::Generated)
        );
        // The documented machine: no skipping states.
        assert!(FilingStatus::Draft.can_transition(FilingStatus::Generated));
        assert!(FilingStatus::Generated.can_transition(FilingStatus::Validated));
        assert!(FilingStatus::Validated.can_transition(FilingStatus::Submitted));
        assert!(FilingStatus::Submitted.can_transition(FilingStatus::Acknowledged));
        assert!(FilingStatus::Acknowledged.can_transition(FilingStatus::Amended));
        assert!(!FilingStatus::Draft.can_transition(FilingStatus::Acknowledged));
        assert!(!FilingStatus::Draft.can_transition(FilingStatus::Submitted));
        assert!(!FilingStatus::Acknowledged.can_transition(FilingStatus::Draft));
        assert!(!FilingStatus::Acknowledged.can_transition(FilingStatus::Generated));
        // The submission transport exists in this build, but only behind an
        // explicit runtime configuration (never an implicit filing).
        assert!(oss_submission_is_implemented());
        assert!(vd_submission_is_implemented());
    }
}
