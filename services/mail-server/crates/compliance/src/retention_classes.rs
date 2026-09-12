//! Retention classes — the legal buckets behind the operational RET-001..023
//! registry.
//!
//! [`crate::retention`] answers "how long may the platform keep this by
//! policy?"; a retention class answers "what does the law require or allow?".
//! The distinction matters at erasure time: a statutory class (Estonian
//! accounting evidence, seven years) has an independent legal-retention
//! obligation, so an ordinary Art. 17 erasure must NOT delete records in that
//! class — it moves them to the legally-restricted archive
//! ([`crate::legal_archive`]) and discloses what was retained, why and until
//! when.
//!
//! Seeding is DATA, not schema: [`ensure_seeded`] is an idempotent
//! `INSERT … ON CONFLICT (id) DO NOTHING`, so the compliance service can run
//! it with DML-only credentials and legitimate Legal edits made through the
//! registry survive subsequent boots.
//!
//! LAWYER-FREE ZONE: no class invents a legal conclusion. The statutory
//! accounting class carries the seven-year floor the GDPR governance finding
//! states for Estonia; every class is seeded with
//! `review_status = 'legal_input_required'` until Legal confirms wording and
//! applicability.

use chrono::{DateTime, Duration, Months, Utc};
use sqlx::PgPool;

/// The statutory accounting-evidence class (Estonian Accounting Act).
///
/// Seven years is the legal floor for accounting source documents; the DSAR
/// erasure path uses this constant to resolve what must be archived instead
/// of deleted.
pub const STATUTORY_ACCOUNTING_CLASS_ID: &str = "RC-STAT-ACCT-7Y";

/// One legally-grounded retention bucket.
#[derive(Debug, Clone, PartialEq)]
pub struct RetentionClass {
    pub id: String,
    pub name: String,
    pub description: String,
    pub statutory: bool,
    /// Minimum retention the platform must honour (days). For statutory
    /// classes this is the legal floor.
    pub minimum_days: i32,
    pub maximum_days: Option<i32>,
    /// Operational default when the class is not statutory.
    pub retention_days: i32,
    pub legal_basis_reference: Option<String>,
    pub jurisdiction: Option<String>,
    pub customer_selectable: bool,
    /// The RET-xxx category this class operationalises, when one exists.
    pub registry_category_id: Option<String>,
    pub review_status: String,
}

impl RetentionClass {
    /// Statutory expiry for a record in this class, measured from the
    /// record's own issue date. For statutory classes the MINIMUM is the
    /// obligation: expiry is never earlier than `minimum_days`, and a whole
    /// number of years is applied as CALENDAR years (seven years from
    /// 2026-01-01 is 2033-01-01, not 2555 fixed days, which would land two
    /// days early because of leap years).
    pub fn expiry_for(&self, issued_at: DateTime<Utc>) -> DateTime<Utc> {
        let days = if self.statutory {
            self.minimum_days.max(self.retention_days)
        } else {
            self.retention_days
        };
        if days > 0 && days % 365 == 0 {
            let years = (days / 365) as u32;
            return issued_at
                .checked_add_months(Months::new(years * 12))
                .unwrap_or(issued_at + Duration::days(i64::from(days)));
        }
        issued_at + Duration::days(i64::from(days))
    }
}

const LEGAL_INPUT: &str = "legal_input_required";

/// The seeded catalogue. Every entry is traceable to the finding or to the
/// operational registry category it operationalises; none asserts a legal
/// conclusion that Legal has not recorded.
pub fn seeded_retention_classes() -> Vec<RetentionClass> {
    vec![
        RetentionClass {
            id: STATUTORY_ACCOUNTING_CLASS_ID.into(),
            name: "Statutory accounting evidence (EE)".into(),
            description: "Invoices, credit notes and accounting source documents. Estonian \
                          accounting law requires accounting evidence to be retained for seven \
                          years; this obligation is independent of, and survives, an ordinary \
                          GDPR Art. 17 erasure. Records in this class are moved to the \
                          legally-restricted archive, not deleted."
                .into(),
            statutory: true,
            minimum_days: 2555,
            maximum_days: None,
            retention_days: 2555,
            legal_basis_reference: Some(
                "Estonian Accounting Act (Raamatupidamise seadus) — accounting evidence \
                 retention, seven years. Wording to be confirmed by Legal."
                    .into(),
            ),
            jurisdiction: Some("EE".into()),
            customer_selectable: false,
            registry_category_id: Some("RET-018".into()),
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-MESSAGE-CONTENT-7D".into(),
            name: "Message content (operational)".into(),
            description: "Message bodies, subject lines and attachments stored for delivery \
                          and short-lived troubleshooting."
                .into(),
            statutory: false,
            minimum_days: 0,
            maximum_days: Some(365),
            retention_days: 7,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: true,
            registry_category_id: Some("RET-001".into()),
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-EVENT-30D".into(),
            name: "Delivery/engagement events (operational)".into(),
            description: "Send, delivery, bounce, open and click events used for deliverability \
                          and abuse prevention."
                .into(),
            statutory: false,
            minimum_days: 1,
            maximum_days: Some(365),
            retention_days: 30,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: true,
            registry_category_id: Some("RET-007".into()),
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-AUDIT-365D".into(),
            name: "Audit / accountability trail (operational)".into(),
            description: "Tamper-evident audit log used for security, accountability and \
                          incident investigation."
                .into(),
            statutory: false,
            minimum_days: 30,
            maximum_days: Some(2555),
            retention_days: 365,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: true,
            registry_category_id: Some("RET-017".into()),
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-SUPPRESSION-INDEFINITE".into(),
            name: "Suppression / opt-out records".into(),
            description: "Do-not-contact records. Kept for as long as needed to honour the \
                          opt-out; deleting them would enable re-mailing a complainant."
                .into(),
            statutory: false,
            minimum_days: 0,
            maximum_days: None,
            retention_days: 0,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: false,
            registry_category_id: Some("RET-013".into()),
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-DSR-CASE-365D".into(),
            name: "DSR case records".into(),
            description: "Data-subject request records, verification outbox rows and produced \
                          exports, kept so the controller can demonstrate compliance (Art. 5(2), \
                          Art. 30)."
                .into(),
            statutory: false,
            minimum_days: 30,
            maximum_days: Some(2555),
            retention_days: 365,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: false,
            registry_category_id: None,
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-BREACH-RECORD-2555D".into(),
            name: "Breach/incident records".into(),
            description: "Breach reports, authority submissions and subject-notification \
                          evidence, kept to demonstrate accountability (Art. 33(5))."
                .into(),
            statutory: false,
            minimum_days: 365,
            maximum_days: Some(3650),
            retention_days: 2555,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: false,
            registry_category_id: None,
            review_status: LEGAL_INPUT.into(),
        },
        RetentionClass {
            id: "RC-OP-CONSENT-EVIDENCE-730D".into(),
            name: "Consent evidence".into(),
            description: "Signed consent certificates proving when and how consent was given \
                          or withdrawn."
                .into(),
            statutory: false,
            minimum_days: 30,
            maximum_days: Some(3650),
            retention_days: 730,
            legal_basis_reference: None,
            jurisdiction: None,
            customer_selectable: false,
            registry_category_id: None,
            review_status: LEGAL_INPUT.into(),
        },
    ]
}

/// Idempotently seed the catalogue. `ON CONFLICT DO NOTHING` is deliberate:
/// a class Legal has edited through the registry API must not be overwritten
/// on the next service boot.
pub async fn ensure_seeded(db: &PgPool) -> Result<usize, String> {
    let mut inserted = 0usize;
    for class in seeded_retention_classes() {
        let rows = sqlx::query(
            "INSERT INTO retention_classes
               (id, name, description, statutory, minimum_days, maximum_days,
                retention_days, legal_basis_reference, jurisdiction,
                customer_selectable, registry_category_id, review_status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&class.id)
        .bind(&class.name)
        .bind(&class.description)
        .bind(class.statutory)
        .bind(class.minimum_days)
        .bind(class.maximum_days)
        .bind(class.retention_days)
        .bind(&class.legal_basis_reference)
        .bind(&class.jurisdiction)
        .bind(class.customer_selectable)
        .bind(&class.registry_category_id)
        .bind(&class.review_status)
        .execute(db)
        .await
        .map_err(|e| format!("DB error seeding retention_classes: {e}"))?;
        inserted += rows.rows_affected() as usize;
    }
    Ok(inserted)
}

#[derive(sqlx::FromRow)]
struct RetentionClassRow {
    id: String,
    name: String,
    description: String,
    statutory: bool,
    minimum_days: i32,
    maximum_days: Option<i32>,
    retention_days: i32,
    legal_basis_reference: Option<String>,
    jurisdiction: Option<String>,
    customer_selectable: bool,
    registry_category_id: Option<String>,
    review_status: String,
}

impl RetentionClassRow {
    fn into_class(self) -> RetentionClass {
        RetentionClass {
            id: self.id,
            name: self.name,
            description: self.description,
            statutory: self.statutory,
            minimum_days: self.minimum_days,
            maximum_days: self.maximum_days,
            retention_days: self.retention_days,
            legal_basis_reference: self.legal_basis_reference,
            jurisdiction: self.jurisdiction,
            customer_selectable: self.customer_selectable,
            registry_category_id: self.registry_category_id,
            review_status: self.review_status,
        }
    }
}

/// Read one retention class.
pub async fn get(db: &PgPool, id: &str) -> Result<Option<RetentionClass>, String> {
    let row: Option<RetentionClassRow> = sqlx::query_as(
        "SELECT id, name, description, statutory, minimum_days, maximum_days,
                retention_days, legal_basis_reference, jurisdiction,
                customer_selectable, registry_category_id, review_status
         FROM retention_classes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error reading retention class {id}: {e}"))?;
    Ok(row.map(RetentionClassRow::into_class))
}

/// Read every class, statutory first.
pub async fn list(db: &PgPool) -> Result<Vec<RetentionClass>, String> {
    let rows: Vec<RetentionClassRow> = sqlx::query_as(
        "SELECT id, name, description, statutory, minimum_days, maximum_days,
                retention_days, legal_basis_reference, jurisdiction,
                customer_selectable, registry_category_id, review_status
         FROM retention_classes
         ORDER BY statutory DESC, minimum_days DESC, id",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error listing retention classes: {e}"))?;
    Ok(rows
        .into_iter()
        .map(RetentionClassRow::into_class)
        .collect())
}

/// Read the statutory accounting class, failing loudly when the registry has
/// not been seeded — an erasure must never silently treat a statutory record
/// as deletable because a lookup returned nothing.
pub async fn statutory_accounting_class(db: &PgPool) -> Result<RetentionClass, String> {
    get(db, STATUTORY_ACCOUNTING_CLASS_ID)
        .await?
        .ok_or_else(|| {
            format!(
                "retention class {STATUTORY_ACCOUNTING_CLASS_ID} is not seeded — refusing to \
                 decide statutory retention on an empty registry (run ensure_seeded)"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn statutory_accounting_class_is_seven_years_and_not_selectable() {
        let classes = seeded_retention_classes();
        let acct = classes
            .iter()
            .find(|c| c.id == STATUTORY_ACCOUNTING_CLASS_ID)
            .expect("statutory accounting class must be seeded");
        assert!(acct.statutory);
        assert!(
            acct.minimum_days >= 2555,
            "seven years (2555 days) is the legal floor, got {}",
            acct.minimum_days
        );
        assert!(
            !acct.customer_selectable,
            "a statutory class cannot be shortened by customer selection"
        );
        assert!(
            acct.legal_basis_reference
                .as_deref()
                .is_some_and(|r| !r.trim().is_empty()),
            "a statutory class must name its legal reference"
        );
    }

    #[test]
    fn all_seeded_classes_await_legal_review() {
        for class in seeded_retention_classes() {
            assert_eq!(
                class.review_status, LEGAL_INPUT,
                "{} must not claim legal review it has not had",
                class.id
            );
        }
    }

    #[test]
    fn statutory_expiry_uses_the_minimum_floor() {
        let mut class = seeded_retention_classes()
            .into_iter()
            .find(|c| c.id == STATUTORY_ACCOUNTING_CLASS_ID)
            .unwrap();
        assert_eq!(
            class.expiry_for(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            Utc.with_ymd_and_hms(2033, 1, 1, 0, 0, 0).unwrap(),
            "issued 2026-01-01 expires 2033-01-01 (seven years)"
        );
        // Even if an operational default were mistakenly shortened, the
        // statutory floor wins.
        class.retention_days = 30;
        assert_eq!(
            class.expiry_for(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            Utc.with_ymd_and_hms(2033, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn every_class_maps_to_a_real_operational_category_or_none() {
        let registry = crate::retention::seed_retention_registry();
        for class in seeded_retention_classes() {
            if let Some(id) = &class.registry_category_id {
                assert!(
                    registry.get(id).is_some(),
                    "{} maps to unknown registry category {id}",
                    class.id
                );
            }
        }
    }
}
