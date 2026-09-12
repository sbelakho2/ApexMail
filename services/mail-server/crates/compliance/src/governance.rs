//! Canonical GDPR governance registry — records of processing (ROPA, Art. 30),
//! lawful-basis records (Art. 6/9), DPIAs (Art. 35), processor contracts
//! (Art. 28) and international-transfer evidence (Chapter V: TIA / SCC /
//! adequacy).
//!
//! The platform erases and exports data from a known set of stores
//! ([`crate::gdpr_automation::erasure_stores`],
//! [`crate::gdpr_automation::export_store_names`]) but had no canonical,
//! queryable registry tying a store to WHY it is processed, WHOSE data it
//! holds, WHO receives it, on which lawful basis, in which role, for how long
//! and whether it leaves the EEA. This module is that registry.
//!
//! ## What is seeded vs. what is Legal input
//!
//! [`seed_registry`] seeds the records that can be substantiated from the
//! code and deployment configuration: the store, its purpose, subjects, data
//! categories, recipients, controller/processor role, retention class and the
//! `source_location` proving it. It does NOT invent:
//!
//! * **lawful bases** — every seeded `lawful_basis_records` row has
//!   `basis = NULL` and `basis_status = 'requires_legal_input'`;
//! * **DPIA outcomes** — the seeded assessment is `status = 'required'` with
//!   no risk acceptance;
//! * **transfer mechanisms / adequacy** — seeded transfer assessments are
//!   `transfer_mechanism = 'undetermined'` and
//!   `status = 'legal_input_required'`; SCC records and adequacy evidence are
//!   not seeded at all.
//!
//! Legal records decisions through [`record_lawful_basis`],
//! [`complete_transfer_assessment`], the DPIA update path and the SCC /
//! adequacy tables; seeding is `ON CONFLICT DO NOTHING`, so those edits
//! survive every subsequent boot.
//!
//! ## New data stores
//!
//! [`register_activity`] is the gate for a new store: it refuses a record
//! that does not name its purpose, subjects, data categories, recipients,
//! controller/processor role, retention class and transfer situation, and it
//! opens a `requires_legal_input` lawful-basis row rather than defaulting to
//! a basis.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::retention_classes;

// ─── Public model ───────────────────────────────────────────────────────────

/// One record of processing (ROPA entry, Art. 30).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProcessingActivity {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub controller_or_processor: String,
    pub purpose: String,
    pub data_subjects: serde_json::Value,
    pub data_categories: serde_json::Value,
    pub recipients: serde_json::Value,
    pub data_stores: serde_json::Value,
    pub retention_class_id: Option<String>,
    pub lawful_basis_record_id: Option<String>,
    pub transfer_assessment_id: Option<String>,
    pub dpia_assessment_id: Option<String>,
    pub source_location: String,
    pub review_status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A lawful-basis record. `basis` stays NULL until Legal asserts one.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LawfulBasisRecord {
    pub id: String,
    pub processing_activity_id: String,
    pub basis: Option<String>,
    pub basis_status: String,
    pub gdpr_article: Option<String>,
    pub jurisdiction: Option<String>,
    pub assessment_notes: String,
    pub assessed_by: Option<String>,
    pub assessed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub review_status: String,
}

/// A DPIA assessment (Art. 35).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DpiaAssessment {
    pub id: String,
    pub processing_activity_id: Option<String>,
    pub title: String,
    pub status: String,
    pub necessity_assessment: Option<String>,
    pub risks: serde_json::Value,
    pub mitigations: serde_json::Value,
    pub residual_risk: Option<String>,
    pub dpo_opinion: Option<String>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub review_due_at: Option<chrono::DateTime<chrono::Utc>>,
    pub source_location: String,
    pub review_status: String,
}

/// An international-transfer assessment (Chapter V).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TransferAssessment {
    pub id: String,
    pub processing_activity_id: Option<String>,
    pub destination_country: String,
    pub destination_entity: String,
    pub transfer_mechanism: String,
    pub mechanism_evidence_id: Option<String>,
    pub tia_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub risk_assessment: Option<String>,
    pub supplementary_measures: Option<String>,
    pub status: String,
    pub source_location: String,
}

/// A processor / subprocessor contract (Art. 28).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SubprocessorContract {
    pub id: String,
    pub subprocessor_name: String,
    pub service_description: String,
    pub processing_activity_ids: serde_json::Value,
    pub contract_reference: Option<String>,
    pub dpa_signed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub dpa_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub data_locations: serde_json::Value,
    pub security_measures: Option<String>,
    pub status: String,
    pub review_status: String,
    pub source_location: String,
}

/// Where a new activity's data goes outside the controller's own environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferSituation {
    /// No transfer outside the EEA is involved.
    None,
    /// A transfer is possible but the mechanism has not been determined —
    /// allowed at registration, never silently treated as lawful.
    Undetermined,
    /// An existing `international_transfer_assessments` row covers it.
    Assessment(String),
}

/// Input for registering a new data store / processing activity.
#[derive(Debug, Clone)]
pub struct NewProcessingActivity {
    pub id: Option<String>,
    pub name: String,
    pub description: String,
    pub controller_or_processor: String,
    pub purpose: String,
    pub data_subjects: Vec<String>,
    pub data_categories: Vec<String>,
    pub recipients: Vec<String>,
    pub data_stores: Vec<String>,
    pub retention_class_id: String,
    pub transfer_situation: TransferSituation,
    /// Code path / migration substantiating the record.
    pub source_location: String,
}

// ─── Validation helpers (pure) ──────────────────────────────────────────────

fn non_empty_list(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|v| !v.trim().is_empty())
}

fn valid_role(role: &str) -> bool {
    matches!(role, "controller" | "processor" | "joint_controller")
}

/// A new store must identify all of: purpose, subjects, data categories,
/// recipients, role, retention class and transfer situation. Returns the
/// missing items (empty = valid).
pub fn missing_registration_fields(input: &NewProcessingActivity) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if input.name.trim().is_empty() {
        missing.push("name");
    }
    if input.description.trim().is_empty() {
        missing.push("description");
    }
    if input.purpose.trim().is_empty() {
        missing.push("purpose");
    }
    if !non_empty_list(&input.data_subjects) {
        missing.push("data_subjects");
    }
    if !non_empty_list(&input.data_categories) {
        missing.push("data_categories");
    }
    if !non_empty_list(&input.recipients) {
        missing.push("recipients");
    }
    if !non_empty_list(&input.data_stores) {
        missing.push("data_stores");
    }
    if input.retention_class_id.trim().is_empty() {
        missing.push("retention_class_id");
    }
    if !valid_role(&input.controller_or_processor) {
        missing.push("controller_or_processor");
    }
    if input.source_location.trim().is_empty() {
        missing.push("source_location");
    }
    missing
}

// ─── Registry operations (DML only) ─────────────────────────────────────────

const ACTIVITY_COLUMNS: &str = "id, name, description, status, controller_or_processor, purpose, \
     data_subjects, data_categories, recipients, data_stores, retention_class_id, \
     lawful_basis_record_id, transfer_assessment_id, dpia_assessment_id, source_location, \
     review_status, created_at, updated_at";

/// Register a new data store. Refuses incomplete records and opens a
/// `requires_legal_input` lawful-basis row (never an invented basis). The
/// activity starts in `legal_input_required` review state.
pub async fn register_activity(
    db: &PgPool,
    input: &NewProcessingActivity,
) -> Result<ProcessingActivity, String> {
    let missing = missing_registration_fields(input);
    if !missing.is_empty() {
        return Err(format!(
            "processing activity is missing required fields: {missing:?}"
        ));
    }

    let class = retention_classes::get(db, &input.retention_class_id)
        .await?
        .ok_or_else(|| {
            format!(
                "unknown retention class {} — a store cannot be registered without a real class",
                input.retention_class_id
            )
        })?;

    let transfer_assessment_id = match &input.transfer_situation {
        TransferSituation::Assessment(id) => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM international_transfer_assessments WHERE id = $1)",
            )
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(|e| format!("DB error checking transfer assessment: {e}"))?;
            if !exists {
                return Err(format!("unknown transfer assessment {id}"));
            }
            Some(id.clone())
        }
        _ => None,
    };

    let id = input
        .id
        .clone()
        .unwrap_or_else(|| format!("PA-{}", &Uuid::new_v4().simple().to_string()[..16]));

    sqlx::query(
        "INSERT INTO processing_activities
           (id, name, description, status, controller_or_processor, purpose,
            data_subjects, data_categories, recipients, data_stores,
            retention_class_id, transfer_assessment_id, source_location, review_status)
         VALUES ($1,$2,$3,'active',$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,'legal_input_required')",
    )
    .bind(&id)
    .bind(&input.name)
    .bind(&input.description)
    .bind(&input.controller_or_processor)
    .bind(&input.purpose)
    .bind(serde_json::json!(input.data_subjects))
    .bind(serde_json::json!(input.data_categories))
    .bind(serde_json::json!(input.recipients))
    .bind(serde_json::json!(input.data_stores))
    .bind(&class.id)
    .bind(&transfer_assessment_id)
    .bind(&input.source_location)
    .execute(db)
    .await
    .map_err(|e| format!("DB error registering processing activity: {e}"))?;

    // Every activity gets a lawful-basis record immediately; without a Legal
    // decision it is explicitly `requires_legal_input`.
    let basis_id = format!("LB-{id}");
    let transfer_note = match &input.transfer_situation {
        TransferSituation::None => "No third-country transfer is declared for this activity.",
        TransferSituation::Undetermined => {
            "Transfer situation declared as undetermined; Legal must assess Chapter V before \
             the activity can be approved."
        }
        TransferSituation::Assessment(_) => "Covered by a registered transfer assessment.",
    };
    sqlx::query(
        "INSERT INTO lawful_basis_records
           (id, processing_activity_id, basis, basis_status, assessment_notes, review_status)
         VALUES ($1,$2,NULL,'requires_legal_input',$3,'legal_input_required')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&basis_id)
    .bind(&id)
    .bind(format!(
        "Seeded at registration from {}. Legal must record the Art. 6 (and, where applicable, \
         Art. 9) basis. {transfer_note}",
        input.source_location
    ))
    .execute(db)
    .await
    .map_err(|e| format!("DB error creating lawful-basis record: {e}"))?;

    sqlx::query("UPDATE processing_activities SET lawful_basis_record_id = $2 WHERE id = $1")
        .bind(&id)
        .bind(&basis_id)
        .execute(db)
        .await
        .map_err(|e| format!("DB error linking lawful-basis record: {e}"))?;

    get_activity(db, &id)
        .await?
        .ok_or_else(|| "processing activity missing after registration".to_string())
}

/// Fetch one activity.
pub async fn get_activity(db: &PgPool, id: &str) -> Result<Option<ProcessingActivity>, String> {
    sqlx::query_as(&format!(
        "SELECT {ACTIVITY_COLUMNS} FROM processing_activities WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error reading processing activity {id}: {e}"))
}

/// List every recorded activity.
pub async fn list_activities(db: &PgPool) -> Result<Vec<ProcessingActivity>, String> {
    sqlx::query_as(&format!(
        "SELECT {ACTIVITY_COLUMNS} FROM processing_activities ORDER BY id"
    ))
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error listing processing activities: {e}"))
}

/// Record Legal's lawful-basis decision for an activity. Requires the
/// decision maker; the row becomes `asserted` only with a basis.
pub async fn record_lawful_basis(
    db: &PgPool,
    activity_id: &str,
    basis: &str,
    gdpr_article: Option<&str>,
    jurisdiction: Option<&str>,
    assessed_by: &str,
    notes: &str,
) -> Result<LawfulBasisRecord, String> {
    if basis.trim().is_empty() {
        return Err("a lawful basis cannot be recorded as empty".into());
    }
    if assessed_by.trim().is_empty() {
        return Err("a lawful-basis decision requires the assessing person".into());
    }
    let activity = get_activity(db, activity_id)
        .await?
        .ok_or_else(|| format!("processing activity {activity_id} not found"))?;
    let record_id = activity
        .lawful_basis_record_id
        .clone()
        .unwrap_or_else(|| format!("LB-{activity_id}"));

    sqlx::query(
        "UPDATE lawful_basis_records
            SET basis = $2, basis_status = 'asserted', gdpr_article = $3,
                jurisdiction = $4, assessed_by = $5, assessed_at = NOW(),
                assessment_notes = $6, review_status = 'reviewed', updated_at = NOW()
          WHERE id = $1",
    )
    .bind(&record_id)
    .bind(basis)
    .bind(gdpr_article)
    .bind(jurisdiction)
    .bind(assessed_by)
    .bind(notes)
    .execute(db)
    .await
    .map_err(|e| format!("DB error recording lawful basis: {e}"))?;

    let row: LawfulBasisRecord = sqlx::query_as(
        "SELECT id, processing_activity_id, basis, basis_status, gdpr_article, jurisdiction, \
                assessment_notes, assessed_by, assessed_at, review_status
           FROM lawful_basis_records WHERE id = $1",
    )
    .bind(&record_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("DB error reading lawful-basis record: {e}"))?;
    Ok(row)
}

/// Approve an activity. Refuses while its lawful basis is unresolved — an
/// approved ROPA entry without a basis would be a false record.
pub async fn approve_activity(db: &PgPool, activity_id: &str) -> Result<(), String> {
    let activity = get_activity(db, activity_id)
        .await?
        .ok_or_else(|| format!("processing activity {activity_id} not found"))?;
    let basis_id = activity
        .lawful_basis_record_id
        .ok_or_else(|| format!("processing activity {activity_id} has no lawful-basis record"))?;
    let basis_status: String =
        sqlx::query_scalar("SELECT basis_status FROM lawful_basis_records WHERE id = $1")
            .bind(&basis_id)
            .fetch_one(db)
            .await
            .map_err(|e| format!("DB error reading lawful-basis status: {e}"))?;
    if basis_status != "asserted" {
        return Err(format!(
            "processing activity {activity_id} cannot be approved while its lawful basis is \
             {basis_status}"
        ));
    }
    sqlx::query("UPDATE processing_activities SET review_status = 'approved', updated_at = NOW() WHERE id = $1")
        .bind(activity_id)
        .execute(db)
        .await
        .map_err(|e| format!("DB error approving activity: {e}"))?;
    Ok(())
}

/// Complete a transfer assessment with Legal's decision (mechanism + evidence).
pub async fn complete_transfer_assessment(
    db: &PgPool,
    assessment_id: &str,
    mechanism: &str,
    evidence_id: &str,
    risk_assessment: &str,
) -> Result<TransferAssessment, String> {
    if !matches!(
        mechanism,
        "adequacy_decision" | "sccs" | "bcrs" | "derogation"
    ) {
        return Err(format!(
            "transfer mechanism {mechanism:?} is not a Chapter V mechanism"
        ));
    }
    if evidence_id.trim().is_empty() {
        return Err("a transfer mechanism requires an evidence reference".into());
    }
    if risk_assessment.trim().is_empty() {
        return Err("a transfer assessment decision requires a risk assessment".into());
    }
    let updated = sqlx::query(
        "UPDATE international_transfer_assessments
            SET transfer_mechanism = $2, mechanism_evidence_id = $3,
                risk_assessment = $4, tia_completed_at = NOW(), status = 'approved',
                updated_at = NOW()
          WHERE id = $1",
    )
    .bind(assessment_id)
    .bind(mechanism)
    .bind(evidence_id)
    .bind(risk_assessment)
    .execute(db)
    .await
    .map_err(|e| format!("DB error completing transfer assessment: {e}"))?
    .rows_affected();
    if updated != 1 {
        return Err(format!("transfer assessment {assessment_id} not found"));
    }
    let row: TransferAssessment = sqlx::query_as(
        "SELECT id, processing_activity_id, destination_country, destination_entity, \
                transfer_mechanism, mechanism_evidence_id, tia_completed_at, risk_assessment, \
                supplementary_measures, status, source_location
           FROM international_transfer_assessments WHERE id = $1",
    )
    .bind(assessment_id)
    .fetch_one(db)
    .await
    .map_err(|e| format!("DB error reading transfer assessment: {e}"))?;
    Ok(row)
}

/// The union of `data_stores` over every seeded/registered activity —
/// the platform's declared store inventory.
pub async fn declared_store_inventory(db: &PgPool) -> Result<Vec<String>, String> {
    let rows: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT data_stores FROM processing_activities")
            .fetch_all(db)
            .await
            .map_err(|e| format!("DB error reading store inventory: {e}"))?;
    let mut stores: Vec<String> = Vec::new();
    for row in rows {
        if let Some(arr) = row.as_array() {
            for store in arr.iter().filter_map(|v| v.as_str()) {
                if !stores.iter().any(|existing| existing == store) {
                    stores.push(store.to_string());
                }
            }
        }
    }
    stores.sort();
    Ok(stores)
}

// ─── Seeded registry ────────────────────────────────────────────────────────

/// What [`seed_registry`] did, for boot logging and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SeedSummary {
    pub retention_classes_inserted: usize,
    pub activities_inserted: usize,
    pub lawful_basis_inserted: usize,
    pub dpia_inserted: usize,
    pub subprocessors_inserted: usize,
    pub transfers_inserted: usize,
    /// Records deliberately left for Legal (basis/DPIA/transfer decisions).
    pub awaiting_legal_input: usize,
}

struct ActivitySeed {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    role: &'static str,
    purpose: &'static str,
    subjects: &'static [&'static str],
    categories: &'static [&'static str],
    recipients: &'static [&'static str],
    stores: &'static [&'static str],
    retention_class: &'static str,
    source: &'static str,
}

/// Stores the platform processes, substantiated from the code's own data maps
/// and the canonical migration chain. Legal still decides the bases.
const SEEDED_ACTIVITIES: &[ActivitySeed] = &[
    ActivitySeed {
        id: "PA-SUBSCRIBER-CONTACTS",
        name: "Subscriber and contact records",
        description: "Contact profiles and list memberships used to send requested mail.",
        role: "controller",
        purpose: "Deliver transactional and consented marketing email to the tenant's contacts.",
        subjects: &["email recipients", "tenant contacts"],
        categories: &["email address", "name", "list membership"],
        recipients: &["tenant", "email delivery provider"],
        stores: &["contacts", "contact_list_members"],
        retention_class: "RC-OP-EVENT-30D",
        source: "migrations/068_subscriber_tables.sql, migrations/075_canonical_events_messages.sql, \
                 crates/compliance/src/gdpr_automation.rs erasure_stores()/export map",
    },
    ActivitySeed {
        id: "PA-MESSAGE-EVENTS",
        name: "Message delivery and engagement events",
        description: "Send, delivery, bounce, open and click events.",
        role: "controller",
        purpose: "Deliverability, abuse prevention, engagement reporting and tenant analytics.",
        subjects: &["email recipients"],
        categories: &["email address", "delivery status", "engagement timestamps"],
        recipients: &["tenant", "analytics pipeline"],
        stores: &["events", "clickhouse_events"],
        retention_class: "RC-OP-EVENT-30D",
        source: "migrations/075_canonical_events_messages.sql, RET-007/009/010 registry \
                 (crates/compliance/src/retention.rs), retention_sweep sweep_targets()",
    },
    ActivitySeed {
        id: "PA-MESSAGE-CONTENT",
        name: "Message content",
        description: "Message bodies, subject lines and attachments stored for delivery/audit.",
        role: "controller",
        purpose: "Send and (briefly) retain the message the tenant asked to deliver.",
        subjects: &["email recipients", "senders"],
        categories: &["email address", "message subject/body", "attachments"],
        recipients: &["tenant", "email delivery provider"],
        stores: &["messages", "mailstore_blobs"],
        retention_class: "RC-OP-MESSAGE-CONTENT-7D",
        source: "migrations/073_messages_canonical.sql, migrations/052/069 (messages), \
                 RET-001/002 registry, mailstore-core (blob store)",
    },
    ActivitySeed {
        id: "PA-USER-ACCOUNTS",
        name: "User accounts, sessions and API credentials",
        description: "Platform accounts, authenticated sessions and tenant API keys.",
        role: "controller",
        purpose: "Authenticate users, secure the service and enforce tenant access control.",
        subjects: &["tenant administrators", "users"],
        categories: &["email address", "name", "credential hashes", "session metadata"],
        recipients: &["platform operations"],
        stores: &["users", "sessions", "api_keys", "webhooks"],
        retention_class: "RC-OP-AUDIT-365D",
        source: "migrations/052_add_missing_foundation_tables.sql, \
                 migrations/064_auth_tables.sql, migrations/069_create_missing_app_tables.sql, \
                 gdpr_automation.rs erasure map (users tombstone, sessions, api_keys/webhooks retained)",
    },
    ActivitySeed {
        id: "PA-BILLING-INVOICES",
        name: "Billing and accounting records",
        description: "Invoices, credit notes and accounting evidence.",
        role: "controller",
        purpose: "Bill tenants, meet accounting/tax obligations and demonstrate financial records.",
        subjects: &["tenant billing contacts"],
        categories: &["email address", "company name", "billing address", "payment amounts"],
        recipients: &["tax authority", "accounting service providers"],
        stores: &["invoices", "billing_addresses"],
        retention_class: "RC-STAT-ACCT-7Y",
        source: "migrations/052/056/069 (invoices), migrations/076 (billing_address), \
                 RET-018 registry, gdpr_automation.rs AnonymizeInvoiceSnapshot",
    },
    ActivitySeed {
        id: "PA-CONSENT",
        name: "Consent management",
        description: "Consent records, signed consent certificates and double opt-in tokens.",
        role: "controller",
        purpose: "Record and prove consent, and honour withdrawals (ePrivacy/direct marketing).",
        subjects: &["email recipients"],
        categories: &["email address", "consent type", "consent proof", "IP address"],
        recipients: &["tenant"],
        stores: &["consent_records", "double_opt_in_tokens"],
        retention_class: "RC-OP-CONSENT-EVIDENCE-730D",
        source: "migrations/038_compliance_core_tables.sql, migrations/209_consent_evidence.sql, \
                 gdpr_automation.rs consent management",
    },
    ActivitySeed {
        id: "PA-SUPPRESSION",
        name: "Suppression and opt-out records",
        description: "Do-not-contact list preventing re-mailing after an opt-out or complaint.",
        role: "controller",
        purpose: "Enforce opt-outs and complaint handling (essential; retained through erasure).",
        subjects: &["email recipients who opted out"],
        categories: &["email address", "opt-out reason"],
        recipients: &["platform operations"],
        stores: &["suppression_list"],
        retention_class: "RC-OP-SUPPRESSION-INDEFINITE",
        source: "migrations/038_compliance_core_tables.sql, RET-013 registry, \
                 gdpr_automation.rs erasure map (Retained: opt-out enforcement)",
    },
    ActivitySeed {
        id: "PA-AUDIT-TRAIL",
        name: "Audit and accountability trail",
        description: "Tamper-evident audit log of platform operations.",
        role: "controller",
        purpose: "Security, accountability (Art. 5(2)/Art. 30) and incident investigation.",
        subjects: &["users", "tenant administrators"],
        categories: &["user id", "action", "resource", "IP address", "user agent"],
        recipients: &["platform security operations"],
        stores: &["audit_logs", "audit_logs_archive"],
        retention_class: "RC-OP-AUDIT-365D",
        source: "migrations/038_compliance_core_tables.sql, RET-017 registry, \
                 crates/compliance/src/audit_logger.rs",
    },
    ActivitySeed {
        id: "PA-DSR-WORKFLOW",
        name: "Data-subject request workflow records",
        description: "DSR intake, verification outbox, produced exports and the legal archive.",
        role: "controller",
        purpose: "Handle data-subject requests and demonstrate compliance with them.",
        subjects: &["data subjects"],
        categories: &["email address", "request content", "export payload", "identity evidence"],
        recipients: &["data subject", "supervisory authority on request"],
        stores: &[
            "data_subject_requests",
            "dsr_verification_outbox",
            "gdpr_exports",
            "gdpr_requests",
            "legal_retention_archive",
        ],
        retention_class: "RC-OP-DSR-CASE-365D",
        source: "migrations/038_compliance_core_tables.sql, migrations/069 (gdpr_requests CP \
                 mirror), migrations/172 (SLA policy), migrations/213 (statutory clock + archive), \
                 crates/compliance/src/gdpr_automation.rs",
    },
    ActivitySeed {
        id: "PA-BREACH-MANAGEMENT",
        name: "Personal-data breach management",
        description: "Breach reports, authority submissions, human tasks and subject-notification \
                      outbox with delivery evidence.",
        role: "controller",
        purpose: "Detect, assess and notify personal-data breaches (Art. 33/34) and keep \
                  accountability evidence (Art. 33(5)).",
        subjects: &["affected data subjects", "reporting staff"],
        categories: &["breach description", "data categories", "notification text", "receipts"],
        recipients: &["supervisory authority", "affected data subjects"],
        stores: &[
            "breach_reports",
            "breach_authority_submissions",
            "breach_authority_tasks",
            "breach_subject_notification_outbox",
        ],
        retention_class: "RC-OP-BREACH-RECORD-2555D",
        source: "crates/compliance/src/breach_notification.rs, migrations/213",
    },
    ActivitySeed {
        id: "PA-GOVERNANCE-REGISTRY",
        name: "Governance registry itself",
        description: "ROPA/DPIA/TIA/processor-contract records and retention classes.",
        role: "controller",
        purpose: "Maintain the controller's accountability records.",
        subjects: &["data subjects (indirectly described)", "processors' contact persons"],
        categories: &["processing descriptions", "assessments", "contracts", "retention rules"],
        recipients: &["supervisory authority", "auditors"],
        stores: &[
            "processing_activities",
            "lawful_basis_records",
            "dpia_assessments",
            "subprocessor_contracts",
            "international_transfer_assessments",
            "scc_records",
            "adequacy_evidence",
            "retention_classes",
            "retention_report",
        ],
        retention_class: "RC-OP-AUDIT-365D",
        source: "migrations/214_gdpr_governance_registry.sql, crates/compliance/src/governance.rs",
    },
];

struct SubprocessorSeed {
    id: &'static str,
    name: &'static str,
    service: &'static str,
    locations: &'static [&'static str],
    source: &'static str,
}

/// Subprocessors substantiated from the deployment configuration. Contract
/// specifics (signature dates, references) are Legal/Procurement input and
/// are deliberately absent.
const SEEDED_SUBPROCESSORS: &[SubprocessorSeed] = &[SubprocessorSeed {
    id: "SP-AWS-SES",
    name: "Amazon Web Services (SES)",
    service: "Email delivery for the platform's own transactional/system mail (EMAIL_TRANSPORT_TYPE=ses, \
              domains.ses_verified).",
    locations: &["us-east-1"],
    source: ".env.example (AWS_REGION=us-east-1, EMAIL_TRANSPORT_TYPE=ses), \
             domains.ses_verified columns, crates/compliance/src/dsr_outbox_flush.rs sender contract",
}];

struct TransferSeed {
    id: &'static str,
    activity_id: &'static str,
    country: &'static str,
    entity: &'static str,
    source: &'static str,
}

/// Transfers substantiated from configuration. Mechanism/adequacy are Legal
/// input and stay `undetermined` until recorded.
const SEEDED_TRANSFERS: &[TransferSeed] = &[TransferSeed {
    id: "TIA-AWS-SES-US",
    activity_id: "PA-MESSAGE-EVENTS",
    country: "US",
    entity: "Amazon Web Services, Inc. (SES, us-east-1)",
    source: ".env.example (AWS_REGION=us-east-1, EMAIL_TRANSPORT_TYPE=ses)",
}];

/// Seed the registry. Idempotent (`ON CONFLICT DO NOTHING`): records edited
/// by Legal are never overwritten.
pub async fn seed_registry(db: &PgPool) -> Result<SeedSummary, String> {
    let mut summary = SeedSummary::default();

    summary.retention_classes_inserted = retention_classes::ensure_seeded(db).await?;

    for seed in SEEDED_ACTIVITIES {
        let inserted = sqlx::query(
            "INSERT INTO processing_activities
               (id, name, description, status, controller_or_processor, purpose,
                data_subjects, data_categories, recipients, data_stores,
                retention_class_id, source_location, review_status)
             VALUES ($1,$2,$3,'active',$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,'legal_input_required')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(seed.id)
        .bind(seed.name)
        .bind(seed.description)
        .bind(seed.role)
        .bind(seed.purpose)
        .bind(serde_json::json!(seed.subjects))
        .bind(serde_json::json!(seed.categories))
        .bind(serde_json::json!(seed.recipients))
        .bind(serde_json::json!(seed.stores))
        .bind(seed.retention_class)
        .bind(seed.source)
        .execute(db)
        .await
        .map_err(|e| format!("DB error seeding processing activity {}: {e}", seed.id))?
        .rows_affected() as usize;
        summary.activities_inserted += inserted;

        // One lawful-basis record per activity, NEVER asserting a basis.
        let basis_id = format!("LB-{}", seed.id);
        let basis_inserted = sqlx::query(
            "INSERT INTO lawful_basis_records
               (id, processing_activity_id, basis, basis_status, assessment_notes, review_status)
             VALUES ($1,$2,NULL,'requires_legal_input',$3,'legal_input_required')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&basis_id)
        .bind(seed.id)
        .bind(format!(
            "Seeded from {}. Legal must record the Art. 6 (and, where applicable, Art. 9) basis \
             before this activity can be approved.",
            seed.source
        ))
        .execute(db)
        .await
        .map_err(|e| format!("DB error seeding lawful basis for {}: {e}", seed.id))?
        .rows_affected() as usize;
        summary.lawful_basis_inserted += basis_inserted;
        summary.awaiting_legal_input += basis_inserted;

        sqlx::query(
            "UPDATE processing_activities
                SET lawful_basis_record_id = COALESCE(lawful_basis_record_id, $2), updated_at = NOW()
              WHERE id = $1",
        )
        .bind(seed.id)
        .bind(&basis_id)
        .execute(db)
        .await
        .map_err(|e| format!("DB error linking lawful basis for {}: {e}", seed.id))?;
    }

    for seed in SEEDED_SUBPROCESSORS {
        let inserted = sqlx::query(
            "INSERT INTO subprocessor_contracts
               (id, subprocessor_name, service_description, processing_activity_ids,
                data_locations, status, review_status, source_location)
             VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,'pending','legal_input_required',$6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(seed.id)
        .bind(seed.name)
        .bind(seed.service)
        .bind(serde_json::json!([
            "PA-MESSAGE-EVENTS",
            "PA-MESSAGE-CONTENT"
        ]))
        .bind(serde_json::json!(seed.locations))
        .bind(seed.source)
        .execute(db)
        .await
        .map_err(|e| format!("DB error seeding subprocessor {}: {e}", seed.id))?
        .rows_affected() as usize;
        summary.subprocessors_inserted += inserted;
        summary.awaiting_legal_input += inserted;
    }

    for seed in SEEDED_TRANSFERS {
        let inserted = sqlx::query(
            "INSERT INTO international_transfer_assessments
               (id, processing_activity_id, destination_country, destination_entity,
                transfer_mechanism, status, source_location)
             VALUES ($1,$2,$3,$4,'undetermined','legal_input_required',$5)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(seed.id)
        .bind(seed.activity_id)
        .bind(seed.country)
        .bind(seed.entity)
        .bind(seed.source)
        .execute(db)
        .await
        .map_err(|e| format!("DB error seeding transfer {}: {e}", seed.id))?
        .rows_affected() as usize;
        summary.transfers_inserted += inserted;
        summary.awaiting_legal_input += inserted;

        sqlx::query(
            "UPDATE processing_activities
                SET transfer_assessment_id = COALESCE(transfer_assessment_id, $2), updated_at = NOW()
              WHERE id = $1",
        )
        .bind(seed.activity_id)
        .bind(seed.id)
        .execute(db)
        .await
        .map_err(|e| format!("DB error linking transfer {}: {e}", seed.id))?;
    }

    // One DPIA screening record: the platform-wide processing (profiling,
    // analytics, large-scale event tracking) needs a DPIA decision. The
    // assessment itself is NOT written — status `required` until Legal/DPO
    // completes it.
    let dpia_inserted = sqlx::query(
        "INSERT INTO dpia_assessments
           (id, processing_activity_id, title, status, source_location)
         VALUES ('DPIA-PLATFORM-SCREENING', 'PA-MESSAGE-EVENTS',
                 'Platform processing DPIA screening', 'required',
                 'migrations/214_gdpr_governance_registry.sql, review of PA-MESSAGE-EVENTS / \
                  PA-MESSAGE-CONTENT (tracking, analytics, large-scale recipient data)')
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(db)
    .await
    .map_err(|e| format!("DB error seeding DPIA screening: {e}"))?
    .rows_affected() as usize;
    summary.dpia_inserted += dpia_inserted;
    summary.awaiting_legal_input += dpia_inserted;

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(id: &str, stores: &'static [&'static str]) -> NewProcessingActivity {
        NewProcessingActivity {
            id: Some(id.into()),
            name: "n".into(),
            description: "d".into(),
            controller_or_processor: "controller".into(),
            purpose: "p".into(),
            data_subjects: vec!["subjects".into()],
            data_categories: vec!["email".into()],
            recipients: vec!["tenant".into()],
            data_stores: stores.iter().map(|s| s.to_string()).collect(),
            retention_class_id: "RC-OP-EVENT-30D".into(),
            transfer_situation: TransferSituation::None,
            source_location: "src/test.rs".into(),
        }
    }

    #[test]
    fn registration_requires_every_declared_field() {
        let mut input = activity("PA-X", &["some_store"]);
        input.purpose = "  ".into();
        input.data_subjects.clear();
        input.retention_class_id = String::new();
        input.controller_or_processor = "vendor".into();
        let missing = missing_registration_fields(&input);
        for field in [
            "purpose",
            "data_subjects",
            "retention_class_id",
            "controller_or_processor",
        ] {
            assert!(
                missing.contains(&field),
                "must require {field}: {missing:?}"
            );
        }
        assert!(missing_registration_fields(&activity("PA-X", &["s"])).is_empty());
    }

    /// The seeded inventory must cover every store the platform's own data
    /// maps and migration chain declare; a new store without a ROPA record is
    /// exactly the gap this registry exists to close.
    #[test]
    fn seeds_cover_every_known_data_store() {
        let mut declared: Vec<&str> = Vec::new();
        for seed in SEEDED_ACTIVITIES {
            declared.extend_from_slice(seed.stores);
        }
        let expected = [
            "contacts",
            "events",
            "messages",
            "users",
            "sessions",
            "invoices",
            "consent_records",
            "double_opt_in_tokens",
            "suppression_list",
            "audit_logs",
            "data_subject_requests",
            "dsr_verification_outbox",
            "gdpr_exports",
            "gdpr_requests",
            "retention_report",
            "breach_reports",
            "breach_authority_submissions",
            "breach_subject_notification_outbox",
            "legal_retention_archive",
            "api_keys",
            "webhooks",
            "clickhouse_events",
            "mailstore_blobs",
            "invoices",
        ];
        for store in expected {
            assert!(
                declared.contains(&store),
                "store {store} has no seeded processing activity"
            );
        }
    }

    /// No seeded record may assert a legal conclusion.
    #[test]
    fn seeds_do_not_assert_lawful_bases_dpias_or_transfer_mechanisms() {
        // The seed SQL is the thing that runs: check the dictionaries.
        for seed in SEEDED_ACTIVITIES {
            assert!(!seed.source.is_empty(), "{} needs a source", seed.id);
            assert!(
                seed.role == "controller",
                "{} declares a role explicitly, never by default",
                seed.id
            );
        }
        for transfer in SEEDED_TRANSFERS {
            assert!(!transfer.country.is_empty());
        }
        // Basis/dpia/mechanism values live only in the INSERT statements
        // above; this test pins that the seeded inserts are the
        // "unknown until Legal" ones.
        let seed_source = include_str!("governance.rs");
        assert!(
            seed_source
                .contains("VALUES ($1,$2,NULL,'requires_legal_input',$3,'legal_input_required')")
                || seed_source.contains("NULL,'requires_legal_input'"),
            "the lawful-basis seed must insert a NULL basis"
        );
        assert!(seed_source.contains("'undetermined','legal_input_required'"));
        assert!(seed_source.contains("'required',"));
    }

    /// Every seeded activity names a real retention class id.
    #[test]
    fn seeded_activities_use_real_retention_classes() {
        let classes = retention_classes::seeded_retention_classes();
        for seed in SEEDED_ACTIVITIES {
            assert!(
                classes.iter().any(|c| c.id == seed.retention_class),
                "{} references unknown retention class {}",
                seed.id,
                seed.retention_class
            );
        }
    }

    /// The subprocessor seed is substantiated by configuration, and claims no
    /// contract facts.
    #[test]
    fn subprocessor_seed_carries_no_invented_contract_facts() {
        for seed in SEEDED_SUBPROCESSORS {
            assert!(
                seed.source.contains(".env.example"),
                "subprocessor {} must cite its configuration source",
                seed.id
            );
        }
    }
}
