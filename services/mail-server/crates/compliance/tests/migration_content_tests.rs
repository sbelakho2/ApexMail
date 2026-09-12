//! F63 regression test: the canonical migration 168 must define the
//! contact_persons table that estonia_ou.rs register_contact_person writes
//! (INSERT ... ON CONFLICT (email) ... RETURNING). If this file fails after
//! 168 was renamed or reshaped, the crate's persistence contract has drifted
//! from the canonical schema — update the migration (or this test)
//! deliberately, never silently.

const MIGRATION_168: &str = include_str!("../../../migrations/168_compliance_contact_persons.sql");

#[test]
fn migration_168_defines_contact_persons() {
    assert!(
        MIGRATION_168.contains("CREATE TABLE IF NOT EXISTS contact_persons"),
        "migration 168 must create contact_persons"
    );

    // register_contact_person upserts ON CONFLICT (email) and binds
    // personal_code / phone as Option<&str>; registry_code is written as the
    // literal company registry code.
    assert!(MIGRATION_168.contains("email             TEXT        NOT NULL UNIQUE"));
    assert!(MIGRATION_168.contains("personal_code     TEXT"));
    assert!(MIGRATION_168.contains("phone             TEXT"));
    assert!(MIGRATION_168.contains("registry_code     VARCHAR(20) NOT NULL"));

    // record_contact_person_verification stores a contact-person id in
    // compliance_deadlines.submission_id; the migration must reconcile the
    // 079 cross-table FK so that UPDATE is not rejected.
    assert!(
        MIGRATION_168.contains("DROP CONSTRAINT %I"),
        "migration 168 must drop the compliance_deadlines.submission_id FK"
    );
}

// ── F81: canonical payroll tax inputs ─────────────────────────────────────

const MIGRATION_199: &str = include_str!("../../../migrations/199_payroll_tax_inputs.sql");

#[test]
fn migration_199_defines_payroll_records_with_per_employee_tax_inputs() {
    assert!(
        MIGRATION_199.contains("CREATE TABLE IF NOT EXISTS payroll_records"),
        "migration 199 must create payroll_records"
    );

    // query_employees (annual/statistical headcount) and tsd_ledger (the
    // TSD's person facts, joined through payroll_postings.payroll_record_id)
    // read the per-period inputs the date-effective policy consumes: the
    // employee's II-pillar choice and the exemption flags. The pension rate
    // must be constrained to the legal choices (0/2/4/6%) with NULL =
    // participation unknown.
    assert!(
        MIGRATION_199.contains("funded_pension_rate               DOUBLE PRECISION"),
        "per-employee pension choice column"
    );
    assert!(
        MIGRATION_199.contains("funded_pension_rate IN (0.0, 0.02, 0.04, 0.06)"),
        "pension rate constrained to the legal choices"
    );
    assert!(MIGRATION_199.contains("pension_exemption                 BOOLEAN"));
    assert!(MIGRATION_199.contains("unemployment_insurance_exemption  BOOLEAN"));

    // Rates themselves are NOT stored as constants here — they come from
    // the versioned date-effective tax policy module per payment period.
    assert!(MIGRATION_199.contains("pay_period                        TIMESTAMPTZ NOT NULL"));
    assert!(
        MIGRATION_199.contains("idx_payroll_records_period"),
        "per-period lookup index"
    );
}
